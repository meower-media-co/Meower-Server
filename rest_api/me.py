from quart import Blueprint, current_app as app, request, abort
from quart_schema import validate_request, validate_querystring
from pydantic import BaseModel, Field
from typing import Optional, List, Literal
from copy import copy
from base64 import b64encode
from io import BytesIO
import pymongo
import uuid
import time
import pyotp
import qrcode
import uuid
import secrets

import security
from database import db, rdb, get_total_pages
from uploads import claim_file, delete_file
from utils import log


me_bp = Blueprint("me_bp", __name__, url_prefix="/me")


class DeleteAccountBody(BaseModel):
    password: str = Field(min_length=1, max_length=255)  # change in API v1

class UpdateConfigBody(BaseModel):
    pfp_data: Optional[int] = Field(default=None)
    avatar: Optional[str] = Field(default=None, max_length=24)
    avatar_color: Optional[str] = Field(default=None, min_length=6, max_length=6)  # hex code without the #
    quote: Optional[str] = Field(default=None, max_length=360)
    unread_inbox: Optional[bool] = Field(default=None)
    theme: Optional[str] = Field(default=None, min_length=1, max_length=256)
    mode: Optional[bool] = Field(default=None)
    layout: Optional[str] = Field(default=None, min_length=1, max_length=256)
    sfx: Optional[bool] = Field(default=None)
    bgm: Optional[bool] = Field(default=None)
    bgm_song: Optional[int] = Field(default=None)
    debug: Optional[bool] = Field(default=None)
    hide_blocked_users: Optional[bool] = Field(default=None)
    favorited_chats: Optional[List[str]] = Field(default=None)

    class Config:
        validate_assignment = True
        str_strip_whitespace = True

class ChangePasswordBody(BaseModel):
    old: str = Field(min_length=1, max_length=255)  # change in API v1
    new: str = Field(min_length=8, max_length=72)

class AddAuthenticatorBody(BaseModel):
    password: str = Field(min_length=1, max_length=255)  # change in API v1
    type: Literal["totp"] = Field()
    nickname: str = Field(default="", max_length=32)
    totp_secret: Optional[str] = Field(default=None, min_length=32, max_length=32)
    totp_code: Optional[str] = Field(default=None, min_length=6, max_length=6)

class UpdateAuthenticatorBody(BaseModel):
    nickname: str = Field(default="", max_length=32)

class RemoveAuthenticatorBody(BaseModel):
    password: str = Field(min_length=1, max_length=255)  # change in API v1

class ResetMFARecoveryCodeBody(BaseModel):
    password: str = Field(min_length=1, max_length=255)  # change in API v1

class GetReportsQueryArgs(BaseModel):
    page: Optional[int] = Field(default=1, ge=1)


@me_bp.get("/")
async def get_me():
    # Check authorization
    if not request.user:
        abort(401)

    # Update last_seen (this is only to remove CL3's dependency on the DB)
    db.usersv0.update_one({"_id": request.user}, {"$set": {"last_seen": int(time.time())}})

    # Get and return account
    return security.get_account(request.user, include_config=True), 200


@me_bp.delete("/")
@validate_request(DeleteAccountBody)
async def delete_account(data: DeleteAccountBody):
    # Check authorization
    if not request.user:
        abort(401)

    # Check ratelimit
    if security.ratelimited(f"login:u:{request.user}"):
        abort(429)

    # Check password
    account = db.usersv0.find_one({"_id": request.user}, projection={"pswd": 1})
    if not security.check_password_hash(data.password, account["pswd"]):
        security.ratelimit(f"login:u:{request.user}", 5, 60)
        return {"error": True, "type": "invalidCredentials"}, 401
    
    # Schedule account for deletion
    db.usersv0.update_one({"_id": request.user}, {"$set": {
        "tokens": [],
        "delete_after": int(time.time())+604800  # 7 days
    }})

    # Disconnect clients
    for client in app.cl.usernames.get(request.user, []):
        client.kick()

    return {"error": False}, 200


@me_bp.patch("/config")
@validate_request(UpdateConfigBody)
async def update_config(data: UpdateConfigBody):
    # Check authorization
    if not request.user:
        abort(401)

    # Check ratelimit
    if security.ratelimited(f"config:{request.user}"):
        abort(429)
    
    # Ratelimit
    security.ratelimit(f"config:{request.user}", 10, 5)

    # Get new config
    new_config = data.model_dump()

    # Filter values that are set to None
    for k, v in copy(new_config).items():
        if v is None:
            del new_config[k]

    # Delete updated profile data if account is restricted
    if security.is_restricted(request.user, security.Restrictions.EDITING_PROFILE):
        if "pfp_data" in new_config:
            del new_config["pfp_data"]
        if "avatar" in new_config:
            del new_config["avatar"]
        if "avatar_color" in new_config:
            del new_config["avatar_color"]
        if "quote" in new_config:
            del new_config["quote"]

    # Claim avatar (and delete old one)
    if "avatar" in new_config:
        cur_avatar = db.usersv0.find_one({"_id": request.user}, projection={"avatar": 1})["avatar"]
        if new_config["avatar"] != "":
            try:
                claim_file(new_config["avatar"], "icons")
            except Exception as e:
                log(f"Unable to claim avatar: {e}")
                return {"error": True, "type": "unableToClaimAvatar"}, 500
        if cur_avatar:
            try:
                delete_file(cur_avatar)
            except Exception as e:
                log(f"Unable to delete avatar: {e}")

    # Update config
    security.update_settings(request.user, new_config)

    # Sync config between sessions
    app.cl.send_event("update_config", new_config, usernames=[request.user])

    # Send updated pfp and quote to other clients
    updated_profile_data = {"_id": request.user}
    if "pfp_data" in new_config:
        updated_profile_data["pfp_data"] = new_config["pfp_data"]
    if "avatar" in new_config:
        updated_profile_data["avatar"] = new_config["avatar"]
    if "avatar_color" in new_config:
        updated_profile_data["avatar_color"] = new_config["avatar_color"]
    if "quote" in new_config:
        updated_profile_data["quote"] = new_config["quote"]
    if len(updated_profile_data) > 1:
        app.cl.send_event("update_profile", updated_profile_data)

    return {"error": False}, 200


@me_bp.get("/relationships")
async def get_relationships():
    # Check authorization
    if not request.user:
        abort(401)

    return {
        "error": False,
        "autoget": [{
            "username": r["_id"]["to"],
            "state": r["state"],
            "updated_at": r["updated_at"]
        } for r in db.relationships.find({"_id.from": request.user})],
        "page#": 1,
        "pages": 1
    }, 200


@me_bp.patch("/password")
@validate_request(ChangePasswordBody)
async def change_password(data: ChangePasswordBody):
    # Check authorization
    if not request.user:
        abort(401)

    # Check ratelimit
    if security.ratelimited(f"login:u:{request.user}"):
        abort(429)

    # Check password
    account = db.usersv0.find_one({"_id": request.user}, projection={"pswd": 1})
    if not security.check_password_hash(data.old, account["pswd"]):
        security.ratelimit(f"login:u:{request.user}", 5, 60)
        return {"error": True, "type": "invalidCredentials"}, 401

    # Update password
    db.usersv0.update_one({"_id": request.user}, {"$set": {"pswd": security.hash_password(data.new)}})

    # Send alert
    app.supporter.create_post("inbox", account["_id"], "Your account password has been changed. If this wasn't requested by you, please secure your account immediately.")

    return {"error": False}, 200


@me_bp.get("/authenticators")
async def get_authenticators():
    return {
        "error": False,
        "autoget": list(db.authenticators.find({"user": request.user}, projection={
            "_id": 1,
            "type": 1,
            "nickname": 1,
            "registered_at": 1,
        })),
        "page#": 1,
        "pages": 1
    }, 200


@me_bp.post("/authenticators")
@validate_request(AddAuthenticatorBody)
async def add_authenticator(data: AddAuthenticatorBody):
    # Check authorization
    if not request.user:
        abort(401)

    # Validate
    if data.type == "totp" and data.totp_secret and data.totp_code:
        if not pyotp.TOTP(data.totp_secret).verify(data.totp_code, valid_window=1):
            return {"error": True, "type": "invalidTOTPCode"}, 401
    else:
        abort(400)

    # Check ratelimit
    if security.ratelimited(f"login:u:{request.user}"):
        abort(429)

    # Check password
    account = db.usersv0.find_one({"_id": request.user}, projection={"pswd": 1, "mfa_recovery_code": 1})
    if not security.check_password_hash(data.password, account["pswd"]):
        security.ratelimit(f"login:u:{request.user}", 5, 60)
        return {"error": True, "type": "invalidCredentials"}, 401
    
    # Register
    authenticator = {
        "_id": str(uuid.uuid4()),
        "user": request.user,
        "type": data.type,
        "nickname": data.nickname,
        "totp_secret": data.totp_secret,
        "registered_at": int(time.time())
    }
    db.authenticators.insert_one(authenticator)

    # Send alert
    app.supporter.create_post("inbox", account["_id"], "A multi-factor authenticator has been added to your account. If this wasn't requested by you, please secure your account immediately.")

    # Return authenticator and MFA recovery code
    del authenticator["user"]
    del authenticator["totp_secret"]
    return {
        "error": False,
        "authenticator": authenticator,
        "mfa_recovery_code": account["mfa_recovery_code"]
    }


@me_bp.patch("/authenticators/<authenticator_id>")
@validate_request(UpdateAuthenticatorBody)
async def update_authenticator(authenticator_id: str, data: UpdateAuthenticatorBody):
    # Check authorization
    if not request.user:
        abort(401)

    # Get authenticator
    authenticator = db.authenticators.find_one({
        "_id": authenticator_id,
        "user": request.user
    }, projection={
        "_id": 1,
        "type": 1,
        "nickname": 1,
        "registered_at": 1,
    })
    if not authenticator:
        abort(404)

    # Update
    updated = {}
    if data.nickname:
        updated["nickname"] = data.nickname
    authenticator.update(updated)
    db.authenticators.update_one({
        "_id": authenticator_id,
        "user": request.user
    }, {"$set": updated})

    return {"error": False, **authenticator}


@me_bp.delete("/authenticators/<authenticator_id>")
@validate_request(RemoveAuthenticatorBody)
async def remove_authenticator(authenticator_id: str, data: RemoveAuthenticatorBody):
    # Check authorization
    if not request.user:
        abort(401)

    # Check ratelimit
    if security.ratelimited(f"login:u:{request.user}"):
        abort(429)

    # Check password
    account = db.usersv0.find_one({"_id": request.user}, projection={"pswd": 1, "mfa_recovery_code": 1})
    if not security.check_password_hash(data.password, account["pswd"]):
        security.ratelimit(f"login:u:{request.user}", 5, 60)
        return {"error": True, "type": "invalidCredentials"}, 401

    # Unregister
    result = db.authenticators.delete_one({
        "_id": authenticator_id,
        "user": request.user
    })
    if result.deleted_count < 1:
        abort(404)

    # Send alert
    app.supporter.create_post("inbox", account["_id"], "A multi-factor authenticator has been removed from your account. If this wasn't requested by you, please secure your account immediately.")

    return {"error": False}


@me_bp.get("/authenticators/totp-secret")
async def get_new_totp_secret():
    # Check authorization
    if not request.user:
        abort(401)

    # Create secret and provisioning URI
    secret = pyotp.random_base32()
    provisioning_uri = pyotp.TOTP(secret).provisioning_uri(name=request.user, issuer_name="Meower")

    # Create QR code
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(provisioning_uri)
    qr.make(fit=True)

    # Create image from QR code
    img = qr.make_image(fill_color="black", back_color="white")
    buffered = BytesIO()
    img.save(buffered, format="WebP")
    img_str = b64encode(buffered.getvalue()).decode("utf-8")

    return {
        "error": False,
        "secret": secret,
        "provisioning_uri": provisioning_uri,
        "qr_code_data_uri": f"data:image/webp;base64,{img_str}"
    }


@me_bp.post("/reset-mfa-recovery-code")
@validate_request(ResetMFARecoveryCodeBody)
async def reset_mfa_recovery_code(data: ResetMFARecoveryCodeBody):
    # Check authorization
    if not request.user:
        abort(401)

    # Check password
    account = db.usersv0.find_one({"_id": request.user}, projection={"pswd": 1})
    if not security.check_password_hash(data.password, account["pswd"]):
        security.ratelimit(f"login:u:{request.user}", 5, 60)
        return {"error": True, "type": "invalidCredentials"}, 401
    
    # Reset MFA recovery code
    mfa_recovery_code = secrets.token_hex(5)
    db.usersv0.update_one({"_id": request.user}, {"$set": {"mfa_recovery_code": mfa_recovery_code}})

    # Send alert
    app.supporter.create_post("inbox", account["_id"], "Your multi-factor authentication recovery code has been reset. If this wasn't requested by you, please secure your account immediately.")

    return {"error": False, "mfa_recovery_code": mfa_recovery_code}


@me_bp.delete("/tokens")
async def delete_tokens():
    # Check authorization
    if not request.user:
        abort(401)
    
    # Revoke tokens
    db.usersv0.update_one({"_id": request.user}, {"$set": {"tokens": []}})

    # Disconnect clients
    for client in app.cl.usernames.get(request.user, []):
        client.kick()

    return {"error": False}, 200


@me_bp.get("/reports")
@validate_querystring(GetReportsQueryArgs)
async def get_report_history(query_args: GetReportsQueryArgs):
    # Check authorization
    if not request.user:
        abort(401)

    # Get reports
    reports = list(
        db.reports.find(
            {"reports.user": request.user},
            projection={"escalated": 0},
            sort=[("reports.time", pymongo.DESCENDING)],
            skip=(query_args.page - 1) * 25,
            limit=25,
        )
    )

    # Get reason, comment, and time
    for report in reports:
        for _report in report["reports"]:
            if _report["user"] == request.user:
                report.update({
                    "reason": _report["reason"],
                    "comment": _report["comment"],
                    "time": _report["time"]
                })
        del report["reports"]

    # Get content
    for report in reports:
        if report["type"] == "post":
            report["content"] = db.posts.find_one(
                {"_id": report.get("content_id")},
                projection={"_id": 1, "u": 1, "isDeleted": 1}
            )
        elif report["type"] == "user":
            report["content"] = security.get_account(report.get("content_id"))

    # Return reports
    return {
        "error": False,
        "autoget": reports,
        "page": query_args.page,
        "page#": query_args.page,
        "pages": get_total_pages("reports", {"reports.user": request.user}),
    }, 200


@me_bp.get("/export")
async def get_current_data_export():
    # Check authorization
    if not request.user:
        abort(401)

    # Get current data export request from the database
    data_export = db.data_exports.find_one({
        "user": request.user,
        "$or": [
            {"status": "pending"},
            {"completed_at": {"$gt": int(time.time())-604800}}
        ]
    }, projection={"error": 0})
    if not data_export:
        abort(404)

    # Return data export request
    return data_export, 200


@me_bp.post("/export")
async def request_data_export():
    # Check authorization
    if not request.user:
        abort(401)

    # Make sure a current data export request doesn't already exist
    if db.data_exports.count_documents({
        "user": request.user,
        "$or": [
            {"status": "pending"},
            {"completed_at": {"$gt": int(time.time())-604800}}
        ]
    }) > 0:
        abort(429)

    # Create data export request
    data_export = {
        "_id": str(uuid.uuid4()),
        "user": request.user,
        "status": "pending",
        "created_at": int(time.time())
    }
    db.data_exports.insert_one(data_export)

    # Tell the data export service to check for new requests
    rdb.publish("data_exports", "0")

    # Return data export request
    return data_export, 200
