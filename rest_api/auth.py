import re, os, requests, pyotp, secrets
from pydantic import BaseModel
from quart import Blueprint, request, abort, current_app as app
from quart_schema import validate_request
from pydantic import Field
from typing import Optional
from database import db, registration_blocked_ips
import security

auth_bp = Blueprint("auth_bp", __name__, url_prefix="/auth")

class AuthRequest(BaseModel):
    username: str = Field(min_length=1, max_length=20)
    password: str = Field(min_length=1, max_length=255)
    totp_code: Optional[str] = Field(default="", min_length=6, max_length=6)
    mfa_recovery_code: Optional[str] = Field(default="", min_length=10, max_length=10)
    captcha: Optional[str] = Field(default="", max_length=2000)


@auth_bp.post("/login")
@validate_request(AuthRequest)
async def login(data: AuthRequest):
    # Make sure IP isn't ratelimited
    if security.ratelimited(f"login:i:{request.ip}"):
        abort(429)
    security.ratelimit(f"login:i:{request.ip}", 50, 900)

    # Get basic account details
    account = db.usersv0.find_one({"lower_username": data.username.lower()}, projection={
        "_id": 1,
        "flags": 1,
        "tokens": 1,
        "pswd": 1,
        "mfa_recovery_code": 1
    })
    if not account:
        abort(401)

    # Make sure account isn't deleted
    if account["flags"] & security.UserFlags.DELETED:
        return {"error": True, "type": "accountDeleted"}, 401

    # Make sure account isn't ratelimited
    if security.ratelimited(f"login:u:{account['_id']}"):
        abort(429)

    # Check credentials
    if data.password not in account["tokens"]:
        # Check password
        if not security.check_password_hash(data.password, account["pswd"]):
            security.ratelimit(f"login:u:{account['_id']}", 5, 60)
            abort(401)

        # Check MFA
        authenticators = list(db.authenticators.find({"user": account["_id"]}))
        if len(authenticators) > 0:
            if data.totp_code:
                passed = False
                for authenticator in authenticators:
                    if authenticator["type"] != "totp":
                        continue
                    if pyotp.TOTP(authenticator["totp_secret"]).verify(data.totp_code, valid_window=1):
                        passed = True
                        break
                if not passed:
                    security.ratelimit(f"login:u:{account['_id']}", 5, 60)
                    abort(401)
            elif data.mfa_recovery_code:
                if data.mfa_recovery_code == account["mfa_recovery_code"]:
                    db.authenticators.delete_many({"user": account["_id"]})
                    db.usersv0.update_one({"_id": account["_id"]}, {"$set": {
                        "mfa_recovery_code": secrets.token_hex(5)
                    }})
                    app.supporter.create_post("inbox", account["_id"], "All multi-factor authenticators have been removed from your account by someone who used your multi-factor authentication recovery code. If this wasn't you, please secure your account immediately.")
                else:
                    security.ratelimit(f"login:u:{account['_id']}", 5, 60)
                    abort(401)
            else:
                mfa_methods = set()
                for authenticator in authenticators:
                    mfa_methods.add(authenticator["type"])
                return {
                    "error": True,
                    "type": "mfaRequired",
                    "mfa_methods": list(mfa_methods)
                }, 401

    # Return account and token
    return {
        "error": False,
        "account": security.get_account(account['_id'], True),
        "token": security.create_user_token(account['_id'], request.ip, used_token=data.password)
    }, 200

@auth_bp.post("/register")
@validate_request(AuthRequest)
async def register(data: AuthRequest):
    # Make sure registration isn't disabled
    if not app.supporter.registration:
        return {"error": True, "type": "registrationDisabled"}, 403
    
    # Make sure IP isn't being ratelimited
    if security.ratelimited(f"register:{request.ip}:f") or security.ratelimited(f"register:{request.ip}:s"):
        abort(429)

    # Make sure password is between 8-72 characters
    if len(data.password) < 8 or len(data.password) > 72:
        abort(400)

    # Make sure username matches regex
    if not re.fullmatch(security.USERNAME_REGEX, data.username):
        abort(400)
    
    # Make sure IP isn't blocked from creating new accounts
    if registration_blocked_ips.search_best(request.ip):
        security.ratelimit(f"register:{request.ip}:f", 5, 30)
        return {"error": True, "type": "registrationBlocked"}, 403

    # Make sure username isn't taken
    if security.account_exists(data.username, ignore_case=True):
        security.ratelimit(f"register:{request.ip}:f", 5, 30)
        return {"error": True, "type": "usernameExists"}, 409

    # Check captcha
    if os.getenv("CAPTCHA_SECRET"):
        if not requests.post("https://api.hcaptcha.com/siteverify", data={
            "secret": os.getenv("CAPTCHA_SECRET"),
            "response": data.captcha,
        }).json()["success"]:
            return {"error": True, "type": "invalidCaptcha"}, 403

    # Create account
    security.create_account(data.username, data.password, request.ip)

    # Ratelimit
    security.ratelimit(f"register:{request.ip}:s", 5, 900)
    
    # Return account and token
    return {
        "error": False,
        "account": security.get_account(data.username, True),
        "token": security.create_user_token(data.username, request.ip, None)
    }, 200
