# noinspection PyTypeChecker
from quart import Blueprint, current_app as app, request, abort
from pydantic import BaseModel, Field
from typing import Optional, List
from copy import copy
import pymongo
import uuid
import time

import security
from database import db, get_total_pages, rdb
from .api_types import AuthenticatedRequest, MeowerQuart


request: AuthenticatedRequest
app: MeowerQuart

me_bp = Blueprint("me_bp", __name__, url_prefix="/me")


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
    active_dms: Optional[List[str]] = Field(default=None)

    class Config:
        validate_assignment = True
        str_strip_whitespace = True


@me_bp.get("/")
async def get_me():
    # Check authorization
    if not request.user:
        abort(401)

    # Get and return account
    return security.get_account(request.user, include_config=True), 200


@me_bp.patch("/config")
async def update_config():
    # Check authorization
    if not request.user:
        abort(401)

    # Check ratelimit
    if security.ratelimited(f"config:{request.user}"):
        abort(429)
    
    # Ratelimit
    security.ratelimit(f"config:{request.user}", 10, 5)

    # Get new config
    try:
        new_config = UpdateConfigBody(**await request.json).model_dump()
    except: abort(400)

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

    # Update config
    security.update_settings(request.user, new_config)

    # Sync config between sessions
    app.cl.broadcast({
        "mode": "update_config",
        "payload": new_config
    }, direct_wrap=True, usernames=[request.user])

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
        app.cl.broadcast({
            "mode": "update_profile",
            "payload": updated_profile_data
        }, direct_wrap=True)

    return {"error": False}, 200


@me_bp.get("/reports")
async def get_report_history():
    # Check authorization
    if not request.user:
        abort(401)

    # Get page
    try:
        page = int(request.args["page"])
    except:
        page = 1

    # Get reports
    reports = list(
        db.reports.find(
            {"reports.user": request.user},
            projection={"escalated": 0},
            sort=[("reports.time", pymongo.DESCENDING)],
            skip=(page - 1) * 25,
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
                {"_id": report.get("content_id")}, projection={"_id": 1, "u": 1, "isDeleted": 1}
            )
        elif report["type"] == "user":
            report["content"] = security.get_account(report.get("content_id"))

    # Return reports
    payload = {
        "error": False,
        "page#": page,
        "pages": get_total_pages("reports", {"reports.user": request.user}),
    }
    if "autoget" in request.args:
        payload["autoget"] = reports
    else:
        payload["index"] = [report["_id"] for report in reports]
    return payload, 200


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

    # Add download token that lasts 15 minutes
    if data_export["status"] == "completed":
        data_export["download_token"], _ = security.create_token("access_data_export", 900, {
            "id": data_export["_id"]
        })

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
