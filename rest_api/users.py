from quart import Blueprint, current_app as app, request, abort
from quart_schema import validate_querystring, validate_request
from pydantic import BaseModel, Field
from typing import Literal, Optional
import pymongo
import uuid
import time

import security
from database import db, get_total_pages


users_bp = Blueprint("users_bp", __name__, url_prefix="/users/<username>")

class GetPostsQueryArgs(BaseModel):
    page: Optional[int] = Field(default=1, ge=1)

class UpdateRelationshipBody(BaseModel):
    state: Literal[
        0,  # no relationship
        #1,  # following (doesn't do anything yet)
        2,  # blocking
    ]

    class Config:
        validate_assignment = True

class ReportBody(BaseModel):
    reason: str = Field(default="No reason provided", min_length=1, max_length=2000)
    comment: str = Field(default="", max_length=2000)

    class Config:
        validate_assignment = True
        str_strip_whitespace = True

@users_bp.before_request
async def check_user_exists():
    username = request.view_args.get("username")
    user = db.usersv0.find_one({"lower_username": username.lower()}, projection={"_id": 1, "flags": 1})
    if (not user) or (user["flags"] & security.UserFlags.DELETED == security.UserFlags.DELETED):
        abort(404)
    else:
        request.view_args["username"] = user["_id"]


@users_bp.get("/")
async def get_user(username):
    account = security.get_account(username, (request.user and request.user.lower() == username.lower()))
    account["error"] = False
    return account, 200


@users_bp.get("/posts")
@validate_querystring(GetPostsQueryArgs)
async def get_user_posts(username, query_args: GetPostsQueryArgs):
    query = {"post_origin": "home", "isDeleted": False, "u": username}
    return {
        "error": False,
        "autoget": app.supporter.parse_posts_v0(db.posts.find(
            query,
            sort=[("t.e", pymongo.DESCENDING)],
            skip=(query_args.page-1)*25,
            limit=25
        ), requester=request.user),
        "page": query_args.page,
        "page#": query_args.page,
        "pages": get_total_pages("posts", query)
    }, 200


@users_bp.get("/relationship")
async def get_relationship(username):
    # Check authorization
    if not request.user:
        abort(401)

    # Make sure the requested user isn't the requester
    if request.user == username:
        abort(400)

    # Get relationship
    relationship = db.relationships.find_one({"_id": {"from": request.user, "to": username}})

    # Return relationship
    if relationship:
        del relationship["_id"]
        return relationship, 200
    else:
        return {
            "state": 0,
            "updated_at": None
        }, 200


@users_bp.patch("/relationship")
@validate_request(UpdateRelationshipBody)
async def update_relationship(username, data: UpdateRelationshipBody):
    # Check authorization
    if not request.user:
        abort(401)

    # Check ratelimit
    if security.ratelimited(f"relationships:{request.user}"):
        abort(429)

    # Ratelimit
    security.ratelimit(f"relationships:{request.user}", 10, 15)

    # Make sure the requested user isn't the requester
    if request.user == username:
        abort(400)

    # Get relationship
    relationship = db.relationships.find_one({"_id": {"from": request.user, "to": username}})
    if not relationship:
        relationship = {
            "_id": {"from": request.user, "to": username},
            "state": 0,
            "updated_at": None
        }

    # Make sure the state relationship state changed
    if data.state == relationship["state"]:
        del relationship["_id"]
        return relationship, 200

    # Update relationship
    relationship["state"] = data.state
    relationship["updated_at"] = int(time.time())
    if data.state == 0:
        db.relationships.delete_one({"_id": {"from": request.user, "to": username}})
    else:
        db.relationships.update_one({"_id": {"from": request.user, "to": username}}, {"$set": relationship}, upsert=True)

    # Sync relationship between sessions
    app.cl.send_event("update_relationship", {
        "username": username,
        "state": relationship["state"],
        "updated_at": relationship["updated_at"]
    }, usernames=[request.user])

    # Return updated relationship
    del relationship["_id"]
    return relationship, 200

@users_bp.post("/report")
@validate_request(ReportBody)
async def report_post(username, data: ReportBody):
    if not request.user:
        abort(401)

    security.ratelimit(f"report:{request.user}", 3, 5)
    
    report = db.reports.find_one({
        "content_id": username,
        "status": "pending",
        "type": "user"
    })

    if not report:
        report = {
            "_id": str(uuid.uuid4()),
            "type": "user",
            "content_id": username,
            "status": "pending",
            "escalated": False,
            "reports": []
        }

    for _report in report["reports"]:
        if _report["user"] == request.user:
            report["reports"].remove(_report)
            break
    
    report["reports"].append({
        "user": request.user,
        "ip": request.ip,
        "reason": data.reason,
        "comment": data.comment,
        "time": int(time.time())
    })

    db.reports.update_one({"_id": report["_id"]}, {"$set": report}, upsert=True)

    return {"error": False}, 200


@users_bp.get("/dm")
async def get_dm_chat(username):
    # Check authorization
    if not request.user:
        abort(401)

    # Check ratelimit
    if security.ratelimited(f"create_chat:{request.user}"):
        abort(429)

    # Ratelimit
    security.ratelimit(f"create_chat:{request.user}", 5, 30)

    # Make sure the requested user isn't the requester
    if request.user == username:
        abort(400)

    # Get existing chat or create new chat
    chat = db.chats.find_one({
        "members": {"$all": [request.user, username]},
        "type": 1,
        "deleted": False
    })
    if not chat:
        # Check restrictions
        if security.is_restricted(request.user, security.Restrictions.NEW_CHATS):
            return {"error": True, "type": "accountBanned"}, 403

        # Create chat
        chat = {
            "_id": str(uuid.uuid4()),
            "type": 1,
            "nickname": None,
            "owner": None,
            "members": [request.user, username],
            "created": int(time.time()),
            "last_active": 0,
            "deleted": False
        }
        db.chats.insert_one(chat)

    # Return chat
    if chat["last_active"] == 0:
        chat["last_active"] = int(time.time())
    chat.update({
        "error": False,
        "emojis": list(db.chat_emojis.find({
            "chat_id": chat["_id"]
        }, projection={"chat_id": 0, "created_at": 0, "created_by": 0})),
        "stickers": list(db.chat_stickers.find({
            "chat_id": chat["_id"]
        }, projection={"chat_id": 0, "created_at": 0, "created_by": 0}))
    })
    return chat, 200
