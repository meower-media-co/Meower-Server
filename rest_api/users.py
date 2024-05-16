# noinspection PyTypeChecker
from quart import Blueprint, current_app as app, request, abort
from pydantic import BaseModel
from typing import Literal
import pymongo
import uuid
import time

import security
from database import db, get_total_pages
from .api_types import AuthenticatedRequest, MeowerQuart

request: AuthenticatedRequest
app: MeowerQuart

users_bp = Blueprint("users_bp", __name__, url_prefix="/users/<username>")


class UpdateRelationshipBody(BaseModel):
    state: Literal[
        0,  # no relationship
        #1,  # following (doesn't do anything yet)
        2,  # blocking
    ]

    class Config:
        validate_assignment = True


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
async def get_posts(username):
    # Get page
    try:
        page = int(request.args["page"])
    except:
        page = 1

    # Get posts
    query = {"post_origin": "home", "isDeleted": False, "u": username}
    posts = list(db.posts.find(query, sort=[("t.e", pymongo.DESCENDING)], skip=(page-1)*25, limit=25))

    # Return posts
    payload = {
        "error": False,
        "page#": page,
        "pages": get_total_pages("posts", query)
    }
    if "autoget" in request.args:
        payload["autoget"] = posts
    else:
        payload["index"] = [post["_id"] for post in posts]
    return payload, 200


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
async def update_relationship(username):
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

    # Get body
    try:
        body = UpdateRelationshipBody(**await request.json)
    except: abort(400)

    # Get relationship
    relationship = db.relationships.find_one({"_id": {"from": request.user, "to": username}})
    if not relationship:
        relationship = {
            "_id": {"from": request.user, "to": username},
            "state": 0,
            "updated_at": None
        }

    # Make sure the state relationship state changed
    if body.state == relationship["state"]:
        del relationship["_id"]
        return relationship, 200

    # Update relationship
    relationship["state"] = body.state
    relationship["updated_at"] = int(time.time())
    if body.state == 0:
        db.relationships.delete_one({"_id": {"from": request.user, "to": username}})
    else:
        db.relationships.update_one({"_id": {"from": request.user, "to": username}}, {"$set": relationship}, upsert=True)

    # Sync relationship between sessions
    app.cl.broadcast({
        "mode": "update_relationship",
        "payload": {
            "username": username,
            "state": relationship["state"],
            "updated_at": relationship["updated_at"]
        }
    }, direct_wrap=True, usernames=[request.user])

    # Return updated relationship
    del relationship["_id"]
    return relationship, 200


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
    return chat, 200
