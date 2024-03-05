# noinspection PyTypeChecker
from quart import Blueprint, current_app as app, request, abort
from pydantic import BaseModel, Field
from threading import Thread
import pymongo
import uuid
import time

import security
from database import db, get_total_pages
from .api_types import AuthenticatedRequest, MeowerQuart

request: AuthenticatedRequest
app: MeowerQuart


posts_bp = Blueprint("posts_bp", __name__, url_prefix="/posts")


class PostBody(BaseModel):
    content: str = Field(min_length=1, max_length=4000)

    class Config:
        validate_assignment = True
        str_strip_whitespace = True


@posts_bp.get("/")
async def get_post():
    # Get post ID
    post_id = request.args.get("id")
    if not post_id:
        abort(400)
    
    # Get post
    post = db.posts.find_one({"_id": post_id, "isDeleted": False})
    if not post:
        abort(404)

    # Check access
    if (post["post_origin"] == "inbox") and (post["u"] != request.user):
        abort(404)
    elif post["post_origin"] not in ["home", "inbox"]:
        if db.chats.count_documents({
            "_id": post["post_origin"],
            "members": request.user,
            "deleted": False
        }, limit=1) < 1:
            abort(404)

    # Return post
    post["error"] = False
    return post, 200


@posts_bp.patch("/")
async def update_post():
    # Check authorization
    if not request.user:
        abort(401)

    # Check ratelimit
    if security.ratelimited(f"post:{request.user}"):
        abort(429)

    # Ratelimit
    security.ratelimit(f"post:{request.user}", 6, 5)

    # Get body
    try:
        body = PostBody(**await request.json)
    except: abort(400)

    # Get post ID
    post_id = request.args.get("id")
    if not post_id:
        abort(400)
    
    # Get post
    post = db.posts.find_one({"_id": post_id, "isDeleted": False})
    if not post:
        abort(404)

    # Check access
    if (post["post_origin"] == "inbox") and (post["u"] != request.user):
        abort(404)
    elif post["post_origin"] not in ["home", "inbox"]:
        chat = db.chats.find_one({
            "_id": post["post_origin"],
            "members": request.user,
            "deleted": False
        })
        if not chat:
            abort(404)

    # Check permissions
    if post["post_origin"] == "inbox" or post["u"] != request.user:
        abort(403)

    # Check restrictions
    if post["post_origin"] == "home" and security.is_restricted(request.user, security.Restrictions.HOME_POSTS):
        return {"error": True, "type": "accountBanned"}, 403
    elif post["post_origin"] != "home" and security.is_restricted(request.user, security.Restrictions.CHAT_POSTS):
        return {"error": True, "type": "accountBanned"}, 403

    # Make sure new content isn't the same as the old content
    if post.get("unfiltered_p", post["p"]) == body.content:
        post["error"] = False
        return post, 200

    # Add revision
    db.post_revisions.insert_one({
        "_id": str(uuid.uuid4()),
        "post_id": post["_id"],
        "old_content": post.get("unfiltered_p", post["p"]),
        "new_content": body.content,
        "time": int(time.time())
    })

    # Update post
    post["edited_at"] = int(time.time())
    filtered_content = app.supporter.wordfilter(body.content)
    if filtered_content != body.content:
        post["p"] = filtered_content
        post["unfiltered_p"] = body.content
        db.posts.update_one({"_id": post_id}, {"$set": {
            "p": post["p"],
            "unfiltered_p": post["unfiltered_p"],
            "edited_at": post["edited_at"]
        }})
    else:
        post["p"] = body.content
        if "unfiltered_p" in post:
            del post["unfiltered_p"]
        db.posts.update_one({"_id": post_id}, {"$set": {
            "p": post["p"],
            "edited_at": post["edited_at"]
        }, "$unset": {
            "unfiltered_p": ""
        }})

    # Send update post event
    # noinspection PyUnboundLocalVariable
    app.cl.broadcast({
        "mode": "update_post",
        "payload": post
    }, direct_wrap=True, usernames=(None if post["post_origin"] == "home" else chat["members"]))

    # Return post
    post["error"] = False
    return post, 200


@posts_bp.delete("/")
async def delete_post():
    # Check authorization
    if not request.user:
        abort(401)

    # Check ratelimit
    if security.ratelimited(f"post:{request.user}"):
        abort(429)

    # Ratelimit
    security.ratelimit(f"post:{request.user}", 6, 5)

    # Get post ID
    post_id = request.args.get("id")
    if not post_id:
        abort(400)
    
    # Get post
    post = db.posts.find_one({"_id": post_id, "isDeleted": False})
    if not post:
        abort(404)

    # Check access
    if post["post_origin"] not in {"home", "inbox"}:
        chat = db.chats.find_one({
            "_id": post["post_origin"],
            "members": request.user,
            "deleted": False
        }, projection={"owner": 1, "members": 1})
        if not chat:
            abort(404)
    if post["post_origin"] == "inbox" or post["u"] != request.user:
        # noinspection PyUnboundLocalVariable
        if (post["post_origin"] in ["home", "inbox"]) or (chat["owner"] != request.user):
            abort(403)

    # Update post
    db.posts.update_one({"_id": post_id}, {"$set": {
        "isDeleted": True,
        "deleted_at": int(time.time())
    }})

    # Send delete post event
    app.cl.broadcast({
        "mode": "delete",
        "id": post_id
    }, direct_wrap=True, usernames=(None if post["post_origin"] == "home" else chat["members"]))

    return {"error": False}, 200


@posts_bp.get("/<chat_id>")
async def get_chat_posts(chat_id):
    # Check authorization
    if not request.user:
        abort(401)

    # Get page
    try:
        page = int(request.args["page"])
    except:
        page = 1

    # Make sure chat exists
    if db.chats.count_documents({
        "_id": chat_id,
        "members": request.user,
        "deleted": False
    }, limit=1) < 1:
        abort(404)

    # Get posts
    query = {"post_origin": chat_id, "isDeleted": False}
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


@posts_bp.post("/<chat_id>")
async def create_chat_post(chat_id):
    # Check authorization
    if not request.user:
        abort(401)

    # Check ratelimit
    if security.ratelimited(f"post:{request.user}"):
        abort(429)

    # Ratelimit
    security.ratelimit(f"post:{request.user}", 6, 5)

    # Check restrictions
    if security.is_restricted(request.user, security.Restrictions.CHAT_POSTS):
        return {"error": True, "type": "accountBanned"}, 403

    # Get body
    try:
        body = PostBody(**await request.json)
    except: abort(400)

    if chat_id != "livechat":
        # Get chat
        chat = db.chats.find_one({
            "_id": chat_id,
            "members": request.user,
            "deleted": False
        }, projection={"type": 1, "members": 1})
        if not chat:
            abort(404)
        
        # DM stuff
        if chat["type"] == 1:
            # Check privacy options
            if db.relationships.count_documents({"$or": [
                {"_id": {"from": chat["members"][0], "to": chat["members"][1]}},
                {"_id": {"from": chat["members"][1], "to": chat["members"][0]}}
            ], "state": 2}, limit=1) > 0:
                abort(403)

            # Update user settings
            Thread(target=db.user_settings.bulk_write, args=([
                pymongo.UpdateMany({"$or": [
                    {"_id": chat["members"][0]},
                    {"_id": chat["members"][1]}
                ]}, {"$pull": {"active_dms": chat_id}}),
                pymongo.UpdateMany({"$or": [
                    {"_id": chat["members"][0]},
                    {"_id": chat["members"][1]}
                ]}, {"$push": {"active_dms": {
                    "$each": [chat_id],
                    "$position": 0,
                    "$slice": -150
                }}})
            ],)).start()

    # Create post
    # noinspection PyUnboundLocalVariable
    post = app.supporter.create_post(chat_id, request.user, body.content, chat_members=(None if chat_id == "livechat" else chat["members"]))

    # Return new post
    post["error"] = False
    return post, 200
