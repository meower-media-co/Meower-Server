from quart import Blueprint, current_app as app, request, abort
from quart_schema import validate_querystring, validate_request
from pydantic import BaseModel, Field
from typing import Optional
from threading import Thread
from copy import copy
import pymongo, uuid, time, emoji

import security
from database import db, get_total_pages
from uploads import claim_file, delete_file
from utils import log


posts_bp = Blueprint("posts_bp", __name__, url_prefix="/posts")


class PostIdQueryArgs(BaseModel):
    id: str = Field()

class PagedQueryArgs(BaseModel):
    page: Optional[int] = Field(default=1, ge=1)

class PostBody(BaseModel):
    content: Optional[str] = Field(default="", max_length=4000)
    nonce: Optional[str] = Field(default=None, max_length=64)
    attachments: Optional[list[str]] = Field(default_factory=list)
    reply_to: Optional[list[str]] = Field(default_factory=list)
    stickers: Optional[list[str]] = Field(default_factory=list)

    class Config:
        validate_assignment = True
        str_strip_whitespace = True

class ReportBody(BaseModel):
    reason: str = Field(default="No reason provided", max_length=2000)
    comment: str = Field(default="", max_length=2000)

    class Config:
        validate_assignment = True
        str_strip_whitespace = True


@posts_bp.get("/")
@validate_querystring(PostIdQueryArgs)
async def get_post(query_args: PostIdQueryArgs):    
    # Get post
    post = db.posts.find_one({"_id": query_args.id, "isDeleted": False})
    if not post:
        abort(404)

    # Check access
    if (post["post_origin"] == "inbox") and (post["u"] not in ["Server", request.user]):
        abort(404)
    elif post["post_origin"] not in ["home", "inbox"]:
        if not db.chats.count_documents({
            "_id": post["post_origin"],
            "members": request.user,
            "deleted": False
        }, limit=1):
            abort(404)
    
    # Return post
    post["error"] = False
    return app.supporter.parse_posts_v0([post], requester=request.user)[0], 200


@posts_bp.patch("/")
@validate_querystring(PostIdQueryArgs)
@validate_request(PostBody)
async def update_post(query_args: PostIdQueryArgs, data: PostBody):
    # Check authorization
    if not request.user:
        abort(401)

    if not (request.flags & security.UserFlags.POST_RATELIMIT_BYPASS):
        # Check ratelimit
        if security.ratelimited(f"post:{request.user}"):
            abort(429)

        # Ratelimit
        security.ratelimit(f"post:{request.user}", 6, 5)
    
    # Get post
    post = db.posts.find_one({"_id": query_args.id, "isDeleted": False})
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
    if post["p"] == data.content:
        post["error"] = False
        return app.supporter.parse_posts_v0([post], requester=request.user)[0], 200

    # Make sure the post has text content
    if not data.content:
        abort(400)

    # Add revision
    db.post_revisions.insert_one({
        "_id": str(uuid.uuid4()),
        "post_id": post["_id"],
        "old_content": post["p"],
        "new_content": data.content,
        "time": int(time.time())
    })

    # Update post
    post["edited_at"] = int(time.time())
    post["p"] = data.content
    db.posts.update_one({"_id": query_args.id}, {"$set": {
        "p": post["p"],
        "edited_at": post["edited_at"]
    }})

    # Send update post event
    app.cl.send_event("update_post", post, usernames=(None if post["post_origin"] == "home" else chat["members"]))

    # Return post
    post["error"] = False
    return app.supporter.parse_posts_v0([post], requester=request.user)[0], 200

@posts_bp.post("/<post_id>/report")
@validate_request(ReportBody)
async def report_post(post_id, data: ReportBody):
    if not request.user:
        abort(401)
    post = db.posts.find_one({"_id": post_id})
    if not post:
        abort(404)
    
    security.ratelimit(f"report:{request.user}", 3, 5)
    
    report = db.reports.find_one({
        "content_id": post_id,
        "status": "pending",
        "type": "post"
    })

    if not report:
        report = {
            "_id": str(uuid.uuid4()),
            "type": "post",
            "content_id": post_id,
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

    unique_ips = set([_report["ip"] for _report in report["reports"]])

    if report["status"] == "pending" and not report["escalated"] and len(unique_ips) >= 3:
        db.reports.update_one({"_id": report["_id"]}, {"$set": {"escalated": True}})
        db.posts.update_one({"_id": post_id, "isDeleted": False}, {"$set": {
            "isDeleted": True,
            "mod_deleted": True,
            "deleted_at": int(time.time())
        }})

    return {"error": False}, 200


@posts_bp.post("/<post_id>/pin")
async def pin_post(post_id):
    if not request.user:
        abort(401)
    post = db.posts.find_one({"_id": post_id})
    if not post:
        abort(404)
    query = {"_id": post["post_origin"]}

    has_perm = security.has_permission(request.permissions, security.AdminPermissions.EDIT_CHATS)
    if not has_perm:
        query["members"] = request.user
        query["deleted"] = False



    chat = db.chats.find_one(query)
    if not chat:
        abort(401)

    if not (request.user == chat["owner"] or chat["allow_pinning"] or has_perm):
        abort(401)

    db.posts.update_one({"_id": post_id}, {"$set": {
        "pinned": True
    }})

    post["pinned"] = True

    app.cl.send_event("update_post", post, usernames=(None if post["post_origin"] == "home" else chat["members"]))

    post["error"] = False
    return app.supporter.parse_posts_v0([post], requester=request.user)[0], 200


@posts_bp.delete("/<post_id>/pin")
async def unpin_post(post_id):
    if not request.user:
        abort(401)

    post = db.posts.find_one({"_id": post_id})
    if not post:
        abort(404)

    query = {"_id": post["post_origin"]}
    has_perm = security.has_permission(request.permissions, security.AdminPermissions.EDIT_CHATS)
    if not has_perm:
        query["members"] = request.user
        query["deleted"] = False

    chat = db.chats.find_one(query)
    if not chat:
        abort(401)

    if not (request.user == chat["owner"] or chat["allow_pinning"] or has_perm):
        abort(401)


    db.posts.update_one({"_id": post_id}, {"$set": {
        "pinned": False
    }})

    post["pinned"] = False

    app.cl.send_event("update_post", post, usernames=(None if post["post_origin"] == "home" else chat["members"]))

    post["error"] = False
    return app.supporter.parse_posts_v0([post], requester=request.user)[0], 200


@posts_bp.delete("/<post_id>/attachments/<attachment_id>")
async def delete_attachment(post_id: str, attachment_id: str):
    # Check authorization
    if not request.user:
        abort(401)
    
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

    # Delete attachment
    for attachment in copy(post["attachments"]):
        if attachment["id"] == attachment_id:
            try:
                delete_file(attachment_id)
            except Exception as e:
                log(f"Unable to delete attachment: {e}")
            post["attachments"].remove(attachment)

    if post["p"] or post["attachments"] > 0:
        # Update post
        db.posts.update_one({"_id": post_id}, {"$set": {
            "attachments": post["attachments"]
        }})

        # Send update post event
        app.cl.send_event("update_post", post, usernames=(None if post["post_origin"] == "home" else chat["members"]))
    else:  # delete post if no content and attachments remain
        # Update post
        db.posts.update_one({"_id": post_id}, {"$set": {
            "isDeleted": True,
            "deleted_at": int(time.time())
        }})

        # Send delete post event
        app.cl.send_event("delete_post", {
            "chat_id": post["post_origin"],
            "post_id": post_id
        }, usernames=(None if post["post_origin"] == "home" else chat["members"]))

    # Return post
    post["error"] = False
    return app.supporter.parse_posts_v0([post], requester=request.user)[0], 200


@posts_bp.delete("/")
@validate_querystring(PostIdQueryArgs)
async def delete_post(query_args: PostIdQueryArgs):
    # Check authorization
    if not request.user:
        abort(401)

    if not (request.flags & security.UserFlags.POST_RATELIMIT_BYPASS):
        # Check ratelimit
        if security.ratelimited(f"post:{request.user}"):
            abort(429)

        # Ratelimit
        security.ratelimit(f"post:{request.user}", 6, 5)
    
    # Get post
    post = db.posts.find_one({"_id": query_args.id, "isDeleted": False})
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
        if (post["post_origin"] in ["home", "inbox"]) or (chat["owner"] != request.user):
            abort(403)

    # Delete attachments
    for attachment in post["attachments"]:
        try:
            delete_file(attachment["id"])
        except Exception as e:
            log(f"Unable to delete attachment: {e}")

    # Update post
    db.posts.update_one({"_id": query_args.id}, {"$set": {
        "isDeleted": True,
        "deleted_at": int(time.time())
    }})

    # Send delete post event
    app.cl.send_event("delete_post", {
        "chat_id": post["post_origin"],
        "post_id": query_args.id
    }, usernames=(None if post["post_origin"] == "home" else chat["members"]))

    return {"error": False}, 200


@posts_bp.get("/<chat_id>")
@validate_querystring(PagedQueryArgs)
async def get_chat_posts(chat_id, query_args: PagedQueryArgs):
    # Check authorization
    if not request.user:
        abort(401)

    # Make sure chat exists
    if not db.chats.count_documents({
        "_id": chat_id,
        "members": request.user,
        "deleted": False
    }, limit=1):
        abort(404)

    # Get and return posts
    query = {"post_origin": chat_id, "isDeleted": False}
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
        "pages": (get_total_pages("posts", query) if request.user else 1)
    }, 200


@posts_bp.post("/<chat_id>")
@validate_request(PostBody)
async def create_chat_post(chat_id, data: PostBody):
    # Check authorization
    if not request.user:
        abort(401)

    if not (request.flags & security.UserFlags.POST_RATELIMIT_BYPASS):
        # Check ratelimit
        if security.ratelimited(f"post:{request.user}"):
            abort(429)

        # Ratelimit
        security.ratelimit(f"post:{request.user}", 6, 5)

    # Check restrictions
    if security.is_restricted(request.user, security.Restrictions.CHAT_POSTS):
        return {"error": True, "type": "accountBanned"}, 403

    # Make sure there's not too many attachments
    if len(data.attachments) > 10:
        return {"error": True, "type": "tooManyAttachments"}, 400

    # Make sure the post isn't replying to too many posts
    if len(data.reply_to) > 10:
        return {"error": True, "type": "tooManyReplies"}, 400
    
    # Make sure there's not too many stickers
    if len(data.stickers) > 10:
        return {"error": True, "type": "tooManyStickers"}, 400

    # Make sure stickers exist
    for sticker_id in copy(data.stickers):
        if not db.chat_stickers.count_documents({"_id": sticker_id}, limit=1):
            data.stickers.remove(sticker_id)

    # Make sure replied to post IDs exist and are unique
    unique_reply_to_post_ids = []
    if chat_id != "livechat":
        for post_id in data.reply_to:
            if db.posts.count_documents({"_id": post_id, "post_origin": chat_id}, limit=1) and \
                post_id not in unique_reply_to_post_ids:
                unique_reply_to_post_ids.append(post_id)

    # Claim attachments
    attachments = []
    if chat_id != "livechat":
        for attachment_id in set(data.attachments):
            try:
                attachments.append(claim_file(attachment_id, "attachments"))
            except Exception as e:
                log(f"Unable to claim attachment: {e}")
                return {"error": True, "type": "unableToClaimAttachment"}, 500

    # Make sure the post has text content or at least 1 attachment or at least 1 sticker
    if not data.content and not attachments and not data.stickers:
        abort(400)

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
    post = app.supporter.create_post(
        chat_id,
        request.user,
        data.content,
        attachments=attachments,
        stickers=data.stickers,
        nonce=data.nonce,
        chat_members=(None if chat_id == "livechat" else chat["members"]),
        reply_to=unique_reply_to_post_ids
    )

    # Return new post
    post["error"] = False
    return app.supporter.parse_posts_v0([post], requester=request.user)[0], 200

@posts_bp.get("/<post_id>/reactions/<emoji_reaction>")
@validate_querystring(PagedQueryArgs)
async def get_post_reactors(query_args: PagedQueryArgs, post_id: str, emoji_reaction: str):
    # Get necessary post details and check access
    post = db.posts.find_one({
        "_id": post_id,
        "isDeleted": {"$ne": True}
    }, projection={"_id": 1, "post_origin": 1, "u": 1})
    if not post:
        abort(404)
    elif post["post_origin"] != "home" and not request.user:
        abort(404)
    elif post["post_origin"] == "inbox" and post["u"] not in ["Server", request.user]:
        abort(404)
    elif post["post_origin"] not in ["home", "inbox"]:
        if not db.chats.count_documents({
            "_id": post["post_origin"],
            "members": request.user,
            "deleted": False
        }, limit=1):
            abort(404)

    # Get and return reactors
    query = {"_id.post_id": post_id, "_id.emoji": emoji_reaction}
    return {
        "error": False,
        "autoget": [security.get_account(r["_id"]["user"]) for r in db.post_reactions.find(
            query,
            sort=[("time", pymongo.DESCENDING)],
            skip=(query_args.page-1)*25,
            limit=25
        )],
        "page#": query_args.page,
        "pages": (get_total_pages("post_reactions", query) if request.user else 1)
    }, 200

@posts_bp.post("/<post_id>/reactions/<emoji_reaction>")
async def add_post_reaction(post_id: str, emoji_reaction: str):
    # Check authorization
    if not request.user:
        abort(401)

    # Ratelimit
    if security.ratelimited(f"react:{request.user}"):
        abort(429)
    security.ratelimit(f"react:{request.user}", 5, 5)

    # Check if the emoji is only one emoji, with support for variants
    if not (emoji.purely_emoji(emoji_reaction) and len(emoji.distinct_emoji_list(emoji_reaction)) == 1):
        # Check if the emoji is a custom emoji
        if not db.chat_emojis.count_documents({"_id": emoji_reaction}, limit=1):
            abort(400)

    # Get necessary post details and check access
    post = db.posts.find_one({
        "_id": post_id,
        "isDeleted": {"$ne": True}
    }, projection={
        "_id": 1,
        "post_origin": 1,
        "u": 1,
        "reactions": 1
    })
    if not post:
        abort(404)
    elif post["post_origin"] == "inbox" and post["u"] not in ["Server", request.user]:
        abort(404)
    elif post["post_origin"] not in ["home", "inbox"]:
        if not db.chats.count_documents({
            "_id": post["post_origin"],
            "members": request.user,
            "deleted": False
        }, limit=1):
            abort(404)

    # Make sure there's not too many reactions (50)
    if len(post["reactions"]) >= 50:
        return {"error": True, "type": "tooManyReactions"}, 403

    # Add reaction
    db.post_reactions.update_one({"_id": {
        "post_id": post["_id"],
        "emoji": emoji_reaction,
        "user": request.user
    }}, {"$set": {"time": int(time.time())}}, upsert=True)

    # Update post
    existing_reaction = None
    for reaction in post["reactions"]:
        if reaction["emoji"] == emoji_reaction:
            existing_reaction = reaction
            break
    if existing_reaction:
        existing_reaction["count"] = db.post_reactions.count_documents({
            "_id.post_id": post["_id"],
            "_id.emoji": reaction["emoji"]
        })
    else:
        post["reactions"].append({
            "emoji": emoji_reaction,
            "count": 1
        })
    db.posts.update_one({"_id": post["_id"]}, {"$set": {
        "reactions": post["reactions"]
    }})

    # Send event
    app.cl.send_event("post_reaction_add", {
        "chat_id": post["post_origin"],
        "post_id": post["_id"],
        "emoji": emoji_reaction,
        "username": request.user
    })

    return {"error": False}, 200

@posts_bp.delete("/<post_id>/reactions/<emoji_reaction>/<username>")
async def remove_post_reaction(post_id: str, emoji_reaction: str, username: str):
    # Check authorization
    if not request.user:
        abort(401)

    # @me -> requester
    if username == "@me":
        username = request.user

    # Ratelimit
    if security.ratelimited(f"react:{request.user}"):
        abort(429)
    security.ratelimit(f"react:{request.user}", 5, 5)

    # Make sure reaction exists
    if not db.post_reactions.count_documents({"_id": {
        "post_id": post_id,
        "emoji": emoji_reaction,
        "user": username
    }}, limit=1):
        abort(404)

    # Get necessary post details and check access
    post = db.posts.find_one({
        "_id": post_id,
        "isDeleted": {"$ne": True}
    }, projection={
        "_id": 1,
        "post_origin": 1,
        "u": 1,
        "reactions": 1
    })
    if not post:
        abort(404)
    elif post["post_origin"] == "inbox" and post["u"] not in ["Server", request.user]:
        abort(404)
    elif post["post_origin"] not in ["home", "inbox"]:
        chat = db.chats.find_one({
            "_id": post["post_origin"],
            "members": request.user,
            "deleted": False
        }, projection={"owner": 1})
        if not chat:
            abort(404)

    # Make sure requester can remove the reaction
    if request.user != username:
        if (post["post_origin"] in ["home", "inbox"]) or (chat["owner"] != request.user):
            abort(403)

    # Remove reaction
    db.post_reactions.delete_one({"_id": {
        "post_id": post["_id"],
        "emoji": emoji_reaction,
        "user": username
    }})

    # Update post
    for reaction in post["reactions"]:
        if reaction["emoji"] != emoji_reaction:
            continue
        reaction["count"] = db.post_reactions.count_documents({
            "_id.post_id": post["_id"],
            "_id.emoji": reaction["emoji"]
        })
        if not reaction["count"]:
            post["reactions"].remove(reaction)
        break
    db.posts.update_one({"_id": post["_id"]}, {"$set": {
        "reactions": post["reactions"]
    }})

    # Send event
    app.cl.send_event("post_reaction_remove", {
        "chat_id": post["post_origin"],
        "post_id": post["_id"],
        "emoji": emoji_reaction,
        "username": username
    })

    return {"error": False}, 200
