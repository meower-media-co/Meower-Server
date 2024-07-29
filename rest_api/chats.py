from quart import Blueprint, current_app as app, request, abort
from quart_schema import validate_querystring, validate_request
from pydantic import BaseModel, Field
from typing import Optional, Literal
import pymongo, uuid, time, re

import security
from database import db, get_total_pages
from uploads import claim_file, delete_file
from utils import log

chats_bp = Blueprint("chats_bp", __name__, url_prefix="/chats")


class GetPostsQueryArgs(BaseModel):
    page: Optional[int] = Field(default=1, ge=1)

class ChatBody(BaseModel):
    nickname: str = Field(default=None, min_length=1, max_length=32)
    icon: str = Field(default=None, max_length=24)
    icon_color: str = Field(default=None, min_length=6, max_length=6)  # hex code without the #
    allow_pinning: bool = Field(default=None)

    class Config:
        validate_assignment = True
        str_strip_whitespace = True

class EmoteBody(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=32)


@chats_bp.get("/")
async def get_chats():
    # Check authorization
    if not request.user:
        abort(401)

    # Get chats
    chats = app.supporter.get_chats(request.user)

    # Add emotes
    [chat.update({
        "emojis": list(db.chat_emojis.find({
            "chat_id": chat["_id"]
        }, projection={"chat_id": 0, "created_at": 0, "created_by": 0})),
        "stickers": list(db.chat_stickers.find({
            "chat_id": chat["_id"]
        }, projection={"chat_id": 0, "created_at": 0, "created_by": 0}))
    }) for chat in chats]

    # Get and return chats
    return {
        "error": False,
        "autoget": chats,
        "page": 1,
        "page#": 1,
        "pages": 1
    }, 200


@chats_bp.post("/")
@validate_request(ChatBody)
async def create_chat(data: ChatBody):
    # Check authorization
    if not request.user:
        abort(401)

    # Check ratelimit
    if security.ratelimited(f"create_chat:{request.user}"):
        abort(429)

    # Ratelimit
    security.ratelimit(f"create_chat:{request.user}", 5, 30)

    # Check restrictions
    if security.is_restricted(request.user, security.Restrictions.NEW_CHATS):
        return {"error": True, "type": "accountBanned"}, 403
    
    # Make sure the requester isn't in too many chats
    if db.chats.count_documents({"type": 0, "members": request.user}, limit=150) >= 150:
        return {"error": True, "type": "tooManyChats"}, 403

    # Claim icon
    if data.icon:
        try:
            claim_file(data.icon, "icons")
        except Exception as e:
            log(f"Unable to claim icon: {e}")
            return {"error": True, "type": "unableToClaimIcon"}, 500

    # Create chat
    if data.icon is None:
        data.icon = ""
    if data.icon_color is None:
        data.icon_color = "000000"
    if data.allow_pinning is None:
        data.allow_pinning = False
    chat = {
        "_id": str(uuid.uuid4()),
        "type": 0,
        "nickname": data.nickname,
        "icon": data.icon,
        "icon_color": data.icon_color,
        "owner": request.user,
        "members": [request.user],
        "created": int(time.time()),
        "last_active": int(time.time()),
        "deleted": False,
        "allow_pinning": data.allow_pinning
    }
    db.chats.insert_one(chat)

    # Add emotes
    chat.update({
        "emojis": list(db.chat_emojis.find({
            "chat_id": chat["_id"]
        }, projection={"chat_id": 0, "created_at": 0, "created_by": 0})),
        "stickers": list(db.chat_stickers.find({
            "chat_id": chat["_id"]
        }, projection={"chat_id": 0, "created_at": 0, "created_by": 0}))
    })


    # Tell the requester the chat was created
    app.cl.send_event("create_chat", chat, usernames=[request.user])

    # Return chat
    chat["error"] = False
    return chat, 200


@chats_bp.get("/<chat_id>")
async def get_chat(chat_id):
    # Check authorization
    if not request.user:
        abort(401)

    # Get chat
    chat = db.chats.find_one({"_id": chat_id, "members": request.user, "deleted": False})
    if not chat:
        abort(404)

    # Return chat
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


@chats_bp.patch("/<chat_id>")
@validate_request(ChatBody)
async def update_chat(chat_id, data: ChatBody):
    # Check authorization
    if not request.user:
        abort(401)

    # Check ratelimit
    if security.ratelimited(f"update_chat:{request.user}"):
        abort(429)

    # Ratelimit
    security.ratelimit(f"update_chat:{request.user}", 5, 5)

    # Check restrictions
    if security.is_restricted(request.user, security.Restrictions.EDITING_CHAT_DETAILS):
        return {"error": True, "type": "accountBanned"}, 403

    # Get chat
    chat = db.chats.find_one({"_id": chat_id, "members": request.user, "deleted": False})
    if not chat:
        abort(404)

    # Make sure requester is owner
    if chat["owner"] != request.user:
        abort(403)

    # Get updated values
    updated_vals = {"_id": chat_id}
    if data.nickname is not None and chat["nickname"] != data.nickname:
        updated_vals["nickname"] = data.nickname
        app.supporter.create_post(chat_id, "Server", f"@{request.user} changed the nickname of the group chat to '{chat['nickname']}'.", chat_members=chat["members"])
    if data.icon is not None and chat["icon"] != data.icon:
        # Claim icon (and delete old one)
        if data.icon != "":
            try:
                updated_vals["icon"] = claim_file(data.icon, "icons")["id"]
            except Exception as e:
                log(f"Unable to claim icon: {e}")
                return {"error": True, "type": "unableToClaimIcon"}, 500
        if chat["icon"]:
            try:
                delete_file(chat["icon"])
            except Exception as e:
                log(f"Unable to delete icon: {e}")
        app.supporter.create_post(chat_id, "Server", f"@{request.user} changed the icon of the group chat.", chat_members=chat["members"])
    if data.icon_color is not None and chat["icon_color"] != data.icon_color:
        updated_vals["icon_color"] = data.icon_color
        if data.icon is None or chat["icon"] == data.icon:
            app.supporter.create_post(chat_id, "Server", f"@{request.user} changed the icon of the group chat.", chat_members=chat["members"])
    if data.allow_pinning is not None:
        chat["allow_pinning"] = data.allow_pinning
    
    # Update chat
    db.chats.update_one({"_id": chat_id}, {"$set": updated_vals})

    # Send update chat event
    app.cl.send_event("update_chat", updated_vals, usernames=chat["members"])

    # Return chat
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


@chats_bp.delete("/<chat_id>")
async def leave_chat(chat_id):
    # Check authorization
    if not request.user:
        abort(401)

    # Check ratelimit
    if security.ratelimited(f"update_chat:{request.user}"):
        abort(429)

    # Ratelimit
    security.ratelimit(f"update_chat:{request.user}", 5, 5)

    # Get chat
    chat = db.chats.find_one({"_id": chat_id, "members": request.user, "deleted": False})
    if not chat:
        abort(404)

    if chat["type"] == 0:
        # Remove member
        chat["members"].remove(request.user)

        # Update chat if it's not empty, otherwise delete the chat
        if len(chat["members"]) > 0:
            # Transfer ownership, if owner
            if chat["owner"] == request.user:
                chat["owner"] = chat["members"][0]
            
            # Update chat
            db.chats.update_one({"_id": chat_id}, {
                "$set": {"owner": chat["owner"]},
                "$pull": {"members": request.user}
            })

            # Send update chat event
            app.cl.send_event("update_chat", {
                "_id": chat_id,
                "owner": chat["owner"],
                "members": chat["members"]
            }, usernames=chat["members"])

            # Send in-chat notification
            app.supporter.create_post(chat_id, "Server", f"@{request.user} has left the group chat.", chat_members=chat["members"])
        else:
            if chat["icon"]:
                try:
                    delete_file(chat["icon"])
                except Exception as e:
                    log(f"Unable to delete icon: {e}")
            db.posts.delete_many({"post_origin": chat_id, "isDeleted": False})
            db.chats.delete_one({"_id": chat_id})
    elif chat["type"] == 1:
        # Remove chat from requester's active DMs list
        db.user_settings.update_one({"_id": request.user}, {
            "$pull": {"active_dms": chat_id}
        })
    else:
        abort(500)

    # Send delete event to client
    app.cl.send_event("delete_chat", {"chat_id": chat_id}, usernames=[request.user])

    return {"error": False}, 200


@chats_bp.post("/<chat_id>/typing")
async def emit_typing(chat_id):
    # Check authorization
    if not request.user:
        abort(401)

    # Check ratelimit
    if security.ratelimited(f"typing:{request.user}"):
        abort(429)

    # Ratelimit
    security.ratelimit(f"typing:{request.user}", 6, 5)

    # Check restrictions
    if security.is_restricted(request.user, security.Restrictions.CHAT_POSTS):
        return {"error": True, "type": "accountBanned"}, 403

    # Get chat
    if chat_id != "livechat":
        chat = db.chats.find_one({
            "_id": chat_id,
            "members": request.user,
            "deleted": False
        }, projection={"members": 1})
        if not chat:
            abort(404)

    # Send typing event
    app.cl.send_event("typing", {
        "chat_id": chat_id, "username": request.user
    }, usernames=(None if chat_id == "livechat" else chat["members"]))

    return {"error": False}, 200


@chats_bp.put("/<chat_id>/members/<username>")
async def add_chat_member(chat_id, username):
    # Check authorization
    if not request.user:
        abort(401)

    # Check ratelimit
    if security.ratelimited(f"update_chat:{request.user}"):
        abort(429)

    # Ratelimit
    security.ratelimit(f"update_chat:{request.user}", 5, 5)

    # Check restrictions
    if security.is_restricted(request.user, security.Restrictions.NEW_CHATS):
        return {"error": True, "type": "accountBanned"}, 403

    # Get chat
    chat = db.chats.find_one({"_id": chat_id, "members": request.user, "deleted": False})
    if not chat:
        abort(404)

    # Make sure the chat isn't full
    if chat["type"] == 1 or len(chat["members"]) >= 256:
        return {"error": True, "type": "chatFull"}, 403

    # Make sure the user isn't already in the chat
    if username in chat["members"]:
        return {"error": True, "type": "chatMemberAlreadyExists"}, 409

    # Make sure requested user exists and isn't deleted
    user = db.usersv0.find_one({"_id": username}, projection={"permissions": 1})
    if (not user) or (user["permissions"] is None):
        abort(404)

    # Make sure requested user isn't blocked or is blocking client
    if db.relationships.count_documents({"$or": [
        {
            "_id": {"from": request.user, "to": username},
            "state": 2
        },
        {
            "_id": {"from": username, "to": request.user},
            "state": 2
        }
    ]}, limit=1) > 0:
        abort(403)

    # Update chat
    chat["members"].append(username)
    db.chats.update_one({"_id": chat_id}, {"$addToSet": {"members": username}})

    # Send create chat event
    app.cl.send_event("create_chat", chat, usernames=[username])

    # Send update chat event
    app.cl.send_event("update_chat", {
        "_id": chat_id,
        "members": chat["members"]
    }, usernames=chat["members"])

    # Send inbox message to user
    app.supporter.create_post("inbox", username, f"You have been added to the group chat '{chat['nickname']}' by @{request.user}!")

    # Send in-chat notification
    app.supporter.create_post(chat_id, "Server", f"@{request.user} added @{username} to the group chat.", chat_members=chat["members"])

    # Return chat
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


@chats_bp.delete("/<chat_id>/members/<username>")
async def remove_chat_member(chat_id, username):
    # Check authorization
    if not request.user:
        abort(401)

    # Check ratelimit
    if security.ratelimited(f"update_chat:{request.user}"):
        abort(429)

    # Ratelimit
    security.ratelimit(f"update_chat:{request.user}", 5, 5)

    # Get chat
    chat = db.chats.find_one({
        "_id": chat_id,
        "members": {"$all": [request.user, username]},
        "deleted": False
    })
    if not chat:
        abort(404)

    # Make sure requester is owner
    if chat["owner"] != request.user:
        abort(403)

    # Update chat
    chat["members"].remove(username)
    db.chats.update_one({"_id": chat_id}, {"$pull": {"members": username}})

    # Send delete chat event to user
    app.cl.send_event("delete_chat", {"chat_id": chat_id}, usernames=[username])

    # Send update chat event
    app.cl.send_event("update_chat", {
        "_id": chat_id,
        "members": chat["members"]
    }, usernames=chat["members"])

    # Send inbox message to user
    app.supporter.create_post("inbox", username, f"You have been removed from the group chat '{chat['nickname']}' by @{request.user}!")

    # Send in-chat notification
    app.supporter.create_post(chat_id, "Server", f"@{request.user} removed @{username} from the group chat.", chat_members=chat["members"])

    # Return chat
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


@chats_bp.post("/<chat_id>/members/<username>/transfer")
async def transfer_chat_ownership(chat_id, username):
    # Check authorization
    if not request.user:
        abort(401)

    # Check ratelimit
    if security.ratelimited(f"update_chat:{request.user}"):
        abort(429)

    # Ratelimit
    security.ratelimit(f"update_chat:{request.user}", 5, 5)

    # Get chat
    chat = db.chats.find_one({
        "_id": chat_id,
        "members": {"$all": [request.user, username]},
        "deleted": False
    })
    if not chat:
        abort(404)

    # Make sure requester is owner
    if chat["owner"] != request.user:
        abort(403)

    # Make sure requested user isn't already owner
    if chat["owner"] == username:
        chat["error"] = False
        return chat, 200

    # Update chat
    chat["owner"] = username
    db.chats.update_one({"_id": chat_id}, {"$set": {"owner": username}})

    # Send update chat event
    app.cl.send_event("update_chat", {
        "_id": chat_id,
        "owner": chat["owner"]
    }, usernames=chat["members"])

    # Send in-chat notification
    app.supporter.create_post(chat_id, "Server", f"@{request.user} transferred ownership of the group chat to @{username}.", chat_members=chat["members"])

    # Return chat
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


@chats_bp.get("/<chat_id>/pins")
@validate_querystring(GetPostsQueryArgs)
def get_chat_pins(chat_id, query_args: GetPostsQueryArgs):
    # Check authorization
    if not request.user:
        abort(401)

    # Make sure chat exists and requester has access
    if not db.chats.count_documents({
        "_id": chat_id,
        "members": request.user,
        "deleted": False
    }, limit=1):
        abort(404)

    # Get and return pinned posts
    query = {"post_origin": chat_id, "pinned": True}
    return {
        "error": False,
        "autoget": app.supporter.parse_posts_v0(
            db.posts.find(
                query,
                sort=[("t.e", pymongo.DESCENDING)],
                skip=(query_args.page-1)*25,
                limit=25
            ),
            include_replies=True,
            requester=request.user
        ),
        "page#": query_args.page,
        "pages": (get_total_pages("posts", query) if request.user else 1)
    }, 200


@chats_bp.get("/<chat_id>/<emote_type>")
async def get_chat_emotes(chat_id: str, emote_type: Literal["emojis", "stickers"]):
    # Make sure emote type is valid
    if emote_type not in ["emojis", "stickers"]:
        abort(404)

    # Check authorization
    if not request.user:
        abort(401)

    # Make sure chat exists and requester has access
    if not db.chats.count_documents({
        "_id": chat_id,
        "members": request.user,
        "deleted": False
    }, limit=1):
        abort(404)

    # Get and return emotes
    return {
        "error": False,
        "autoget": list(db[f"chat_{emote_type}"].find({
            "chat_id": chat_id
        }, sort=[("created_at", pymongo.DESCENDING)], projection={
            "chat_id": 0,
            "created_at": 0,
            "created_by": 0
        })),
        "page#": 1,
        "pages": 1
    }, 200


@chats_bp.get("/<chat_id>/<emote_type>/<emote_id>")
async def get_chat_emote(chat_id: str, emote_type: Literal["emojis", "stickers"], emote_id: str):
    # Make sure emote type is valid
    if emote_type not in ["emojis", "stickers"]:
        abort(404)

    # Check authorization
    if not request.user:
        abort(401)

    # Make sure chat exists and requester has access
    if not db.chats.count_documents({
        "_id": chat_id,
        "members": request.user,
        "deleted": False
    }, limit=1):
        abort(404)

    # Get emote
    emote = db[f"chat_{emote_type}"].find_one({
        "_id": emote_id,
        "chat_id": chat_id
    }, projection={"chat_id": 0, "created_at": 0, "created_by": 0})
    if not emote:
        abort(404)

    # Return emote
    emote["error"] = False
    return emote, 200


@chats_bp.put("/<chat_id>/<emote_type>/<emote_id>")
@validate_request(EmoteBody)
async def create_chat_emote(chat_id: str, emote_type: Literal["emojis", "stickers"], emote_id: str, data: EmoteBody):
    # Make sure emote type is valid
    if emote_type not in ["emojis", "stickers"]:
        abort(404)

    # Check authorization
    if not request.user:
        abort(401)

    # Check ratelimit
    if security.ratelimited(f"update_chat:{request.user}"):
        abort(429)

    # Ratelimit
    security.ratelimit(f"update_chat:{request.user}", 5, 5)

    # Get chat
    chat = db.chats.find_one({
        "_id": chat_id,
        "members": {"$all": [request.user]},
        "deleted": False
    })
    if not chat:
        abort(404)

    # Make sure chat is DM or requester is owner
    if chat["type"] != 1 and chat["owner"] != request.user:
        abort(403)

    # Make sure there's not too many emotes in the chat (100 for emojis, 25 for stickers)
    if emote_type == "emojis":
        if db.chat_emojis.count_documents({"chat_id": chat_id}, limit=100) >= 100:
            return {"error": True, "type": "tooManyEmojis"}, 403
    elif emote_type == "stickers":
        if db.chat_stickers.count_documents({"chat_id": chat_id}, limit=25) >= 25:
            return {"error": True, "type": "tooManyStickers"}, 403

    # Claim file
    try:
        file = claim_file(emote_id, emote_type)
    except Exception as e:
        log(f"Unable to claim emote: {e}")
        return {"error": True, "type": "unableToClaimEmote"}, 500

    # Fall back to filename if no name is specified
    if not data.name:
        name_pattern = re.compile(r'[^A-Za-z0-9\-\_]')
        data.name = name_pattern.sub("_", file["filename"])[:20]

    # Create emote
    emote = {
        "_id": emote_id,
        "chat_id": chat_id,
        "name": data.name,
        "animated": (file["mime"] == "image/gif"),
        "created_at": int(time.time()),
        "created_by": request.user
    }
    db[f"chat_{emote_type}"].insert_one(emote)
    del emote["created_at"]
    del emote["created_by"]
    app.cl.send_event(f"create_{emote_type[:-1]}", emote, usernames=chat["members"])

    # Return new emote
    del emote["chat_id"]
    emote["error"] = False
    return emote, 200


@chats_bp.patch("/<chat_id>/<emote_type>/<emote_id>")
@validate_request(EmoteBody)
async def update_chat_emote(chat_id: str, emote_type: Literal["emojis", "stickers"], emote_id: str, data: EmoteBody):
    # Make sure emote type is valid
    if emote_type not in ["emojis", "stickers"]:
        abort(404)

    # Make sure a new name is being specified
    if not data.name:
        abort(400)

    # Check authorization
    if not request.user:
        abort(401)

    # Check ratelimit
    if security.ratelimited(f"update_chat:{request.user}"):
        abort(429)

    # Ratelimit
    security.ratelimit(f"update_chat:{request.user}", 5, 5)

    # Get chat
    chat = db.chats.find_one({
        "_id": chat_id,
        "members": {"$all": [request.user]},
        "deleted": False
    })
    if not chat:
        abort(404)

    # Make sure chat is DM or requester is owner
    if chat["type"] != 1 and chat["owner"] != request.user:
        abort(403)

    # Get emote
    emote = db[f"chat_{emote_type}"].find_one({
        "_id": emote_id,
        "chat_id": chat_id
    }, projection={"chat_id": 0, "created_at": 0, "created_by": 0})
    if not emote:
        abort(404)

    # Update emote name
    emote["name"] = data.name
    db[f"chat_{emote_type}"].update_one({"_id": emote_id}, {"$set": {"name": data.name}})
    app.cl.send_event(f"update_{emote_type[:-1]}", {
        "_id": emote_id,
        "chat_id": chat_id,
        "name": data.name
    }, usernames=chat["members"])

    # Return updated emote
    emote["error"] = False
    return emote, 200


@chats_bp.delete("/<chat_id>/<emote_type>/<emote_id>")
async def delete_chat_emote(chat_id: str, emote_type: Literal["emojis", "stickers"], emote_id: str):
    # Make sure emote type is valid
    if emote_type not in ["emojis", "stickers"]:
        abort(404)

    # Check authorization
    if not request.user:
        abort(401)

    # Check ratelimit
    if security.ratelimited(f"update_chat:{request.user}"):
        abort(429)

    # Ratelimit
    security.ratelimit(f"update_chat:{request.user}", 5, 5)

    # Get chat
    chat = db.chats.find_one({
        "_id": chat_id,
        "members": {"$all": [request.user]},
        "deleted": False
    })
    if not chat:
        abort(404)

    # Make sure chat is DM or requester is owner
    if chat["type"] != 1 and chat["owner"] != request.user:
        abort(403)

    # Delete emote
    result = db[f"chat_{emote_type}"].delete_one({"_id": emote_id, "chat_id": chat_id})
    if not result.deleted_count:
        abort(404)
    app.cl.send_event(f"delete_{emote_type[:-1]}", {
        "_id": emote_id,
        "chat_id": chat_id
    }, usernames=chat["members"])
    delete_file(emote_id)

    return {"error": False}, 200
