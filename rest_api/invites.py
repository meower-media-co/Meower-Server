# noinspection PyTypeChecker
from quart import Blueprint, current_app as app, request, abort
import time

from database import db
from .api_types import AuthenticatedRequest, MeowerQuart

request: AuthenticatedRequest
app: MeowerQuart

invites_bp = Blueprint("invites_bp", __name__, url_prefix="/invites/<invite_code>")


@invites_bp.get("/")
async def get_invite_details(invite_code):
    # Get invite
    invite = db.chat_invites.find_one({"_id": invite_code})
    if not invite:
        abort(404)

    # Get chat
    chat = db.chats.find_one({"_id": invite["chat_id"]})
    if not chat:
        abort(404)

    return {
        "error": False,
        "invite": invite,
        "chat": chat
    }, 200


@invites_bp.post("/")
async def accept_invite(invite_code):
    # Check authorization
    if not request.user:
        abort(401)

    # Get invite
    invite = db.chat_invites.find_one({"_id": invite_code})
    if not invite:
        abort(404)

    # Get chat
    chat = db.chats.find_one({"_id": invite["chat_id"]})
    if not chat:
        abort(404)

    # Make sure requester isn't already in the chat
    if request.user in chat["members"]:
        return {"error": True, "type": "chatMemberAlreadyExists"}, 409

    # Make sure the chat isn't full
    if len(chat["members"]) >= 256:
        return {"error": True, "type": "chatFull"}, 403

    # Make sure requester isn't banned from the chat
    ban = db.chat_bans.find_one({
        "_id": {"chat": chat["_id"], "user": request.user},
        "$or": [
            {"expires": None},
            {"expires": {"$gt": int(time.time())}}
        ]
    }, projection={"moderator": 0})
    if ban is not None:
        return {"error": True, "type": "chatBanned", "ban": ban}, 403
    
    # Update chat
    chat["members"].append(request.user)
    db.chats.update_one({"_id": chat["_id"]}, {"$addToSet": {"members": request.user}})

    # Send in-chat notification
    app.supporter.create_post(chat["_id"], "Server", f" @{request.user} has joined the group chat via an invite from @{invite['inviter']}", chat_members=chat["members"])

    # Send chat creation event
    app.cl.broadcast({
        "mode": "create_chat",
        "payload": chat
    }, direct_wrap=True,  usernames=[request.user])

    # Send chat update event
    app.cl.broadcast({
        "mode": "update_chat",
        "payload": {
            "_id": invite["chat_id"],
            "members": chat["members"]
        }
    }, direct_wrap=True, usernames=chat["members"])

    chat["error"] = False
    return chat, 200

