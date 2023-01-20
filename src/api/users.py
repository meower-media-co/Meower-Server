from sanic import Blueprint, json, HTTPResponse
from sanic_ext import validate
from pydantic import BaseModel, Field

from src.util import status
from src.entities import users, chats

v0 = Blueprint("v0_users", url_prefix="/users/<username:str>")
v1 = Blueprint("v1_users", url_prefix="/users/<user_id:str>")

@v0.get("/")
async def v0_get_user(request, username: str):
    try:
        user_id = users.get_id_from_username(username)
        user = users.get_user(user_id)
    except status.notFound:
        return json({"error": True, "type": "notFound"}, status=404)
    except:
        return json({"error": True, "type": "internal"}, status=500)
    else:
        resp = user.legacy
        resp["error"] = False
        return json(resp)

@v1.get("/")
async def v1_get_user(request, user_id: str):
    user = users.get_user(user_id)

    if (request.ctx.user is not None) and (request.ctx.user.id == user.id):
        return json(user.client)
    else:
        return json(user.public)

@v1.post("/follow")
async def v1_follow_user(request, user_id: str):
    if request.ctx.user is None:
        raise status.notAuthenticated

    user = users.get_user(user_id)

    if request.ctx.user == user.id:
        raise status.missingPermissions
    else:
        user.follow_user(request.ctx.user)

    return HTTPResponse(status=204)

@v1.post("/unfollow")
async def v1_unfollow_user(request, user_id: str):
    if request.ctx.user is None:
        raise status.notAuthenticated

    user = users.get_user(user_id)

    if request.ctx.user == user.id:
        raise status.missingPermissions
    else:
        user.unfollow_user(request.ctx.user)

    return HTTPResponse(status=204)

@v1.post("/block")
async def v1_block_user(request, user_id: str):
    if request.ctx.user is None:
        raise status.notAuthenticated

    user = users.get_user(user_id)

    if request.ctx.user == user.id:
        raise status.missingPermissions
    else:
        user.block_user(request.ctx.user)

    return HTTPResponse(status=204)

@v1.post("/unblock")
async def v1_unblock_user(request, user_id: str):
    if request.ctx.user is None:
        raise status.notAuthenticated

    user = users.get_user(user_id)

    if request.ctx.user == user.id:
        raise status.missingPermissions
    else:
        user.unblock_user(request.ctx.user)

    return HTTPResponse(status=204)

@v1.get("/dm")
async def v1_dm_user(request, user_id: str):
    if request.ctx.user is None:
        raise status.notAuthenticated

    user = users.get_user(user_id)

    if request.ctx.user == user.id:
        raise status.missingPermissions
    else:
        chat = chats.get_dm_chat(request.ctx.user, user)

    return json(chat.public)