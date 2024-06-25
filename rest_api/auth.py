import re
from time import time
import uuid
from pydantic import BaseModel
from quart import Blueprint, request, abort, current_app as app
from quart_schema import validate_request
from pydantic import Field
from database import db, registration_blocked_ips
import security

auth_bp = Blueprint("auth_bp", __name__, url_prefix="/auth")
time

class AuthRequest(BaseModel):
    username: str = Field(min_length=1, max_length=20)
    password: str = Field(min_length=1, max_length=255)


@auth_bp.post('/login')
@validate_request(AuthRequest)
async def login(data: AuthRequest):
    for bucket_id in [
        f"login:i:{request.ip}",
        f"login:u:{data.username}:s",
        f"login:u:{data.username}:f"
    ]:
        if security.ratelimited(bucket_id):
            abort(429)

    account = db.usersv0.find_one({"_id": data.username}, projection={
        "tokens": 1,
        "pswd": 1,
        "flags": 1,
        "permissions": 1,
        "ban": 1,
        "delete_after": 1
    })

    if not account:
        abort(404)

    if (account["flags"] & security.UserFlags.DELETED) or (account["delete_after"] is not None and account["delete_after"] <= time() + 60):
        security.ratelimit(f"login:u:{data.username}:f", 5, 60)
        return {"error": True, "type": "accountDeleted"}, 401

    if (data.password not in account["tokens"]) and (not security.check_password_hash(data.password, account["pswd"])):
        security.ratelimit(f"login:u:{data.username}:f", 5, 60)
        abort(401)

    db.netlog.update_one({"_id": {"ip": request.ip, "user": data.username}}, {"$set": {"last_used": int(time())}}, upsert=True)

    security.ratelimit(f"login:u:{data.username}:s", 25, 300)

    token = security.generate_token()

    db.usersv0.update_one({"_id": data.username}, {
        "$addToSet": {"tokens": token},
        "$set": {"last_seen": int(time()), "delete_after": None}
    })

    return {"error": False, "token": token, "account": security.get_account(data.username, True)}, 200

@auth_bp.post('/register')
@validate_request(AuthRequest)
async def register(data: AuthRequest):
    if not app.supporter.registration:
        return {"error": True, "type": "registrationDisabled"}, 403
    
    if security.ratelimited(f"register:{request.ip}:f"):
        abort(429)

    if not re.fullmatch(security.USERNAME_REGEX, data.username):
        return {"error": True, "type": "invalidUsername"}, 400
    
    if registration_blocked_ips.search_best(request.ip):
        security.ratelimit(f"register:{request.ip}:f", 5, 30)
        return {"error": True, "type": "registrationBlocked"}, 403

    if security.account_exists(data.username):
        security.ratelimit(f"register:{request.ip}:f", 5, 30)
        return {"error": True, "type": "usernameExists"}, 409
    
    token = security.generate_token()

    security.create_account(data.username, data.password, token)

    security.ratelimit(f"register:{request.ip}:s", 5, 900)

    db.netlog.update_one({"_id": {"ip": request.ip, "user": data.username}}, {"$set": {"last_used": int(time())}}, upsert=True)

    app.supporter.create_post("inbox", data.username, "Welcome to Meower! We welcome you with open arms! You can get started by making friends in the global chat or home, or by searching for people and adding them to a group chat. We hope you have fun!")

    if security.get_netinfo(request.ip)["vpn"]:
        db.reports.insert_one({
            "_id": str(uuid.uuid4()),
            "type": "user",
            "content_id": data.username,
            "status": "pending",
            "escalated": False,
            "reports": [{
                "user": "Server",
                "ip": request.ip,
                "reason": "User registered while using a VPN.",
                "comment": "",
                "time": int(time())
            }]
        })
    
    return {"error": False, "token": token, "account": security.get_account(data.username, True)}, 200
