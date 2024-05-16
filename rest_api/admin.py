from quart import Blueprint, current_app as app, request, abort
from pydantic import BaseModel, Field
from typing import List, Optional, Literal
from base64 import b64decode
from copy import copy
import time
import pymongo
import msgpack

import security
from database import db, rdb, get_total_pages, blocked_ips, registration_blocked_ips
from better_profanity import profanity


admin_bp = Blueprint("admin_bp", __name__, url_prefix="/admin")


class UpdateReportBody(BaseModel):
    status: Literal["no_action_taken", "action_taken"]

    class Config:
        validate_assignment = True


class UpdateNotesBody(BaseModel):
    notes: str

    class Config:
        validate_assignment = True
        str_strip_whitespace = True


class UpdateUserBanBody(BaseModel):
    state: Literal[
        "none", "temp_restriction", "perm_restriction", "temp_ban", "perm_ban"
    ]
    restrictions: int
    expires: int
    reason: str

    class Config:
        validate_assignment = True
        str_strip_whitespace = True


class UpdateUserBody(BaseModel):
    experiments: Optional[int] = Field(default=None, ge=0)
    permissions: Optional[int] = Field(default=None, ge=0)

    class Config:
        validate_assignment = True


class UpdateChatBody(BaseModel):
    nickname: str = Field(default=None, min_length=1, max_length=32)
    icon: str = Field(default=None, max_length=24)
    icon_color: str = Field(default=None, min_length=1, max_length=6)
    allow_pinning: bool = Field(default=None)

    class Config:
        validate_assignment = True
        str_strip_whitespace = True

class UpdateProfanityBody(BaseModel):
    items: List[str]

    class Config:
        validate_assignment = True
        str_strip_whitespace = True

class InboxMessageBody(BaseModel):
    content: str = Field(min_length=1, max_length=4000)

    class Config:
        validate_assignment = True
        str_strip_whitespace = True


class NetblockBody(BaseModel):
    type: int = Literal[0, 1]

    class Config:
        validate_assignment = True


@admin_bp.before_request
async def check_admin_perms():
    if request.method != "OPTIONS":
        if (not request.user) or (not request.permissions):
            abort(401)


@admin_bp.get("/reports")
async def get_reports():
    # Check permissions
    if not security.has_permission(request.permissions, security.AdminPermissions.VIEW_REPORTS):
        abort(403)

    # Construct query
    query = {}
    if "status" in request.args:
        query["status"] = request.args["status"]
    if "type" in request.args:
        query["type"] = request.args["type"]

    # Get page
    try:
        page = int(request.args["page"])
    except:
        page = 1

    # Get reports
    reports = list(
        db.reports.find(
            query,
            projection={"reports.ip": 0},
            sort=[("escalated", pymongo.DESCENDING), ("reports.time", pymongo.DESCENDING)],
            skip=(page - 1) * 25,
            limit=25,
        )
    )

    # Get content
    for report in reports:
        if report["type"] == "post":
            report["content"] = db.posts.find_one(
                {"_id": report.get("content_id")}
            )
        elif report["type"] == "user":
            report["content"] = security.get_account(report.get("content_id"))

    # Add log
    security.add_audit_log(
        "got_reports",
        request.user,
        request.ip,
        {
            "status": request.args.get("status", "any"),
            "type": request.args.get("type", "any"),
            "page": page,
        },
    )

    # Return reports
    payload = {
        "error": False,
        "page#": page,
        "pages": get_total_pages("reports", query),
    }
    if "autoget" in request.args:
        payload["autoget"] = reports
    else:
        payload["index"] = [report["_id"] for report in reports]
    return payload, 200


@admin_bp.get("/reports/<report_id>")
async def get_report(report_id):
    # Check permissions
    if not security.has_permission(request.permissions, security.AdminPermissions.VIEW_REPORTS):
        abort(403)

    # Get report
    report = db.reports.find_one(
        {"_id": report_id}, projection={"reports.ip": 0}
    )
    if not report:
        abort(404)

    # Get content
    if report["type"] == "post":
        report["content"] = db.posts.find_one(
            {"_id": report.pop("content_id")}
        )
    elif report["type"] == "user":
        report["content"] = security.get_account(report.get("content_id"))

    # Add log
    security.add_audit_log(
        "got_report", request.user, request.ip, {"report_id": report_id}
    )

    # Return report
    report["error"] = False
    return report, 200


@admin_bp.patch("/reports/<report_id>")
async def update_report(report_id):
    # Check permissions
    if not security.has_permission(request.permissions, security.AdminPermissions.EDIT_REPORTS):
        abort(403)

    # Get body
    try:
        body = UpdateReportBody(**await request.json)
    except:
        abort(400)

    # Get report
    report = db.reports.find_one(
        {"_id": report_id}, projection={"reports.ip": 0}
    )
    if not report:
        abort(404)

    # Update report
    report["status"] = body.status
    report["escalated"] = False
    db.reports.update_one(
        {"_id": report_id}, {"$set": {"status": body.status, "escalated": False}}
    )

    # Get content
    if report["type"] == "post":
        report["content"] = db.posts.find_one(
            {"_id": report.pop("content_id")}
        )
    elif report["type"] == "user":
        report["content"] = security.get_account(report.get("content_id"))

    # Add log
    security.add_audit_log(
        "updated_report",
        request.user,
        request.ip,
        {"report_id": report_id, "status": body.status, "escalated": False},
    )

    # Return report
    report["error"] = False
    return report, 200


@admin_bp.post("/reports/<report_id>/escalate")
async def escalate_report(report_id):
    # Check permissions
    if not security.has_permission(request.permissions, security.AdminPermissions.EDIT_REPORTS):
        abort(403)

    # Get report
    report = db.reports.find_one(
        {"_id": report_id}, projection={"reports.ip": 0}
    )
    if not report:
        abort(404)

    # Update report
    report["status"] = "pending"
    report["escalated"] = True
    db.reports.update_one(
        {"_id": report_id}, {"$set": {"status": "pending", "escalated": True}}
    )

    # Get content
    if report["type"] == "post":
        report["content"] = db.posts.find_one(
            {"_id": report.pop("content_id")}
        )
    elif report["type"] == "user":
        report["content"] = security.get_account(report.get("content_id"))

    # Add log
    security.add_audit_log(
        "updated_report",
        request.user,
        request.ip,
        {"report_id": report_id, "status": "pending", "escalated": True},
    )

    # Return report
    report["error"] = False
    return report, 200


@admin_bp.get("/notes/<identifier>")
async def get_admin_notes(identifier):
    # Check permissions
    if not security.has_permission(request.permissions, security.AdminPermissions.VIEW_NOTES):
        abort(403)

    # Get notes
    notes = db.admin_notes.find_one({"_id": identifier})

    # Add log
    security.add_audit_log(
        "got_notes", request.user, request.ip, {"identifier": identifier}
    )

    # Return notes
    if notes:
        notes["error"] = False
        return notes, 200
    else:
        return {
            "_id": identifier,
            "notes": "",
            "last_modified_by": None,
            "last_modified_at": None,
            "error": False,
        }, 200


@admin_bp.put("/notes/<identifier>")
async def edit_admin_note(identifier):
    # Check permissions
    if not security.has_permission(request.permissions, security.AdminPermissions.EDIT_NOTES):
        abort(403)

    # Get body
    try:
        body = UpdateNotesBody(**await request.json)
    except:
        abort(400)

    # Update notes
    notes = {
        "_id": identifier,
        "notes": body.notes,
        "last_modified_by": request.user,
        "last_modified_at": int(time.time()),
    }
    db.admin_notes.update_one(
        {"_id": identifier}, {"$set": notes}, upsert=True
    )

    # Add log
    security.add_audit_log(
        "updated_notes",
        request.user,
        request.ip,
        {"identifier": identifier, "notes": body.notes},
    )

    # Return new notes
    notes["error"] = False
    return notes, 200


@admin_bp.get("/posts/<post_id>")
async def get_post(post_id):
    # Check permissions
    if not security.has_permission(request.permissions, security.AdminPermissions.VIEW_POSTS):
        abort(403)

    # Get post
    post = db.posts.find_one({"_id": post_id})
    if not post:
        abort(404)

    # Get post revisions
    post["revisions"] = list(
        db.post_revisions.find(
            {"post_id": post_id}, sort=[("time", pymongo.DESCENDING)]
        )
    )

    # Return post
    post["error"] = False
    return post, 200


@admin_bp.delete("/posts/<post_id>")
async def delete_post(post_id):
    # Check permissions
    if not security.has_permission(request.permissions, security.AdminPermissions.DELETE_POSTS):
        abort(403)

    # Get post
    post = db.posts.find_one({"_id": post_id})
    if not post:
        abort(404)

    # Update post
    post["isDeleted"] = True
    post["deleted_at"] = int(time.time())
    post["mod_deleted"] = True
    db.posts.update_one(
        {"_id": post_id},
        {
            "$set": {
                "isDeleted": True,
                "deleted_at": int(time.time()),
                "mod_deleted": True,
            }
        },
    )

    # Send delete post event
    if post["post_origin"] == "home" or (post["post_origin"] == "inbox" and post["u"] == "Server"):
        app.cl.broadcast({
            "mode": "delete",
            "id": post_id
        }, direct_wrap=True)
    elif post["post_origin"] == "inbox":
        app.cl.broadcast({
            "mode": "delete",
            "id": post_id
        }, direct_wrap=True, usernames=[post["u"]])
    else:
        chat = db.chats.find_one({
            "_id": post["post_origin"],
            "members": request.user,
            "deleted": False
        }, projection={"members": 1})
        if chat:
            app.cl.broadcast({
                "mode": "delete",
                "id": post_id
            }, direct_wrap=True, usernames=chat["members"])

    # Return updated post
    post["error"] = False
    return post, 200


@admin_bp.post("/posts/<post_id>/restore")
async def restore_post(post_id):
    # Check permissions
    if not security.has_permission(request.permissions, security.AdminPermissions.DELETE_POSTS):
        abort(403)

    # Get post
    post = db.posts.find_one({"_id": post_id})
    if not post:
        abort(404)

    # Update post
    post["isDeleted"] = False
    if "deleted_at" in post:
        del post["deleted_at"]
    if "mod_deleted" in post:
        del post["mod_deleted"]
    db.posts.update_one(
        {"_id": post_id},
        {"$set": {"isDeleted": False}, "$unset": {"deleted_at": "", "mod_deleted": ""}},
    )

    # Return updated post
    post["error"] = False
    return post, 200


@admin_bp.get("/users")
async def get_users():
    # Get page
    try:
        page = int(request.args["page"])
    except:
        page = 1

    # Get usernames
    usernames = [user["_id"] for user in db.usersv0.find({}, sort=[("created", pymongo.DESCENDING)], skip=(page-1)*25, limit=25)]

    # Add log
    security.add_audit_log("got_users", request.user, request.ip, {"page": page})

    # Return users
    payload = {
        "error": False,
        "page#": page,
        "pages": get_total_pages("usersv0", {}),
    }
    if "autoget" in request.args:
        payload["autoget"] = [security.get_account(username) for username in usernames]
    else:
        payload["index"] = usernames
    return payload, 200


@admin_bp.get("/users/<username>")
async def get_user(username):
    # Get account
    account = db.usersv0.find_one({"_id": username})
    if not account:
        abort(404)

    # Construct payload
    payload = {
        "_id": account["_id"],
        "created": account["created"],
        "uuid": account["uuid"],
        "pfp_data": account["pfp_data"],
        "avatar": account["avatar"],
        "avatar_color": account["avatar_color"],
        "quote": account["quote"],
        "flags": account["flags"],
        "experiments": account["experiments"],
        "permissions": account["permissions"],
        "last_seen": account["last_seen"],
        "delete_after": account["delete_after"],
    }

    if not (
        (account["flags"] & security.UserFlags.SYSTEM) == security.UserFlags.SYSTEM
        or (account["flags"] & security.UserFlags.DELETED) == security.UserFlags.DELETED
    ):
        # Add user settings or unread inbox state
        if security.has_permission(request.permissions, security.AdminPermissions.SYSADMIN):
            payload.update({"settings": security.DEFAULT_USER_SETTINGS})
            user_settings = db.user_settings.find_one({"_id": username})
            if user_settings:
                del user_settings["_id"]
                payload["settings"].update(user_settings)
        elif security.has_permission(request.permissions, security.AdminPermissions.VIEW_POSTS):
            payload.update(
                {"settings": {"unread_inbox": security.DEFAULT_USER_SETTINGS["unread_inbox"]}}
            )
            user_settings = db.user_settings.find_one(
                {"_id": username}, projection={"unread_inbox": 1}
            )
            if user_settings:
                del user_settings["_id"]
                payload["settings"].update(user_settings)

        # Add ban state
        if security.has_permission(
            request.permissions, security.AdminPermissions.VIEW_BAN_STATES
        ):
            payload["ban"] = account["ban"]

        # Add alts and recent IPs
        if security.has_permission(request.permissions, security.AdminPermissions.VIEW_ALTS):
            # Get netlogs
            netlogs = [
                {
                    "ip": netlog["_id"]["ip"],
                    "user": netlog["_id"]["user"],
                    "last_used": netlog["last_used"],
                }
                for netlog in db.netlog.find(
                    {"_id.user": username}, sort=[("last_used", pymongo.DESCENDING)]
                )
            ]

            # Get alts
            alts = [
                netlog["_id"]["user"]
                for netlog in db.netlog.find(
                    {"_id.ip": {"$in": [netlog["ip"] for netlog in netlogs]}}
                )
            ]
            if username in alts:
                alts.remove(username)
            payload["alts"] = list(set(alts))

            # Get recent IP info
            if security.has_permission(request.permissions, security.AdminPermissions.VIEW_IPS):
                payload["recent_ips"] = [
                    {
                        "ip": netlog["ip"],
                        "netinfo": security.get_netinfo(netlog["ip"]),
                        "last_used": netlog["last_used"],
                        "blocked": (
                            blocked_ips.search_best(netlog["ip"])
                            is not None
                        ),
                        "registration_blocked": (
                            registration_blocked_ips.search_best(
                                netlog["ip"]
                            )
                            is not None
                        ),
                    }
                    for netlog in netlogs
                ]

    # Add log
    security.add_audit_log(
        "got_user",
        request.user,
        request.ip,
        {"username": username, "returned_fields": list(payload.keys())},
    )

    payload["error"] = False
    return payload, 200


@admin_bp.patch("/users/<username>")
async def update_user(username):
    # Check permissions
    if not security.has_permission(request.permissions, security.AdminPermissions.SYSADMIN):
        abort(403)

    # Get body
    try:
        body = UpdateUserBody(**await request.json)
    except:
        abort(400)

    # Make sure user exists
    if not security.account_exists(username):
        abort(404)

    # Create updated fields var
    updated_fields = {}

    # Experiments
    if body.experiments is not None:
        updated_fields["experiments"] = body.experiments
        security.add_audit_log(
            "updated_experiments",
            request.user,
            request.ip,
            {"username": username, "experiments": body.experiments},
        )

    # Permissions
    if body.permissions is not None:
        updated_fields["permissions"] = body.permissions
        security.add_audit_log(
            "updated_permissions",
            request.user,
            request.ip,
            {"username": username, "permissions": body.permissions},
        )

    # Update user
    db.usersv0.update_one({"_id": username}, {"$set": updated_fields})

    # Sync config between sessions
    app.cl.broadcast({
        "mode": "update_config",
        "payload": updated_fields
    }, direct_wrap=True, usernames=[username])

    # Send updated experiments and permissions to other clients
    app.cl.broadcast({
        "mode": "update_profile",
        "payload": {
            "_id": username,
            "experiments": body.experiments,
            "permissions": body.permissions,
        }
    }, direct_wrap=True)

    return {"error": False}, 200


@admin_bp.delete("/users/<username>")
async def delete_user(username):
    # Check permissions
    if not security.has_permission(request.permissions, security.AdminPermissions.DELETE_USERS):
        abort(403)

    # Make sure user exists
    if not security.account_exists(username):
        abort(404)

    # Make sure user isn't protected
    if not security.has_permission(request.permissions, security.AdminPermissions.SYSADMIN):
        account = db.usersv0.find_one(
            {"_id": username}, projection={"flags": 1}
        )
        if (account["flags"] & security.UserFlags.PROTECTED) == security.UserFlags.PROTECTED:
            abort(403)

    # Get deletion mode
    deletion_mode = request.args.get("mode")

    # Delete account (or not, depending on the mode)
    if deletion_mode == "cancel":
        db.usersv0.update_one(
            {"_id": username}, {"$set": {"delete_after": None}}
        )
    elif deletion_mode in ["schedule", "immediate", "purge"]:
        db.usersv0.update_one(
            {"_id": username},
            {
                "$set": {
                    "tokens": [],
                    "delete_after": int(time.time()) + (604800 if deletion_mode == "schedule" else 0),
                }
            },
        )
        for client in app.cl.usernames.get(username, []):
            client.kick(statuscode="LoggedOut")
        if deletion_mode in ["immediate", "purge"]:
            security.delete_account(username, purge=(deletion_mode == "purge"))
    else:
        abort(400)

    return {"error": False}, 200


@admin_bp.post("/users/<username>/ban")
async def ban_user(username):
    # Check permissions
    if not security.has_permission(
        request.permissions, security.AdminPermissions.EDIT_BAN_STATES
    ):
        abort(403)

    # Get body
    try:
        body = UpdateUserBanBody(**await request.json)
    except:
        abort(400)

    # Make sure user exists
    if not security.account_exists(username):
        abort(404)

    # Make sure user isn't protected
    if not security.has_permission(request.permissions, security.AdminPermissions.SYSADMIN):
        account = db.usersv0.find_one(
            {"_id": username}, projection={"flags": 1}
        )
        if (account["flags"] & security.UserFlags.PROTECTED) == security.UserFlags.PROTECTED:
            abort(403)

    # Update user
    db.usersv0.update_one(
        {"_id": username}, {"$set": {"ban": body.model_dump()}}
    )

    # Add log
    security.add_audit_log(
        "banned",
        request.user,
        request.ip,
        {"username": username, "ban": body.model_dump()},
    )

    # Kick client or send updated ban state
    if (body.state == "perm_ban") or (
        body.state == "temp_ban" and body.expires > time.time()
    ):
        for client in app.cl.usernames.get(username, []):
            client.kick(statuscode="Banned")
    else:
        app.cl.broadcast({
            "mode": "update_config",
            "payload": {
                "ban": body.model_dump()
            }
        }, direct_wrap=True, usernames=[username])

    return {"error": False}, 200


@admin_bp.get("/users/<username>/posts")
async def get_user_posts(username):
    # Check permissions
    if not security.has_permission(request.permissions, security.AdminPermissions.VIEW_POSTS):
        abort(401)

    # Get post origin
    post_origin = request.args.get("origin") 

    # Get page
    try:
        page = int(request.args["page"])
    except:
        page = 1

    # Get posts
    if post_origin:
        query = {
            "post_origin": post_origin,
            "$or": [{"isDeleted": False}, {"isDeleted": True}],
            "u": username,
        }
    else:
        query = {"u": username}
    posts = list(
        db.posts.find(
            query, sort=[("t.e", pymongo.DESCENDING)], skip=(page - 1) * 25, limit=25
        )
    )

    # Add log
    security.add_audit_log(
        "got_user_posts",
        request.user,
        request.ip,
        {"username": username, "post_origin": post_origin, "page": page},
    )

    # Return posts
    payload = {
        "error": False,
        "page#": page,
        "pages": get_total_pages("posts", query),
    }
    if "autoget" in request.args:
        payload["autoget"] = posts
    else:
        payload["index"] = [post["_id"] for post in posts]
    return payload, 200


@admin_bp.delete("/users/<username>/posts")
async def clear_user_posts(username):
    # Check permissions
    if not security.has_permission(request.permissions, security.AdminPermissions.DELETE_POSTS):
        abort(401)

    # Get post origin
    post_origin = request.args.get("origin") 

    # Make sure user isn't protected
    if not security.has_permission(request.permissions, security.AdminPermissions.SYSADMIN):
        account = db.usersv0.find_one(
            {"_id": username}, projection={"flags": 1}
        )
        if account and (account["flags"] & security.UserFlags.PROTECTED) == security.UserFlags.PROTECTED:
            abort(403)

    # Delete posts
    if post_origin:
        query = {"post_origin": post_origin, "isDeleted": False, "u": username}
    else:
        query = {"u": username, "isDeleted": False}
    db.posts.update_many(
        query,
        {
            "$set": {
                "isDeleted": True,
                "mod_deleted": True,
                "deleted_at": int(time.time()),
            }
        },
    )

    # Add log
    security.add_audit_log(
        "clear_user_posts",
        request.user,
        request.ip,
        {"username": username, "post_origin": post_origin},
    )

    return {"error": False}, 200


@admin_bp.post("/users/<username>/alert")
async def send_alert(username):
    # Check permissions
    if not security.has_permission(request.permissions, security.AdminPermissions.SEND_ALERTS):
        abort(401)

    # Get body
    try:
        body = InboxMessageBody(**await request.json)
    except:
        abort(400)

    # Make sure user exists
    if not security.account_exists(username):
        abort(404)

    # Create inbox message
    post = app.supporter.create_post("inbox", username, body.content)

    # Add log
    security.add_audit_log(
        "alerted",
        request.user,
        request.ip,
        {"username": username, "content": body.content},
    )

    # Return new post
    post["error"] = False
    return post, 200


@admin_bp.post("/users/<username>/kick")
async def kick_user(username):
    # Check permissions
    if not security.has_permission(request.permissions, security.AdminPermissions.KICK_USERS):
        abort(401)

    # Revoke tokens
    db.usersv0.update_one({"_id": username}, {"$set": {"tokens": []}})

    # Kick clients
    for client in app.cl.usernames.get(username, []):
        client.kick(statuscode="Kicked")

    # Add log
    security.add_audit_log(
        "kicked", request.user, request.ip, {"username": username}
    )

    return {"error": False}, 200


@admin_bp.delete("/users/<username>/avatar")
async def clear_avatar(username):
    # Check permissions
    if not security.has_permission(
        request.permissions, security.AdminPermissions.CLEAR_PROFILE_DETAILS
    ):
        abort(401)

    # Make sure user isn't protected
    if not security.has_permission(request.permissions, security.AdminPermissions.SYSADMIN):
        account = db.usersv0.find_one(
            {"_id": username}, projection={"flags": 1}
        )
        if account and (account["flags"] & security.UserFlags.PROTECTED) == security.UserFlags.PROTECTED:
            abort(403)

    # Update user
    db.usersv0.update_one(
        {"_id": username, "$ne": {"avatar": None}}, {"$set": {"avatar": ""}}
    )

    # Sync config between sessions
    app.cl.broadcast({
        "mode": "update_config",
        "payload": {
            "avatar": ""
        }
    }, direct_wrap=True, usernames=[username])

    # Send updated avatar to other clients
    app.cl.broadcast({
        "mode": "update_profile",
        "payload": {
            "_id": username,
            "avatar": ""
        }
    }, direct_wrap=True)

    # Add log
    security.add_audit_log(
        "cleared_avatar", request.user, request.ip, {"username": username}
    )

    return {"error": False}, 200


@admin_bp.delete("/users/<username>/quote")
async def clear_quote(username):
    # Check permissions
    if not security.has_permission(
        request.permissions, security.AdminPermissions.CLEAR_PROFILE_DETAILS
    ):
        abort(401)

    # Make sure user isn't protected
    if not security.has_permission(request.permissions, security.AdminPermissions.SYSADMIN):
        account = db.usersv0.find_one(
            {"_id": username}, projection={"flags": 1}
        )
        if account and (account["flags"] & security.UserFlags.PROTECTED) == security.UserFlags.PROTECTED:
            abort(403)

    # Update user
    db.usersv0.update_one(
        {"_id": username, "quote": {"$ne": None}}, {"$set": {"quote": ""}}
    )

    # Sync config between sessions
    app.cl.broadcast({
        "mode": "update_config",
        "payload": {
            "quote": ""
        }
    }, direct_wrap=True, usernames=[username])

     # Send updated quote to other clients
    app.cl.broadcast({
        "mode": "update_profile",
        "payload": {
            "_id": username,
            "quote": ""
        }
    }, direct_wrap=True)

    # Add log
    security.add_audit_log(
        "cleared_quote", request.user, request.ip, {"username": username}
    )

    return {"error": False}, 200


@admin_bp.get("/chats/<chat_id>")
async def get_chat(chat_id):
    # Check permissions
    if not security.has_permission(request.permissions, security.AdminPermissions.VIEW_CHATS):
        abort(403)

    # Get chat
    chat = db.chats.find_one({"_id": chat_id})
    if not chat:
        abort(404)

    # Add log
    security.add_audit_log("got_chat", request.user, request.ip, {"chat_id": chat_id})

    # Return chat
    chat["error"] = False
    return chat, 200


@admin_bp.patch("/chats/<chat_id>")
async def update_chat(chat_id):
    # Check permissions
    if not security.has_permission(request.permissions, security.AdminPermissions.EDIT_CHATS):
        abort(403)

    # Get body
    try:
        body = UpdateChatBody(**await request.json)
    except: abort(400)

    # Get chat
    chat = db.chats.find_one({"_id": chat_id})
    if not chat:
        abort(404)

    # Get updated values
    updated_vals = {"_id": chat_id}
    if body.nickname is not None and chat["nickname"] != body.nickname:
        updated_vals["nickname"] = app.supporter.wordfilter(body.nickname)
    if body.icon is not None and chat["icon"] != body.icon:
        updated_vals["icon"] = body.icon
    if body.icon_color is not None and chat["icon_color"] != body.icon_color:
        updated_vals["icon_color"] = body.icon_color
    if body.allow_pinning is not None:
        updated_vals["allow_pinning"] = body.allow_pinning
    
    # Update chat
    db.chats.update_one({"_id": chat_id}, {"$set": updated_vals})

    # Send update chat event
    app.cl.broadcast({
        "mode": "update_chat",
        "payload": updated_vals
    }, direct_wrap=True, usernames=chat["members"])

    # Add log
    updated_vals["chat_id"] = updated_vals.pop("_id")
    security.add_audit_log("updated_chat", request.user, request.ip, updated_vals)

    # Return chat
    chat["error"] = False
    return chat, 200


@admin_bp.delete("/chats/<chat_id>")
async def delete_chat(chat_id):
    # Check permissions
    if not security.has_permission(request.permissions, security.AdminPermissions.EDIT_CHATS):
        abort(403)

    # Get chat
    chat = db.chats.find_one({"_id": chat_id})
    if not chat:
        abort(404)

    # Update chat
    chat["deleted"] = True
    db.chats.update_one({"_id": chat_id}, {"$set": {"deleted": True}})

    # Send delete chat event
    app.cl.broadcast({
        "mode": "delete",
        "id": chat_id
    }, direct_wrap=True, usernames=chat["members"])

    # Add log
    security.add_audit_log("deleted_chat", request.user, request.ip, {"chat_id": chat_id})

    # Return chat
    chat["error"] = False
    return chat, 200


@admin_bp.post("/chats/<chat_id>/restore")
async def restore_chat(chat_id):
    # Check permissions
    if not security.has_permission(request.permissions, security.AdminPermissions.EDIT_CHATS):
        abort(403)

    # Get chat
    chat = db.chats.find_one({"_id": chat_id})
    if not chat:
        abort(404)

    # Update chat
    chat["deleted"] = False
    db.chats.update_one({"_id": chat_id}, {"$set": {"deleted": False}})

    # Send create chat event
    app.cl.broadcast({
        "mode": "create_chat",
        "payload": chat
    }, direct_wrap=True, usernames=chat["members"])

    # Add log
    security.add_audit_log("restored_chat", request.user, request.ip, {"chat_id": chat_id})

    # Return chat
    chat["error"] = False
    return chat, 200


@admin_bp.put("/chats/<chat_id>/members/<username>")
async def add_chat_member(chat_id, username):
    # Check permissions
    if not security.has_permission(request.permissions, security.AdminPermissions.EDIT_CHATS):
        abort(403)

    # Get chat
    chat = db.chats.find_one({"_id": chat_id})
    if not chat:
        abort(404)

    # Make sure the user isn't already in the chat
    if username in chat["members"]:
        return {"error": True, "type": "chatMemberAlreadyExists"}, 409

    # Make sure requested user exists and isn't deleted
    user = db.usersv0.find_one({"_id": username}, projection={"permissions": 1})
    if (not user) or (user["permissions"] is None):
        abort(404)

    # Update chat
    chat["members"].append(username)
    db.chats.update_one({"_id": chat_id}, {"$addToSet": {"members": username}})

    # Send create chat event
    app.cl.broadcast({
        "mode": "create_chat",
        "payload": chat
    }, direct_wrap=True, usernames=[username])

    # Send update chat event
    app.cl.broadcast({
        "mode": "update_chat",
        "payload": {
            "_id": chat_id,
            "members": chat["members"]
        }
    }, direct_wrap=True, usernames=chat["members"])

    # Add log
    security.add_audit_log("added_chat_member", request.user, request.ip, {"chat_id": chat_id, "username": username})

    # Return chat
    chat["error"] = False
    return chat, 200


@admin_bp.delete("/chats/<chat_id>/members/<username>")
async def remove_chat_member(chat_id, username):
    # Check permissions
    if not security.has_permission(request.permissions, security.AdminPermissions.EDIT_CHATS):
        abort(403)

    # Get chat
    chat = db.chats.find_one({
        "_id": chat_id,
        "members": username
    })
    if not chat:
        abort(404)

    # Update chat
    chat["members"].remove(username)
    db.chats.update_one({"_id": chat_id}, {"$pull": {"members": username}})

    # Send update chat event
    app.cl.broadcast({
        "mode": "update_chat",
        "payload": {
            "_id": chat_id,
            "members": chat["members"]
        }
    }, direct_wrap=True, usernames=chat["members"])

    # Send delete chat event to user
    app.cl.broadcast({
        "mode": "delete",
        "id": chat_id
    }, direct_wrap=True, usernames=[username])

    # Add log
    security.add_audit_log("removed_chat_member", request.user, request.ip, {"chat_id": chat_id, "username": username})

    # Return chat
    chat["error"] = False
    return chat, 200


@admin_bp.post("/chats/<chat_id>/members/<username>/transfer")
async def transfer_chat_ownership(chat_id, username):
    # Check permissions
    if not security.has_permission(request.permissions, security.AdminPermissions.EDIT_CHATS):
        abort(403)

    # Get chat
    chat = db.chats.find_one({
        "_id": chat_id,
        "members": username
    })
    if not chat:
        abort(404)

    # Make sure requested user isn't already owner
    if chat["owner"] == username:
        chat["error"] = False
        return chat, 200

    # Update chat
    chat["owner"] = username
    db.chats.update_one({"_id": chat_id}, {"$set": {"owner": username}})

    # Send update chat event
    app.cl.broadcast({
        "mode": "update_chat",
        "payload": {
            "_id": chat_id,
            "owner": chat["owner"]
        }
    }, direct_wrap=True, usernames=chat["members"])

    # Add log
    security.add_audit_log("transferred_chat_ownership", request.user, request.ip, {"chat_id": chat_id, "username": username})

    # Return chat
    chat["error"] = False
    return chat, 200


@admin_bp.get("/chats/<chat_id>/posts")
async def get_chat_posts(chat_id):
    # Check permissions
    if not security.has_permission(request.permissions, security.AdminPermissions.VIEW_CHATS):
        abort(403)

    # Get page
    try:
        page = int(request.args["page"])
    except:
        page = 1

    # Make sure chat exists
    if db.chats.count_documents({
        "_id": chat_id
    }, limit=1) < 1:
        abort(404)

    # Get posts
    query = {"post_origin": chat_id, "$or": [{"isDeleted": False}, {"isDeleted": True}]}
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


@admin_bp.get("/netinfo/<ip>")
async def get_netinfo(ip):
    # Check permissions
    if not security.has_permission(request.permissions, security.AdminPermissions.VIEW_IPS):
        abort(403)

    # Get netinfo
    netinfo = security.get_netinfo(ip)

    # Get netblocks
    netblocks = []
    for radix_node in blocked_ips.search_covering(ip):
        netblocks.append(db.netblock.find_one({"_id": radix_node.prefix}))
    for radix_node in registration_blocked_ips.search_covering(ip):
        netblocks.append(db.netblock.find_one({"_id": radix_node.prefix}))

    # Get netlogs
    netlogs = [
        {
            "ip": netlog["_id"]["ip"],
            "user": netlog["_id"]["user"],
            "last_used": netlog["last_used"],
        }
        for netlog in db.netlog.find(
            {"_id.ip": ip}, sort=[("last_used", pymongo.DESCENDING)]
        )
    ]

    # Add log
    security.add_audit_log("got_netinfo", request.user, request.ip, {"ip": ip})

    # Return netinfo, netblocks, and netlogs
    return {
        "error": False,
        "netinfo": netinfo,
        "netblocks": netblocks,
        "netlogs": netlogs,
    }, 200


@admin_bp.get("/netblocks")
async def get_netblocks():
    # Check permissions
    if not security.has_permission(request.permissions, security.AdminPermissions.VIEW_IPS):
        abort(401)

    # Get page
    try:
        page = int(request.args["page"])
    except:
        page = 1

    # Get netblocks
    netblocks = list(db.netblock.find({}, sort=[("created", pymongo.DESCENDING)], skip=(page-1)*25, limit=25))

    # Add log
    security.add_audit_log("got_netblocks", request.user, request.ip, {"page": page})

    # Return netblocks
    payload = {
        "error": False,
        "page#": page,
        "pages": get_total_pages("netblock", {})
    }
    if "autoget" in request.args:
        payload["autoget"] = netblocks
    else:
        payload["index"] = [netblock["_id"] for netblock in netblocks]
    return payload, 200


@admin_bp.get("/netblocks/<cidr>")
async def get_netblock(cidr):
    # Check permissions
    if not security.has_permission(request.permissions, security.AdminPermissions.VIEW_IPS):
        abort(401)

    # b64 decode CIDR
    cidr = b64decode(cidr.encode()).decode()

    # Get netblock
    netblock = db.netblock.find_one({"_id": cidr})
    if not netblock:
        abort(404)

    # Add log
    security.add_audit_log(
        "got_netblock", request.user, request.ip, {"cidr": cidr, "netblock": netblock}
    )

    # Return netblock
    netblock["error"] = False
    return netblock, 200


@admin_bp.put("/netblocks/<cidr>")
async def create_netblock(cidr):
    # Check permissions
    if not security.has_permission(request.permissions, security.AdminPermissions.BLOCK_IPS):
        abort(401)

    # b64 decode CIDR
    cidr = b64decode(cidr.encode()).decode()

    # Get body
    try:
        body = NetblockBody(**await request.json)
    except:
        abort(400)

    # Construct netblock obj
    netblock = {
        "_id": cidr,
        "type": body.type,
        "created": int(time.time())
    }

    # Remove from Radix
    if blocked_ips.search_exact(cidr):
        blocked_ips.delete(cidr)
    if registration_blocked_ips.search_exact(cidr):
        registration_blocked_ips.delete(cidr)

    # Add to Radix
    if body.type == 0:
        radix_node = blocked_ips.add(cidr)
    elif body.type == 1:
        radix_node = registration_blocked_ips.add(cidr)

    # Modify netblock with new Radix node prefix
    netblock["_id"] = radix_node.prefix

    # Add netblock to database
    db.netblock.update_one(
        {"_id": netblock["_id"]}, {"$set": netblock}, upsert=True
    )

    # Kick clients
    if body.type == 0:
        for client in copy(app.cl.clients):
            if blocked_ips.search_best(client.ip):
                client.kick(statuscode="Blocked")

    # Add log
    security.add_audit_log(
        "created_netblock",
        request.user,
        request.ip,
        {"cidr": cidr, "netblock": netblock},
    )

    # Return netblock
    netblock["error"] = False
    return netblock, 200


@admin_bp.delete("/netblocks/<cidr>")
async def delete_netblock(cidr):
    # Check permissions
    if not security.has_permission(request.permissions, security.AdminPermissions.BLOCK_IPS):
        abort(401)

    # b64 decode CIDR
    cidr = b64decode(cidr.encode()).decode()

    # Remove from database
    db.netblock.delete_one({"_id": cidr})

    # Remove from Radix
    if blocked_ips.search_exact(cidr):
        blocked_ips.delete(cidr)
    if registration_blocked_ips.search_exact(cidr):
        registration_blocked_ips.delete(cidr)

    # Add log
    security.add_audit_log(
        "deleted_netblock", request.user, request.ip, {"cidr": cidr}
    )

    return {"error": False}, 200


@admin_bp.get("/announcements")
async def get_announcements():
    # Check permissions
    if not security.has_permission(request.permissions, security.AdminPermissions.VIEW_POSTS):
        abort(401)

    # Get page
    try:
        page = int(request.args["page"])
    except:
        page = 1

    # Get posts
    query = {
        "post_origin": "inbox",
        "$or": [{"isDeleted": False}, {"isDeleted": True}],
        "u": "Server",
    }
    posts = list(
        db.posts.find(
            query, sort=[("t.e", pymongo.DESCENDING)], skip=(page - 1) * 25, limit=25
        )
    )

    # Add log
    security.add_audit_log(
        "got_announcements", request.user, request.ip, {"page": page}
    )

    # Return posts
    payload = {
        "error": False,
        "page#": page,
        "pages": get_total_pages("posts", query),
    }
    if "autoget" in request.args:
        payload["autoget"] = posts
    else:
        payload["index"] = [post["_id"] for post in posts]
    return payload, 200


@admin_bp.post("/announcements")
async def send_announcement():
    # Check permissions
    if not security.has_permission(
        request.permissions, security.AdminPermissions.SEND_ANNOUNCEMENTS
    ):
        abort(401)

    # Get body
    try:
        body = InboxMessageBody(**await request.json)
    except:
        abort(400)

    # Create announcement
    post = app.supporter.create_post("inbox", "Server", body.content)

    # Add log
    security.add_audit_log(
        "sent_announcement", request.user, request.ip, {"content": body.content}
    )

    # Return new post
    post["error"] = False
    return post, 200


@admin_bp.post("/server/kick-all")
async def kick_all_clients():
    # Check permissions
    if not security.has_permission(request.permissions, security.AdminPermissions.SYSADMIN):
        abort(401)

    # Kick all clients
    for client in copy(app.cl.clients):
        client.kick()

    # Add log
    security.add_audit_log("kicked_all", request.user, request.ip, {})

    return {"error": False}, 200


@admin_bp.post("/server/enable-repair-mode")
async def enable_repair_mode():
    # Check permissions
    if not security.has_permission(request.permissions, security.AdminPermissions.SYSADMIN):
        abort(401)

    # Update database item
    db.config.update_one({"_id": "status"}, {"$set": {"repair_mode": True}})

    # Update supporter attribute
    app.supporter.repair_mode = True

    # Kick all clients
    for client in copy(app.cl.clients):
        client.kick(statuscode="Kicked")

    # Add log
    security.add_audit_log("enabled_repair_mode", request.user, request.ip, {})

    return {"error": False}, 200


@admin_bp.post("/server/registration/disable")
async def disable_registration():
    # Check permissions
    if not security.has_permission(request.permissions, security.AdminPermissions.SYSADMIN):
        abort(401)

    # Update database item
    db.config.update_one({"_id": "status"}, {"$set": {"registration": False}})

    # Update supporter attribute
    app.supporter.registration = False

    # Add log
    security.add_audit_log("disabled_registration", request.user, request.ip, {})

    return {"error": False}, 200


@admin_bp.post("/server/registration/enable")
async def enable_registration():
    # Check permissions
    if not security.has_permission(request.permissions, security.AdminPermissions.SYSADMIN):
        abort(401)

    # Update database item
    db.config.update_one({"_id": "status"}, {"$set": {"registration": True}})

    # Update supporter attribute
    app.supporter.registration = True

    # Add log
    security.add_audit_log("enabled_registration", request.user, request.ip, {})

    return {"error": False}, 200

@admin_bp.post("/server/profanity/<mode>/")
async def add_profanity_blacklist(mode):
    if not security.has_permission(request.permissions, security.AdminPermissions.CHANGE_PROFANITY):
        abort(401)

    if mode not in ["whitelist", "blacklist"]: abort(404)

    try:
        data = UpdateProfanityBody(**await request.json)
    except: abort(400)

    db.config.update_one({"_id": "filter"}, {
            "$push": {
                mode: {
                    "$each": data.items
                }
            }
    })

    for item in data.items:
        if item in app.supporter.filter[mode]: continue
        app.supporter.filter[mode].append(item)

    return {"error": False}

# When testing the lib, that mb.py uses, does not support DELETE bodies
@admin_bp.post("/server/profanity/<mode>/delete")
async def delete_profanity_whitelist(mode):
    if not security.has_permission(request.permissions, security.AdminPermissions.CHANGE_PROFANITY):
        abort(401)

    if mode not in ["whitelist", "blacklist"]: abort(404)

    try:
        data = UpdateProfanityBody(**await request.json)
    except: abort(400)

    db.config.update_one({"_id": "filter"}, {
        "$pull": {
            mode: {
                "$in": data.items
            }
        }
    })

    for word in data.items:
        if word not in app.supporter.filter[mode]: continue
        app.supporter.filter[mode].remove(word)

    return {"error": False}


@admin_bp.get("/server/profanity/<mode>")
async def get_profanity_whitelist(mode: str):
    if not security.has_permission(request.permissions, security.AdminPermissions.CHANGE_PROFANITY):
        abort(401)

    try:
        page = int(request.args["page"])
    except:
        page = 1

    if mode not in ["whitelist", "blacklist"]:
        abort(404)

    page_size = 25
    max_pages = len(app.supporter.filter[mode])//page_size

    if page > max_pages:
        page = max_pages

    return {
        "error": False,
        "page#": page,
        "pages": max_pages,
        mode: app.supporter.filter[mode][page * 25: page * 25 + 25]
    }
