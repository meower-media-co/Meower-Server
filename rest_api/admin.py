from quart import Blueprint, current_app as app, request, abort
from quart_schema import validate_querystring, validate_request
from pydantic import BaseModel, Field
from typing import Optional, Literal
from base64 import b64decode
from copy import copy
import time, pymongo

import security
from database import db, get_total_pages, blocked_ips, registration_blocked_ips


admin_bp = Blueprint("admin_bp", __name__, url_prefix="/admin")


class GetReportsQueryArgs(BaseModel):
    status: Optional[Literal[
        "pending",
        "no_action_taken",
        "action_taken"
    ]] = Field(default=None)
    type: Optional[Literal["post", "user"]] = Field(default=None)
    page: Optional[int] = Field(default=1, ge=1)

class UpdateReportBody(BaseModel):
    status: Literal["no_action_taken", "action_taken"]

    class Config:
        validate_assignment = True

class UpdateNotesBody(BaseModel):
    notes: str

    class Config:
        validate_assignment = True
        str_strip_whitespace = True

class GetUsersQueryArgs(BaseModel):
    page: Optional[int] = Field(default=1, ge=1)

class UpdateUserBody(BaseModel):
    permissions: Optional[int] = Field(default=None, ge=0)

    class Config:
        validate_assignment = True

class DeleteUserQueryArgs(BaseModel):
    mode: Literal[
        "cancel",
        "schedule",
        "immediate",
        "purge"
    ] = Field()

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

class GetUserPostsQueryArgs(BaseModel):
    origin: Optional[str] = Field(default=None)
    page: Optional[int] = Field(default=1, ge=1)

class ClearUserPostsQueryArgs(BaseModel):
    origin: str = Field(min_length=1)

class UpdateChatBody(BaseModel):
    nickname: str = Field(default=None, min_length=1, max_length=32)
    icon: str = Field(default=None, max_length=24)
    icon_color: str = Field(default=None, min_length=1, max_length=6)
    allow_pinning: bool = Field(default=None)

    class Config:
        validate_assignment = True
        str_strip_whitespace = True

class GetChatPostsQueryArgs(BaseModel):
    page: Optional[int] = Field(default=1, ge=1)

class InboxMessageBody(BaseModel):
    content: str = Field(min_length=1, max_length=4000)

    class Config:
        validate_assignment = True
        str_strip_whitespace = True

class GetNetblocksQueryArgs(BaseModel):
    page: Optional[int] = Field(default=1, ge=1)

class NetblockBody(BaseModel):
    type: Literal[0, 1] = Field()

    class Config:
        validate_assignment = True

class GetAnnouncementsQueryArgs(BaseModel):
    page: Optional[int] = Field(default=1, ge=1)


@admin_bp.before_request
async def check_admin_perms():
    if request.method != "OPTIONS":
        if (not request.user) or (not request.permissions):
            abort(401)


@admin_bp.get("/reports")
@validate_querystring(GetReportsQueryArgs)
async def get_reports(query_args: GetReportsQueryArgs):
    # Check permissions
    if not security.has_permission(request.permissions, security.AdminPermissions.VIEW_REPORTS):
        abort(403)

    # Construct query
    query = {}
    if "status" in request.args:
        query["status"] = query_args.status
    if "type" in request.args:
        query["type"] = query_args.type

    # Get reports
    reports = list(
        db.reports.find(
            query,
            projection={"reports.ip": 0},
            sort=[("escalated", pymongo.DESCENDING), ("reports.time", pymongo.DESCENDING)],
            skip=(query_args.page - 1) * 25,
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
            "page": query_args.page,
        },
    )

    # Return reports
    return {
        "error": False,
        "autoget": reports,
        "page#": query_args.page,
        "pages": get_total_pages("reports", query),
    }, 200


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
@validate_request(UpdateReportBody)
async def update_report(report_id, data: UpdateReportBody):
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
    report["status"] = data.status
    report["escalated"] = False
    db.reports.update_one(
        {"_id": report_id}, {"$set": {"status": data.status, "escalated": False}}
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
        {"report_id": report_id, "status": data.status, "escalated": False},
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
@validate_request(UpdateNotesBody)
async def edit_admin_note(identifier, data: UpdateNotesBody):
    # Check permissions
    if not security.has_permission(request.permissions, security.AdminPermissions.EDIT_NOTES):
        abort(403)

    # Update notes
    notes = {
        "_id": identifier,
        "notes": data.notes,
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
        {"identifier": identifier, "notes": data.notes},
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
@validate_querystring(GetUsersQueryArgs)
async def get_users(query_args: GetUsersQueryArgs):
    # Get usernames
    usernames = [user["_id"] for user in db.usersv0.find({}, sort=[("created", pymongo.DESCENDING)], skip=(query_args.page-1)*25, limit=25)]

    # Add log
    security.add_audit_log("got_users", request.user, request.ip, {"page": query_args.page})

    # Return users
    return {
        "error": False,
        "autoget": [security.get_account(username) for username in usernames],
        "page#": query_args.page,
        "pages": get_total_pages("usersv0", {}),
    }, 200


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
@validate_request(UpdateUserBody)
async def update_user(username, data: UpdateUserBody):
    # Check permissions
    if not security.has_permission(request.permissions, security.AdminPermissions.SYSADMIN):
        abort(403)

    # Make sure user exists
    if not security.account_exists(username):
        abort(404)

    # Create updated fields var
    updated_fields = {}

    # Permissions
    if data.permissions is not None:
        updated_fields["permissions"] = data.permissions
        security.add_audit_log(
            "updated_permissions",
            request.user,
            request.ip,
            {"username": username, "permissions": data.permissions},
        )

    # Update user
    db.usersv0.update_one({"_id": username}, {"$set": updated_fields})

    # Sync config between sessions
    app.cl.broadcast({
        "mode": "update_config",
        "payload": updated_fields
    }, direct_wrap=True, usernames=[username])

    # Send updated values to other clients
    app.cl.broadcast({
        "mode": "update_profile",
        "payload": {
            "_id": username,
            "permissions": data.permissions,
        }
    }, direct_wrap=True)

    return {"error": False}, 200


@admin_bp.delete("/users/<username>")
@validate_querystring(DeleteUserQueryArgs)
async def delete_user(username, query_args: DeleteUserQueryArgs):
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
    deletion_mode = query_args.mode

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
@validate_request(UpdateUserBanBody)
async def ban_user(username, data: UpdateUserBanBody):
    # Check permissions
    if not security.has_permission(
        request.permissions, security.AdminPermissions.EDIT_BAN_STATES
    ):
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

    # Update user
    db.usersv0.update_one(
        {"_id": username}, {"$set": {"ban": data.model_dump()}}
    )

    # Add log
    security.add_audit_log(
        "banned",
        request.user,
        request.ip,
        {"username": username, "ban": data.model_dump()},
    )

    # Kick client or send updated ban state
    if (data.state == "perm_ban") or (
        data.state == "temp_ban" and data.expires > time.time()
    ):
        for client in app.cl.usernames.get(username, []):
            client.kick(statuscode="Banned")
    else:
        app.cl.broadcast({
            "mode": "update_config",
            "payload": {
                "ban": data.model_dump()
            }
        }, direct_wrap=True, usernames=[username])

    return {"error": False}, 200


@admin_bp.get("/users/<username>/posts")
@validate_querystring(GetUserPostsQueryArgs)
async def get_user_posts(username, query_args: GetUserPostsQueryArgs):
    # Check permissions
    if not security.has_permission(request.permissions, security.AdminPermissions.VIEW_POSTS):
        abort(401)

    # Get posts
    if query_args.origin:
        query = {
            "post_origin": query_args.origin,
            "$or": [{"isDeleted": False}, {"isDeleted": True}],
            "u": username,
        }
    else:
        query = {"u": username}
    posts = list(
        db.posts.find(
            query, sort=[("t.e", pymongo.DESCENDING)], skip=(query_args.page - 1) * 25, limit=25
        )
    )

    # Add log
    security.add_audit_log(
        "got_user_posts",
        request.user,
        request.ip,
        {"username": username, "post_origin": query_args.origin, "page": query_args.page},
    )

    # Return posts
    return {
        "error": False,
        "autoget": posts,
        "page#": query_args.page,
        "pages": get_total_pages("posts", query),
    }, 200


@admin_bp.delete("/users/<username>/posts")
@validate_querystring(ClearUserPostsQueryArgs)
async def clear_user_posts(username, query_args: ClearUserPostsQueryArgs):
    # Check permissions
    if not security.has_permission(request.permissions, security.AdminPermissions.DELETE_POSTS):
        abort(401)

    # Make sure user isn't protected
    if not security.has_permission(request.permissions, security.AdminPermissions.SYSADMIN):
        account = db.usersv0.find_one(
            {"_id": username}, projection={"flags": 1}
        )
        if account and (account["flags"] & security.UserFlags.PROTECTED) == security.UserFlags.PROTECTED:
            abort(403)

    # Delete posts
    if query_args.origin:
        query = {"post_origin": query_args.origin, "isDeleted": False, "u": username}
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
        {"username": username, "post_origin": query_args.origin},
    )

    return {"error": False}, 200


@admin_bp.post("/users/<username>/alert")
@validate_request(InboxMessageBody)
async def send_alert(username, data: InboxMessageBody):
    # Check permissions
    if not security.has_permission(request.permissions, security.AdminPermissions.SEND_ALERTS):
        abort(401)

    # Make sure user exists
    if not security.account_exists(username):
        abort(404)

    # Create inbox message
    post = app.supporter.create_post("inbox", username, data.content)

    # Add log
    security.add_audit_log(
        "alerted",
        request.user,
        request.ip,
        {"username": username, "content": data.content},
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
@validate_request(UpdateChatBody)
async def update_chat(chat_id, data: UpdateChatBody):
    # Check permissions
    if not security.has_permission(request.permissions, security.AdminPermissions.EDIT_CHATS):
        abort(403)

    # Get chat
    chat = db.chats.find_one({"_id": chat_id})
    if not chat:
        abort(404)

    # Get updated values
    updated_vals = {"_id": chat_id}
    if data.nickname is not None and chat["nickname"] != data.nickname:
        updated_vals["nickname"] = data.nickname
    if data.icon == "":
        updated_vals["icon"] = data.icon
    if data.icon_color is not None and chat["icon_color"] != data.icon_color:
        updated_vals["icon_color"] = data.icon_color
    if data.allow_pinning is not None:
        updated_vals["allow_pinning"] = data.allow_pinning
    
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
@validate_querystring(GetChatPostsQueryArgs)
async def get_chat_posts(chat_id, query_args: GetChatPostsQueryArgs):
    # Check permissions
    if not security.has_permission(request.permissions, security.AdminPermissions.VIEW_CHATS):
        abort(403)

    # Make sure chat exists
    if db.chats.count_documents({
        "_id": chat_id
    }, limit=1) < 1:
        abort(404)

    # Get posts
    query = {"post_origin": chat_id, "$or": [{"isDeleted": False}, {"isDeleted": True}]}
    posts = list(db.posts.find(query, sort=[("t.e", pymongo.DESCENDING)], skip=(query_args.page-1)*25, limit=25))

    # Return posts
    return {
        "error": False,
        "autoget": posts,
        "page#": query_args.page,
        "pages": get_total_pages("posts", query)
    }, 200


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
@validate_querystring(GetNetblocksQueryArgs)
async def get_netblocks(query_args: GetNetblocksQueryArgs):
    # Check permissions
    if not security.has_permission(request.permissions, security.AdminPermissions.VIEW_IPS):
        abort(401)

    # Get netblocks
    netblocks = list(db.netblock.find({}, sort=[("created", pymongo.DESCENDING)], skip=(query_args.page-1)*25, limit=25))

    # Add log
    security.add_audit_log("got_netblocks", request.user, request.ip, {"page": query_args.page})

    # Return netblocks
    return {
        "error": False,
        "autoget": netblocks,
        "page#": query_args.page,
        "pages": get_total_pages("netblock", {})
    }, 200


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
@validate_request(NetblockBody)
async def create_netblock(cidr, data: NetblockBody):
    # Check permissions
    if not security.has_permission(request.permissions, security.AdminPermissions.BLOCK_IPS):
        abort(401)

    # b64 decode CIDR
    cidr = b64decode(cidr.encode()).decode()

    # Construct netblock obj
    netblock = {
        "_id": cidr,
        "type": data.type,
        "created": int(time.time())
    }

    # Remove from Radix
    if blocked_ips.search_exact(cidr):
        blocked_ips.delete(cidr)
    if registration_blocked_ips.search_exact(cidr):
        registration_blocked_ips.delete(cidr)

    # Add to Radix
    if data.type == 0:
        radix_node = blocked_ips.add(cidr)
    elif data.type == 1:
        radix_node = registration_blocked_ips.add(cidr)

    # Modify netblock with new Radix node prefix
    netblock["_id"] = radix_node.prefix

    # Add netblock to database
    db.netblock.update_one(
        {"_id": netblock["_id"]}, {"$set": netblock}, upsert=True
    )

    # Kick clients
    if data.type == 0:
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
@validate_querystring(GetAnnouncementsQueryArgs)
async def get_announcements(query_args: GetAnnouncementsQueryArgs):
    # Check permissions
    if not security.has_permission(request.permissions, security.AdminPermissions.VIEW_POSTS):
        abort(401)

    # Get posts
    query = {
        "post_origin": "inbox",
        "$or": [{"isDeleted": False}, {"isDeleted": True}],
        "u": "Server",
    }
    posts = list(
        db.posts.find(
            query, sort=[("t.e", pymongo.DESCENDING)], skip=(query_args.page - 1) * 25, limit=25
        )
    )

    # Add log
    security.add_audit_log(
        "got_announcements", request.user, request.ip, {"page": query_args.page}
    )

    # Return posts
    return {
        "error": False,
        "autoget": posts,
        "page#": query_args.page,
        "pages": get_total_pages("posts", query),
    }, 200


@admin_bp.post("/announcements")
@validate_request(InboxMessageBody)
async def send_announcement(data: InboxMessageBody):
    # Check permissions
    if not security.has_permission(
        request.permissions, security.AdminPermissions.SEND_ANNOUNCEMENTS
    ):
        abort(401)

    # Create announcement
    post = app.supporter.create_post("inbox", "Server", data.content)

    # Add log
    security.add_audit_log(
        "sent_announcement", request.user, request.ip, {"content": data.content}
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
