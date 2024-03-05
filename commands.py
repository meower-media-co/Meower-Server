from cloudlink import CloudlinkServer, CloudlinkClient
from supporter import Supporter
from database import db, registration_blocked_ips, get_total_pages
from threading import Thread
import pymongo
import security
import time
import re
import uuid

class MeowerCommands:
    def __init__(self, cl: CloudlinkServer, supporter: Supporter):
        self.cl = cl
        self.supporter = supporter

        # Authentication
        self.cl.add_command("authpswd", self.authpswd)
        self.cl.add_command("gen_account", self.gen_account)

        # Accounts
        self.cl.add_command("get_profile", self.get_profile)
        self.cl.add_command("update_config", self.update_config)
        self.cl.add_command("change_pswd", self.change_pswd)
        self.cl.add_command("del_tokens", self.del_tokens)
        self.cl.add_command("del_account", self.del_account)

        # Chats
        self.cl.add_command("create_chat", self.create_chat)
        self.cl.add_command("leave_chat", self.leave_chat)
        self.cl.add_command("get_chat_list", self.get_chat_list)
        self.cl.add_command("get_chat_data", self.get_chat_data)
        self.cl.add_command("add_to_chat", self.add_to_chat)
        self.cl.add_command("remove_from_chat", self.remove_from_chat)
        self.cl.add_command("set_chat_state", self.set_chat_state)

        # Posts
        self.cl.add_command("post_home", self.post_home)
        self.cl.add_command("post_chat", self.post_chat)
        self.cl.add_command("delete_post", self.delete_post)

        # Moderation
        self.cl.add_command("report", self.report)

    async def authpswd(self, client: CloudlinkClient, val, listener: str = None):
        # Make sure the client isn't already authenticated
        if client.username:
            return await client.send_statuscode("OK", listener)
        
        # Check val datatype
        if not isinstance(val, dict):
            return await client.send_statuscode("Datatype", listener)
        
        # Check val syntax
        if ("username" not in val) or ("pswd" not in val):
            return await client.send_statuscode("Syntax", listener)
        
        # Extract username and password
        username = val["username"]
        password = val["pswd"]

        # Check username and password datatypes
        if (not isinstance(username, str)) or (not isinstance(password, str)):
            return await client.send_statuscode("Datatype", listener)
        
        # Check username and password syntax
        if len(username) < 1 or len(username) > 20 or len(password) < 1 or len(password) > 255:
            return await client.send_statuscode("Syntax", listener)
        
        # Check ratelimits
        for bucket_id in [
            f"login:i:{client.ip}",
            f"login:u:{username}:s",
            f"login:u:{username}:f"
        ]:
            if security.ratelimited(bucket_id):
                return await client.send_statuscode("RateLimit", listener)
        
        # Ratelimit IP
        security.ratelimit(f"login:i:{client.ip}", 100, 1800)

        # Get tokens, password, permissions, ban state, and delete after timestamp
        account = db.usersv0.find_one({"_id": username}, projection={
            "tokens": 1,
            "pswd": 1,
            "flags": 1,
            "permissions": 1,
            "ban": 1,
            "delete_after": 1
        })
        if not account:
            return await client.send_statuscode("IDNotFound", listener)
        elif (account["flags"] & security.UserFlags.DELETED) or (account["delete_after"] and account["delete_after"] <= time.time()+60):
            security.ratelimit(f"login:u:{username}:f", 5, 60)
            return await client.send_statuscode("Deleted", listener)
        
        # Check password
        if (password not in account["tokens"]) and (not security.check_password_hash(password, account["pswd"])):
            security.ratelimit(f"login:u:{username}:f", 5, 60)
            return await client.send_statuscode("PasswordInvalid", listener)
        
        # Update netlog
        netlog_result = db.netlog.update_one({"_id": {"ip": client.ip, "user": username}}, {"$set": {"last_used": int(time.time())}}, upsert=True)

        # Check ban
        if (account["ban"]["state"] == "perm_ban") or (account["ban"]["state"] == "temp_ban" and account["ban"]["expires"] > time.time()):
            security.ratelimit(f"login:u:{username}:f", 5, 60)
            await client.send({
                "mode": "banned",
                "payload": account["ban"]
            }, direct_wrap=True, listener=listener)
            return await client.send_statuscode("Banned", listener)

        # Ratelimit successful login
        security.ratelimit(f"login:u:{username}:s", 25, 300)

        # Alert user of new IP address if user has admin permissions
        if account["permissions"] and netlog_result.upserted_id:
            self.supporter.create_post("inbox", username, f"Your account was logged into on a new IP address ({client.ip})! You are receiving this message because you have admin permissions. Please make sure to keep your account secure.")
        
        # Alert user if account was pending deletion
        if account["delete_after"]:
            self.supporter.create_post("inbox", username, f"Your account was scheduled for deletion but you logged back in. Your account is no longer scheduled for deletion! If you didn't request for your account to be deleted, please change your password immediately.")

        # Generate new token
        token = security.generate_token()

        # Update user
        db.usersv0.update_one({"_id": username}, {
            "$addToSet": {"tokens": token},
            "$set": {"last_seen": int(time.time()), "delete_after": None}
        })

        # Authenticate client
        client.set_username(username)

        # Get relationships
        relationships = [{
            "username": relationship["_id"]["to"],
            "state": relationship["state"],
            "updated_at": relationship["updated_at"]
        } for relationship in db.relationships.find({"_id.from": username})]

        # Return info to sender
        await client.send({
            "mode": "auth",
            "payload": {
                "username": username,
                "token": token,
                "account": security.get_account(username, True),
                "relationships": relationships
        }}, direct_wrap=True, listener=listener)
        
        # Tell the client it is authenticated
        await client.send_statuscode("OK", listener)

    async def gen_account(self, client: CloudlinkClient, val, listener: str = None):
        # Make sure the client isn't already authenticated
        if client.username:
            return await client.send_statuscode("OK", listener)
        
        # Make sure registration isn't disabled
        if not self.supporter.registration:
            return await client.send_statuscode("Disabled", listener)

        # Check val datatype
        if not isinstance(val, dict):
            return await client.send_statuscode("Datatype", listener)
        
        # Check val syntax
        if ("username" not in val) or ("pswd" not in val):
            return await client.send_statuscode("Syntax", listener)
        
        # Extract username and password
        username = val["username"]
        password = val["pswd"]

        # Check username and password datatypes
        if (not isinstance(username, str)) or (not isinstance(password, str)):
            return await client.send_statuscode("Datatype", listener)
        
        # Check username and password syntax
        if len(username) < 1 or len(username) > 20 or len(password) < 1 or len(password) > 255:
            return await client.send_statuscode("Syntax", listener)
        
        # Check username regex
        if not re.fullmatch(security.USERNAME_REGEX, username):
            return await client.send_statuscode("IllegalChars", listener)
        
        # Check ratelimit
        if security.ratelimited(f"registration:{client.ip}:f") or security.ratelimited(f"registration:{client.ip}:s"):
            return await client.send_statuscode("RateLimit", listener)

        # Check whether IP is blocked from creating new accounts
        if registration_blocked_ips.search_best(client.ip):
            security.ratelimit(f"registration:{client.ip}:f", 5, 30)
            return await client.send_statuscode("Blocked", listener)

        # Make sure username doesn't already exist
        if security.account_exists(username, ignore_case=True):
            security.ratelimit(f"registration:{client.ip}:f", 5, 30)
            return await client.send_statuscode("IDExists", listener)

        # Generate new token
        token = security.generate_token()

        # Create account
        security.create_account(username, password, token=token)

        # Ratelimit
        security.ratelimit(f"registration:{client.ip}:s", 5, 900)

        # Update netlog
        db.netlog.update_one({"_id": {"ip": client.ip, "user": username}}, {"$set": {"last_used": int(time.time())}}, upsert=True)

        # Send welcome message
        self.supporter.create_post("inbox", username, "Welcome to Meower! We welcome you with open arms! You can get started by making friends in the global chat or home, or by searching for people and adding them to a group chat. We hope you have fun!")

        # Authenticate client
        client.set_username(username)

        # Return info to sender
        await client.send({
            "mode": "auth",
            "payload": {
                "username": username,
                "token": token,
                "account": security.get_account(username, True),
                "relationships": []
        }}, direct_wrap=True, listener=listener)
        
        # Tell the client it is authenticated
        await client.send_statuscode("OK", listener)

        # Auto-report if client is on a VPN
        if security.get_netinfo(client.ip)["vpn"]:
            db.reports.insert_one({
                "_id": str(uuid.uuid4()),
                "type": "user",
                "content_id": username,
                "status": "pending",
                "escalated": False,
                "reports": [{
                    "user": "Server",
                    "ip": client.ip,
                    "reason": "User registered while using a VPN.",
                    "comment": "",
                    "time": int(time.time())
                }]
            })

    async def get_profile(self, client: CloudlinkClient, val, listener: str = None):        
        # Check datatype
        if not isinstance(val, str):
            return await client.send_statuscode("Datatype", listener)
        
        # Check syntax
        if len(val) < 1 or len(val) > 20:
            return await client.send_statuscode("Syntax", listener)
        
        # Get profile
        account = security.get_account(val, (client.username and val.lower() == client.username.lower()))
        if not account:
            return await client.send_statuscode("IDNotFound", listener)
        
        # Return profile
        await client.send({
            "mode": "profile",
            "payload": account,
            "user_id": account["_id"]
        }, direct_wrap=True, listener=listener)
        await client.send_statuscode("OK", listener)

    async def update_config(self, client: CloudlinkClient, val, listener: str = None):
        # Make sure the client is authenticated
        if not client.username:
            return await client.send_statuscode("Refused", listener)
        
        # Check datatype
        if not isinstance(val, dict):
            return await client.send_statuscode("Datatype", listener)
        
        # Check ratelimit
        if security.ratelimited(f"config:{client.username}"):
            return await client.send_statuscode("RateLimit", listener)
        
        # Ratelimit
        security.ratelimit(f"config:{client.username}", 10, 5)

        # Delete quote if account is restricted
        if "quote" in val:
            if security.is_restricted(client.username, security.Restrictions.EDITING_QUOTE):
                del val["quote"]

        # Update config
        security.update_settings(client.username, val)

        # Sync config between sessions
        self.cl.broadcast({
            "mode": "update_config",
            "payload": val
        }, direct_wrap=True, usernames=[client.username])

        # Tell the client the config was updated
        await client.send_statuscode("OK", listener)

    async def change_pswd(self, client: CloudlinkClient, val, listener: str = None):
        # Make sure the client is authenticated
        if not client.username:
            return await client.send_statuscode("Refused", listener)
        
        # Check datatype
        if not isinstance(val, dict):
            return await client.send_statuscode("Datatype", listener)

        # Check syntax
        if ("old" not in val) or ("new" not in val):
            return await client.send_statuscode("Syntax", listener)
        
        # Extract old password and new password
        old_pswd = val["old"]
        new_pswd = val["new"]

        # Check old password and new password datatypes
        if (not isinstance(old_pswd, str)) or (not isinstance(new_pswd, str)):
            return await client.send_statuscode("Datatype", listener)
        
        # Check old password and new password syntax
        if len(old_pswd) < 1 or len(old_pswd) > 255 or len(new_pswd) < 8 or len(new_pswd) > 255:
            return await client.send_statuscode("Syntax", listener)
        
        # Check ratelimit
        if security.ratelimited(f"login:u:{client.username}:f"):
            return await client.send_statuscode("RateLimit", listener)

        # Ratelimit
        security.ratelimit(f"login:u:{client.username}:f", 5, 60)

        # Check password
        account = db.usersv0.find_one({"_id": client.username}, projection={"pswd": 1})
        if not security.check_password_hash(old_pswd, account["pswd"]):
            return await client.send_statuscode("PasswordInvalid", listener)
        
        # Update password
        db.usersv0.update_one({"_id": client.username}, {"$set": {"pswd": security.hash_password(new_pswd)}})

        # Tell the client the password was updated
        await client.send_statuscode("OK", listener)

    async def del_tokens(self, client: CloudlinkClient, val, listener: str = None):
        # Make sure the client is authenticated
        if not client.username:
            return await client.send_statuscode("Refused", listener)
        
        # Revoke tokens
        db.usersv0.update_one({"_id": client.username}, {"$set": {"tokens": []}})

        # Tell the client the tokens were revoked
        await client.send_statuscode("OK", listener)

        # Disconnect the client
        for client in self.cl.usernames.get(client.username, []):
            client.kick(statuscode="LoggedOut")

    async def del_account(self, client: CloudlinkClient, val, listener: str = None):
        # Make sure the client is authenticated
        if not client.username:
            return await client.send_statuscode("Refused", listener)
        
        # Check datatype
        if not isinstance(val, str):
            return await client.send_statuscode("Datatype", listener)
        
        # Check syntax
        if len(val) < 1 or len(val) > 255:
            return await client.send_statuscode("Syntax", listener)
        
        # Check ratelimit
        if security.ratelimited(f"login:u:{client.username}:f"):
            return await client.send_statuscode("RateLimit", listener)

        # Ratelimit
        security.ratelimit(f"login:u:{client.username}:f", 5, 60)
        
        # Check password
        account = db.usersv0.find_one({"_id": client.username}, projection={"pswd": 1})
        if not security.check_password_hash(val, account["pswd"]):
            return await client.send_statuscode("PasswordInvalid", listener)

        # Schedule account for deletion
        db.usersv0.update_one({"_id": client.username}, {"$set": {
            "tokens": [],
            "delete_after": int(time.time())+604800  # 7 days
        }})

        # Tell the client their account was scheduled for deletion
        await client.send_statuscode("OK", listener)

        # Disconnect the client
        for client in self.cl.usernames.get(client.username, []):
            client.kick(statuscode="LoggedOut")

    async def create_chat(self, client: CloudlinkClient, val, listener: str = None):
        # Make sure the client is authenticated
        if not client.username:
            return await client.send_statuscode("Refused", listener)
        
        # Check ratelimit
        if security.ratelimited(f"create_chat:{client.username}"):
            return await client.send_statuscode("RateLimit", listener)

        # Ratelimit
        security.ratelimit(f"create_chat:{client.username}", 5, 30)

        # Check restrictions
        if security.is_restricted(client.username, security.Restrictions.NEW_CHATS):
            return await client.send_statuscode("Banned", listener)

        # Check datatype
        if not isinstance(val, str):
            return await client.send_statuscode("Datatype", listener)
        
        # Check syntax
        if len(val) < 1 or len(val) > 50:
            return await client.send_statuscode("Syntax", listener)

        # Make sure the client isn't in too many chats
        if db.chats.count_documents({"type": 0, "members": client.username}, limit=150) >= 150:
            return await client.send_statuscode("Syntax", listener)

        # Create chat
        chat = {
            "_id": str(uuid.uuid4()),
            "type": 0,
            "nickname": self.supporter.wordfilter(val),
            "owner": client.username,
            "members": [client.username],
            "created": int(time.time()),
            "last_active": int(time.time()),
            "deleted": False
        }
        db.chats.insert_one(chat)

        # Tell the client the chat was created
        self.cl.broadcast({
            "mode": "create_chat",
            "payload": chat
        }, direct_wrap=True, usernames=[client.username])
        await client.send_statuscode("OK", listener)

    async def leave_chat(self, client: CloudlinkClient, val, listener: str = None):
        # Make sure the client is authenticated
        if not client.username:
            return await client.send_statuscode("Refused", listener)
        
        # Check ratelimit
        if security.ratelimited(f"update_chat:{client.username}"):
            return await client.send_statuscode("RateLimit", listener)

        # Ratelimit
        security.ratelimit(f"update_chat:{client.username}", 5, 5)

        # Check datatype
        if not isinstance(val, str):
            return await client.send_statuscode("Datatype", listener)
        
        # Check syntax
        if len(val) < 1 or len(val) > 50:
            return await client.send_statuscode("Syntax", listener)

        # Get chat
        chat = db.chats.find_one({"_id": val, "members": client.username, "deleted": False})
        if not chat:
            return await client.send_statuscode("IDNotFound", listener)

        if chat["type"] == 0:
            # Remove member
            chat["members"].remove(client.username)

            # Update chat if it's not empty, otherwise delete the chat
            if len(chat["members"]) > 0:
                # Transfer ownership, if owner
                if chat["owner"] == client.username:
                    chat["owner"] = chat["members"][0]
                
                # Update chat
                db.chats.update_one({"_id": val}, {
                    "$set": {"owner": chat["owner"]},
                    "$pull": {"members": client.username}
                })

                # Delete invites
                db.chat_invites.delete_many({"chat_id": chat["_id"], "inviter": client.username})

                # Send update chat event
                self.cl.broadcast({
                    "mode": "update_chat",
                    "payload": {
                        "_id": chat["_id"],
                        "owner": chat["owner"],
                        "members": chat["members"]
                    }
                }, direct_wrap=True, usernames=chat["members"])

                # Send in-chat notification
                self.supporter.create_post(chat["_id"], "Server", f"@{client.username} has left the group chat.", chat_members=chat["members"])
            else:
                db.posts.delete_many({"post_origin": val, "isDeleted": False})
                db.chats.delete_one({"_id": val})
        elif chat["type"] == 1:
            # Remove chat from client's active DMs list
            db.user_settings.update_one({"_id": client}, {
                "$pull": {"active_dms": val}
            })
        else:
            return await client.send_statuscode("InternalServerError", listener)

        # Send delete event to client
        self.cl.broadcast({
            "mode": "delete",
            "id": chat["_id"]
        }, direct_wrap=True, usernames=[client.username])

        # Tell the client it left the chat
        await client.send_statuscode("OK", listener)

    async def get_chat_list(self, client: CloudlinkClient, val, listener: str = None):
        # Make sure the client is authenticated
        if not client.username:
            return await client.send_statuscode("Refused", listener)
        
        # Get page
        page = 1
        if isinstance(val, dict):
            try:
                page = int(val["page"])
            except: pass

        # Get chats
        query = {"members": client.username, "type": 0}
        chats = list(db.chats.find(query, skip=(page-1)*25, limit=25))

        # Return chats
        await client.send({
            "mode": "chats",
            "payload": {
                "all_chats": chats,
                "index": [chat["_id"] for chat in chats],
                "page#": page,
                "pages": get_total_pages("chats", query)
            }
        }, direct_wrap=True, listener=listener)
        await client.send_statuscode("OK", listener)
    
    async def get_chat_data(self, client: CloudlinkClient, val, listener: str = None):
        # Make sure the client is authenticated
        if not client.username:
            return await client.send_statuscode("Refused", listener)
        
        # Check datatype
        if not isinstance(val, str):
            return await client.send_statuscode("Datatype", listener)
        
        # Check syntax
        if len(val) < 1 or len(val) > 50:
            return await client.send_statuscode("Syntax", listener)
        
        # Get chat
        chat = db.chats.find_one({"_id": val, "members": client.username, "deleted": False})
        if not chat:
            return await client.send_statuscode("IDNotFound", listener)
        
        # Return chat
        chat["chatid"] = chat["_id"]
        await client.send({
            "mode": "chat_data",
            "payload": chat
        }, direct_wrap=True, listener=listener)
        await client.send_statuscode("OK", listener)

    async def add_to_chat(self, client: CloudlinkClient, val, listener: str = None):
        # Make sure the client is authenticated
        if not client.username:
            return await client.send_statuscode("Refused", listener)
        
        # Check ratelimit
        if security.ratelimited(f"update_chat:{client}"):
            return await client.send_statuscode("RateLimit", listener)

        # Ratelimit
        security.ratelimit(f"update_chat:{client}", 5, 5)

        # Check restrictions
        if security.is_restricted(client, security.Restrictions.NEW_CHATS):
            return await client.send_statuscode("Banned", listener)

        # Check val datatype
        if not isinstance(val, dict):
            return await client.send_statuscode("Datatype", listener)

        # Check val syntax
        if ("chatid" not in val) or ("username" not in val):
            return await client.send_statuscode("Syntax", listener)

        # Extract chatid and username
        chatid = val["chatid"]
        username = val["username"]

        # Check chatid and username datatypes
        if (not isinstance(chatid, str)) or (not isinstance(username, str)):
            return await client.send_statuscode("Datatype", listener)
        
        # Check chatid and username syntax
        if (len(chatid) > 50) or (len(username) > 20):
            return await client.send_statuscode("Syntax", listener)

        # Get chat
        chat = db.chats.find_one({"_id": chatid, "members": client.username, "deleted": False})
        if not chat:
            return await client.send_statuscode("IDNotFound", listener)

        # Make sure the chat isn't full
        if chat["type"] == 1 or len(chat["members"]) >= 256:
            return await client.send_statuscode("ChatFull", listener)
        
        # Make sure the user isn't already in the chat
        if username in chat["members"]:
            return await client.send_statuscode("IDExists", listener)

        # Make sure requested user exists and isn't deleted
        user = db.usersv0.find_one({"_id": username}, projection={"permissions": 1})
        if (not user) or (user["permissions"] is None):
            return await client.send_statuscode("IDNotFound", listener)

        # Make sure requested user isn't blocked or is blocking client
        if db.relationships.count_documents({"$or": [
            {
                "_id": {"from": client.username, "to": username},
                "state": 2
            },
            {
                "_id": {"from": username, "to": client.username},
                "state": 2
            }
        ]}, limit=1) > 0:
            return await client.send_statuscode("MissingPermissions", listener)

        # Make sure requested user isn't banned from the chat
        if db.chat_bans.count_documents({"_id": {
            "chat": chat["_id"],
            "user": username
        }, "$or": [
            {"expires": None},
            {"expires": {"$gt": int(time.time())}}
        ]}, limit=1) > 0:
            return await client.send_statuscode("UserBanned", listener)

        # Update chat
        chat["members"].append(username)
        db.chats.update_one({"_id": chatid}, {"$addToSet": {"members": username}})

        # Send create chat event
        self.cl.broadcast({
            "mode": "create_chat",
            "payload": chat
        }, direct_wrap=True, usernames=[username])

        # Send update chat event
        self.cl.broadcast({
            "mode": "update_chat",
            "payload": {
                "_id": chatid,
                "members": chat["members"]
            }
        }, direct_wrap=True, usernames=chat["members"])

        # Send inbox message to user
        self.supporter.create_post("inbox", username, f"You have been added to the group chat '{chat['nickname']}' by @{client.username}!")

        # Send in-chat notification
        self.supporter.create_post(chatid, "Server", f"@{client.username} added @{username} to the group chat.", chat_members=chat["members"])

        # Tell the client the user was added
        await client.send_statuscode("OK", listener)

    async def remove_from_chat(self, client: CloudlinkClient, val: dict, listener: str = None):
        # Make sure the client is authenticated
        if not client.username:
            return await client.send_statuscode("Refused", listener)
        
        # Check ratelimit
        if security.ratelimited(f"update_chat:{client}"):
            return await client.send_statuscode("RateLimit", listener)

        # Ratelimit
        security.ratelimit(f"update_chat:{client}", 5, 5)

        # Check val datatype
        if not isinstance(val, dict):
            return await client.send_statuscode("Datatype", listener)

        # Check val syntax
        if ("chatid" not in val) or ("username" not in val):
            return await client.send_statuscode("Syntax", listener)

        # Extract chatid and username
        chatid = val["chatid"]
        username = val["username"]

        # Check chatid and username datatypes
        if (not isinstance(chatid, str)) or (not isinstance(username, str)):
            return await client.send_statuscode("Datatype", listener)
        
        # Check chatid and username syntax
        if (len(chatid) > 50) or (len(username) > 20):
            return await client.send_statuscode("Syntax", listener)

        # Get chat
        chat = db.chats.find_one({
            "_id": chatid,
            "members": {"$all": [client.username, username]},
            "deleted": False
        })
        if not chat:
            return await client.send_statuscode("IDNotFound", listener)

        # Make sure client is owner of chat
        if chat["owner"] != client.username:
            return await client.send_statuscode("MissingPermissions", listener)
        
        # Update chat
        chat["members"].remove(username)
        db.chats.update_one({"_id": chatid}, {"$pull": {"members": username}})

        # Delete invites
        db.chat_invites.delete_many({"chat_id": chat["_id"], "inviter": username})

        # Send delete chat event
        self.cl.broadcast({
            "mode": "delete",
            "id": chat["_id"]
        }, direct_wrap=True, usernames=[username])

        # Send update chat event
        self.cl.broadcast({
            "mode": "update_chat",
            "payload": {
                "_id": chatid,
                "members": chat["members"]
            }
        }, direct_wrap=True, usernames=[username])

        # Send inbox message to user
        self.supporter.create_post("inbox", username, f"You have been removed from the group chat '{chat['nickname']}' by @{client.username}!")

        # Send in-chat notification
        self.supporter.create_post(chatid, "Server", f"@{client.username} removed @{username} from the group chat.", chat_members=chat["members"])

        # Tell the client the user was added
        await client.send_statuscode("OK", listener)

    async def set_chat_state(self, client: CloudlinkClient, val: dict, listener: str = None):
        # Make sure the client is authenticated
        if not client.username:
            return await client.send_statuscode("Refused", listener)

        # Check val datatype
        if not isinstance(val, dict):
            return await client.send_statuscode("Datatype", listener)
        
        # Check val syntax
        if ("chatid" not in val) or ("state" not in val):
            return await client.send_statuscode("Syntax", listener)
        
        # Extract chatid and state
        chatid = val["chatid"]
        state = val["state"]

        # Check chatid and state datatypes
        if (not isinstance(chatid, str)) or (not isinstance(state, int)):
            return await client.send_statuscode("Datatype", listener)
        
        # Check chatid syntax
        if len(chatid) < 1 or len(chatid) > 50:
            return await client.send_statuscode("Syntax", listener)

        # Get chat
        if chatid != "livechat":
            chat = db.chats.find_one({
                "_id": chatid,
                "members": client.username,
                "deleted": False
            })
            if not chat:
                return await client.send_statuscode("IDNotFound", listener)

        
        # Send new state
        # noinspection PyUnboundLocalVariable
        self.cl.broadcast({
            "chatid": chatid,
            "u": client.username,
            "state": state
        }, direct_wrap=True, usernames=(chat["members"] if chatid != "livechat" else None))

        # Tell the client the new state was sent
        await client.send_statuscode("OK", listener)

    async def post_home(self, client: CloudlinkClient, val: str, listener: str = None):
        # Make sure the client is authenticated
        if not client.username:
            return await client.send_statuscode("Refused", listener)
        
        # Check datatype
        if not isinstance(val, str):
            return await client.send_statuscode("Datatype", listener)
        
        # Check syntax
        if len(val) < 1 or len(val) > 4000:
            return await client.send_statuscode("Syntax", listener)
        
        # Check ratelimit
        if security.ratelimited(f"post:{client.username}"):
            return await client.send_statuscode("RateLimit", listener)

        # Ratelimit
        security.ratelimit(f"post:{client.username}", 6, 5)

        # Check restrictions
        if security.is_restricted(client.username, security.Restrictions.HOME_POSTS):
            return await client.send_statuscode("Banned", listener)
        
        # Create post
        self.supporter.create_post("home", client.username, val)
        
        # Tell the client the post was created
        await client.send_statuscode("OK", listener)

    async def post_chat(self, client: CloudlinkClient, val: dict, listener: str = None):
        # Make sure the client is authenticated
        if not client.username:
            return await client.send_statuscode("Refused", listener)
        
        # Check ratelimit
        if security.ratelimited(f"post:{client.username}"):
            return await client.send_statuscode("RateLimit", listener)

        # Ratelimit
        security.ratelimit(f"post:{client.username}", 6, 5)

        # Check val datatype
        if not isinstance(val, dict):
            return await client.send_statuscode("Datatype", listener)
        
        # Check val syntax
        if ("chatid" not in val) or ("p" not in val):
            return await client.send_statuscode("Syntax", listener)
        
        # Extract chatid and content
        chatid = val["chatid"]
        content = val["p"]

        # Check chatid and content datatypes
        if (not isinstance(chatid, str)) or (not isinstance(content, str)):
            return await client.send_statuscode("Datatype", listener)
        
        # Check chatid and content syntax
        if len(chatid) < 1 or len(chatid) > 50 or len(content) < 1 or len(content) > 4000:
            return await client.send_statuscode("Syntax", listener)

        # Check restrictions
        if security.is_restricted(client.username, security.Restrictions.CHAT_POSTS):
            return await client.send_statuscode("Banned", listener)

        if chatid != "livechat":
            # Get chat
            chat = db.chats.find_one({
                "_id": chatid,
                "members": client.username,
                "deleted": False
            }, projection={"type": 1, "members": 1})
            if not chat:
                return await client.send_statuscode("IDNotFound", listener)
            
            # DM stuff
            if chat["type"] == 1:
                # Check privacy options
                if db.relationships.count_documents({"$or": [
                    {"_id": {"from": chat["members"][0], "to": chat["members"][1]}},
                    {"_id": {"from": chat["members"][1], "to": chat["members"][0]}}
                ], "state": 2}, limit=1) > 0:
                    return await client.send_statuscode("MissingPermissions", listener)

                # Update user settings
                Thread(target=db.user_settings.bulk_write, args=([
                    pymongo.UpdateMany({"$or": [
                        {"_id": chat["members"][0]},
                        {"_id": chat["members"][1]}
                    ]}, {"$pull": {"active_dms": chatid}}),
                    pymongo.UpdateMany({"$or": [
                        {"_id": chat["members"][0]},
                        {"_id": chat["members"][1]}
                    ]}, {"$push": {"active_dms": {
                        "$each": [chatid],
                        "$position": 0,
                        "$slice": -150
                    }}})
                ],)).start()

        # Create post
        # noinspection PyUnboundLocalVariable
        self.supporter.create_post(chatid, client.username, content, chat_members=(chat["members"] if chatid != "livechat" else None))
        
        # Tell the client the post was created
        await client.send_statuscode("OK", listener)

    async def delete_post(self, client: CloudlinkClient, val: str, listener: str = None):
        # Make sure the client is authenticated
        if not client.username:
            return await client.send_statuscode("Refused", listener)
        
        # Check datatype
        if not isinstance(val, str):
            return await client.send_statuscode("Datatype", listener)
        
        # Check syntax
        if len(val) < 1 or len(val) > 50:
            return await client.send_statuscode("Syntax", listener)

        # Check ratelimit
        if security.ratelimited(f"del_post:{client.username}"):
            return await client.send_statuscode("RateLimit", listener)

        # Ratelimit
        security.ratelimit(f"del_post:{client.username}", 6, 5)

        # Get post
        post = db.posts.find_one({"_id": val, "isDeleted": False})
        if not post:
            return await client.send_statuscode("IDNotFound", listener)

        # Check access
        if post["post_origin"] not in ["home", "inbox"]:
            chat = db.chats.find_one({
                "_id": post["post_origin"],
                "members": client.username,
                "deleted": False
            }, projection={"owner": 1, "members": 1})
            if not chat:
                return await client.send_statuscode("MissingPermissions", listener)
        if post["post_origin"] == "inbox" or post["u"] != client.username:
            # noinspection PyUnboundLocalVariable

            if (post["post_origin"] in ["home", "inbox"]) or (chat["owner"] != client.username):
                return await client.send_statuscode("MissingPermissions", listener)

        # Update post
        db.posts.update_one({"_id": post["_id"]}, {"$set": {
            "isDeleted": True,
            "deleted_at": int(time.time())
        }})

        # Send delete post event
        self.cl.broadcast({
            "mode": "delete",
            "id": post["_id"]
        }, direct_wrap=True, usernames=chat["members"])

        await client.send_statuscode("OK", listener)

    # noinspection PyMethodMayBeStatic,PyTypeChecker
    async def report(self, client: CloudlinkClient, val: str, listener: str = None):
        # Make sure the client is authenticated
        if not client.username:
            return await client.send_statuscode("Refused", listener)
        
        # Check datatype
        if not isinstance(val, dict):
            return await client.send_statuscode("Datatype", listener)

        # Check val syntax
        if ("type" not in val) or ("id" not in val):
            return await client.send_statuscode("Syntax", listener)

        # Extract type, ID, reason, and comment
        content_type = val["type"]
        content_id = val["id"]
        reason = val.get("reason", "No reason specified")
        comment = val.get("comment", "")

        # Check type, ID, reason, and comment datatypes
        if (not isinstance(content_type, int)) or (not isinstance(content_id, str)) or (not isinstance(reason, str)) or (not isinstance(comment, str)):
            return await client.send_statuscode("Datatype", listener)
        
        # Make sure the content exists
        if content_type == 0:
            post = db.posts.find_one({
                "_id": content_id,
                "post_origin": {"$ne": "inbox"},
                "isDeleted": False
            }, projection={"post_origin": 1})
            if not post:
                return await client.send_statuscode("IDNotFound", listener)
            elif post["post_origin"] != "home":
                if db.chats.count_documents({
                    "_id": post["post_origin"],
                    "members": client.username,
                    "deleted": False
                }, limit=1) < 1:
                    return await client.send_statuscode("IDNotFound", listener)
        elif content_type == 1:
            if db.usersv0.count_documents({"_id": content_id}, limit=1) < 1:
                return await client.send_statuscode("IDNotFound", listener)
        else:
            return await client.send_statuscode("IDNotFound", listener)
        
        # Create report
        report = db.reports.find_one({
            "content_id": content_id,
            "status": "pending",
            "type": {0: "post", 1: "user"}[content_type]
        })
        if not report:
            report = {
                "_id": str(uuid.uuid4()),
                "type": {0: "post", 1: "user"}[content_type],
                "content_id": content_id,
                "status": "pending",
                "escalated": False,
                "reports": []
            }
        for _report in report["reports"]:
            # noinspection PyTypeChecker
            if _report["user"] == client.username:
                report["reports"].remove(_report)
                break
        report["reports"].append({
            "user": client.username,
            "ip": client.ip,
            "reason": reason,
            "comment": comment,
            "time": int(time.time())
        })
        db.reports.update_one({"_id": report["_id"]}, {"$set": report}, upsert=True)

        # Tell the client the report was created
        await client.send_statuscode("OK", listener)

        # Automatically remove post and escalate report if report threshold is reached
        if content_type == 0 and report["status"] == "pending" and (not report["escalated"]):
            # noinspection PyTypeChecker
            unique_ips = set([_report["ip"] for _report in report["reports"]])
            if len(unique_ips) >= 3:
                db.reports.update_one({"_id": report["_id"]}, {"$set": {"escalated": True}})
                db.posts.update_one({"_id": content_id, "isDeleted": False}, {"$set": {
                    "isDeleted": True,
                    "mod_deleted": True,
                    "deleted_at": int(time.time())
                }})
