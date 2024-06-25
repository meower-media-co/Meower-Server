import time
from cloudlink import CloudlinkServer, CloudlinkClient
from supporter import Supporter
from database import db
import security


class MeowerCommands:
    def __init__(self, cl: CloudlinkServer, supporter: Supporter):
        self.cl = cl
        self.supporter = supporter
        self.cl.add_command("authpswd", self.authpswd)

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
        db.netlog.update_one({"_id": {"ip": client.ip, "user": username}}, {"$set": {"last_used": int(time.time())}}, upsert=True)

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
