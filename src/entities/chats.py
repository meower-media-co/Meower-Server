from datetime import datetime
from secrets import token_urlsafe

from src.util import status, uid, events, bitfield, flags
from src.entities import users
from src.database import db

LIVECHAT = {
    "_id": "livechat",
    "created": uid.timestamp(epoch=0)
}

class Chat:
    def __init__(
        self,
        _id: str,
        name: str = None,
        direct: bool = False,
        flags: int = 0,
        members: list = [],
        active: list = [],
        permissions: dict = {},
        invite_code: str = None,
        created: datetime = None,
        deleted_at: datetime = None
    ):
        self.id = _id
        self.name = name
        self.direct = direct
        self.flags = flags
        self.members = [users.get_user(member_id) for member_id in members]
        self.active = active
        self.permissions = permissions
        self.invite_code = invite_code
        self.created = created
        self.deleted_at = deleted_at

    @property
    def public(self):
        return {
            "id": self.id,
            "name": self.name,
            "direct": self.direct,
            "flags": self.flags,
            "members": self.partial_members,
            "permissions": self.permissions,
            "invite_code": self.invite_code,
            "created": int(self.created.timestamp())
        }
    
    @property
    def legacy_public(self):
        owner = self.members[0].username
        for user_id, level in self.permissions.items():
            if level == 2:
                for user in self.members:
                    if user.id == user_id:
                        owner = user.username
        return {
            "_id": self.id,
            "nickname": (f"{self.members[0].username} & {self.members[1].username}" if self.direct else self.name),
            "owner": owner,
            "members": [member.username for member in self.members]
        }

    @property
    def owner(self):
        for user_id, level in self.permissions.items():
            if level == 2:
                for user in self.members:
                    if user.id == user_id:
                        return user

    @property
    def partial_members(self):
        return [member.partial for member in self.members]

    def update_name(self, name: str):
        if self.id == "livechat":
            raise status.missingPermissions
        elif self.direct:
            raise status.missingPermissions

        self.name = name
        db.chats.update_one({"_id": self.id}, {"$set": {"name": self.name}})
        events.emit_event("chat_updated", self.id, {
            "chat_id": self.id,
            "name": self.name
        })

    def has_member(self, user: any):
        if self.id == "livechat":
            return True
        for member in self.members:
            if member.id == user.id:
                return True
        return False

    def add_member(self, user: any):
        if self.id == "livechat":
            raise status.missingPermissions
        elif self.direct:
            raise status.missingPermissions
        elif self.has_member(user):
            raise status.chatMemberAlreadyExists

        self.members.append(user)
        db.chats.update_one({"_id": self.id}, {"$addToSet": {"members": user.id}})
        events.emit_event("chat_updated", self.id, {
            "chat_id": self.id,
            "members": self.partial_members
        })
        events.emit_event("chat_created", user.id, self.public)

    def remove_member(self, user: any):
        if self.id == "livechat":
            raise status.missingPermissions
        elif self.direct:
            raise status.missingPermissions
        elif not self.has_member(user):
            raise status.resourceNotFound

        for member in self.members:
            if member.id == user.id:
                self.members.remove(member)
        if user.id in self.permissions:
            del self.permissions[user.id]
        db.chats.update_one({"_id": self.id}, {
            "$pull": {"members": user.id},
            "$set": {"permissions": self.permissions}
        })
        events.emit_event("chat_deleted", user.id, {
            "id": self.id
        })

        if len(self.members) == 0:
            self.delete()
        else:
            events.emit_event("chat_updated", self.id, {
                "id": self.id,
                "members": self.partial_members,
                "permissions": self.permissions
            })

            if not self.owner:
                self.transfer_ownership(self.members[0])

    def promote_member(self, user: any):
        if self.id == "livechat":
            raise status.missingPermissions
        elif self.direct:
            raise status.missingPermissions
        elif not self.has_member(user):
            raise status.resourceNotFound

        if self.permissions.get(user.id, 0) < 1:
            self.permissions[user.id] = 1
            db.chats.update_one({"_id": self.id}, {"$set": {"permissions": self.permissions}})
            events.emit_event("chat_updated", self.id, {
                "id": self.id,
                "permissions": self.permissions
            })
    
    def demote_member(self, user: any):
        if self.id == "livechat":
            raise status.missingPermissions
        elif self.direct:
            raise status.missingPermissions
        elif not self.has_member(user):
            raise status.resourceNotFound

        if self.permissions.get(user.id, 0) == 1:
            self.permissions[user.id] = 0
            db.chats.update_one({"_id": self.id}, {"$set": {"permissions": self.permissions}})
            events.emit_event("chat_updated", self.id, {
                "id": self.id,
                "permissions": self.permissions
            })

    def transfer_ownership(self, user: any):
        if self.id == "livechat":
            raise status.missingPermissions
        elif self.direct:
            raise status.missingPermissions
        elif not self.has_member(user):
            raise status.resourceNotFound
        elif self.permissions.get(user.id, 0) >= 2:
            raise status.missingPermissions
        
        # Demote old owner
        if self.owner:
            self.permissions[self.owner.id] = 0

        # Promote new owner
        self.permissions[user.id] = 2

        db.chats.update_one({"_id": self.id}, {"$set": {"permissions": self.permissions}})
        events.emit_event("chat_updated", self.id, {
            "id": self.id,
            "permissions": self.permissions
        })

    def emit_typing(self, user: any):
        events.emit_event("typing_start", self.id, {
            "chat_id": self.id,
            "user_id": user.id
        })

    def refresh_invite_code(self):
        if self.id == "livechat":
            raise status.missingPermissions
        elif self.direct:
            raise status.missingPermissions
        elif bitfield.has(self.flags, flags.chats.vanityInviteCode):
            raise status.missingPermissions

        self.invite_code = token_urlsafe(6)
        db.chats.update_one({"_id": self.id}, {"$set": {"invite_code": self.invite_code}})
        events.emit_event("chat_updated", self.id, {
            "id": self.id,
            "invite_code": self.invite_code
        })

    def delete(self):
        if self.id == "livechat":
            raise status.missingPermissions
        elif self.direct:
            raise status.missingPermissions
        
        self.deleted_at = uid.timestamp()
        db.chats.update_one({"_id": self.id}, {"$set": {"deleted_at": self.deleted_at}})
        for member in self.members:
            events.emit_event("chat_deleted", member.id, {
                "id": self.id
            })

def create_chat(name: str, owner_id: str):
    chat = {
        "_id": uid.snowflake(),
        "name": name,
        "direct": False,
        "members": [owner_id],
        "active": [owner_id],
        "permissions": {owner_id: 2},
        "invite_code": token_urlsafe(6),
        "created": uid.timestamp()
    }
    db.chats.insert_one(chat)
    chat = Chat(**chat)
    events.emit_event("chat_created", owner_id, chat.public)
    return chat

def get_chat(chat_id: str):
    if chat_id == "livechat":
        chat = LIVECHAT
    else:
        # Get chat from database
        chat = db.chats.find_one({"_id": chat_id})

    # Return chat object
    if chat:
        return Chat(**chat)
    else:
        raise status.resourceNotFound

def get_chat_by_invite_code(invite_code: str):
    # Get chat from database
    chat = db.chats.find_one({"invite_code": invite_code})

    # Return chat object
    if chat:
        return Chat(**chat)
    else:
        raise status.resourceNotFound

def get_dm_chat(user1: any, user2: any):
    if user1.id == user2.id:
        raise status.missingPermissions

    chat = db.chats.find_one({"members": {"$all": [user1.id, user2.id]}, "direct": True, "deleted_at": None})
    if chat:
        return Chat(**chat)
    else:
        chat = {
            "_id": uid.snowflake(),
            "direct": True,
            "members": [user1.id, user2.id],
            "created": uid.timestamp()
        }
        db.chats.insert_one(chat)

        chat = Chat(**chat)
        events.emit_event("chat_created", user1.id, chat.public)

        return chat

def get_active_chats(user: any):
    return [Chat(**chat) for chat in db.chats.find({"members": {"$all": [user.id]}, "active": {"$all": [user.id]}, "deleted_at": None})]

def get_all_chats(user_id: str, before: str = None, after: str = None, skip: int = 0, limit: int = 25):
    # Create ID range
    if before is not None:
        id_range = {"$lt": before}
    elif after is not None:
        id_range = {"$gt": after}
    else:
        id_range = {"$gt": "0"}

    # Fetch and return all chats
    return [Chat(**chat) for chat in db.chats.find({"members": {"$all": [user_id]}, "deleted_at": None, "_id": id_range}, sort=[("time", -1)], skip=skip, limit=limit)]

def get_all_chat_ids(user_id: str):
    # Fetch and return all chat IDs
    return [chat["_id"] for chat in db.chats.find({"members": {"$all": [user_id]}, "deleted_at": None}, projection={"_id": 1})]
