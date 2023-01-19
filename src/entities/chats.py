from datetime import datetime
from secrets import token_urlsafe
import time

from src.util import status, uid, events
from src.entities import users
from src.database import db

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
        deleted: bool = False,
        delete_after: datetime = None
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
        self.deleted = deleted
        self.delete_after = delete_after

    @property
    def public(self):
        return {
            "id": self.id,
            "name": self.name,
            "direct": self.direct,
            "flags": self.public_flags,
            "members": self.partial_members,
            "permissions": self.permissions,
            "invite_code": self.invite_code,
            "created": int(self.created.timestamp())
        }

    @property
    def partial_members(self):
        return [member.partial for member in self.members]

    def update_name(self, name: str):
        self.name = name
        db.chats.update_one({"_id": self.id}, {"$set": {"name": self.name}})
        events.emit_event("chat_updated", {
            "chat_id": self.id,
            "name": self.name
        })

    def has_member(self, user: users.User):
        for member in self.members:
            if member.id == user.id:
                return True
        return False

    def add_member(self, user: users.User):
        if self.has_member(user):
            return

        self.members.append(user)
        db.chats.update_one({"_id": self.id}, {"$addToSet": {"members": user.id}})
        events.emit_event("chat_updated", {
            "chat_id": self.id,
            "members": self.partial_members
        })
        events.emit_event("chat_created", {
            "chat": self.public,
            "user_id": user.id
        })

        if len(self.members) == 1:
            self.transfer_ownership(user)

    def remove_member(self, user: users.User):
        if not self.has_member(user):
            return

        for member in self.members:
            if member.id == user.id:
                self.members.remove(member)
        db.chats.update_one({"_id": self.id}, {"$pull": {"members": user.id}})
        events.emit_event("chat_deleted", {
            "chat_id": self.id,
            "user_id": user.id
        })

        if len(self.members) == 0:
            self.delete()
        else:
            events.emit_event("chat_updated", {
                "chat_id": self.id,
                "members": self.partial_members
            })
            self.transfer_ownership(self.members[0])

    def promote_member(self, user: users.User):
        if self.permissions.get(user.id, 0) < 1:
            self.permissions[user.id] = 1
            db.chats.update_one({"_id": self.id}, {"$set": {"permissions": self.permissions}})
            events.emit_event("chat_updated", {
                "chat_id": self.id,
                "permissions": self.permissions
            })
    
    def demote_member(self, user: users.User):
        if self.permissions.get(user.id, 0) == 1:
            self.permissions[user.id] = 0
            db.chats.update_one({"_id": self.id}, {"$set": {"permissions": self.permissions}})
            events.emit_event("chat_updated", {
                "chat_id": self.id,
                "permissions": self.permissions
            })

    def transfer_ownership(self, user: users.User):
        if self.permissions.get(user.id, 0) < 2:
            # Demote old owner
            for user_id, level in self.permissions.items():
                if level == 2:
                    self.permissions[user_id] = 0

            # Promote new owner
            self.permissions[user.id] = 2

            db.chats.update_one({"_id": self.id}, {"$set": {"permissions": self.permissions}})
            events.emit_event("chat_updated", {
                "chat_id": self.id,
                "permissions": self.permissions
            })

    def refresh_invite_code(self):
        self.invite_code = token_urlsafe(6)
        db.chats.update_one({"_id": self.id}, {"$set": {"invite_code": self.invite_code}})
        events.emit_event("chat_updated", {
            "chat_id": self.id,
            "invite_code": self.invite_code
        })

    def delete(self):
        if self.deleted:
            db.chat_messages.delete_many({"chat_id": self.id})
            db.chats.delete_one({"_id": self.id})
            del self
        else:
            self.deleted = True
            self.delete_after = uid.timestamp(epoch=int(time.time() + 1209600))
            db.chats.update_one({"_id": self.id}, {"$set": {"deleted": self.deleted, "delete_after": self.delete_after}})
            for member in self.members:
                events.emit_event("chat_deleted", {
                    "chat_id": self.id,
                    "user_id": member.id
                })

def create_chat(name: str, owner: users.User):
    chat = {
        "_id": uid.snowflake(),
        "name": name,
        "direct": False,
        "invite_code": token_urlsafe(6),
        "created": uid.timestamp(),
        "deleted": False
    }
    db.chats.insert_one(chat)

    chat = Chat(**chat)
    chat.add_member(owner)

    return Chat(**chat)

def get_chat(chat_id: str):
    chat = db.chats.find_one({"_id": chat_id})
    if chat is None:
        raise status.notFound
    
    return Chat(**chat)

def get_dm_chat(user1: users.User, user2: users.User):
    chat = db.chats.find_one({"members": {"$all": [user1.id, user2.id]}, "direct": True})
    if chat is not None:
        return Chat(**chat)
    else:
        chat = {
            "_id": uid.snowflake(),
            "direct": True,
            "members": [user1.id, user2.id],
            "created": uid.timestamp(),
            "deleted": False
        }
        db.chats.insert_one(chat)

        chat = Chat(**chat)
        events.emit_event("chat_created", {
            "chat": chat.public,
            "user_id": user1.id
        })

        return chat

def get_active_chats(user: users.User):
    return [Chat(**chat) for chat in db.chats.find({"members": {"$all": [user.id]}, "active": {"$all": [user.id]}})]