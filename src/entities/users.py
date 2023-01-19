from copy import copy
from datetime import datetime
import time
import string

from src.util import status, uid, bitfield, flags
from src.database import db

SERVER = {
    "_id": "0",
    "username": "Server",
    "lower_username": "server",
    "flags": bitfield.create([flags.user.system]),
    "created": uid.timestamp(epoch=0),
    "badges": ["MEOWY"]
}

DELETED = {
    "_id": "1",
    "username": "Deleted",
    "lower_username": "deleted",
    "flags": bitfield.create([flags.user.deleted]),
    "created": uid.timestamp(epoch=0)
}

MEOWER = {
    "_id": "2",
    "username": "Meower",
    "lower_username": "meower",
    "flags": bitfield.create([flags.user.system]),
    "created": uid.timestamp(epoch=0),
    "badges": ["MEOWY"]
}

PERMITTED_CHARS_USERNAME = set(string.ascii_letters + string.digits + "_-.")

CONFIG_KEYS = {
    "theme": dict,
    "sfx": bool,
    "bgm": bool,
    "bgm_song": int,
    "debug": bool
}

class User:
    def __init__(
        self,
        _id: str,
        username: str,
        lower_username: str,
        theme: dict = {},
        flags: int = 0,
        admin: int = 0,
        created: datetime = None,
        icon: dict = {"type": 0, "data": 2},
        quote: str = "",
        badges: list = [],
        stats: dict = {"followers": 0, "following": 0},
        redirect_to: str = None,
        delete_after: datetime = None
    ):
        self.id = _id
        self.username = username
        self.lower_username = lower_username
        self.flags = flags
        self.admin = admin
        self.created = created
        self.theme = theme
        self.icon = icon
        self.quote = quote
        self.badges = badges
        self.stats = stats
        self.redirect_to = redirect_to
        self.delete_after = delete_after

        if self.redirect_to is not None:
            self = get_user(self.redirect_to)

    @property
    def public(self):
        return {
            "id": self.id,
            "username": self.username,
            "public_flags": self.public_flags,
            "created": int(self.created.timestamp()),
            "theme": self.theme,
            "icon": self.icon,
            "quote": self.quote,
            "stats": self.stats,
            "badges": self.badges
        }

    @property
    def client(self):
        return {
            "id": self.id,
            "username": self.username,
            "flags": self.flags,
            "public_flags": self.public_flags,
            "admin": self.admin,
            "created": self.created,
            "theme": self.theme,
            "icon": self.icon,
            "quote": self.quote,
            "stats": self.stats,
            "badges": self.badges
        }

    @property
    def partial(self):
        return {
            "id": self.id,
            "username": self.username,
            "public_flags": self.public_flags,
            "icon": self.icon
        }

    @property
    def public_flags(self):
        pub_flags = copy(self.flags)
        for flag in [
            flags.user.child,
            flags.user.terminated
        ]:
            pub_flags = bitfield.remove(pub_flags, flag)
        return pub_flags
    
    def count_stats(self):
        followers = db.relationships.count_documents({"to": self.id})
        following = db.relationships.count_documents({"from": self.id})
        self.stats = {"followers": followers, "following": following}

    def get_relationships(self, state: int):
        return list(db.relationships.find({"from": self.id, "state": state}))

    def get_relationship(self, user):
        relationship = db.relationships.find_one({"from": self.id, "to": user.id}, projection={"_id": 0, "last_updated": 0})
        if relationship is None:
            relationship = {
                "from": self.id,
                "to": user.id,
                "state": 0,
                "last_updated": None
            }
        else:
            relationship["last_updated"] = relationship["last_updated"].timestamp()
        return relationship

    def change_relationship(self, user, state: int):
        if state == 0:
            db.relationships.delete_one({"from": self.id, "to": user.id})
        else:
            db.relationships.update_one({"from": self.id, "to": user.id})

    @property
    def username_history(self):
        return list(db.username_history.find({"user": self._id}, projection={"_id": 0, "user": 0}, sort=[("time", 1)]))

    @property
    def config(self):
        return db.user_config.find_one({"_id": self._id}, projection={"_id": 0, "last_updated": 0})

    def update_config(self, new_data: dict):
        for key, value in new_data.items():
            if (key not in CONFIG_KEYS) or (not isinstance(value, type(CONFIG_KEYS[key]))):
                del new_data[key]
        new_data["last_updated"] = uid.timestamp()
        db.user_config.update_one({"_id": self._id}, {"$set": new_data})
        return status.ok

    def update_username(self, username: str, by_admin: bool = False, store_history: bool = True):
        if (not isinstance(username, str)) or (not isinstance(by_admin, bool)) or (not isinstance(store_history, bool)):
            raise status.invalidDatatype

        if not username_available(username):
            raise status.alreadyExists

        # Add old username to username history
        if store_history:
            db.username_history.insert_one({
                "_id": uid.snowflake(),
                "user_id": self.id,
                "old_username": self.username,
                "new_username": username,
                "by_admin": by_admin,
                "time": int(time.time())
            })

        # Update current user
        self.username = username
        self.lower_username = username.lower()
        db.users.update_one({"_id": self.id}, {"$set": {
            "username": self.username,
            "lower_username": self.lower_username
        }})

def create_user(username: str, flags: int = 0):
    userdata = {
        "_id": uid.snowflake(),
        "username": username,
        "lower_username": username.lower(),
        "flags": flags,
        "created": uid.timestamp()
    }
    db.users.insert_one(userdata)
    return User(**userdata)

def get_user(user_id: str, return_deleted: bool = True):
    if user_id == "0":
        user = SERVER
    elif user_id == "1":
        user = DELETED
    elif user_id == "2":
        user = MEOWER
    else:
        user = db.users.find_one({"_id": user_id})
        if (user is None) and return_deleted:
            user = DELETED

    if user is None:
        raise status.notFound
    else:
        return User(**user)

def username_available(username: str):
    if username.lower() in ["server", "deleted", "meower"]:
        return False

    return (db.users.find_one({"lower_username": username.lower()}, projection={"_id": 1}) is None)

def get_id_from_username(username: str):
    user = db.users.find_one({"lower_username": username.lower()}, projection={"_id": 1})

    if user is None:
        raise status.notFound
    else:
        return user["_id"]