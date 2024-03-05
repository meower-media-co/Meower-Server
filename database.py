import pymongo
import redis
import os
from radix import Radix

from utils import log


# Create Redis connection
log("Connecting to Redis...")
try:
    rdb = redis.from_url(os.getenv("REDIS_URI", "redis://127.0.0.1:6379/0"))
except Exception as e:
    log(f"Failed to connect to database! Error: {e}")
    exit()
else:
    log("Successfully connected to Redis!")


# Create database connection
log("Connecting to database...")
try:
    db = pymongo.MongoClient(os.getenv("MONGO_URI", "mongodb://127.0.0.1:27017"))[os.getenv("MONGO_DB", "meowerserver")]
    db.command("ping")
except Exception as e:
    log(f"Failed to connect to database! Error: {e}")
    exit()
else:
    log("Successfully connected to database!")


# Create usersv0 indexes
try: db.usersv0.create_index([("lower_username", pymongo.ASCENDING)], name="lower_username", unique=True)
except: pass
try: db.usersv0.create_index([("created", pymongo.DESCENDING)], name="recent_users")
except: pass
try:
    db.usersv0.create_index([
        ("lower_username", pymongo.TEXT),
        ("quote", pymongo.TEXT)
    ], name="search", partialFilterExpression={"pswd": {"$type": "string"}})
except: pass
try: db.usersv0.create_index([
        ("delete_after", pymongo.ASCENDING)
    ], name="scheduled_deletions", partialFilterExpression={"delete_after": {"$type": "number"}})
except: pass

# Create data exports indexes
try: db.data_exports.create_index([("user", pymongo.ASCENDING)], name="user")
except: pass

# Create relationships indexes
try: db.relationships.create_index([("_id.from", pymongo.ASCENDING)], name="from")
except: pass

# Create netinfo indexes
try: db.netinfo.create_index([("last_refreshed", pymongo.ASCENDING)], name="last_refreshed")
except: pass

# Create netlog indexes
try: db.netlog.create_index([("_id.ip", pymongo.ASCENDING)], name="ip")
except: pass
try: db.netlog.create_index([("_id.user", pymongo.ASCENDING)], name="user")
except: pass
try: db.netlog.create_index([("last_used", pymongo.ASCENDING)], name="last_used")
except: pass

# Create posts indexes
try:
    db.posts.create_index([
        ("post_origin", pymongo.ASCENDING),
        ("isDeleted", pymongo.ASCENDING),
        ("t.e", pymongo.DESCENDING),
        ("u", pymongo.ASCENDING)
    ], name="default")
except: pass
try:
    db.posts.create_index([
        ("u", pymongo.ASCENDING)
    ], name="user")
except: pass
try:
    db.posts.create_index([
        ("p", pymongo.TEXT)
    ], name="search", partialFilterExpression={"post_origin": "home", "isDeleted": False})
except: pass
try:
    db.posts.create_index([
        ("deleted_at", pymongo.ASCENDING)
    ], name="scheduled_purges", partialFilterExpression={"isDeleted": True, "mod_deleted": False})
except: pass

# Create post revisions indexes
try:
    db.post_revisions.create_index([
        ("post_id", pymongo.ASCENDING),
        ("time", pymongo.DESCENDING)
    ], name="post_revisions")
except: pass
try:
    db.post_revisions.create_index([
        ("time", pymongo.ASCENDING)
    ], name="scheduled_purges")
except: pass

# Create chats indexes
try:
    db.chats.create_index([
        ("members", pymongo.ASCENDING),
        ("type", pymongo.ASCENDING)
    ], name="user_chats")
except: pass

# Create chat invites indexes
try:
    db.chat_invites.create_index([
        ("chat_id", pymongo.ASCENDING)
    ], name="chat")
except: pass

# Create chat bans indexes
try:
    db.chat_bans.create_index([
        ("_id.chat", pymongo.ASCENDING)
    ], name="chat")
except: pass
try:
    db.chat_bans.create_index([
        ("_id.user", pymongo.ASCENDING)
    ], name="user")
except: pass

# Create reports indexes
try:
    db.reports.create_index([
        ("content_id", pymongo.ASCENDING)
    ], name="pending_reports", partialFilterExpression={"status": "pending"})
except: pass
try:
    db.reports.create_index([
        ("escalated", pymongo.DESCENDING),
        ("reports.time", pymongo.DESCENDING),
        ("status", pymongo.ASCENDING),
        ("type", pymongo.ASCENDING)
    ], name="all_reports")
except: pass

# Create audit log indexes
try:
    db.audit_log.create_index([
        ("time", pymongo.ASCENDING),
        ("type", pymongo.ASCENDING)
    ], name="scheduled_purges")
except: pass


# Create default database items
for username in ["Server", "Deleted", "Meower", "Admin", "username"]:
    try:
        db.usersv0.insert_one({
            "_id": username,
            "lower_username": username.lower(),
            "uuid": None,
            "created": None,
            "pfp_data": None,
            "quote": None,
            "pswd": None,
            "tokens": None,
            "flags": 1,
            "permissions": None,
            "ban": None,
            "last_seen": None,
            "delete_after": None
        })
    except: pass
try:
    db.config.insert_one({
        "_id": "migration",
        "database": 1
    })
except: pass
try:
    db.config.insert_one({
        "_id": "status",
        "repair_mode": False,
        "registration": True
    })
except: pass
try:
    db.config.insert_one({
        "_id": "filter",
        "whitelist": [],
        "blacklist": []
    })
except: pass


# Load netblocks
blocked_ips = Radix()
registration_blocked_ips = Radix()
for netblock in db.netblock.find({}):
    try:
        if netblock["type"] == 0:
            blocked_ips.add(netblock["_id"])
        if netblock["type"] == 1:
            registration_blocked_ips.add(netblock["_id"])
    except Exception as e:
        log(f"Failed to load netblock {netblock['_id']}: {e}")
    log(f"Successfully loaded {len(blocked_ips.nodes())} netblock(s) into Radix!")
    log(f"Successfully loaded {len(registration_blocked_ips.nodes())} registration netblock(s) into Radix!")


def get_total_pages(collection: str, query: dict, page_size: int = 25) -> int:
    item_count = db[collection].count_documents(query)
    pages = (item_count // page_size)
    if (item_count % page_size) > 0:
        pages += 1
    return pages
