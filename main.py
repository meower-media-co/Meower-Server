# Initialize API
from flask import Flask, request
meower = Flask(__name__)

# Initialize Utils
from apiv0.utils import log, timestamp, check_for_spam, check_for_bad_chars_post, check_for_bad_chars_username, user_status, send_payload
meower.log = log
meower.timestamp = timestamp
meower.check_for_spam = check_for_spam
meower.check_for_bad_chars_post = check_for_bad_chars_post
meower.check_for_bad_chars_username = check_for_bad_chars_username
meower.user_status = user_status
meower.send_payload = send_payload

# Initialize Responder
from apiv0.respond import respond
meower.respond = respond

# Initialize database
import pymongo
meower.log("Connecting to MongoDB... (if it looks like the server is stuck, it probably couldn't connect to the database)")
meower.db = pymongo.MongoClient("mongodb://localhost:27017").meowerserver

# Register blueprints
from apiv0.errors import errors
meower.register_blueprint(errors)
from apiv0.general import general
meower.register_blueprint(general, name="compatibility_general") # Keep general endpoints as root for compatibility
meower.register_blueprint(general, url_prefix="/v0")
from apiv0.admin import admin
meower.register_blueprint(admin, url_prefix="/v0/admin")
from apiv0.oauth import oauth
meower.register_blueprint(oauth, url_prefix="/v0/oauth")
from apiv0.users import users
meower.register_blueprint(users, url_prefix="/v0/users")
from apiv0.home import home
meower.register_blueprint(home, url_prefix="/v0/home")
from apiv0.chats import chats
meower.register_blueprint(chats, url_prefix="/v0/chats")
from apiv0.search import search
meower.register_blueprint(search, url_prefix="/v0/search")

# Initialize Socket
from flask_sock import Sock
from apiv0.socket import Socket
sock = Sock(meower)
meower.sock_next_id = 0
meower.sock_clients = {}
meower.sock_login_codes = {}
@sock.route("/v0/socket")
def socket_server(client):
	return Socket(meower, client)

# Initialize CORS
from flask_cors import CORS
CORS(meower, resources={r'*': {'origins': '*'}})

# Load IP bans into memory
meower.log("Loading IP bans...")
meower.ip_banlist = []
ip_bans = meower.db.netlog.find({"blocked": True})
for ip in ip_bans:
	meower.ip_banlist.append(ip["_id"])

# Set repair mode and scratch deprecated state
data = meower.db["config"].find_one({"_id": "status"})
if data is None:
	meower.log("Failed getting server status. Enabling repair mode to be safe.")
	meower.repair_mode = True
	meower.scratch_deprecated = False
else:
	meower.repair_mode = data["repairMode"]
	meower.scratch_deprecated = data["scratchDeprecated"]

# Set email authentication key
data = meower.db["config"].find_one({"_id": "auth_keys"})
if data is None:
	meower.log("Failed getting authentication keys. Some functions will be disabled.")
	meower.auth_keys = None
else:
	del data["_id"]
	meower.auth_keys = data

# Run Flask app
meower.run(host="0.0.0.0", port=3000, debug=True)