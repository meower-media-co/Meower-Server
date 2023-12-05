from datetime import datetime
from better_profanity import profanity
from threading import Thread
from copy import copy
from radix import Radix
import uuid
import time
import traceback
import sys

"""

Meower Supporter Module

This module provides logging, error traceback, and other miscellaneous supportive functionality.
This keeps the main.py clean and more understandable.

"""


class Supporter:
    def __init__(self, cl=None, packet_callback=None):
        self.blocked_ips = Radix()
        self.registration_blocked_ips = Radix()
        self.filter = None
        self.repair_mode = True
        self.registration = False
        self.ratelimits = {}
        self.cl = cl
        self.profanity = profanity
        self.packet_handler = packet_callback

        self.files = None

        if self.cl:
            # Add custom status codes to CloudLink
            self.cl.codes["KeyNotFound"] = "I:010 | Key Not Found"
            self.cl.codes["PasswordInvalid"] = "I:011 | Invalid Password"
            self.cl.codes["GettingReady"] = "I:012 | Getting ready"
            self.cl.codes[
                "ObsoleteClient"
            ] = "I:013 | Client is out-of-date or unsupported"
            self.cl.codes["Pong"] = "I:014 | Pong"
            self.cl.codes["IDExists"] = "I:015 | Account exists"
            self.cl.codes["2FAOnly"] = "I:016 | 2FA Required"
            self.cl.codes["MissingPermissions"] = "I:017 | Missing permissions"
            self.cl.codes["Banned"] = "E:018 | Account Banned"
            self.cl.codes["IllegalChars"] = "E:019 | Illegal characters detected"
            self.cl.codes["Kicked"] = "E:020 | Kicked"
            self.cl.codes["ChatExists"] = "E:021 | Chat exists"
            self.cl.codes["ChatNotFound"] = "E:022 | Chat not found"
            self.cl.codes["ChatFull"] = "E:023 | Chat full"
            self.cl.codes["LoggedOut"] = "I:024 | Logged out"
            self.cl.codes["Deleted"] = "E:025 | Deleted"

        if self.cl:
            # Specify server callbacks
            self.cl.callback("on_packet", self.on_packet)
            self.cl.callback("on_close", self.on_close)
            self.cl.callback("on_connect", self.on_connect)

        self.log("Supporter initialized!")

    def full_stack(self):
        exc = sys.exc_info()[0]
        if exc is not None:
            f = sys.exc_info()[-1].tb_frame.f_back
            stack = traceback.extract_stack(f)
        else:
            stack = traceback.extract_stack()[:-1]
        trc = "Traceback (most recent call last):\n"
        stackstr = trc + "".join(traceback.format_list(stack))
        if exc is not None:
            stackstr += "  " + traceback.format_exc().lstrip(trc)
        return stackstr

    def log(self, event):
        print("{0}: {1}".format(self.timestamp(4), event))

    def sendPacket(self, payload, listener_detected=False, listener_id=None):
        if self.cl:
            if listener_detected and "id" in payload:
                payload["listener"] = listener_id
            self.cl.sendPacket(payload)

    def get_client_statedata(
        self, client
    ):  # "steals" information from the CloudLink module to get better client data
        if not self.cl:
            return []

        if isinstance(client, str):
            tmp = client
            client = []
            for session in self.cl._get_obj_of_username(tmp):
                client.append(session["id"])
        elif isinstance(client, dict):
            client = [client["id"]]
        elif isinstance(client, int):
            client = [client]
        else:
            raise Exception("client is not a supported datatype")

        statedata = []
        for session in client:
            if session in self.cl.statedata["ulist"]["objs"]:
                statedata.append(self.cl.statedata["ulist"]["objs"][session])
        return statedata

    def modify_client_statedata(
        self, client, key, newvalue
    ):  # WARN: Use with caution: DO NOT DELETE UNNECESSARY KEYS!
        if not self.cl:
            return False

        if isinstance(client, str):
            tmp = client
            client = []
            for session in self.cl._get_obj_of_username(tmp):
                client.append(session["id"])
        elif isinstance(client, dict):
            client = [client["id"]]
        elif isinstance(client, int):
            client = [client]
        else:
            raise Exception("client is not a supported datatype")

        for session in client:
            if session in self.cl.statedata["ulist"]["objs"]:
                self.cl.statedata["ulist"]["objs"][session][key] = newvalue
        return True

    def delete_client_statedata(
        self, client, key
    ):  # WARN: Use with caution: DO NOT DELETE UNNECESSARY KEYS!
        if self.cl:
            if isinstance(client, str):
                client = self.cl._get_obj_of_username(client)
            if not client == None:
                if client["id"] in self.cl.statedata["ulist"]["objs"]:
                    if key in self.cl.statedata["ulist"]["objs"][client["id"]]:
                        try:
                            del self.cl.statedata["ulist"]["objs"][client["id"]][key]
                            return True
                        except:
                            self.log("{0}".format(self.full_stack()))
                            return False
                else:
                    return False

    def on_close(self, client):
        if self.cl:
            if self.cl._get_username_of_obj(client):
                if self.files:
                    self.files.db.usersv0.update_one(
                        {
                            "_id": self.cl._get_username_of_obj(client),
                            "last_seen": {"$ne": None},
                        },
                        {"$set": {"last_seen": int(time.time())}},
                    )
                self.log("{0} Logged out.".format(self.cl._get_username_of_obj(client)))

    def on_connect(self, client):
        if self.cl:
            if self.repair_mode:
                self.log(
                    "Refusing connection from {0} due to repair mode being enabled".format(
                        client["id"]
                    )
                )
                self.cl.kickClient(client)
            elif self.blocked_ips.search_best(self.cl.getIPofObject(client)):
                self.log(
                    "Refusing connection for {0} due to their IP being blocked".format(
                        client["id"]
                    )
                )
                self.cl.kickClient(client)
            else:
                self.log("{0} Connected.".format(client["id"]))
                self.modify_client_statedata(client, "authtype", "")
                self.modify_client_statedata(client, "authed", False)

    def on_packet(self, message):
        if self.cl:
            # CL Turbo Support
            listener_detected = "listener" in message
            listener_id = message.get("listener")

            # Read packet contents
            id = message["id"]
            val = message["val"]
            clienttype = None
            client = id
            if isinstance(id, dict):
                ip = self.cl.getIPofObject(client)
                clienttype = 0
            elif isinstance(id, str):
                ip = self.cl.getIPofUsername(client)
                clienttype = 1

            # Handle packet
            cmd = None
            if "cmd" in message:
                cmd = message["cmd"]

            if not self.packet_handler == None:
                self.packet_handler(
                    cmd, ip, val, listener_detected, listener_id, client, clienttype
                )

    def timestamp(self, ttype):
        today = datetime.now()
        if ttype == 1:
            return {
                "mo": (datetime.now()).strftime("%m"),
                "d": (datetime.now()).strftime("%d"),
                "y": (datetime.now()).strftime("%Y"),
                "h": (datetime.now()).strftime("%H"),
                "mi": (datetime.now()).strftime("%M"),
                "s": (datetime.now()).strftime("%S"),
                "e": (int(time.time())),
            }
        elif ttype == 2:
            return str(today.strftime("%H%M%S"))
        elif ttype == 3:
            return str(today.strftime("%d%m%Y%H%M%S"))
        elif ttype == 4:
            return today.strftime("%m/%d/%Y %H:%M.%S")
        elif ttype == 5:
            return today.strftime("%d%m%Y")

    def wordfilter(self, message):
        # Word censor
        if self.filter:
            self.profanity.load_censor_words(whitelist_words=self.filter["whitelist"])
            message = self.profanity.censor(message)
            self.profanity.load_censor_words(
                whitelist_words=self.filter["whitelist"],
                custom_words=self.filter["blacklist"],
            )
            message = self.profanity.censor(message)
        else:
            self.log(
                "Failed loading profanity filter! Using default filter as fallback."
            )
            self.profanity.load_censor_words()
            message = self.profanity.censor(message)
        return message

    def isAuthenticated(self, client):
        if not self.cl:
            return None

        tmp = self.get_client_statedata(client)

        if len(tmp) > 1:
            # this will only occur if there are multiple valid sessions
            return True

        # this will occur if there is only one session present
        return tmp[0]["authed"]

    def setAuthenticatedState(self, client, value):
        if self.cl:
            self.modify_client_statedata(client, "authed", value)

    def autoID(self, client, username):
        if self.cl:
            # really janky code that automatically sets user ID
            self.modify_client_statedata(client, "username", username)

            # multisession
            if not username in self.cl.statedata["ulist"]["usernames"]:
                self.cl.statedata["ulist"]["usernames"][username] = []
            self.cl.statedata["ulist"]["usernames"][username].append(client["id"])

            self.sendPacket({"cmd": "ulist", "val": self.cl._get_ulist()})
            self.log("{0} autoID given".format(username))

    def kickUser(self, username, status="Kicked"):
        if self.cl:
            if username in self.cl.getUsernames():
                self.log("Kicking {0}".format(username))

                # Unauthenticate client
                sessions = copy(self.cl.statedata["ulist"]["usernames"][username])
                self.log("{0}'s sessions: {1}".format(username, sessions))

                # Process multi session
                for session in sessions:
                    self.log("Closing {0}'s session: {1}".format(username, session))

                    # Grab object
                    client = self.cl.statedata["ulist"]["objs"][session]["object"]

                    # Thread final closing
                    def run(client):
                        # Tell client it's going to get kicked
                        try:
                            self.sendPacket(
                                {
                                    "cmd": "direct",
                                    "val": self.cl.codes[status],
                                    "id": client,
                                }
                            )
                            time.sleep(1)
                            client["handler"].send_close(
                                1000, bytes("", encoding="utf-8")
                            )
                        except Exception as e:
                            self.log(
                                "Client {0} Broken pipe error: {1}".format(
                                    client["id"], e
                                )
                            )
                            self.cl._closed_connection_server(client, self.cl)

                    Thread(target=run, args=(client,)).start()

            # Update userlists
            self.sendPacket({"cmd": "ulist", "val": self.cl._get_ulist()})

    def ratelimited(self, bucket_id):
        if bucket_id not in self.ratelimits:
            return False

        remaining, expires = self.ratelimits.get(bucket_id, [0, 0])
        if remaining > 0 or expires < time.time():
            return False
        else:
            return True

    def ratelimit(self, bucket_id, limit, seconds):
        remaining, expires = self.ratelimits.get(bucket_id, [0, 0])

        if expires < time.time():
            remaining = limit
            expires = time.time() + seconds

        remaining -= 1
        self.ratelimits[bucket_id] = [remaining, expires]

    def clear_ratelimit(self, bucket_id):
        if bucket_id in self.ratelimits:
            del self.ratelimits[bucket_id]

    def createPost(
        self, post_origin, user, content, chat_members=None
    ):  # TODO: needs checking
        # Create post ID and get timestamp
        post_id = str(uuid.uuid4())
        timestamp = self.timestamp(1).copy()

        # Construct post object
        post = {
            "_id": post_id,
            "type": 2 if post_origin == "inbox" else 1,
            "post_origin": post_origin,
            "u": user,
            "t": timestamp,
            "p": content,
            "post_id": post_id,
            "isDeleted": False,
        }

        # Profanity filter
        filtered_content = self.wordfilter(content)
        if filtered_content != content:
            post["p"] = filtered_content
            post["unfiltered_p"] = content

        # Add database item and send live packet
        if post_origin == "home":
            self.files.db.posts.insert_one(post)
            self.sendPacket({"cmd": "direct", "val": {"mode": 1, **post}})
            return True, post
        elif post_origin == "inbox":
            self.files.db.posts.insert_one(post)
            if user == "Server":
                self.files.db.user_settings.update_many(
                    {}, {"$set": {"unread_inbox": True}}
                )
                self.sendPacket(
                    {"cmd": "direct", "val": {"mode": "inbox_message", "payload": post}}
                )
            else:
                self.files.db.user_settings.update_one(
                    {"_id": user}, {"$set": {"unread_inbox": True}}
                )
                self.sendPacket(
                    {
                        "cmd": "direct",
                        "val": {"mode": "inbox_message", "payload": post},
                        "id": user,
                    }
                )
            return True, post
        elif post_origin == "livechat":
            self.sendPacket({"cmd": "direct", "val": {"state": 2, **post}})
            return True, post
        else:
            self.files.db.posts.insert_one(post)
            self.files.db.chats.update_one(
                {"_id": post_origin}, {"$set": {"last_active": int(time.time())}}
            )
            self.sendPacket(
                {"cmd": "direct", "val": {"state": 2, **post}, "id": chat_members}
            )
            return True, post
