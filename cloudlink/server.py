from asyncio import Future
from cloudlink.client import CloudlinkClient
from cloudlink.packets import handle_packets
from json import dumps
from os import getenv
from typing import Optional, Iterable, Any
from websockets import WebSocketServerProtocol, broadcast, serve

class CloudlinkServer:
    def __init__(self):
        self.real_ip_header = getenv("REAL_IP_HEADER")
        self.clients: set[CloudlinkClient] = set()
        self.usernames: dict[str, list[CloudlinkClient]] = {}
    
    def get_ulist(self):
        ulist = ";".join(self.usernames.keys())
        if ulist:
            ulist += ";"
        return ulist

    async def client_handler(self, websocket: WebSocketServerProtocol):
        # Create CloudlinkClient
        client = CloudlinkClient(self, websocket)

        # Add to sets
        self.clients.add(client)

        # Send ulist
        client.send("ulist", self.get_ulist())

        # Minimal TA implementation
        if client.proto_version == 0:
            client.send_statuscode("TAEnabled")
            client.send_statuscode("OK")

        # Process incoming packets
        try:
            await handle_packets(client)
        except: pass
        finally:
            self.clients.remove(client)
            client.logout()

    def send_event(
        self,
        cmd: str,
        val: Any,
        extra: Optional[dict] = None,
        clients: Optional[Iterable] = None,
        usernames: Optional[Iterable] = None
    ):
        if extra is None:
            extra = {}

        # Get clients
        if clients is None and usernames is None:
            clients = self.clients
        else:
            clients = [] if clients is None else clients
            if usernames is not None:
                for username in usernames:
                    clients += self.usernames.get(username, [])

        # Parse post
        if cmd == "post" or cmd == "update_post":
            val = self.supporter.parse_posts_v0([val])[0]

        # Send v1 packet
        broadcast({
            client.websocket for client in clients
            if client.proto_version == 1
        }, dumps({"cmd": cmd, "val": val, **extra}))

        # Send v0 packet
        if cmd in ["statuscode", "ulist"]:  # root commands
            val = {"cmd": cmd, "val": val, **extra}
        else:
            if cmd == "post":
                if val.get("post_origin") == "home":
                    val = {"mode": 1, **val}
                else:
                    val = {"state": 2, **val}
            elif cmd == "typing":
                if val.get("chat_id") == "home":
                    val = {"state": 101, "chatid": "livechat", "u": val.get("username")}
                else:
                    val = {"state": 100, "chatid": val.get("chat_id"), "u": val.get("username")}
            elif cmd == "delete_chat":
                val = {"mode": "delete", "id": val.get("chat_id")}
            elif cmd == "delete_post":
                val = {"mode": "delete", "id": val.get("post_id")}
            else:
                val = {"mode": cmd, "payload": val}
            val = {"cmd": "direct", "val": val, **extra}
        broadcast({
            client.websocket for client in clients
            if client.proto_version == 0
        }, dumps(val))

    async def run(self, host: str = "0.0.0.0", port: int = 3000):
        self.stop = Future()
        self.server = await serve(self.client_handler, host, port)
        await self.stop
        await self.server.close()
