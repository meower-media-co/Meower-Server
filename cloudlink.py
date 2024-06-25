import websockets
import asyncio
import json
from typing import Optional, Iterable, TypedDict
from inspect import getfullargspec
from os import getenv

class CloudlinkPacket(TypedDict):
    cmd: str
    val: any
    id: Optional[str]
    name: Optional[str]
    origin: Optional[str]
    listener: Optional[str]

class CloudlinkServer:
    def __init__(self):
        self.real_ip_header: Optional[str] = getenv("REAL_IP_HEADER")
        self.statuscodes: dict[str, str] = {
            "PasswordInvalid": "I:011 | Invalid Password",
            "Banned": "E:018 | Account Banned",
            "Kicked": "E:020 | Kicked",
            "LoggedOut": "I:024 | Logged out",
            "Deleted": "E:025 | Deleted",
            "OK": "I:100 | OK",
            "Syntax": "E:101 | Syntax",
            "Datatype": "E:102 | Datatype",
            "IDNotFound": "E:103 | ID not found",
            "InternalServerError": "E:104 | Internal",
            "RateLimit": "E:106 | Too many requests",
            "TAEnabled": "I:112 | Trusted Access enabled",
            "IDRequired": "E:116 | Username required",
            "Invalid": "E:118 | Invalid command",
            "Blocked": "E:119 | IP Blocked",
        }
        self.callbacks: dict[str, list[function]] = {}  # {"callback_name": [function1, function2, ...]}
        self.commands: dict[str, function] = {}  # {"command_name": function1(client: CloudlinkClient, val: any)}
        self.websockets: set[websockets.WebSocketServerProtocol] = set()
        self.clients: set[CloudlinkClient] = set()
        self.usernames: dict[str, list[CloudlinkClient]] = {}  # {"username": [cl_client1, cl_client2, ...]}
        CloudlinkCommands(self)
    
    async def client_handler(self, websocket: websockets.WebSocketServerProtocol):
        
        # Create CloudlinkClient
        cl_client = CloudlinkClient(self, websocket)

        # Add to websockets and clients sets
        self.websockets.add(websocket)
        self.clients.add(cl_client)

        # Run callbacks
        for callback in self.callbacks.get("on_open", []):
            await callback(cl_client)

        # Send ulist
        await cl_client.send({"cmd": "ulist", "val": self.get_ulist()})

        await cl_client.send_statuscode("TAEnabled")

        # Process incoming packets until WebSocket closes
        try:
            async for packet in websocket:
                # Parse packet
                try:
                    packet: CloudlinkPacket = json.loads(packet)
                except:
                    await cl_client.send_statuscode("Syntax")
                    continue
                else:
                    if not isinstance(packet, dict):
                        await cl_client.send_statuscode("Syntax")
                        continue

                # Make sure the packet includes `cmd` and `val`
                if "cmd" not in packet or "val" not in packet:
                    await cl_client.send_statuscode("Syntax", packet.get("listener"))
                    continue

                # Pseudo Pseudo Trusted Access
                if packet["cmd"] in ["direct", "gmsg"]:
                    if isinstance(packet["val"], str):
                        await cl_client.send_statuscode("OK", packet.get("listener"))
                        continue
                # Unwrap "direct" cmd
                if packet["cmd"] == "direct" and isinstance(packet["val"], dict):
                    packet["cmd"] = packet["val"].get("cmd")
                    if not packet["cmd"]:
                        await cl_client.send_statuscode("Syntax", packet.get("listener"))
                        continue
                    elif packet["cmd"] == "type":
                        continue

                    packet["val"] = packet["val"].get("val")
                    if packet["val"] is None:
                        await cl_client.send_statuscode("Syntax", packet.get("listener"))
                        continue

                # Get command function
                cmd_func = self.commands.get(packet["cmd"])
                if not cmd_func:
                    await cl_client.send_statuscode("Invalid", packet.get("listener"))
                    continue

                # Execute command
                try:
                    # Extra args mainly used for pvar
                    extra_args = {}
                    if "id" in getfullargspec(cmd_func).args:
                        extra_args["id"] = packet.get("id")
                    if "name" in getfullargspec(cmd_func).args:
                        extra_args["name"] = packet.get("name")
                    
                    await cmd_func(cl_client, packet["val"], packet.get("listener"), **extra_args)
                except Exception as e:
                    print(e)
                    await cl_client.send_statuscode("InternalServerError", packet.get("listener"))
        except: pass
        finally:
            self.websockets.remove(websocket)
            self.clients.remove(cl_client)
            cl_client.remove_username()

            for callback in self.callbacks.get("on_close", []):
                await callback(cl_client)

    def add_callback(self, event_name: str, event_callback):
        if event_name in self.callbacks:
            self.callbacks[event_name].append(event_callback)
        else:
            self.callbacks[event_name] = [event_callback]

    def add_command(self, command_name: str, command_func):
        self.commands[command_name] = command_func
    
    def broadcast(
        self,
        packet: CloudlinkPacket,
        direct_wrap: bool = False,
        clients: Optional[Iterable] = None,
        usernames: Optional[Iterable] = None
    ):
        if direct_wrap:
            packet = {"cmd": "direct", "val": packet.copy()}

        if clients is None and usernames is None:
            _clients = self.clients
        else:
            _clients = []
            if clients is not None:
                _clients += clients
            if usernames is not None:
                for username in usernames:
                    _clients += self.usernames.get(username, [])

        websockets.broadcast({client.websocket for client in _clients}, json.dumps(packet))

    def get_ulist(self):
        ulist = ";".join(self.usernames.keys())
        if ulist:
            ulist += ";"
        return ulist

    def send_ulist(self):
        return self.broadcast({"cmd": "ulist", "val": self.get_ulist()})

    async def run(self, host: str = "0.0.0.0", port: int = 3000):
        self.stop = asyncio.Future()
        self.server = await websockets.serve(self.client_handler, host, port)
        await self.stop
        await self.server.close()

class CloudlinkClient:
    def __init__(
        self,
        server: CloudlinkServer,
        websocket: websockets.WebSocketServerProtocol
    ):
        # Set server and client objs
        self.server = server
        self.websocket = websocket

        # Set username and IP
        self.username: Optional[str] = None
        self.ip: str = self.get_ip()

    def get_ip(self):
        if self.server.real_ip_header and self.server.real_ip_header in self.websocket.request_headers:
            return self.websocket.request_headers[self.server.real_ip_header]
        elif type(self.websocket.remote_address) == tuple:
            return self.websocket.remote_address[0]
        else:
            return self.websocket.remote_address
            
    def set_username(self, username: str):
        if self.username:
            self.remove_username()

        self.username = username
        if self.username in self.server.usernames:
            self.server.usernames[username].append(self)
        else:
            self.server.usernames[username] = [self]

        self.server.send_ulist()

    def remove_username(self):
        if not self.username:
            return
        
        self.server.usernames[self.username].remove(self)
        if len(self.server.usernames[self.username]) == 0:
            del self.server.usernames[self.username]
        self.username = None

        self.server.send_ulist()

    async def send(self, packet: CloudlinkPacket, direct_wrap: bool = False, listener: Optional[str] = None):
        if direct_wrap:
            packet = {"cmd": "direct", "val": packet.copy()}
        if listener:
            packet["listener"] = listener
        await self.websocket.send(json.dumps(packet))

    async def send_statuscode(self, statuscode: str, listener: Optional[str] = None):
        return await self.send({
            "cmd": "statuscode",
            "val": self.server.statuscodes[statuscode]
        }, listener=listener)

    def kick(self, statuscode: str = None):
        async def _kick():
            if statuscode:
                await self.send({"cmd": "direct", "val": self.server.statuscodes[statuscode]})
                await asyncio.sleep(1)
            await self.websocket.close()
        asyncio.create_task(_kick())

class CloudlinkCommands:
    def __init__(self, cl: CloudlinkServer):
        self.cl = cl

        self.cl.add_command("ping", self.ping)
        self.cl.add_command("pvar", self.pvar)

    async def ping(self, client: CloudlinkClient, val, listener: str = None):
        await client.send_statuscode("OK", listener)
    
    async def pvar(self, client: CloudlinkClient, val, listener: str = None, id: str = None, name: str = None):
        if not client.username:
            await client.send_statuscode("IDRequired", listener)
            return
        if id not in self.cl.usernames:
            await client.send_statuscode("IDNotFound", listener)
            return
        
        packet: CloudlinkPacket = {
            "cmd": "pvar",
            "val": val,
            "name": name,
            "origin": client.username
        }
        self.cl.broadcast(packet, usernames=[id])
        await client.send_statuscode("OK", listener)
