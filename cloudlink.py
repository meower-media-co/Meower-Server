import websockets
import asyncio
import json
from typing import Any, Callable, Dict, Optional, Iterable, TypedDict, Union
from inspect import getfullargspec

from utils import full_stack

VERSION = "0.1.7.7"

class CloudlinkPacket(TypedDict, total=False):
    cmd: str
    val: Any
    id: Optional[str]
    name: Optional[str]
    origin: Optional[str]
    listener: Optional[str]

class CloudlinkServer:
    def __init__(self):
        self.real_ip_header: Optional[str] = None
        self.pseudo_trusted_access: bool = False
        self.motd: Optional[str] = None
        self.statuscodes: dict[str, str] = {}
        self.callbacks: dict[str, list[Callable]] = {}  # {"callback_name": [function1, function2, ...]}
        self.commands: dict[str, Callable] = {}  # {"command_name": function1(client: CloudlinkClient, val: any)}
        self.websockets: set[websockets.WebSocketServerProtocol] = set()
        self.clients: set[CloudlinkClient] = set()
        self.usernames: dict[str, list[CloudlinkClient]] = {}  # {"username": [cl_client1, cl_client2, ...]}
        self.gmsg: str = ""

        # Set default statuscodes
        self.statuscodes.update({
            #"Test": "I:000 | Test", -- unused
            "OK": "I:100 | OK",
            "Syntax": "E:101 | Syntax",
            "Datatype": "E:102 | Datatype",
            "IDNotFound": "E:103 | ID not found",
            "InternalServerError": "E:104 | Internal",
            #"Loop": "E:105 | Loop detected",  -- deprecated
            "RateLimit": "E:106 | Too many requests",
            "TooLarge": "E:107 | Packet too large",
            #"BrokenPipe": "E:108 | Broken pipe",  -- deprecated
            #"EmptyPacket": "E:109 | Empty packet",  -- unused
            "IDConflict": "E:110 | ID conflict",
            "IDSet": "E:111 | ID already set",
            "TAEnabled": "I:112 | Trusted Access enabled",
            #"TAInvalid": "E:113 | TA Key invalid",  -- deprecated
            #"TAExpired": "E:114 | TA Key expired",  -- deprecated
            "Refused": "E:115 | Refused",
            "IDRequired": "E:116 | Username required",
            #"TALostTrust": "E:117 | Trust lost",  -- deprecated
            "Invalid": "E:118 | Invalid command",
            "Blocked": "E:119 | IP Blocked",
            #"IPRequred": "E:120 | IP Address required",  -- deprecated
            #"TooManyUserNameChanges": "E:121 | Too Many Username Changes",  -- deprecated
            "Disabled": "E:122 | Command disabled by sysadmin",
        })

        # Initialise default commands
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

        # Send motd
        if self.motd:
            await cl_client.send({"cmd": "motd", "val": self.motd}, direct_wrap=True)

        # Send version
        await cl_client.send({"cmd": "vers", "val": VERSION}, direct_wrap=True)

        # Send ulist
        await cl_client.send({"cmd": "ulist", "val": self.get_ulist()})

        # Send current gmsg
        await cl_client.send({"cmd": "gmsg", "val": self.gmsg})

        # Send Trusted Access statuscode if Pseudo Trusted Access is enabled
        if self.pseudo_trusted_access:
            await cl_client.send_statuscode("TAEnabled")

        # Process incoming packets until WebSocket closes
        try:
            async for data in websocket:
                # Parse packet
                try:
                    packet: CloudlinkPacket = json.loads(data)
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

                # Pseudo Trusted Access
                if self.pseudo_trusted_access and not cl_client.trusted:
                    if packet["cmd"] in ["direct", "gmsg"]:
                        if isinstance(packet["val"], str):
                            cl_client.trusted = True
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
                    # Extra args mainly used for pmsg, gvar, and pvar
                    extra_args = {}
                    if "id" in getfullargspec(cmd_func).args:
                        extra_args["id"] = packet.get("id")
                    if "name" in getfullargspec(cmd_func).args:
                        extra_args["name"] = packet.get("name")
                    
                    await cmd_func(cl_client, packet["val"], packet.get("listener"), **extra_args)
                except Exception as e:
                    print(full_stack())
                    await cl_client.send_statuscode("InternalServerError", packet.get("listener"))
        except: pass
        finally:
            self.websockets.remove(websocket)
            self.clients.remove(cl_client)
            cl_client.remove_username()

            for callback in self.callbacks.get("on_close", []):
                await callback(cl_client)

    def set_real_ip_header(self, real_ip_header: Optional[str] = None):
        self.real_ip_header = real_ip_header

    def set_pseudo_trusted_access(self, enabled: bool = False):
        self.pseudo_trusted_access = enabled

    def set_motd(self, motd: Optional[str] = None):
        self.motd = motd

    def add_statuscode(self, statuscode_name: str, statuscode_details: str):
        self.statuscodes[statuscode_name] = statuscode_details

    def remove_statuscode(self, statuscode_name: str):
        if statuscode_name in self.statuscodes:
            del self.statuscodes[statuscode_name]

    def add_callback(self, event_name: str, event_callback):
        if event_name in self.callbacks:
            self.callbacks[event_name].append(event_callback)
        else:
            self.callbacks[event_name] = [event_callback]

    def remove_callback(self, event_name: str, event_callback):
        if event_callback in self.callbacks.get(event_name, []):
            self.callbacks[event_name].remove(event_callback)
            if len(self.callbacks[event_name]) == 0:
                del self.callbacks[event_name]

    def add_command(self, command_name: str, command_func):
        self.commands[command_name] = command_func
    
    def remove_command(self, command_name: str):
        if command_name in self.commands:
            del self.commands[command_name]

    def broadcast(
        self,
        packet: Union[CloudlinkPacket, Dict[str, any]],
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
                    type_fix = self.usernames
                    _clients += type_fix.get(username, [])

        websockets.broadcast({client.websocket for client in _clients}, json.dumps(packet))

    def get_ulist(self):
        ulist = ";".join(self.usernames.keys())
        if ulist:
            ulist += ";"
        return ulist

    def send_ulist(self):
        return self.broadcast({"cmd": "ulist", "val": self.get_ulist()})

    # noinspection PyAttributeOutsideInit
    async def run(self, host: str = "0.0.0.0", port: int = 3000):
        self.stop = asyncio.Future()
        self.server = await websockets.serve(self.client_handler, host, port)
        await self.stop
        self.server.close()

class CloudlinkClient:
    def __init__(
        self,
        server: CloudlinkServer,
        websocket: websockets.WebSocketServerProtocol
    ):
        # Set server and client objs
        self.server = server
        self.websocket = websocket

        # Set username, IP, and trusted status
        self.username: Optional[str] = None
        self.ip: str = self.get_ip()
        self.trusted: bool = False

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

    async def send(self, packet: Union[CloudlinkPacket, Dict[str, any]], direct_wrap: bool = False, listener: Optional[str] = None):
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
        self.cl.add_command("get_ulist", self.get_ulist)
        self.cl.add_command("setid", self.setid)
        self.cl.add_command("gmsg", self.gmsg)
        self.cl.add_command("pmsg", self.pmsg)
        self.cl.add_command("gvar", self.gvar)
        self.cl.add_command("pvar", self.pvar)

    async def ping(self, client: CloudlinkClient, val, listener: str = None):
        await client.send_statuscode("OK", listener)
    
    async def get_ulist(self, client: CloudlinkClient, val, listener: str = None):
        await client.send({"cmd": "ulist", "val": self.cl.get_ulist()}, listener)

    async def setid(self, client: CloudlinkClient, val, listener: str = None):
        if client.username:
            await client.send_statuscode("IDSet", listener)
            return
        if val in self.cl.usernames:
            await client.send_statuscode("IDConflict", listener)
            return
        
        client.set_username(val)
        await client.send_statuscode("OK", listener)

    async def gmsg(self, client: CloudlinkClient, val, listener: str = None):
        if not client.username:
            await client.send_statuscode("IDRequired", listener)
            return

        self.cl.gmsg = val
        packet: CloudlinkPacket = {
            "cmd": "gmsg",
            "val": val,
            "origin": client.username
        }
        self.cl.broadcast(packet)
        await client.send_statuscode("OK", listener)

    async def pmsg(self, client: CloudlinkClient, val, listener: str = None, id: str = None):
        if not client.username:
            await client.send_statuscode("IDRequired", listener)
            return
        if id not in self.cl.usernames:
            await client.send_statuscode("IDNotFound", listener)
            return
        
        packet: CloudlinkPacket = {
            "cmd": "pmsg",
            "val": val,
            "origin": client.username
        }
        self.cl.broadcast(packet, usernames=[id])
        await client.send_statuscode("OK", listener)

    async def gvar(self, client: CloudlinkClient, val, listener: str = None, name: str = None):
        if not client.username:
            await client.send_statuscode("IDRequired", listener)
            return
        
        packet: CloudlinkPacket = {
            "cmd": "gvar",
            "val": val,
            "name": name,
            "origin": client.username
        }
        self.cl.broadcast(packet)
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
