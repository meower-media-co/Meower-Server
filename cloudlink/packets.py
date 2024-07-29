from cloudlink.client import CloudlinkClient
from json import loads
from typing import Optional, TypedDict

class CloudlinkPacket(TypedDict):
    cmd: str
    val: any
    listener: Optional[str]

async def handle_packets(cl_client: CloudlinkClient):
	async for packet in cl_client.websocket:
		# Parse packet
		try:
			packet: CloudlinkPacket = loads(packet)
			if not isinstance(packet, dict):
				cl_client.send_statuscode("Syntax")
				continue
			if "cmd" not in packet or "val" not in packet:
				cl_client.send_statuscode("Syntax")
				continue
		except:
			cl_client.send_statuscode("Syntax")
			continue

		if packet["cmd"] == "ping":
			cl_client.send_statuscode("OK", packet.get("listener"))
			continue

		if packet["cmd"] == "authpswd":
			# Make sure the client isn't already authenticated
			if cl_client.username:
				return cl_client.send_statuscode("OK", packet.get("listener"))
			
			# Check val datatype
			if not isinstance(packet.get('val'), dict):
				return cl_client.send_statuscode("Datatype", packet.get("listener"))
			
			# Check val values
			if not packet.get("val").get("username") or not packet.get("val").get("pswd"):
				return cl_client.send_statuscode("Syntax", packet.get("listener"))
			
			cl_client.login(packet.get("val").get("pswd"), packet.get("listener"))
			continue

		cl_client.send_statuscode("Invalid", packet.get("listener"))
