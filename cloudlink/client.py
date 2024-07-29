from cloudlink.types import api_error_statuscode_map, statuscodes
from os import environ
from typing import Literal, TYPE_CHECKING
from urllib.parse import parse_qs, urlparse
from websockets import WebSocketServerProtocol
import requests

if TYPE_CHECKING:
	from cloudlink.server import CloudlinkServer

class CloudlinkClient:
	def __init__(
		self,
		server: 'CloudlinkServer',
		websocket: WebSocketServerProtocol
	):		
		# Setup client
		self.server = server
		self.websocket = websocket
		self.username: str | None = None

		# Parse query params
		query_params = parse_qs(urlparse(self.websocket.path).query)

		try:
			self.proto_version: int = int(query_params.get("v")[0])
		except:
			self.proto_version: int = 0
		
		# Handle client ip
		if "REAL_IP_HEADER" in environ and environ["REAL_IP_HEADER"] in self.websocket.request_headers:
			self.ip: str = self.websocket.request_headers[environ["REAL_IP_HEADER"]]
		elif type(self.websocket.remote_address) == tuple:
			self.ip: str = self.websocket.remote_address[0]
		else:
			self.ip: str = self.websocket.remote_address

		# Automatic login
		if "token" in query_params:
			token = query_params.get("token")[0]
			self.login(token)


	def login(self, token: str, listener: str | None = None):
		# fetch the api account (checks if banned as well)
		account = self.proxy_api_request("/me", "get", headers={"token": token})

		if account:	
			self.username = account.get('lower_username')

			if not self.username in self.server.usernames:
				self.server.usernames[self.username] = []
				self.server.send_event("ulist", self.server.get_ulist())
			
			self.server.usernames[self.username].append(self)

			# Send auth payload
			self.send("auth", {
				"username": self.username,
				"token": token,
				"account": account,
				"relationships": self.proxy_api_request("/me/relationships", "get")["autoget"],
				**({
					"chats": self.proxy_api_request("/chats", "get")["autoget"]
				} if self.proto_version != 0 else {})
			}, listener=listener)


	def logout(self):
		if not self.username:
			return

		# Trigger last_seen update
		self.proxy_api_request("/me", "get")

		# Handle ulist
		self.server.usernames[self.username].remove(self)

		if len(self.server.usernames[self.username]) == 0:
			del self.server.usernames[self.username]
			self.server.send_event('ulist', self.server.get_ulist())
		
		# Reset client
		self.username = None


	def send(self, cmd: str, val: any, extra: dict | None = None, listener: str | None = None):
		if extra is None:
			extra = {}
		if listener:
			extra["listener"] = listener
		return self.server.send_event(cmd, val, extra=extra, clients=[self])


	def send_statuscode(self, statuscode: str, listener: str | None = None):
		return self.send("statuscode", statuscodes[statuscode], listener=listener)


	def proxy_api_request(self, endpoint: str, method: Literal["get", "post", "patch", "delete"], headers: dict[str, str] = {}, json: dict[str, any] | None = None, listener: str | None = None):
		# Set headers
		headers.update({
			"X-Internal-Token": environ.get("INTERNAL_TOKEN"),
			"X-Internal-Ip": self.ip,
		})

		if self.username:
			headers["X-Internal-Username"] = self.username

		resp = getattr(requests, method)(
			f"{environ.get('API_INTERNAL_URL')}{endpoint}",
			headers=headers,
			json=json
		).json()

		if not resp.get('error'):
			return resp
		else:
			if resp["type"] == 'repairModeEnabled':
				self.kick()
			elif resp["type"] in api_error_statuscode_map:
				self.send_statuscode(api_error_statuscode_map[resp["type"]], listener)
			else:
				self.send_statuscode("InternalServerError", listener)
