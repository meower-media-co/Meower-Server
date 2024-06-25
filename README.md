# Meower-Server
Official source code of the Meower server, written in Python. Powered by CloudLink. 

## NOTICE
This is the APIv0 Branch of Code! This API code will only be maintained up until when New Meower is released.

APIv0 will be upgraded automatically to APIv1 when Beta 6 is released. The API can be found at http://localhost:3001/

## Installing Dependencies
* Run `pip3 install -r requirements.txt` in the downloaded and unzipped directory

## Running the server

```py
git clone https://github.com/meower-media-co/Meower-Server.git --recursive
cd Meower-Server
python3 main.py
```

To connect to the server, change the IP settings of your client to connect to ws://127.0.0.1:3000/.

### Rest API

This Rest API is configured to use CF Argo Tunnels for getting client IPs, but otherwise everything will function.

Currently supported functions of the API:

* /home - Gets the current homepage index.
* /home?page=# - Lets you get a certain page # of the homepage.
* /home?autoget - Automatically fetches all posts currently present on the page.
* /ip - Gets the client's IP address and returns with plaintext. Only works if the server is communicating with a client over CF Argo Tunnels.
* /posts?id=(Post ID) - Gets a Post ID, use /home to get an index of posts.
* /status - Status for the Meower Server.
* /posts/(Chat ID) - Gets the specified chat ID's index.
* /reports - Gets the reports index (only accessable if a moderator or higher.
* /inbox - Gets the specified user's inbox.
* /search/home?q=(Query) - Searches home.
* /search/users?q=(Query) - Searches users.
* /users/(Username) - Gets the specified user's info.
* /users/(Username)/posts - Gets the specified user's posts.
* /statistics - Shows Meower's statistics (users, posts, and chats)
### Trust keys and access control

In development, Meower is configured to use "meower" as a CloudLink Trust key. If you notice a forked server using this key, please request for it to be removed. This key is intended for development purposes only.

Meower is configured to use CloudLink's Trusted Access feature, which implements the following security features:
1. IP blocker feature
2. Client kicking
3. Trust keys
4. Protection from maliciously modified clients

## Contributing to the source

1. Make a fork of the repo
2. Modify your source
3. Open a PR
