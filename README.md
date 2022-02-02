# Meower-server
Official source code of the Meower server, written in Python. Powered by CloudLink.

## Dependencies
* Run "pip install -r requirements.txt" in the downloaded and unzipped directory

## Running the server
Simply download and run meower.py to start a localhost server.

To connect to the server, change the IP settings of your client to connect to ws://127.0.0.1:3000/.

### Trust keys and access control

In development, Meower is configured to use "meower" as a CloudLink Trust key. If you notice a forked server using this key, please request for it to be removed. This key is intended for development purposes only.

Meower is configured to use CloudLink's Trusted Access feature, which implements the following security features:
1. IP blocker feature
2. Client kicking
3. Trust keys
4. Protection from maliciously modified clients

## Contributing to the source

1. Make a fork of the repo.
2. Modify your source.
3. Make a PR request.
