# Load .env file
from dotenv import load_dotenv
load_dotenv()

import asyncio
import os
import uvicorn

from threading import Thread

from cloudlink import CloudlinkServer
from supporter import Supporter
from commands import MeowerCommands
from security import background_tasks_loop
from grpc_auth import service as grpc_auth
from rest_api import app as rest_api


if __name__ == "__main__":
    # Create Cloudlink server
    cl = CloudlinkServer()

    # Create Supporter class
    supporter = Supporter(cl)

    # Initialise Meower commands
    MeowerCommands(cl, supporter)

    # Start background tasks loop
    Thread(target=background_tasks_loop, daemon=True).start()

    # Start gRPC services
    Thread(target=grpc_auth.serve, daemon=True).start()

    # Initialise REST API
    rest_api.cl = cl
    rest_api.supporter = supporter

    # Start REST API
    Thread(target=uvicorn.run, args=(rest_api,), kwargs={
        "host": os.getenv("API_HOST", "0.0.0.0"),
        "port": int(os.getenv("API_PORT", 3001)),
        "root_path": os.getenv("API_ROOT", "")
    }, daemon=True).start()

    # Start Cloudlink server
    asyncio.run(cl.run(host=os.getenv("CL3_HOST", "0.0.0.0"), port=int(os.getenv("CL3_PORT", 3000))))
