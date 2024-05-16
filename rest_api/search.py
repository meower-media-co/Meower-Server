from quart import Blueprint, request, abort

import security
from database import db, get_total_pages
from .api_types import AuthenticatedRequest, MeowerQuart

request: AuthenticatedRequest
app: MeowerQuart

search_bp = Blueprint("search_bp", __name__, url_prefix="/search")


@search_bp.get("/home")
async def search_home():
    # Get query
    q = request.args.get("q")
    if not q:
        abort(400)
    elif len(q) > 4000:
        q = q[:4000]

    # Get page
    try:
        page = int(request.args["page"])
    except:
        page = 1

    # Get posts
    query = {"post_origin": "home", "isDeleted": False, "$text": {"$search": q}}
    posts = list(db.posts.find(query, skip=(page-1)*25, limit=25))

    # Return posts
    payload = {
        "error": False,
        "page#": page,
        "pages": get_total_pages("posts", query)
    }
    if "autoget" in request.args:
        payload["autoget"] = posts
    else:
        payload["index"] = [post["_id"] for post in posts]
    return payload, 200


@search_bp.get("/users")
async def search_users():
    # Get query
    q = request.args.get("q")
    if not q:
        abort(400)
    elif len(q) > 20:
        q = q[:20]

    # Get page
    try:
        page = int(request.args["page"])
    except:
        page = 1

    # Get users
    query = {"pswd": {"$type": "string"}, "$text": {"$search": q}}
    usernames = [user["_id"] for user in db.usersv0.find(query, skip=(page-1)*25, limit=25, projection={"_id": 1})]

    # Return users
    payload = {
        "error": False,
        "page#": page,
        "pages": get_total_pages("usersv0", query)
    }
    if "autoget" in request.args:
        payload["autoget"] = [security.get_account(username) for username in usernames]
    else:
        payload["index"] = usernames
    return payload, 200
