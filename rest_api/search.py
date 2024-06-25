from quart import Blueprint
from quart_schema import validate_querystring
from pydantic import BaseModel, Field
from typing import Optional

import security
from database import db, get_total_pages


search_bp = Blueprint("search_bp", __name__, url_prefix="/search")


class SearchQueryArgs(BaseModel):
    q: str = Field(min_length=1, max_length=4000)
    page: Optional[int] = Field(default=1, ge=1)


@search_bp.get("/home")
@validate_querystring(SearchQueryArgs)
async def search_home(query_args: SearchQueryArgs):
    # Get posts
    query = {"post_origin": "home", "isDeleted": False, "$text": {"$search": query_args.q}}
    posts = list(db.posts.find(query, skip=(query_args.page-1)*25, limit=25))

    # Return posts
    return {
        "error": False,
        "autoget": posts,
        "page#": query_args.page,
        "pages": get_total_pages("posts", query)
    }, 200


@search_bp.get("/users")
@validate_querystring(SearchQueryArgs)
async def search_users(query_args: SearchQueryArgs):
    # Get users
    query = {"pswd": {"$type": "string"}, "$text": {"$search": query_args.q}}
    usernames = [user["_id"] for user in db.usersv0.find(query, skip=(query_args.page-1)*25, limit=25, projection={"_id": 1})]

    # Return users
    return {
        "error": False,
        "autoget": [security.get_account(username) for username in usernames],
        "page#": query_args.page,
        "pages": get_total_pages("usersv0", query)
    }, 200
