from sanic import Blueprint, json
from sanic_ext import validate
from pydantic import BaseModel, Field
from typing import Optional, Dict, Union

from .global_models import AuthorMasquerade
from src.util import security
from src.entities import posts

v0 = Blueprint("v0_home", url_prefix="/home")
v1 = Blueprint("v1_home", url_prefix="/home")


class NewPostForm(BaseModel):
    masquerade: Optional[dict] = Field()
    bridged: Optional[bool] = Field()
    content: str = Field(
        min_length=1,
        max_length=4000
    )


@v0.get("/")
async def v0_get_home(request):
    fetched_posts = posts.get_latest_posts()
    return json({
        "error": False,
        "autoget": [post.legacy_public for post in fetched_posts],
        "page#": 1,
        "pages": 1
    })


@v1.get("/")
@security.sanic_protected(allow_bots=False)
async def v1_get_feed(request):
    fetched_posts = posts.get_feed(request.ctx.user, before=request.args.get("before"), after=request.args.get("after"),
                                   limit=int(request.args.get("limit", 25)))
    return json([post.public for post in fetched_posts])


@v1.get("/latest")
async def v1_get_latest_posts(request):
    fetched_posts = posts.get_latest_posts(before=request.args.get("before"), after=request.args.get("after"),
                                           limit=int(request.args.get("limit", 25)))
    return json([post.public for post in fetched_posts])


@v1.get("/trending")
async def v1_get_trending_posts(request):
    fetched_posts = posts.get_top_posts(before=request.args.get("before"), after=request.args.get("after"),
                                        limit=int(request.args.get("limit", 25)))
    return json([post.public for post in fetched_posts])


@v1.post("/")
@validate(json=NewPostForm)
@security.sanic_protected(ratelimit_key="create_post", ratelimit_scope="user", ignore_suspension=False)
async def v1_create_post(request, body: NewPostForm):
    if body.masquerade:
        AuthorMasquerade(**body.masquerade)

    post = posts.create_post(request.ctx.user, body.content, masquerade=body.masquerade, bridged=body.bridged)
    return json(post.public)
