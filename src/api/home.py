from sanic import Blueprint, json
from sanic_ext import validate
from pydantic import BaseModel, Field

from src.util import status
from src.entities import posts

v1 = Blueprint("v1_home", url_prefix="/home")

class NewPostForm(BaseModel):
    content: str = Field(
        min_length=1,
        max_length=4000
    )

@v1.post("/")
@validate(json=NewPostForm)
async def v1_create_post(request, body: NewPostForm):
    if request.ctx.user is None:
        raise status.notAuthenticated

    post = posts.create_post(request.ctx.user, body.content)
    return json(post.public)

@v1.get("/")
async def v1_get_feed(request):
    if request.ctx.user is None:
        raise status.notAuthenticated
    
    fetched_posts = posts.get_feed(request.ctx.user, before=request.args.get("before"), after=request.args.get("after"), limit=int(request.args.get("limit", 25)))
    return json({"posts": [post.public for post in fetched_posts]})

@v1.get("/latest")
async def v1_get_latest_posts(request):
    fetched_posts = posts.get_latest_posts(before=request.args.get("before"), after=request.args.get("after"), limit=int(request.args.get("limit", 25)))
    return json({"posts": [post.public for post in fetched_posts]})

@v1.get("/trending")
async def v1_get_trending_posts(request):
    fetched_posts = posts.get_top_posts(before=request.args.get("before"), after=request.args.get("after"), limit=int(request.args.get("limit", 25)))
    return json({"posts": [post.public for post in fetched_posts]})

@v1.get("/search")
async def v1_search_posts(request):
    fetched_posts = posts.search_posts(request.args.get("q"), before=request.args.get("before"), after=request.args.get("after"), limit=int(request.args.get("limit", 25)))
    return json({"posts": [post.public for post in fetched_posts]})