from quart import Blueprint, current_app as app, request, abort
from quart_schema import validate_querystring, validate_request
from pydantic import BaseModel, Field
from typing import Optional
import pymongo, copy

import security
from database import db, get_total_pages
from uploads import claim_file
from utils import log


home_bp = Blueprint("home_bp", __name__, url_prefix="/home")


class GetHomeQueryArgs(BaseModel):
    page: Optional[int] = Field(default=1, ge=1)

class PostBody(BaseModel):
    content: Optional[str] = Field(default="", max_length=4000)
    nonce: Optional[str] = Field(default=None, max_length=64)
    attachments: Optional[list[str]] = Field(default_factory=list)
    reply_to: Optional[list[str]] = Field(default_factory=list)
    stickers: Optional[list[str]] = Field(default_factory=list)

    class Config:
        validate_assignment = True
        str_strip_whitespace = True


@home_bp.get("/")
@validate_querystring(GetHomeQueryArgs)
async def get_home_posts(query_args: GetHomeQueryArgs):
    query = {"post_origin": "home", "isDeleted": False}
    return {
        "error": False,
        "autoget": app.supporter.parse_posts_v0(db.posts.find(
            query,
            sort=[("t.e", pymongo.DESCENDING)],
            skip=(query_args.page-1)*25,
            limit=25
        ), requester=request.user),
        "page": query_args.page,
        "page#": query_args.page,
        "pages": (get_total_pages("posts", query) if request.user else 1)
    }, 200


@home_bp.post("/")
@validate_request(PostBody)
async def create_home_post(data: PostBody):
    # Check authorization
    if not request.user:
        abort(401)

    if not (request.flags & security.UserFlags.POST_RATELIMIT_BYPASS):
        # Check ratelimit
        if security.ratelimited(f"post:{request.user}"):
            abort(429)

        # Ratelimit
        security.ratelimit(f"post:{request.user}", 6, 5)

    # Check restrictions
    if security.is_restricted(request.user, security.Restrictions.HOME_POSTS):
        return {"error": True, "type": "accountBanned"}, 403

    # Make sure there's not too many attachments
    if len(data.attachments) > 10:
        return {"error": True, "type": "tooManyAttachments"}, 400

    # Make sure the post isn't replying to too many posts
    if len(data.reply_to) > 10:
        return {"error": True, "type": "tooManyReplies"}, 400
    
    # Make sure there's not too many stickers
    if len(data.stickers) > 10:
        return {"error": True, "type": "tooManyStickers"}, 400
    
    # Make sure stickers exist
    for sticker_id in copy.copy(data.stickers):
        if not db.chat_stickers.count_documents({"_id": sticker_id}, limit=1):
            data.stickers.remove(sticker_id)

    # Make sure replied to post IDs exist and are unique
    unique_reply_to_post_ids = []
    for post_id in data.reply_to:
        if db.posts.count_documents({"_id": post_id, "post_origin": "home"}, limit=1) and \
            post_id not in unique_reply_to_post_ids:
            unique_reply_to_post_ids.append(post_id)

    # Claim attachments
    attachments = []
    for attachment_id in set(data.attachments):
        try:
            attachments.append(claim_file(attachment_id, "attachments"))
        except Exception as e:
            log(f"Unable to claim attachment: {e}")
            return {"error": True, "type": "unableToClaimAttachment"}, 500

    # Make sure the post has text content or at least 1 attachment or at least 1 sticker
    if not data.content and not attachments and not data.stickers:
        abort(400)

    # Create post
    post = app.supporter.create_post(
        "home",
        request.user,
        data.content,
        attachments=attachments,
        stickers=data.stickers,
        nonce=data.nonce,
        reply_to=unique_reply_to_post_ids
    )

    # Return new post
    post["error"] = False
    return app.supporter.parse_posts_v0([post], requester=request.user)[0], 200


@home_bp.post("/typing")
async def emit_typing():
    # Check authorization
    if not request.user:
        abort(401)

    # Check ratelimit
    if security.ratelimited(f"typing:{request.user}"):
        abort(429)

    # Ratelimit
    security.ratelimit(f"typing:{request.user}", 6, 5)

    # Check restrictions
    if security.is_restricted(request.user, security.Restrictions.HOME_POSTS):
        return {"error": True, "type": "accountBanned"}, 403

    # Send new state
    app.cl.send_event("typing", {"chat_id": "home", "username": request.user})

    return {"error": False}, 200
