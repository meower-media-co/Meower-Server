from typing import Optional, Union

from pydantic import BaseModel, Field
from quart import Quart, Request

import cloudlink
from supporter import Supporter


class AuthenticatedRequest(Request):
    user: Union[str, None] = None
    ip: str
    permissions: Union[int, None] = None


class MeowerQuart(Quart):
    supporter: Supporter
    cl: cloudlink.CloudlinkServer


class BanBody(BaseModel):
    reason: Optional[str] = Field(default="", max_length=360)
    expires: Optional[int] = Field(default=None)

    class Config:
        validate_assignment = True
        str_strip_whitespace = True

