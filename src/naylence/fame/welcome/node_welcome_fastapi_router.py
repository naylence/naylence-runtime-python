from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from naylence.fame.core import FameEnvelopeWith, NodeHelloFrame, create_fame_envelope
from naylence.fame.util import logging
from naylence.fame.welcome.welcome_service import WelcomeService

if TYPE_CHECKING:
    from fastapi import APIRouter

logger = logging.getLogger(__name__)

PROTO_MAJOR = 1
DEFAULT_PREFIX = f"/fame/v{PROTO_MAJOR}/welcome"


def create_node_welcome_fastapi_router(
    *,
    welcome_service: WelcomeService,
    prefix: str = DEFAULT_PREFIX,
    expected_audience: str = "fame.fabric",
) -> APIRouter:
    from fastapi import APIRouter, HTTPException

    router = APIRouter(prefix=prefix)

    @router.post("/hello")
    async def handle_hello(request: Request, hello_env: FameEnvelopeWith[NodeHelloFrame]):
        auth_header = request.headers.get("authorization", "")

        # ① Perform authorization check
        if welcome_service.authorizer:
            auth_result = await welcome_service.authorizer.authenticate(auth_header)
            if auth_result is None:
                logger.warning(
                    "client_authentication_failed",
                    authorizer_type=type(welcome_service.authorizer).__name__,
                )
                raise HTTPException(401, "Authentication failed")
        try:
            welcome = await welcome_service.handle_hello(hello_env.frame)
            env = create_fame_envelope(frame=welcome)
            body = jsonable_encoder(env, by_alias=True, exclude_none=True)
            return JSONResponse(content=body)

        except ValidationError as ve:
            logger.error("Validation error", exc_info=True)
            raise HTTPException(status_code=422, detail=str(ve))
        except Exception as e:
            logger.error("Intenal error", exc_info=True)
            raise HTTPException(status_code=500, detail=str(e))

    return router
