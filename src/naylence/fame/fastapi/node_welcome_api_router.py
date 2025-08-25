from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import ValidationError

from naylence.fame.core import FameEnvelopeWith, NodeHelloFrame, create_fame_envelope
from naylence.fame.util import logging
from naylence.fame.welcome.welcome_service import WelcomeService

if TYPE_CHECKING:
    from fastapi import APIRouter

logger = logging.getLogger(__name__)

PROTO_MAJOR = 1
DEFAULT_PREFIX = f"/fame/v{PROTO_MAJOR}/welcome"


def create_welcome_router(*, welcome_service: WelcomeService, prefix: str = DEFAULT_PREFIX) -> APIRouter:
    from fastapi import APIRouter, HTTPException

    router = APIRouter(prefix=prefix)

    @router.post("/hello")
    async def handle_hello(hello_env: FameEnvelopeWith[NodeHelloFrame]):
        try:
            welcome = await welcome_service.handle_hello(hello_env.frame)
            env = create_fame_envelope(frame=welcome)
            return env

        except ValidationError as ve:
            logger.error("Validation error", exc_info=True)
            raise HTTPException(status_code=422, detail=str(ve))
        except Exception as e:
            logger.error("Intenal error", exc_info=True)
            raise HTTPException(status_code=500, detail=str(e))

    return router
