from __future__ import annotations

from typing import Callable, Optional

from fastapi import APIRouter

DEFAULT_PREFIX = ""


def create_jwks_router(
    *,
    get_jwks_json: Optional[Callable] = None,
    prefix=DEFAULT_PREFIX,
) -> APIRouter:
    """
    Returns an APIRouter exposing JWKS at:
        GET .well-known/jwks.json
    """

    if get_jwks_json:
        jwks = get_jwks_json()
    else:
        from naylence.fame.security.crypto.providers.crypto_provider import (
            get_crypto_provider,
        )

        jwks = get_crypto_provider().get_jwks()

    router = APIRouter(prefix=prefix)

    @router.get("/.well-known/jwks.json")
    async def serve_jwks():
        return jwks

    return router
