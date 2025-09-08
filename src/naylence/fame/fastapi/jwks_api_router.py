from __future__ import annotations

import os
import re
from typing import Callable, Optional

from fastapi import APIRouter

DEFAULT_PREFIX = ""

ENV_VAR_KEY_TYPES = "FAME_JWKS_KEY_TYPES"


def create_jwks_router(
    *,
    get_jwks_json: Optional[Callable] = None,
    prefix=DEFAULT_PREFIX,
    key_types: Optional[list[str]] = None,
) -> APIRouter:
    """
    Returns an APIRouter exposing JWKS at:
        GET .well-known/jwks.json

    Args:
        get_jwks_json: Optional callable to get JWKS data
        prefix: Router prefix
        key_types: Optional list of key types to include (e.g., ["RSA", "EC"]).
                  If None, no filtering is applied.

    Environment Variables:
        FAME_JWKS_KEY_TYPES: Comma or space separated list of key types to include.
                            Takes priority over the key_types parameter.
    """

    if get_jwks_json:
        jwks = get_jwks_json()
    else:
        from naylence.fame.security.crypto.providers.crypto_provider import (
            get_crypto_provider,
        )

        jwks = get_crypto_provider().get_jwks()

    def get_allowed_key_types():
        """Get allowed key types from environment variable or parameter."""
        # Environment variable takes priority
        env_key_types = os.getenv(ENV_VAR_KEY_TYPES)
        if env_key_types:
            # Split by comma or space and strip whitespace
            return [kty.strip() for kty in re.split(r"[,\s]+", env_key_types) if kty.strip()]

        # Fallback to parameter
        return key_types

    def filter_keys_by_type(jwks_data):
        """Filter keys by allowed key types."""
        allowed_types = get_allowed_key_types()

        # If no filtering is configured, return original data
        if not allowed_types:
            return jwks_data

        if isinstance(jwks_data, dict) and "keys" in jwks_data:
            filtered_keys = [key for key in jwks_data["keys"] if key.get("kty") in allowed_types]
            return {**jwks_data, "keys": filtered_keys}
        return jwks_data

    router = APIRouter(prefix=prefix)

    @router.get("/.well-known/jwks.json")
    async def serve_jwks():
        return filter_keys_by_type(jwks)

    return router
