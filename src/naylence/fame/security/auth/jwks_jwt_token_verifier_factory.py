from typing import Any, Optional

from pydantic import Field, field_validator

from naylence.fame.constants.ttl_constants import DEFAULT_JWKS_CACHE_TTL_SEC
from naylence.fame.security.auth.token_verifier import TokenVerifier
from naylence.fame.security.auth.token_verifier_factory import (
    TokenVerifierConfig,
    TokenVerifierFactory,
)
from naylence.fame.util.ttl_validation import validate_cache_ttl_sec


class JWKSVerifierConfig(TokenVerifierConfig):
    type: str = "JWKSJWTTokenVerifier"

    jwks_url: str = Field(..., description="URL to fetch JWKS")
    issuer: str = Field(..., description="Expected token issuer")
    cache_ttl_sec: int = Field(DEFAULT_JWKS_CACHE_TTL_SEC, description="JWKS cache TTL in seconds")

    @field_validator("cache_ttl_sec")
    @classmethod
    def validate_cache_ttl_sec(cls, v: int) -> int:
        """Validate JWKS cache TTL is within acceptable bounds."""
        return validate_cache_ttl_sec(v) or v


class JWKSTokenVerifierFactory(TokenVerifierFactory):
    async def create(
        self,
        config: Optional[JWKSVerifierConfig | dict[str, Any]] = None,
        **kwargs: Any,
    ) -> TokenVerifier:
        if not config:
            raise ValueError("Config not set")

        if isinstance(config, dict):
            config = JWKSVerifierConfig(**config)

        from naylence.fame.security.auth.jwks_jwt_token_verifier import (
            JWKSJWTTokenVerifier,
        )

        return JWKSJWTTokenVerifier(
            jwks_url=config.jwks_url,
            issuer=config.issuer,
            cache_ttl_sec=config.cache_ttl_sec,
        )
