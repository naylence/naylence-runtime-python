from __future__ import annotations

from typing import Any, Optional

from pydantic import Field, field_validator

from naylence.fame.constants.ttl_constants import (
    DEFAULT_JWKS_CACHE_TTL_SEC,
    DEFAULT_OAUTH2_TTL_SEC,
    MAX_OAUTH2_TTL_SEC,
)
from naylence.fame.factory import create_resource
from naylence.fame.security.auth.authorizer import Authorizer
from naylence.fame.security.auth.authorizer_factory import (
    AuthorizerConfig,
    AuthorizerFactory,
)
from naylence.fame.security.auth.token_issuer_factory import TokenIssuerConfig
from naylence.fame.security.auth.token_verifier_factory import TokenVerifierConfig
from naylence.fame.util.logging import getLogger
from naylence.fame.util.ttl_validation import validate_oauth2_ttl_sec

logger = getLogger(__name__)


class OAuth2AuthorizerConfig(AuthorizerConfig):
    """Configuration for OAuth2-based node attach authorizer"""

    type: str = "OAuth2Authorizer"

    # OAuth2 token verification settings
    issuer: str = Field(description="OAuth2 issuer URL")
    audience: Optional[str] = Field(
        default=None,
        description="Expected audience for tokens (defaults to node physical path if not provided)",
    )
    jwks_url: Optional[str] = Field(
        default=None,
        description="JWKS URL for token verification (auto-derived if not provided)",
    )
    algorithm: str = Field(default="RS256", description="JWT signing algorithm")

    # Authorization policy settings
    required_scopes: Optional[list[str]] = Field(
        default=None, description="List of scopes that grant node connection permission"
    )
    require_scope: bool = Field(default=True, description="Whether to enforce scope validation")
    default_ttl_sec: int = Field(
        default=DEFAULT_OAUTH2_TTL_SEC,
        description="Default TTL for authorized connections in seconds",
    )
    max_ttl_sec: int = Field(
        default=MAX_OAUTH2_TTL_SEC,
        description="Maximum TTL for authorized connections in seconds",
    )

    # Token subject node identity enforcement
    enforce_token_subject_node_identity: bool = Field(
        default=False,
        description=(
            "Whether to enforce that node system IDs are prefixed with a hash of the "
            "token subject claim. When enabled, nodes must use TokenSubjectNodeIdentityPolicy."
        ),
    )
    trusted_client_scope: str = Field(
        default="node.trusted",
        description=(
            "OAuth2 scope that indicates a trusted client (e.g., client credentials). "
            "Tokens with this scope bypass token subject node identity enforcement."
        ),
    )

    @field_validator("enforce_token_subject_node_identity", mode="before")
    @classmethod
    def validate_enforce_token_subject_node_identity(cls, v: Any) -> bool:
        """Normalize string/bool values to boolean."""
        if isinstance(v, bool):
            return v
        if isinstance(v, str):
            return v.lower() in ("true", "1", "yes")
        return bool(v)

    @field_validator("default_ttl_sec")
    @classmethod
    def validate_default_ttl_sec(cls, v: int) -> int:
        """Validate default OAuth2 TTL is within acceptable bounds."""
        return int(validate_oauth2_ttl_sec(v) or v)

    @field_validator("max_ttl_sec")
    @classmethod
    def validate_max_ttl_sec(cls, v: int) -> int:
        """Validate maximum OAuth2 TTL is within acceptable bounds."""
        return int(validate_oauth2_ttl_sec(v) or v)

    token_verifier_config: Optional[TokenVerifierConfig] = Field(
        default=None,
        description="Configuration for TokenIssuer to enable reverse authorization",
    )

    # Reverse authorization settings (optional)
    token_issuer_config: Optional[TokenIssuerConfig] = Field(
        default=None,
        description="Configuration for TokenIssuer to enable reverse authorization",
    )
    reverse_auth_ttl_sec: int = Field(
        default=86400, description="TTL for reverse authorization tokens in seconds"
    )


class OAuth2AuthorizerFactory(AuthorizerFactory):
    async def create(
        self,
        config: Optional[OAuth2AuthorizerConfig | dict[str, Any]] = None,
        **kwargs: Any,
    ) -> Authorizer:
        if not config:
            raise ValueError("OAuth2AuthorizerConfig is required")

        if isinstance(config, dict):
            config = OAuth2AuthorizerConfig(**config)
        elif not isinstance(config, OAuth2AuthorizerConfig):
            raise ValueError("OAuth2AuthorizerConfig is required")

        # Create the JWT token verifier configuration
        jwks_url = config.jwks_url
        if not jwks_url:
            # Auto-derive JWKS URL from issuer
            issuer = config.issuer.rstrip("/")
            jwks_url = f"{issuer}/.well-known/jwks.json"

        # Use the existing JWKS verifier configuration
        from naylence.fame.security.auth.jwks_jwt_token_verifier_factory import (
            JWKSVerifierConfig,
        )

        verifier_config = config.token_verifier_config or JWKSVerifierConfig(
            type="JWKSJWTTokenVerifier",
            jwks_url=jwks_url,
            issuer=config.issuer,
            cache_ttl_sec=DEFAULT_JWKS_CACHE_TTL_SEC,  # Use centralized constant
        )

        from naylence.fame.security.auth.token_verifier_factory import (
            TokenVerifierFactory,
        )

        verifier = await create_resource(TokenVerifierFactory, verifier_config)

        # Create token issuer if configured (for reverse authorization)
        token_issuer = None
        if config.token_issuer_config:
            try:
                from naylence.fame.security.auth.token_issuer_factory import (
                    TokenIssuerFactory,
                )

                token_issuer = await create_resource(TokenIssuerFactory, config.token_issuer_config)
                logger.debug(
                    "token_issuer_created_for_reverse_auth",
                    issuer_type=config.token_issuer_config.type,
                )
            except Exception as e:
                # Log warning but continue without reverse auth
                logger.warning(
                    "failed_to_create_token_issuer_for_reverse_auth",
                    error=str(e),
                    issuer_config=config.token_issuer_config,
                )

        # Lazy import to avoid circular dependencies
        from naylence.fame.security.auth.oauth2_authorizer import OAuth2Authorizer

        return OAuth2Authorizer(
            token_verifier=verifier,
            audience=config.audience,
            required_scopes=config.required_scopes,
            require_scope=config.require_scope,
            default_ttl_sec=config.default_ttl_sec,
            max_ttl_sec=config.max_ttl_sec,
            token_issuer=token_issuer,
            reverse_auth_ttl_sec=config.reverse_auth_ttl_sec,
            enforce_token_subject_node_identity=config.enforce_token_subject_node_identity,
            trusted_client_scope=config.trusted_client_scope,
        )
