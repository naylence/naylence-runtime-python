from typing import Annotated, Any, Optional

from pydantic import Field, field_validator

from naylence.fame.constants.ttl_constants import DEFAULT_JWT_TOKEN_TTL_SEC
from naylence.fame.factory import create_resource
from naylence.fame.security.auth.token_verifier import TokenVerifier
from naylence.fame.security.auth.token_verifier_factory import (
    TokenVerifierConfig,
    TokenVerifierFactory,
)
from naylence.fame.security.credential.credential_provider_factory import (
    CredentialProviderConfig,
    CredentialProviderFactory,
)
from naylence.fame.security.credential.secret_source import SecretSource
from naylence.fame.util.ttl_validation import validate_jwt_token_ttl_sec


class JWTVerifierConfig(TokenVerifierConfig):
    type: str = "JWTTokenVerifier"
    issuer: str = Field(..., description="Expected token issuer")
    public_key_pem: Optional[str] = Field(
        None,
        description="Public key PEM for signature verification (used in local/dev)",
    )
    hmac_secret: Optional[Annotated[CredentialProviderConfig, SecretSource]] = Field(
        default=None,
        description="Base64-encoded HMAC secret for symmetric algorithms; defaults to crypto provider. "
        "Can be plain text, env://VAR, secret://name, or provider config",
    )
    ttl_sec: int = Field(DEFAULT_JWT_TOKEN_TTL_SEC, description="Token TTL in seconds")

    @field_validator("ttl_sec")
    @classmethod
    def validate_ttl_sec(cls, v: int) -> int:
        """Validate JWT token TTL is within acceptable bounds."""
        return int(validate_jwt_token_ttl_sec(v) or v)


class JWTTokenVerifierFactory(TokenVerifierFactory):
    async def create(
        self, config: Optional[JWTVerifierConfig | dict[str, Any]] = None, **kwargs: Any
    ) -> TokenVerifier:
        if not config:
            raise ValueError("Config not set")
        if isinstance(config, dict):
            config = JWTVerifierConfig(**config)

        # Determine verification key - either HMAC secret or public key
        verification_key = None

        if config.hmac_secret:
            # Use credential provider to resolve HMAC secret
            credential_provider = await create_resource(CredentialProviderFactory, config.hmac_secret)
            verification_key = await credential_provider.get()
        elif config.public_key_pem:
            # Use provided public key
            verification_key = config.public_key_pem
        else:
            # Fall back to crypto provider for asymmetric algorithms
            from naylence.fame.security.crypto.providers.crypto_provider import (
                get_crypto_provider,
            )

            crypto_provider = get_crypto_provider()
            verification_key = crypto_provider.signing_public_pem

        if not verification_key:
            raise RuntimeError("JWT verifier requires either 'hmac_secret' or 'public_key_pem'")

        from naylence.fame.security.auth.jwt_token_verifier import JWTTokenVerifier

        return JWTTokenVerifier(
            key=verification_key,
            issuer=config.issuer,
            ttl_sec=config.ttl_sec,
        )
