from typing import Annotated, Any, Optional

from pydantic import Field, field_validator

from naylence.fame.constants.ttl_constants import DEFAULT_JWT_TOKEN_TTL_SEC
from naylence.fame.factory import create_resource
from naylence.fame.security.auth.token_issuer import TokenIssuer
from naylence.fame.security.auth.token_issuer_factory import (
    TokenIssuerConfig,
    TokenIssuerFactory,
)
from naylence.fame.security.credential.credential_provider_factory import (
    CredentialProviderConfig,
    CredentialProviderFactory,
)
from naylence.fame.security.credential.secret_source import SecretSource
from naylence.fame.util.ttl_validation import validate_jwt_token_ttl_sec


class JWTTokenIssuerConfig(TokenIssuerConfig):
    type: str = "JWTTokenIssuer"

    private_key_pem: Optional[Annotated[CredentialProviderConfig, SecretSource]] = Field(
        default=None,
        description="PEM key used to sign JWTs for asymmetric algorithms; defaults to crypto provider. "
        "Can be plain text, env://VAR, secret://name, or provider config",
    )
    hmac_secret: Optional[Annotated[CredentialProviderConfig, SecretSource]] = Field(
        default=None,
        description="Base64-encoded HMAC secret for symmetric algorithms; defaults to crypto provider. "
        "Can be plain text, env://VAR, secret://name, or provider config",
    )
    algorithm: str = Field("EdDSA", description="Token signing algorithm (EdDSA, RS256, HS256, etc.)")
    kid: Optional[str] = Field(default=None, description="Key ID to embed in the JWT header")
    issuer: str = Field(..., description="JWT issuer claim")
    ttl_sec: int = Field(DEFAULT_JWT_TOKEN_TTL_SEC, description="Token TTL in seconds")
    audience: Optional[str] = Field(
        default=None, description="JWT audience claim (defaults to parent path)"
    )

    @field_validator("ttl_sec")
    @classmethod
    def validate_ttl_sec(cls, v: int) -> int:
        """Validate JWT token TTL is within acceptable bounds."""
        return int(validate_jwt_token_ttl_sec(v) or v)


class JWTTokenIssuerFactory(TokenIssuerFactory):
    async def create(
        self,
        config: Optional[JWTTokenIssuerConfig | dict[str, Any]] = None,
        **kwargs: Any,
    ) -> TokenIssuer:
        assert config
        from naylence.fame.security.crypto.providers.crypto_provider import (
            get_crypto_provider,
        )

        if isinstance(config, dict):
            config = JWTTokenIssuerConfig(**config)

        algorithm = config.algorithm
        crypto_provider = get_crypto_provider()

        # Determine signing key based on algorithm type
        signing_key = None
        kid = None
        if algorithm.startswith("HS"):  # HMAC algorithms (HS256, HS384, HS512)
            if config.hmac_secret:
                # Use credential provider to resolve HMAC secret
                credential_provider = await create_resource(CredentialProviderFactory, config.hmac_secret)
                signing_key = await credential_provider.get()
            else:
                # For now, require explicit HMAC secret until crypto provider supports it
                raise RuntimeError(
                    f"HMAC algorithm {algorithm} requires explicit 'hmac_secret' configuration"
                )
        else:  # Asymmetric algorithms (EdDSA, RS256, etc.)
            if config.private_key_pem:
                # Use credential provider to resolve private key
                credential_provider = await create_resource(
                    CredentialProviderFactory, config.private_key_pem
                )
                signing_key = await credential_provider.get()
            else:
                # Fall back to crypto provider
                signing_key = crypto_provider.signing_private_pem
            if not signing_key:
                raise RuntimeError(f"Asymmetric algorithm {algorithm} requires 'private_key_pem'")

            kid = crypto_provider.signature_key_id

        kid = config.kid or kid
        issuer = config.issuer
        ttl_sec = config.ttl_sec

        if not kid or not issuer:
            raise RuntimeError("JWT issuer requires 'kid' and 'issuer'")

        from naylence.fame.security.auth.jwt_token_issuer import JWTTokenIssuer

        return JWTTokenIssuer(
            signing_key_pem=signing_key,
            kid=kid,
            issuer=issuer,
            algorithm=algorithm,
            ttl_sec=ttl_sec,
            audience=config.audience,
        )


# Backward compatibility classes
class JWTTokenIssuerConfigCompat(JWTTokenIssuerConfig):
    type: str = "JWTTokenIssuer"


class JWTTokenIssuerFactoryCompat(TokenIssuerFactory):
    async def create(
        self,
        config: Optional[JWTTokenIssuerConfig | dict[str, Any]] = None,
        **kwargs: Any,
    ) -> TokenIssuer:
        # Create the generic JWT issuer but return the compatibility wrapper
        from naylence.fame.security.crypto.providers.crypto_provider import (
            get_crypto_provider,
        )

        assert config
        if isinstance(config, dict):
            config = JWTTokenIssuerConfig(**config)

        algorithm = config.algorithm
        crypto_provider = get_crypto_provider()

        # Determine signing key based on algorithm type
        signing_key = None
        if algorithm.startswith("HS"):  # HMAC algorithms (HS256, HS384, HS512)
            if config.hmac_secret:
                # Use credential provider to resolve HMAC secret
                credential_provider = await create_resource(CredentialProviderFactory, config.hmac_secret)
                signing_key = await credential_provider.get()
            else:
                # For now, require explicit HMAC secret until crypto provider supports it
                raise RuntimeError(
                    f"HMAC algorithm {algorithm} requires explicit 'hmac_secret' configuration"
                )
        else:  # Asymmetric algorithms (EdDSA, RS256, etc.)
            if config.private_key_pem:
                # Use credential provider to resolve private key
                credential_provider = await create_resource(
                    CredentialProviderFactory, config.private_key_pem
                )
                signing_key = await credential_provider.get()
            else:
                # Fall back to crypto provider
                signing_key = crypto_provider.signing_private_pem
            if not signing_key:
                raise RuntimeError(f"Asymmetric algorithm {algorithm} requires 'private_key_pem'")

        kid = config.kid
        issuer = config.issuer
        ttl_sec = config.ttl_sec

        if not kid or not issuer:
            raise RuntimeError("JWT issuer requires 'kid' and 'issuer'")

        from naylence.fame.security.auth.jwt_token_issuer import JWTTokenIssuer

        return JWTTokenIssuer(
            signing_key_pem=signing_key,
            kid=kid,
            issuer=issuer,
            algorithm=algorithm,
            ttl_sec=ttl_sec,
            audience=config.audience,
        )
