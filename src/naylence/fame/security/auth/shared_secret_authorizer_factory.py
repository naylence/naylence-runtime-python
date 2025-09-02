from __future__ import annotations

from typing import Annotated, Any, Optional

from pydantic import Field

from naylence.fame.factory import create_resource
from naylence.fame.security.auth.authorizer import Authorizer
from naylence.fame.security.auth.authorizer_factory import (
    AuthorizerConfig,
    AuthorizerFactory,
)
from naylence.fame.security.credential.credential_provider_factory import (
    CredentialProviderConfig,
    CredentialProviderFactory,
    EnvCredentialProviderConfig,
)
from naylence.fame.security.credential.secret_source import SecretSource


class SharedSecretAuthorizerConfig(AuthorizerConfig):
    type: str = "SharedSecretAuthorizer"
    secret: Annotated[CredentialProviderConfig, SecretSource] = Field(
        default=EnvCredentialProviderConfig(var_name="SHARED_SECRET"),
        description="Secret from various sources (plain text, env://VAR, secret://name, "
        "or provider config)",
    )


class SharedSecretAuthorizerFactory(AuthorizerFactory):
    async def create(
        self,
        config: Optional[SharedSecretAuthorizerConfig | dict[str, Any]] = None,
        **kwargs: Any,
    ) -> Authorizer:
        if isinstance(config, dict):
            config = SharedSecretAuthorizerConfig(**config)
        elif not config:
            raise ValueError("SharedSecretAuthorizerConfig is required")

        # Extract credential provider from the unified secret field
        # Pydantic's ResourceConfig automatically handles polymorphic deserialization
        credential_provider_config = config.secret

        # Create the credential provider
        credential_provider = await create_resource(CredentialProviderFactory, credential_provider_config)

        # Lazy import to avoid circular dependencies
        from naylence.fame.security.auth.shared_secret_authorizer import (
            SharedSecretAuthorizer,
        )

        return SharedSecretAuthorizer(
            credential_provider=credential_provider,
        )
