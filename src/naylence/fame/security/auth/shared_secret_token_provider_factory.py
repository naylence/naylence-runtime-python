from __future__ import annotations

from typing import Annotated, Any, Optional

from pydantic import Field

from naylence.fame.factory import create_resource
from naylence.fame.security.auth.token_provider import TokenProvider
from naylence.fame.security.auth.token_provider_factory import (
    TokenProviderConfig,
    TokenProviderFactory,
)
from naylence.fame.security.credential.credential_provider_factory import (
    CredentialProviderConfig,
    CredentialProviderFactory,
    EnvCredentialProviderConfig,
)
from naylence.fame.security.credential.secret_source import SecretSource


class SharedSecretTokenProviderConfig(TokenProviderConfig):
    type: str = "SharedSecretTokenProvider"
    secret: Annotated[CredentialProviderConfig, SecretSource] = Field(
        default=EnvCredentialProviderConfig(var_name="SHARED_SECRET"),
        description="Shared secret from various sources (plain text, env://VAR, secret://name, "
        "or provider config)",
    )


class SharedSecretTokenProviderFactory(TokenProviderFactory):
    async def create(
        self,
        config: Optional[SharedSecretTokenProviderConfig | dict[str, Any]] = None,
        **kwargs: Any,
    ) -> TokenProvider:
        if not config or not isinstance(config, SharedSecretTokenProviderConfig):
            raise ValueError("SharedSecretTokenProviderConfig is required")

        # Extract credential provider from the unified secret field
        # Pydantic's ResourceConfig automatically handles polymorphic deserialization
        credential_provider_config = config.secret

        # Create the credential provider
        credential_provider = await create_resource(CredentialProviderFactory, credential_provider_config)

        from naylence.fame.security.auth.shared_secret_token_provider import (
            SharedSecretTokenProvider,
        )

        return SharedSecretTokenProvider(
            credential_provider=credential_provider,
        )
