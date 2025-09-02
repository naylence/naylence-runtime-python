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
)
from naylence.fame.security.credential.secret_source import SecretSource


class OAuth2ClientCredentialsTokenProviderConfig(TokenProviderConfig):
    type: str = "OAuth2ClientCredentialsTokenProvider"

    token_url: str = Field(description="OAuth2 token endpoint URL")
    client_id: Annotated[CredentialProviderConfig, SecretSource] = Field(
        description="OAuth2 client ID from various sources (plain text, env://VAR, secret://name, "
        " or provider config)"
    )
    client_secret: Annotated[CredentialProviderConfig, SecretSource] = Field(
        description="OAuth2 client secret from various sources (plain text, env://VAR, secret://name, "
        "or provider config)"
    )
    scopes: list[str] = Field(
        default_factory=lambda: ["node.connect"], description="OAuth2 scopes to request"
    )
    audience: Optional[str] = Field(
        default=None,
        description="OAuth2 audience parameter (resource server identifier)",
    )


class OAuth2ClientCredentialsTokenProviderFactory(TokenProviderFactory):
    async def create(
        self,
        config: Optional[OAuth2ClientCredentialsTokenProviderConfig | dict[str, Any]] = None,
        **kwargs: Any,
    ) -> TokenProvider:
        if not config or not isinstance(config, OAuth2ClientCredentialsTokenProviderConfig):
            raise ValueError("OAuth2ClientCredentialsTokenProviderConfig is required")

        # Extract credential provider configs from the unified fields
        # Pydantic's ResourceConfig automatically handles polymorphic deserialization
        client_id_config = config.client_id
        client_secret_config = config.client_secret

        # Create the credential providers for both client_id and client_secret
        client_id_provider = await create_resource(CredentialProviderFactory, client_id_config)
        client_secret_provider = await create_resource(CredentialProviderFactory, client_secret_config)

        from naylence.fame.security.auth.oauth2_client_credentials_token_provider import (
            OAuth2ClientCredentialsTokenProvider,
        )

        return OAuth2ClientCredentialsTokenProvider(
            token_url=config.token_url,
            client_id_provider=client_id_provider,
            client_secret_provider=client_secret_provider,
            scopes=config.scopes,
            audience=config.audience,
        )
