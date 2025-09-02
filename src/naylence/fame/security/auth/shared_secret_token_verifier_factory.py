from __future__ import annotations

from typing import Annotated, Any, Optional

from pydantic import Field

from naylence.fame.factory import create_resource
from naylence.fame.security.auth.shared_secret_token_verifier import (
    SharedSecretTokenVerifier,
)
from naylence.fame.security.auth.token_verifier import TokenVerifier
from naylence.fame.security.auth.token_verifier_factory import (
    TokenVerifierConfig,
    TokenVerifierFactory,
)
from naylence.fame.security.credential.credential_provider_factory import (
    CredentialProviderConfig,
    CredentialProviderFactory,
    EnvCredentialProviderConfig,
)
from naylence.fame.security.credential.secret_source import SecretSource


class SharedSecretVerifierConfig(TokenVerifierConfig):
    type: str = "SharedSecretTokenVerifier"
    secret: Annotated[CredentialProviderConfig, SecretSource] = Field(
        default=EnvCredentialProviderConfig(var_name="SHARED_SECRET"),
        description="Secret from various sources (plain text, env://VAR, secret://name, "
        "or provider config)",
    )


class SharedSecretTokenVerifierFactory(TokenVerifierFactory):
    async def create(
        self,
        config: Optional[TokenVerifierConfig | dict[str, Any]] = None,
        **kwargs: Any,
    ) -> TokenVerifier:
        # If config is a dict, convert it to SharedSecretVerifierConfig
        if isinstance(config, dict):
            config = SharedSecretVerifierConfig(**config)
        if not config or not isinstance(config, SharedSecretVerifierConfig):
            raise ValueError("SharedSecretVerifierConfig is required")

        credential_provider_config = config.secret

        # Create the credential provider
        credential_provider = await create_resource(CredentialProviderFactory, credential_provider_config)

        return SharedSecretTokenVerifier(
            credential_provider=credential_provider,
        )
