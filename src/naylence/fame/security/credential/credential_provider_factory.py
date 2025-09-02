from __future__ import annotations

from typing import Any, Optional, TypeVar

from pydantic import ConfigDict, Field

from naylence.fame.factory import ResourceConfig, ResourceFactory
from naylence.fame.security.credential import CredentialProvider


class CredentialProviderConfig(ResourceConfig):
    """Base configuration for credential providers"""

    model_config = ConfigDict(extra="allow")
    type: str = "CredentialProvider"


C = TypeVar("C", bound=CredentialProviderConfig)


class CredentialProviderFactory(ResourceFactory[CredentialProvider, C]):
    """Factory for creating credential providers"""

    pass


# None credential provider config
class NoneCredentialProviderConfig(CredentialProviderConfig):
    type: str = "NoneCredentialProvider"


# None credential provider factory
class NoneCredentialProviderFactory(CredentialProviderFactory):
    async def create(
        self,
        config: Optional[NoneCredentialProviderConfig | dict[str, Any]] = None,
        **kwargs: Any,
    ) -> CredentialProvider:
        from naylence.fame.security.credential import NoneCredentialProvider

        return NoneCredentialProvider()


# Static credential provider factory
class StaticCredentialProviderConfig(CredentialProviderConfig):
    type: str = "StaticCredentialProvider"
    credential_value: str = Field(description="The static credential value")


class StaticCredentialProviderFactory(CredentialProviderFactory):
    async def create(
        self,
        config: Optional[StaticCredentialProviderConfig | dict[str, Any]] = None,
        **kwargs: Any,
    ) -> CredentialProvider:
        from naylence.fame.security.credential import StaticCredentialProvider

        if not config:
            config = StaticCredentialProviderConfig(credential_value="")
        elif isinstance(config, dict):
            config = StaticCredentialProviderConfig(**config)

        # Handle both base config and specific config types
        return StaticCredentialProvider(config.credential_value)


class EnvCredentialProviderConfig(CredentialProviderConfig):
    """Configuration for environment variable credential provider"""

    type: str = "EnvCredentialProvider"
    var_name: str = Field(description="Environment variable name")


class EnvCredentialProviderFactory(CredentialProviderFactory):
    async def create(
        self,
        config: Optional[EnvCredentialProviderConfig | dict[str, Any]] = None,
        **kwargs: Any,
    ) -> CredentialProvider:
        from naylence.fame.security.credential import EnvCredentialProvider

        if not config:
            config = EnvCredentialProviderConfig(var_name="DEFAULT_VAR")
        elif isinstance(config, dict):
            config = EnvCredentialProviderConfig(**config)

        return EnvCredentialProvider(var_name=config.var_name)


class SecretStoreCredentialProviderConfig(CredentialProviderConfig):
    """Configuration for secret store credential provider (e.g., HashiCorp Vault, AWS Secrets Manager)"""

    type: str = "SecretStoreCredentialProvider"
    secret_name: str = Field(description="Secret name in the store")
    # Additional fields can be added later for specific secret store implementations


class SecretStoreCredentialProviderFactory(CredentialProviderFactory):
    async def create(
        self,
        config: Optional[SecretStoreCredentialProviderConfig | dict[str, Any]] = None,
        **kwargs: Any,
    ) -> CredentialProvider:
        from naylence.fame.security.credential import SecretStoreCredentialProvider

        if not config:
            config = SecretStoreCredentialProviderConfig(secret_name="default")
        elif isinstance(config, dict):
            config = SecretStoreCredentialProviderConfig(**config)

        return SecretStoreCredentialProvider(secret_name=config.secret_name)


# Prompt credential provider factory
class PromptCredentialProviderConfig(CredentialProviderConfig):
    type: str = "PromptCredentialProvider"
    credential_name: str = Field(default="credential", description="The name to display in the prompt")


class PromptCredentialProviderFactory(CredentialProviderFactory):
    async def create(
        self,
        config: Optional[PromptCredentialProviderConfig | dict[str, Any]] = None,
        **kwargs: Any,
    ) -> CredentialProvider:
        from naylence.fame.security.credential import PromptCredentialProvider

        if not config:
            config = PromptCredentialProviderConfig()
        elif isinstance(config, dict):
            config = PromptCredentialProviderConfig(**config)

        return PromptCredentialProvider(credential_name=config.credential_name)
