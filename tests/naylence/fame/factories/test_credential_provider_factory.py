"""Test CredentialProviderFactory to ensure configs resolve to correct subtypes."""

import pytest

from naylence.fame.factory import create_resource
from naylence.fame.security.credential import (
    EnvCredentialProvider,
    NoneCredentialProvider,
    PromptCredentialProvider,
    StaticCredentialProvider,
)
from naylence.fame.security.credential.credential_provider_factory import (
    CredentialProviderFactory,
    EnvCredentialProviderConfig,
    PromptCredentialProviderConfig,
    StaticCredentialProviderConfig,
)


class TestCredentialProviderFactory:
    """Test CredentialProviderFactory and its implementations."""

    @pytest.mark.asyncio
    async def test_none_credential_provider_factory(self):
        """Test NoneCredentialProvider factory creates correct instance."""
        config = {"type": "NoneCredentialProvider"}
        provider = await create_resource(CredentialProviderFactory, config)

        assert isinstance(provider, NoneCredentialProvider)
        assert provider.__class__.__name__ == "NoneCredentialProvider"
        assert await provider.get() is None

    @pytest.mark.asyncio
    async def test_static_credential_provider_factory(self):
        """Test StaticCredentialProvider factory creates correct instance."""
        config = StaticCredentialProviderConfig(credential_value="test-value")
        provider = await create_resource(CredentialProviderFactory, config)

        assert isinstance(provider, StaticCredentialProvider)
        assert provider.__class__.__name__ == "StaticCredentialProvider"
        assert await provider.get() == "test-value"

    @pytest.mark.asyncio
    async def test_env_credential_provider_factory(self):
        """Test EnvCredentialProvider factory creates correct instance."""
        config = EnvCredentialProviderConfig(var_name="TEST_VAR")
        provider = await create_resource(CredentialProviderFactory, config)

        assert isinstance(provider, EnvCredentialProvider)
        assert provider.__class__.__name__ == "EnvCredentialProvider"
        # Don't test actual env var retrieval as it depends on environment

    @pytest.mark.asyncio
    async def test_prompt_credential_provider_factory(self):
        """Test PromptCredentialProvider factory creates correct instance."""
        config = PromptCredentialProviderConfig(credential_name="test-credential")
        provider = await create_resource(CredentialProviderFactory, config)

        assert isinstance(provider, PromptCredentialProvider)
        assert provider.__class__.__name__ == "PromptCredentialProvider"

    @pytest.mark.asyncio
    async def test_credential_provider_factory_from_dict(self):
        """Test factory with dictionary configuration."""
        config = {"type": "StaticCredentialProvider", "credential_value": "dict-value"}
        provider = await create_resource(CredentialProviderFactory, config)

        assert isinstance(provider, StaticCredentialProvider)
        assert await provider.get() == "dict-value"

    @pytest.mark.asyncio
    async def test_credential_provider_factory_invalid_type(self):
        """Test factory with invalid type raises error."""
        config = {"type": "InvalidCredentialProvider"}

        with pytest.raises(Exception):
            await create_resource(CredentialProviderFactory, config)
