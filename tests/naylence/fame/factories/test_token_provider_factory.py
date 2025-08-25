"""Test TokenProviderFactory to ensure configs resolve to correct subtypes."""

import pytest

from naylence.fame.core import create_resource
from naylence.fame.security.auth.none_token_provider import NoneTokenProvider
from naylence.fame.security.auth.oauth2_client_credentials_token_provider import (
    OAuth2ClientCredentialsTokenProvider,
)
from naylence.fame.security.auth.oauth2_client_credentials_token_provider_factory import (
    OAuth2ClientCredentialsTokenProviderConfig,
)
from naylence.fame.security.auth.shared_secret_token_provider import SharedSecretTokenProvider
from naylence.fame.security.auth.shared_secret_token_provider_factory import (
    SharedSecretTokenProviderConfig,
)
from naylence.fame.security.auth.token_provider_factory import (
    TokenProviderFactory,
)
from naylence.fame.security.credential.credential_provider_factory import StaticCredentialProviderConfig


class TestTokenProviderFactory:
    """Test TokenProviderFactory and its implementations."""

    @pytest.mark.asyncio
    async def test_none_token_provider_factory(self):
        """Test NoneTokenProvider factory creates correct instance."""
        config = {"type": "NoneTokenProvider"}
        provider = await create_resource(TokenProviderFactory, config)

        assert isinstance(provider, NoneTokenProvider)
        assert provider.__class__.__name__ == "NoneTokenProvider"
        token = await provider.get_token()
        assert token.value == ""
        assert token.expires_at is not None

    @pytest.mark.asyncio
    async def test_shared_secret_token_provider_factory(self):
        """Test SharedSecretTokenProvider factory creates correct instance."""
        config = SharedSecretTokenProviderConfig(
            secret=StaticCredentialProviderConfig(credential_value="test-secret")
        )
        provider = await create_resource(TokenProviderFactory, config)

        assert isinstance(provider, SharedSecretTokenProvider)
        assert provider.__class__.__name__ == "SharedSecretTokenProvider"
        token = await provider.get_token()
        assert token.value == "test-secret"
        assert token.expires_at is not None

    @pytest.mark.asyncio
    async def test_oauth2_client_credentials_token_provider_factory(self):
        """Test OAuth2ClientCredentialsTokenProvider factory creates correct instance."""
        config = OAuth2ClientCredentialsTokenProviderConfig(
            token_url="https://auth.example.com/token",
            client_id=StaticCredentialProviderConfig(credential_value="client-id"),
            client_secret=StaticCredentialProviderConfig(credential_value="client-secret"),
            scopes=["scope1", "scope2"],
        )
        provider = await create_resource(TokenProviderFactory, config)

        assert isinstance(provider, OAuth2ClientCredentialsTokenProvider)
        assert provider.__class__.__name__ == "OAuth2ClientCredentialsTokenProvider"
        # Note: Not testing actual token retrieval as it requires HTTP calls

    @pytest.mark.asyncio
    async def test_token_provider_factory_from_dict(self):
        """Test factory with dictionary configuration."""
        config = {
            "type": "SharedSecretTokenProvider",
            "secret": {"type": "StaticCredentialProvider", "credential_value": "dict-secret"},
        }
        provider = await create_resource(TokenProviderFactory, config)

        assert isinstance(provider, SharedSecretTokenProvider)
        token = await provider.get_token()
        assert token.value == "dict-secret"
        assert token.expires_at is not None

    @pytest.mark.asyncio
    async def test_token_provider_factory_invalid_type(self):
        """Test factory with invalid type raises error."""
        config = {"type": "InvalidTokenProvider"}

        with pytest.raises(Exception):
            await create_resource(TokenProviderFactory, config)

    @pytest.mark.asyncio
    async def test_oauth2_symmetric_client_credentials(self):
        """Test OAuth2 provider with symmetric client_id and client_secret handling."""
        config = OAuth2ClientCredentialsTokenProviderConfig(
            token_url="https://auth.example.com/token",
            client_id="plain-client-id",  # Plain string (should become StaticCredentialProviderConfig)
            client_secret="env://CLIENT_SECRET",  # Environment variable
            # (should become EnvCredentialProviderConfig)
            scopes=["test.scope"],
        )
        provider = await create_resource(TokenProviderFactory, config)

        assert isinstance(provider, OAuth2ClientCredentialsTokenProvider)
        # Both client_id and client_secret should be handled as credential providers
        assert hasattr(provider, "_client_id_provider")
        assert hasattr(provider, "_client_secret_provider")
        assert provider._client_id_provider is not None
        assert provider._client_secret_provider is not None
