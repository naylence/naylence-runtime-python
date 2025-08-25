import pytest

from naylence.fame.security.credential import (
    EnvCredentialProvider,
    NoneCredentialProvider,
    StaticCredentialProvider,
)


class TestCredentialProviders:
    """Test the credential provider implementations."""

    @pytest.mark.asyncio
    async def test_none_credential_provider(self):
        """Test that NoneCredentialProvider always returns None."""
        provider = NoneCredentialProvider()
        result = await provider.get()
        assert result is None

    @pytest.mark.asyncio
    async def test_static_credential_provider(self):
        """Test StaticCredentialProvider returns configured value."""
        provider = StaticCredentialProvider("test_value")

        assert await provider.get() == "test_value"

    @pytest.mark.asyncio
    async def test_static_credential_provider_empty(self):
        """Test StaticCredentialProvider with None value."""
        provider = StaticCredentialProvider(None)
        assert await provider.get() is None

    @pytest.mark.asyncio
    async def test_env_credential_provider(self, monkeypatch):
        """Test EnvCredentialProvider reads from environment."""
        # Set up environment variable
        monkeypatch.setenv("TEST_CREDENTIAL", "test_value")

        provider = EnvCredentialProvider("TEST_CREDENTIAL")
        assert await provider.get() == "test_value"

        # Test with non-existent variable
        provider_nonexistent = EnvCredentialProvider("NONEXISTENT_VAR")
        assert await provider_nonexistent.get() is None
