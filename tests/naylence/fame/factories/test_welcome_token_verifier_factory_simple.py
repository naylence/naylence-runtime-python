"""Test TokenVerifierFactory to ensure configs resolve to correct subtypes."""

import pytest

from naylence.fame.factory import create_resource
from naylence.fame.security.auth.noop_token_verifier import NoopTokenVerifier
from naylence.fame.security.auth.noop_token_verifier_factory import (
    NoopTokenVerifierConfig,
)
from naylence.fame.security.auth.shared_secret_token_verifier import (
    SharedSecretTokenVerifier,
)
from naylence.fame.security.auth.shared_secret_token_verifier_factory import (
    SharedSecretVerifierConfig,
)
from naylence.fame.security.auth.token_verifier_factory import TokenVerifierFactory
from naylence.fame.security.credential.credential_provider_factory import (
    StaticCredentialProviderConfig,
)


class TestTokenVerifierFactory:
    """Test TokenVerifierFactory and its implementations."""

    @pytest.mark.asyncio
    async def test_noop_token_verifier_factory(self):
        """Test NoopTokenVerifier factory creates correct instance."""
        config = NoopTokenVerifierConfig()
        verifier = await create_resource(TokenVerifierFactory, config)

        assert isinstance(verifier, NoopTokenVerifier)
        assert verifier.__class__.__name__ == "NoopTokenVerifier"

    @pytest.mark.asyncio
    async def test_shared_secret_token_verifier_factory(self):
        """Test SharedSecretTokenVerifier factory creates correct instance."""
        config = SharedSecretVerifierConfig(
            secret=StaticCredentialProviderConfig(credential_value="test-secret")
        )
        verifier = await create_resource(TokenVerifierFactory, config)

        assert isinstance(verifier, SharedSecretTokenVerifier)
        assert verifier.__class__.__name__ == "SharedSecretTokenVerifier"

    @pytest.mark.asyncio
    async def test_token_verifier_factory_from_dict(self):
        """Test factory with dictionary configuration."""
        config = {"type": "NoopTokenVerifier"}
        verifier = await create_resource(TokenVerifierFactory, config)

        assert isinstance(verifier, NoopTokenVerifier)

    @pytest.mark.asyncio
    async def test_shared_secret_verifier_factory_from_dict(self):
        """Test SharedSecret factory with dictionary configuration."""
        config = {
            "type": "SharedSecretTokenVerifier",
            "secret": {
                "type": "StaticCredentialProvider",
                "credential_value": "test-secret",
            },
        }
        verifier = await create_resource(TokenVerifierFactory, config)

        assert isinstance(verifier, SharedSecretTokenVerifier)
        assert verifier.__class__.__name__ == "SharedSecretTokenVerifier"
