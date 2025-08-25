import pytest

from naylence.fame.core import create_resource
from naylence.fame.security.auth.shared_secret_authorizer_factory import (
    SharedSecretAuthorizerConfig,
)
from naylence.fame.security.auth.shared_secret_token_provider_factory import (
    SharedSecretTokenProviderConfig,
)
from naylence.fame.security.auth.shared_secret_token_verifier_factory import (
    SharedSecretVerifierConfig,
)
from naylence.fame.security.auth.token_provider_factory import (
    TokenProviderFactory,
)
from naylence.fame.security.auth.token_verifier_factory import TokenVerifierFactory
from naylence.fame.security.credential.credential_provider_factory import (
    CredentialProviderFactory,
    StaticCredentialProviderConfig,
)


class MockNodeLike:
    """Mock NodeLike object for testing"""

    def __init__(self, node_id: str = "test-node", physical_path: str = "/test/system/path"):
        self._id = node_id
        self._physical_path = physical_path

    @property
    def id(self) -> str:
        return self._id

    @property
    def physical_path(self) -> str:
        return self._physical_path


class TestAuthenticationFactories:
    """Test that the authentication factories work correctly."""

    @pytest.mark.asyncio
    async def test_credential_provider_factory(self):
        """Test credential provider factory creates correct instances."""
        # Test static credential provider
        config = StaticCredentialProviderConfig(credential_value="value")
        provider = await create_resource(CredentialProviderFactory, config, type="StaticCredentialProvider")

        assert await provider.get() == "value"

    @pytest.mark.asyncio
    async def test_token_provider_factory(self):
        """Test token provider factory creates correct instances."""
        # Create token provider config using the new unified secret field
        config = SharedSecretTokenProviderConfig(
            secret=StaticCredentialProviderConfig(credential_value="test-token")
        )

        provider = await create_resource(TokenProviderFactory, config)
        token = await provider.get_token()

        assert token.value == "test-token"
        assert token.expires_at is not None

    @pytest.mark.asyncio
    async def test_token_verifier_factory(self):
        """Test welcome token verifier factory creates correct instances."""
        # Create credential provider config
        credential_config = StaticCredentialProviderConfig(credential_value="test-secret")

        # Create verifier config
        config = SharedSecretVerifierConfig(secret=credential_config)

        verifier = await create_resource(TokenVerifierFactory, config)
        claims = await verifier.verify("test-secret", expected_audience="test-aud")

        assert claims["sub"] == "*"
        assert claims["aud"] == "test-aud"
        assert claims["mode"] == "shared-secret"

    @pytest.mark.asyncio
    async def test_node_attach_authorizer_factory(self):
        """Test node attach authorizer factory creates correct instances."""
        # Create credential provider config
        credential_config = StaticCredentialProviderConfig(credential_value="test-secret")

        # Create authorizer config
        config = SharedSecretAuthorizerConfig(secret=credential_config)

        # Create the factory directly and use it to create the authorizer
        from naylence.fame.security.auth.shared_secret_authorizer_factory import (
            SharedSecretAuthorizerFactory,
        )

        factory = SharedSecretAuthorizerFactory()
        authorizer = await factory.create(config)

        # Test with a mock request
        from naylence.fame.core import NodeAttachFrame

        request = NodeAttachFrame(
            system_id="test-node",
            instance_id="test-instance",
            attach_token="test-secret",
        )

        # Use new two-phase API
        target_node = MockNodeLike(node_id="target-node")

        # First authenticate
        auth_context = await authorizer.authenticate(target_node, "test-secret")
        assert auth_context is not None

        # Then validate the node attach request
        result = await authorizer.validate_node_attach_request(target_node, request, auth_context)
        assert result is not None
        assert result.sub == "test-node"
        assert result.aud == "target-node"
