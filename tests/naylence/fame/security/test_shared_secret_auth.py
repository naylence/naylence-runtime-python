import pytest

from naylence.fame.core import NodeAttachFrame
from naylence.fame.security.auth.shared_secret_authorizer import (
    SharedSecretAuthorizer,
)
from naylence.fame.security.auth.shared_secret_token_provider import (
    SharedSecretTokenProvider,
)
from naylence.fame.security.auth.shared_secret_token_verifier import (
    SharedSecretTokenVerifier,
)
from naylence.fame.security.credential import StaticCredentialProvider


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


class TestSharedSecretAuth:
    """Test shared secret authentication components."""

    @pytest.fixture
    def secret_credential_provider(self):
        """Create a credential provider with a test secret."""
        return StaticCredentialProvider("test-secret-123")

    @pytest.fixture
    def token_provider(self, secret_credential_provider):
        """Create a shared secret token provider."""
        return SharedSecretTokenProvider(secret_credential_provider)

    @pytest.fixture
    def token_verifier(self, secret_credential_provider):
        """Create a shared secret token verifier."""
        return SharedSecretTokenVerifier(secret_credential_provider)

    @pytest.fixture
    def authorizer(self, secret_credential_provider):
        """Create a shared secret node attach authorizer."""
        return SharedSecretAuthorizer(secret_credential_provider)

    @pytest.mark.asyncio
    async def test_token_provider_success(self, token_provider):
        """Test that token provider returns the correct secret."""
        token = await token_provider.get_token()
        assert token.value == "test-secret-123"
        assert token.expires_at is not None

    @pytest.mark.asyncio
    async def test_token_verifier_success(self, token_verifier):
        """Test that token verifier accepts valid tokens."""
        claims = await token_verifier.verify("test-secret-123", expected_audience="test-audience")
        assert claims["sub"] == "*"
        assert claims["aud"] == "test-audience"
        assert claims["mode"] == "shared-secret"

    @pytest.mark.asyncio
    async def test_token_verifier_invalid_token(self, token_verifier):
        """Test that token verifier rejects invalid tokens."""
        with pytest.raises(ValueError, match="Invalid shared secret token"):
            await token_verifier.verify("wrong-secret")

    @pytest.mark.asyncio
    async def test_authorizer_success(self, authorizer):
        """Test that authorizer accepts valid attach requests."""
        request = NodeAttachFrame(
            system_id="child-node",
            instance_id="instance-1",
            assigned_path="/test/path",
            capabilities=["cap1", "cap2"],
            accepted_logicals=["path1.logical"],
            attach_token="test-secret-123",
        )

        # First authenticate to get auth context
        auth_context = await authorizer.authenticate(MockNodeLike(node_id="parent-node"), "test-secret-123")
        assert auth_context is not None

        # Then validate the node attach request
        result = await authorizer.validate_node_attach_request(
            MockNodeLike(node_id="parent-node"), request, auth_context
        )
        assert result is not None
        assert result.sub == "child-node"
        assert result.aud == "parent-node"
        assert result.instance_id == "instance-1"
        assert result.assigned_path == "/test/path"
        assert result.accepted_capabilities == ["cap1", "cap2"]
        assert result.accepted_logicals == ["path1.logical"]

    @pytest.mark.asyncio
    async def test_authorizer_invalid_token(self, authorizer):
        """Test that authorizer rejects invalid tokens."""
        NodeAttachFrame(
            system_id="child-node",
            instance_id="instance-1",
            attach_token="wrong-secret",
        )

        # Try to authenticate with wrong token
        auth_context = await authorizer.authenticate(MockNodeLike(node_id="parent-node"), "wrong-secret")
        assert auth_context is None

    @pytest.mark.asyncio
    async def test_authorizer_no_token(self, authorizer):
        """Test that authorizer rejects requests without tokens."""
        NodeAttachFrame(
            system_id="child-node",
            instance_id="instance-1",
        )

        # Try to authenticate with no credentials
        auth_context = await authorizer.authenticate(MockNodeLike(node_id="parent-node"), "")
        assert auth_context is None
