from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import pytest

from naylence.fame.core import NodeAttachFrame
from naylence.fame.security.auth.oauth2_authorizer_factory import (
    OAuth2AuthorizerConfig,
    OAuth2AuthorizerFactory,
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


@pytest.mark.asyncio
async def test_oauth2_authorizer_factory_creation():
    """Test OAuth2 authorizer factory creation"""
    config = OAuth2AuthorizerConfig(
        type="OAuth2Authorizer",
        issuer="https://auth.example.com",
        audience="fame-sentinel",
        required_scopes=["node.connect"],
        require_scope=True,
        default_ttl_sec=3600,
    )

    factory = OAuth2AuthorizerFactory()
    authorizer = await factory.create(config)

    assert authorizer is not None
    assert hasattr(authorizer, "_token_verifier")
    assert authorizer._token_verifier is not None


@pytest.mark.asyncio
async def test_oauth2_authorizer_jwks_url_derivation():
    """Test that JWKS URL is correctly derived from issuer"""
    config = OAuth2AuthorizerConfig(
        type="OAuth2Authorizer",
        issuer="https://auth.example.com/",  # with trailing slash
        audience="fame-sentinel",
        required_scopes=["node.connect"],
        require_scope=True,
        default_ttl_sec=3600,
    )

    factory = OAuth2AuthorizerFactory()

    # Mock the JWKS verifier to check the URL passed to it
    with patch("naylence.fame.security.auth.oauth2_authorizer_factory.create_resource") as mock_create:
        mock_verifier = AsyncMock()
        mock_create.return_value = mock_verifier

        await factory.create(config)

        # Check that create_resource was called with correct JWKS URL
        mock_create.assert_called_once()
        args = mock_create.call_args
        verifier_config = args[0][1]  # Second argument is the config

        assert verifier_config.jwks_url == "https://auth.example.com/.well-known/jwks.json"
        assert verifier_config.issuer == "https://auth.example.com/"


@pytest.mark.asyncio
async def test_oauth2_authorizer_custom_jwks_url():
    """Test that custom JWKS URL is used when provided"""
    custom_jwks = "https://custom.auth.com/jwks"
    config = OAuth2AuthorizerConfig(
        type="OAuth2Authorizer",
        issuer="https://auth.example.com",
        audience="fame-sentinel",
        jwks_url=custom_jwks,
        required_scopes=["node.connect"],
        require_scope=True,
        default_ttl_sec=3600,
    )

    factory = OAuth2AuthorizerFactory()

    with patch("naylence.fame.security.auth.oauth2_authorizer_factory.create_resource") as mock_create:
        mock_verifier = AsyncMock()
        mock_create.return_value = mock_verifier

        await factory.create(config)

        # Check that create_resource was called with custom JWKS URL
        args = mock_create.call_args
        verifier_config = args[0][1]

        assert verifier_config.jwks_url == custom_jwks


@pytest.mark.asyncio
async def test_oauth2_authorizer_authorization_flow():
    """Test OAuth2 authorizer authorization flow with mock JWT verification"""
    config = OAuth2AuthorizerConfig(
        type="OAuth2Authorizer",
        issuer="https://auth.example.com",
        audience="fame-sentinel",
        required_scopes=["node.connect"],
        require_scope=True,
        default_ttl_sec=3600,
    )

    # Create a mock attach frame
    attach_frame = NodeAttachFrame(
        system_id="test-system",
        instance_id="test-instance",
        attach_token="mock-jwt-token",
        accepted_logicals=["api.services.domain"],  # Using correct field name
        capabilities=["read", "write"],
        corr_id="test-corr-id",
    )

    # Mock the token verifier to return valid claims
    mock_verifier = AsyncMock()
    mock_verifier.verify.return_value = {
        "iss": "https://auth.example.com",
        "aud": "fame-sentinel",
        "scope": "node.connect node.read",  # Include required scope
        "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
        "iat": int(datetime.now(timezone.utc).timestamp()),
        "sub": "oauth-client-id",
    }

    factory = OAuth2AuthorizerFactory()

    with patch("naylence.fame.security.auth.oauth2_authorizer_factory.create_resource") as mock_create:
        mock_create.return_value = mock_verifier

        authorizer = await factory.create(config)

        # Create mock node
        target_node = MockNodeLike(physical_path="fame-sentinel")

        # First authenticate to get auth context
        auth_context = await authorizer.authenticate(target_node, "mock-jwt-token")
        assert auth_context is not None

        # Then validate the node attach request
        result = await authorizer.validate_node_attach_request(target_node, attach_frame, auth_context)

        assert result is not None
        assert result.sub == "oauth-client-id"  # Uses token sub claim
        assert result.instance_id == "test-instance"
        assert result.aud == target_node.id  # Uses target node id
        # The authorizer should pass through the logical addresses from the frame
        assert result.accepted_logicals == attach_frame.accepted_logicals
        assert result.accepted_capabilities == ["read", "write"]
        assert result.scopes is not None
        assert set(result.scopes) == {"node.connect", "node.read"}

        # Verify the token verifier was called with correct parameters
        mock_verifier.verify.assert_called_once_with("mock-jwt-token", expected_audience="fame-sentinel")


def test_oauth2_authorizer_config_validation():
    """Test OAuth2 authorizer config validation"""
    # Test valid config
    config = OAuth2AuthorizerConfig(
        type="OAuth2Authorizer",
        issuer="https://auth.example.com",
        audience="fame-sentinel",
        required_scopes=["node.connect"],
        require_scope=True,
        default_ttl_sec=3600,
    )

    assert config.type == "OAuth2Authorizer"
    assert config.issuer == "https://auth.example.com"
    assert config.audience == "fame-sentinel"
    assert config.required_scopes == ["node.connect"]
    assert config.require_scope is True
    assert config.default_ttl_sec == 3600
    assert config.max_ttl_sec == 86400  # default value
    assert config.algorithm == "RS256"  # default value


@pytest.mark.asyncio
async def test_oauth2_authorizer_factory_invalid_config():
    """Test OAuth2 authorizer factory with invalid config"""
    factory = OAuth2AuthorizerFactory()

    with pytest.raises(ValueError, match="OAuth2AuthorizerConfig is required"):
        await factory.create(None)

    # Test with wrong config type
    from naylence.fame.security.auth.authorizer_factory import AuthorizerConfig

    wrong_config = AuthorizerConfig(type="SomeOtherType")

    with pytest.raises(ValueError, match="OAuth2AuthorizerConfig is required"):
        await factory.create(wrong_config)
