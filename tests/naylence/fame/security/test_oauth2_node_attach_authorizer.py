from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from naylence.fame.core import DeliveryOriginType, NodeAttachFrame, create_fame_envelope
from naylence.fame.security.auth.oauth2_authorizer import OAuth2Authorizer
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
async def test_oauth2_node_attach_authorizer_success():
    """Test OAuth2Authorizer with valid token and scopes"""
    # Mock token verifier
    mock_verifier = AsyncMock()
    mock_verifier.verify.return_value = {
        "iss": "https://auth.example.com",
        "aud": "fame-sentinel",
        "scope": "node.connect node.read",
        "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
        "iat": int(datetime.now(timezone.utc).timestamp()),
        "sub": "oauth-client-id",
    }

    authorizer = OAuth2Authorizer(
        token_verifier=mock_verifier,
        audience="fame-sentinel",
        required_scopes=["node.connect"],
        require_scope=True,
        default_ttl_sec=3600,
    )

    # Create attach frame
    attach_frame = NodeAttachFrame(
        system_id="test-system",
        instance_id="test-instance",
        attach_token="mock-jwt-token",
        accepted_logicals=["api.services.domain"],
        capabilities=["read", "write"],
        corr_id="test-corr-id",
    )

    # Create mock node
    target_node = MockNodeLike(physical_path="fame-sentinel")

    # First authenticate to get auth context
    auth_context = await authorizer.authenticate("mock-jwt-token")
    assert auth_context is not None

    # Then validate the node attach request
    result = await authorizer.validate_node_attach_request(target_node, attach_frame, auth_context)
    assert result is not None
    assert result.sub == "oauth-client-id"  # Uses token sub claim
    assert result.instance_id == "test-instance"
    assert result.aud == target_node.id
    assert result.accepted_logicals == ["api.services.domain"]
    assert result.accepted_capabilities == ["read", "write"]
    assert result.scopes is not None
    assert set(result.scopes) == {"node.connect", "node.read"}

    # Verify token verifier was called correctly
    mock_verifier.verify.assert_called_once_with("mock-jwt-token", expected_audience="fame-sentinel")


@pytest.mark.asyncio
async def test_oauth2_node_attach_authorizer_insufficient_scopes():
    """Test OAuth2Authorizer with insufficient scopes"""
    mock_verifier = AsyncMock()
    mock_verifier.verify.return_value = {
        "iss": "https://auth.example.com",
        "aud": "fame-sentinel",
        "scope": "profile email",  # Missing required scope
        "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
        "sub": "oauth-client-id",
    }

    authorizer = OAuth2Authorizer(
        token_verifier=mock_verifier,
        audience="fame-sentinel",
        required_scopes=["node.connect"],
        require_scope=True,
    )

    attach_frame = NodeAttachFrame(
        system_id="test-system",
        instance_id="test-instance",
        attach_token="mock-jwt-token",
        corr_id="test-corr-id",
    )

    # Test authorization - should fail due to insufficient scopes
    env = create_fame_envelope(frame=attach_frame)
    result = await authorizer.authorize("fame-sentinel", env)

    assert result is None


@pytest.mark.asyncio
async def test_oauth2_node_attach_authorizer_no_scope_requirement():
    """Test OAuth2Authorizer with scope requirement disabled"""
    mock_verifier = AsyncMock()
    mock_verifier.verify.return_value = {
        "iss": "https://auth.example.com",
        "aud": "fame-sentinel",
        "scope": "profile email",  # Different scopes, but requirement is disabled
        "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
        "sub": "oauth-client-id",
    }

    authorizer = OAuth2Authorizer(
        token_verifier=mock_verifier,
        audience="fame-sentinel",
        required_scopes=["node.connect"],
        require_scope=False,  # Disabled scope requirement
    )

    attach_frame = NodeAttachFrame(
        system_id="test-system",
        instance_id="test-instance",
        attach_token="mock-jwt-token",
        corr_id="test-corr-id",
    )

    # Create mock node
    target_node = MockNodeLike(physical_path="fame-sentinel")

    # First authenticate to get auth context
    auth_context = await authorizer.authenticate("mock-jwt-token")
    assert auth_context is not None

    # Then validate the node attach request - should succeed despite different scopes
    result = await authorizer.validate_node_attach_request(target_node, attach_frame, auth_context)

    assert result is not None
    assert result.sub == "oauth-client-id"  # Uses token sub claim
    assert result.scopes is not None
    assert set(result.scopes) == {"profile", "email"}


@pytest.mark.asyncio
async def test_oauth2_node_attach_authorizer_token_verification_failure():
    """Test OAuth2Authorizer with token verification failure"""
    mock_verifier = AsyncMock()
    mock_verifier.verify.side_effect = Exception("Invalid token signature")

    authorizer = OAuth2Authorizer(
        token_verifier=mock_verifier,
        audience="fame-sentinel",
        required_scopes=["node.connect"],
        require_scope=True,
    )

    NodeAttachFrame(
        system_id="test-system",
        instance_id="test-instance",
        attach_token="invalid-jwt-token",
        corr_id="test-corr-id",
    )

    # Create mock node
    MockNodeLike(physical_path="fame-sentinel")

    # Try to authenticate with invalid token - should fail
    auth_context = await authorizer.authenticate("mock-jwt-token")
    assert auth_context is None


@pytest.mark.asyncio
async def test_oauth2_node_attach_authorizer_missing_token():
    """Test OAuth2Authorizer with missing token"""
    mock_verifier = AsyncMock()

    authorizer = OAuth2Authorizer(
        token_verifier=mock_verifier,
        audience="fame-sentinel",
        required_scopes=["node.connect"],
        require_scope=True,
    )

    NodeAttachFrame(
        system_id="test-system",
        instance_id="test-instance",
        attach_token="",  # Empty token
        corr_id="test-corr-id",
    )

    # Create mock node
    MockNodeLike(physical_path="fame-sentinel")

    # Try to authenticate with empty token - should fail
    auth_context = await authorizer.authenticate("")
    assert auth_context is None


def test_oauth2_node_attach_authorizer_scope_extraction():
    """Test scope extraction from various claim formats"""
    mock_verifier = AsyncMock()

    authorizer = OAuth2Authorizer(
        token_verifier=mock_verifier,
        audience="fame-sentinel",
        required_scopes=["node.connect"],
        require_scope=True,
    )

    # Test space-separated scope string (OAuth2 standard)
    claims = {"scope": "node.connect node.read profile"}
    scopes = authorizer._extract_scopes_from_claims(claims)
    assert scopes == {"node.connect", "node.read", "profile"}

    # Test scope array (some providers use this)
    claims = {"scopes": ["node.connect", "node.read", "profile"]}
    scopes = authorizer._extract_scopes_from_claims(claims)
    assert scopes == {"node.connect", "node.read", "profile"}

    # Test both fields present (should combine)
    claims = {"scope": "node.connect node.read", "scopes": ["profile", "email"]}
    scopes = authorizer._extract_scopes_from_claims(claims)
    assert scopes == {"node.connect", "node.read", "profile", "email"}

    # Test no scopes
    claims = {}
    scopes = authorizer._extract_scopes_from_claims(claims)
    assert scopes == set()


@pytest.mark.asyncio
async def test_oauth2_node_attach_authorizer_invalid_frame_type():
    """Test OAuth2Authorizer with invalid frame type"""
    mock_verifier = AsyncMock()
    mock_verifier.verify.return_value = {
        "iss": "https://auth.example.com",
        "aud": "fame-sentinel",
        "scope": "node.connect node.read",
        "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
        "sub": "oauth-client-id",
    }

    authorizer = OAuth2Authorizer(
        token_verifier=mock_verifier,
        audience="fame-sentinel",
        required_scopes=["node.connect"],
        require_scope=True,
    )

    # Create mock node and auth context
    target_node = MockNodeLike(physical_path="fame-sentinel")
    await authorizer.authenticate("mock-jwt-token")

    # Create invalid frame type
    invalid_frame = MagicMock()

    # Create mock node
    target_node = MockNodeLike(physical_path="fame-sentinel")

    # The old interface should return None for invalid frame types
    result = await authorizer.authorize(target_node, invalid_frame)
    assert result is None


@pytest.mark.asyncio
async def test_oauth2_node_attach_authorizer_factory_integration():
    """Test OAuth2Authorizer through factory"""
    config = OAuth2AuthorizerConfig(
        type="OAuth2Authorizer",
        issuer="https://auth.example.com",
        audience="fame-sentinel",
        required_scopes=["node.connect", "node.read"],
        require_scope=True,
        default_ttl_sec=1800,
        max_ttl_sec=7200,
    )

    factory = OAuth2AuthorizerFactory()

    with patch("naylence.fame.security.auth.oauth2_authorizer_factory.create_resource") as mock_create:
        mock_verifier = AsyncMock()
        mock_create.return_value = mock_verifier

        authorizer = await factory.create(config)

        assert isinstance(authorizer, OAuth2Authorizer)
        assert authorizer._required_scopes == {"node.connect", "node.read"}
        assert authorizer._require_scope is True
        assert authorizer._default_ttl_sec == 1800
        assert authorizer._max_ttl_sec == 7200

        # Verify the JWKS verifier config was created correctly
        mock_create.assert_called_once()
        verifier_config = mock_create.call_args[0][1]
        assert verifier_config.jwks_url == "https://auth.example.com/.well-known/jwks.json"
        assert verifier_config.issuer == "https://auth.example.com"


@pytest.mark.asyncio
async def test_oauth2_node_attach_authorizer_with_multiple_required_scopes():
    """Test OAuth2Authorizer with multiple allowed scopes"""
    mock_verifier = AsyncMock()
    mock_verifier.verify.return_value = {
        "iss": "https://auth.example.com",
        "aud": "fame-sentinel",
        "scope": "profile node.read email",  # Has one of the allowed scopes
        "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
        "sub": "oauth-client-id",
    }

    authorizer = OAuth2Authorizer(
        token_verifier=mock_verifier,
        audience="fame-sentinel",
        required_scopes=["node.connect", "node.read", "node.write"],  # Multiple allowed
        require_scope=True,
    )

    attach_frame = NodeAttachFrame(
        system_id="test-system",
        instance_id="test-instance",
        attach_token="mock-jwt-token",
        corr_id="test-corr-id",
    )

    # Create mock node
    target_node = MockNodeLike(physical_path="fame-sentinel")

    # First authenticate to get auth context
    auth_context = await authorizer.authenticate("mock-jwt-token")
    assert auth_context is not None

    # Should succeed because token has "node.read" which is in allowed scopes
    result = await authorizer.validate_node_attach_request(target_node, attach_frame, auth_context)

    assert result is not None
    assert result.sub == "oauth-client-id"  # Uses token sub claim
    assert result.scopes is not None
    assert "node.read" in result.scopes


@pytest.mark.asyncio
async def test_oauth2_node_attach_authorizer_factory_with_no_audience():
    """Test OAuth2Authorizer factory with no audience configured"""
    config = OAuth2AuthorizerConfig(
        type="OAuth2Authorizer",
        issuer="https://auth.example.com",
        # No audience specified - should be None
        required_scopes=["node.connect", "node.read"],
        require_scope=True,
    )

    factory = OAuth2AuthorizerFactory()

    with patch("naylence.fame.security.auth.oauth2_authorizer_factory.create_resource") as mock_create:
        mock_verifier = AsyncMock()
        mock_create.return_value = mock_verifier

        authorizer = await factory.create(config)

        assert isinstance(authorizer, OAuth2Authorizer)
        assert authorizer._audience is None  # Should be None when not configured
        assert authorizer._required_scopes == {"node.connect", "node.read"}
        assert authorizer._require_scope is True

        # Verify the JWKS verifier config was created correctly
        mock_create.assert_called_once()
        verifier_config = mock_create.call_args[0][1]
        assert verifier_config.jwks_url == "https://auth.example.com/.well-known/jwks.json"
        assert verifier_config.issuer == "https://auth.example.com"


@pytest.mark.asyncio
async def test_oauth2_node_attach_authorizer_default_audience_to_target_system_id():
    """Test that audience defaults to target_system_id when not provided"""

    # Create mock verifier that tracks expected audience
    mock_verifier = AsyncMock()

    # Mock successful token verification
    mock_verifier.verify.return_value = {
        "sub": "test-subject",
        "aud": "/test/system/path",  # This should match target_system_id
        "iss": "https://test-issuer.com",
        "exp": 9999999999,
        "scope": "connect manage",
    }

    # Create authorizer with NO audience configured (should default to target_system_id)
    authorizer = OAuth2Authorizer(
        token_verifier=mock_verifier,
        audience=None,  # No audience configured
        required_scopes=["connect", "manage"],
        require_scope=True,
    )

    # Create test frame
    frame = NodeAttachFrame(
        system_id="test-system",
        instance_id="test-instance",
        attach_token="valid.jwt.token",
        origin_type=DeliveryOriginType.DOWNSTREAM,
    )

    target_node = MockNodeLike(physical_path="/test/system/path")

    # Simulate the NodeEventListener callback - this is required in the new architecture
    await authorizer.on_node_started(target_node)

    # First authenticate to get auth context
    auth_context = await authorizer.authenticate("valid.jwt.token")
    assert auth_context is not None

    # Then validate the node attach request
    result = await authorizer.validate_node_attach_request(target_node, frame, auth_context)
    assert result is not None

    # Verify that the token verifier was called with target_node.physical_path as audience
    mock_verifier.verify.assert_called_once_with(
        "valid.jwt.token",
        expected_audience=target_node.physical_path,  # Should use target_node.physical_path as audience
    )

    # Verify successful authorization
    assert result is not None
    assert result.sub == "test-subject"  # Uses token sub claim
    assert result.aud == target_node.id  # Uses target node id
    assert result.instance_id == "test-instance"
    assert "connect" in result.scopes
    assert "manage" in result.scopes


@pytest.mark.asyncio
async def test_oauth2_node_attach_authorizer_configured_audience_overrides_default():
    """Test that configured audience overrides the default target_system_id"""

    # Create mock verifier that tracks expected audience
    mock_verifier = AsyncMock()

    # Mock successful token verification
    mock_verifier.verify.return_value = {
        "sub": "test-subject",
        "aud": "https://api.example.com",  # This should match configured audience
        "iss": "https://test-issuer.com",
        "exp": 9999999999,
        "scope": "connect manage",
    }

    # Create authorizer with CONFIGURED audience
    configured_audience = "https://api.example.com"
    authorizer = OAuth2Authorizer(
        token_verifier=mock_verifier,
        audience=configured_audience,  # Explicit audience configured
        required_scopes=["connect", "manage"],
        require_scope=True,
    )

    # Create test frame
    frame = NodeAttachFrame(
        system_id="test-system",
        instance_id="test-instance",
        attach_token="valid.jwt.token",
        origin_type=DeliveryOriginType.DOWNSTREAM,
    )

    target_node = MockNodeLike(physical_path="/test/system/path")

    # First authenticate to get auth context
    auth_context = await authorizer.authenticate("valid.jwt.token")
    assert auth_context is not None

    # Then validate the node attach request
    result = await authorizer.validate_node_attach_request(target_node, frame, auth_context)
    assert result is not None

    # Verify that the token verifier was called with CONFIGURED audience, not target_node.physical_path
    mock_verifier.verify.assert_called_once_with(
        "valid.jwt.token",
        expected_audience=configured_audience,  # Should use configured audience
    )

    # Verify successful authorization
    assert result is not None
    assert result.sub == "test-subject"  # Uses token sub claim
    assert result.aud == target_node.id  # Uses target node id
    assert result.instance_id == "test-instance"
