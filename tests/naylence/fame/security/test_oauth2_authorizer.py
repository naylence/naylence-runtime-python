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
        auth_context = await authorizer.authenticate("mock-jwt-token")
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


@pytest.mark.asyncio
async def test_oauth2_authorizer_rejects_mismatched_node_identity():
    """Test OAuth2 authorizer rejects node attach when node identity doesn't match token subject"""
    config = OAuth2AuthorizerConfig(
        type="OAuth2Authorizer",
        issuer="https://auth.example.com",
        audience="fame-sentinel",
        required_scopes=["node.connect"],
        require_scope=True,
        default_ttl_sec=3600,
        enforce_token_subject_node_identity=True,
    )

    # Create an attach frame with a system_id that doesn't match token subject
    attach_frame = NodeAttachFrame(
        system_id="wrong-prefix-node",  # Should be fingerprint of 'oauth-client-id'
        instance_id="test-instance",
        attach_token="mock-jwt-token",
        accepted_logicals=["api.services.domain"],
        capabilities=["read", "write"],
        corr_id="test-corr-id",
    )

    mock_verifier = AsyncMock()
    mock_verifier.verify.return_value = {
        "iss": "https://auth.example.com",
        "aud": "fame-sentinel",
        "scope": "node.connect node.read",
        "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
        "iat": int(datetime.now(timezone.utc).timestamp()),
        "sub": "oauth-client-id",
    }

    factory = OAuth2AuthorizerFactory()

    with patch("naylence.fame.security.auth.oauth2_authorizer_factory.create_resource") as mock:
        mock.return_value = mock_verifier
        authorizer = await factory.create(config)

        target_node = MockNodeLike(physical_path="fame-sentinel")

        auth_context = await authorizer.authenticate("mock-jwt-token")
        result = await authorizer.validate_node_attach_request(target_node, attach_frame, auth_context)

        # Should reject because system_id doesn't match fingerprint of token subject
        assert result is None


@pytest.mark.asyncio
async def test_oauth2_authorizer_accepts_matching_node_identity():
    """Test OAuth2 authorizer accepts node attach when node identity matches token subject"""
    from naylence.fame.core import generate_id

    config = OAuth2AuthorizerConfig(
        type="OAuth2Authorizer",
        issuer="https://auth.example.com",
        audience="fame-sentinel",
        required_scopes=["node.connect"],
        require_scope=True,
        default_ttl_sec=3600,
        enforce_token_subject_node_identity=True,
    )

    token_subject = "oauth-client-id"
    expected_prefix = generate_id(mode="fingerprint", material=token_subject, length=8)

    # Create an attach frame with matching system_id
    attach_frame = NodeAttachFrame(
        system_id=f"{expected_prefix}-my-node",
        instance_id="test-instance",
        attach_token="mock-jwt-token",
        accepted_logicals=["api.services.domain"],
        capabilities=["read", "write"],
        corr_id="test-corr-id",
    )

    mock_verifier = AsyncMock()
    mock_verifier.verify.return_value = {
        "iss": "https://auth.example.com",
        "aud": "fame-sentinel",
        "scope": "node.connect node.read",
        "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
        "iat": int(datetime.now(timezone.utc).timestamp()),
        "sub": token_subject,
    }

    factory = OAuth2AuthorizerFactory()

    with patch("naylence.fame.security.auth.oauth2_authorizer_factory.create_resource") as mock:
        mock.return_value = mock_verifier
        authorizer = await factory.create(config)

        target_node = MockNodeLike(physical_path="fame-sentinel")

        auth_context = await authorizer.authenticate("mock-jwt-token")
        result = await authorizer.validate_node_attach_request(target_node, attach_frame, auth_context)

        # Should accept because system_id starts with fingerprint of token subject
        assert result is not None
        assert result.sub == token_subject


@pytest.mark.asyncio
async def test_oauth2_authorizer_trusted_client_bypasses_identity_check():
    """Test OAuth2 authorizer allows trusted clients to bypass identity enforcement"""
    config = OAuth2AuthorizerConfig(
        type="OAuth2Authorizer",
        issuer="https://auth.example.com",
        audience="fame-sentinel",
        required_scopes=["node.connect"],
        require_scope=True,
        default_ttl_sec=3600,
        enforce_token_subject_node_identity=True,
        trusted_client_scope="node.trusted",
    )

    # Create an attach frame with a system_id that doesn't match token subject
    attach_frame = NodeAttachFrame(
        system_id="arbitrary-node-id",  # Would normally fail identity check
        instance_id="test-instance",
        attach_token="mock-jwt-token",
        accepted_logicals=["api.services.domain"],
        capabilities=["read", "write"],
        corr_id="test-corr-id",
    )

    mock_verifier = AsyncMock()
    mock_verifier.verify.return_value = {
        "iss": "https://auth.example.com",
        "aud": "fame-sentinel",
        "scope": "node.connect node.trusted",  # Has trusted scope
        "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
        "iat": int(datetime.now(timezone.utc).timestamp()),
        "sub": "oauth-client-id",
    }

    factory = OAuth2AuthorizerFactory()

    with patch("naylence.fame.security.auth.oauth2_authorizer_factory.create_resource") as mock:
        mock.return_value = mock_verifier
        authorizer = await factory.create(config)

        target_node = MockNodeLike(physical_path="fame-sentinel")

        auth_context = await authorizer.authenticate("mock-jwt-token")
        result = await authorizer.validate_node_attach_request(target_node, attach_frame, auth_context)

        # Should accept because token has trusted scope, bypassing identity check
        assert result is not None
        assert result.sub == "oauth-client-id"


def test_oauth2_authorizer_config_enforce_flag_string_parsing():
    """Test that enforce_token_subject_node_identity parses string values"""
    # Test string "true"
    config1 = OAuth2AuthorizerConfig(
        type="OAuth2Authorizer",
        issuer="https://auth.example.com",
        enforce_token_subject_node_identity="true",  # type: ignore
    )
    assert config1.enforce_token_subject_node_identity is True

    # Test string "false"
    config2 = OAuth2AuthorizerConfig(
        type="OAuth2Authorizer",
        issuer="https://auth.example.com",
        enforce_token_subject_node_identity="false",  # type: ignore
    )
    assert config2.enforce_token_subject_node_identity is False

    # Test boolean True
    config3 = OAuth2AuthorizerConfig(
        type="OAuth2Authorizer",
        issuer="https://auth.example.com",
        enforce_token_subject_node_identity=True,
    )
    assert config3.enforce_token_subject_node_identity is True
