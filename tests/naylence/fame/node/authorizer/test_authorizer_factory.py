#!/usr/bin/env python3
"""
Test the generic Authorizer factory implementation.
"""

from unittest.mock import MagicMock

import pytest

from naylence.fame.core import FameEnvelope
from naylence.fame.core.protocol.delivery_context import AuthorizationContext
from naylence.fame.factory import ExtensionManager, create_resource
from naylence.fame.security.auth.authorizer import Authorizer
from naylence.fame.security.auth.authorizer_factory import (
    AuthorizerFactory,
)
from naylence.fame.security.auth.noop_authorizer import NoopAuthorizer
from naylence.fame.security.auth.noop_authorizer_factory import (
    NoopAuthorizerConfig,
    NoopAuthorizerFactory,
)


class TestAuthorizerFactory:
    """Test the generic Authorizer factory and its implementations."""

    def setup_method(self):
        """Set up the extension manager for each test."""
        ExtensionManager.lazy_init(group="naylence.AuthorizerFactory", base_type=AuthorizerFactory)

    def test_noop_authorizer_config(self):
        """Test NoopAuthorizerConfig creation and validation."""
        config = NoopAuthorizerConfig()
        assert config.type == "NoopAuthorizer"

    @pytest.mark.asyncio
    async def test_noop_authorizer_factory_creation(self):
        """Test NoopAuthorizerFactory creates correct instance."""
        config = NoopAuthorizerConfig()
        factory = NoopAuthorizerFactory()

        authorizer = await factory.create(config)

        assert isinstance(authorizer, NoopAuthorizer)
        assert isinstance(authorizer, Authorizer)

    @pytest.mark.asyncio
    async def test_noop_authorizer_via_resource_factory(self):
        """Test creating NoopAuthorizer via the resource factory system."""
        config = NoopAuthorizerConfig()

        authorizer = await create_resource(AuthorizerFactory, config)

        assert isinstance(authorizer, NoopAuthorizer)
        assert isinstance(authorizer, Authorizer)

    @pytest.mark.asyncio
    async def test_noop_authorizer_authorization_behavior(self):
        """Test NoopAuthorizer allows all requests."""
        authorizer = NoopAuthorizer()

        # Mock node and envelope
        mock_node = MagicMock()
        mock_envelope = MagicMock(spec=FameEnvelope)

        # Test with no existing auth context
        result = await authorizer.authorize(mock_node, mock_envelope, None)
        assert isinstance(result, AuthorizationContext)

        # Test with existing auth context
        existing_context = AuthorizationContext()
        result = await authorizer.authorize(mock_node, mock_envelope, existing_context)
        assert result is existing_context

    @pytest.mark.asyncio
    async def test_factory_with_dict_config(self):
        """Test factory creation with dictionary configuration."""
        config_dict = {"type": "NoopAuthorizer"}

        factory = NoopAuthorizerFactory()
        authorizer = await factory.create(config_dict)

        assert isinstance(authorizer, NoopAuthorizer)

    def test_authorizer_protocol_compliance(self):
        """Test that NoopAuthorizer implements the Authorizer protocol correctly."""
        authorizer = NoopAuthorizer()

        # Check that it has the required methods
        assert hasattr(authorizer, "authorize")
        assert callable(authorizer.authorize)

        # Verify it's recognized as implementing the protocol
        assert isinstance(authorizer, Authorizer)


if __name__ == "__main__":
    pytest.main([__file__])
