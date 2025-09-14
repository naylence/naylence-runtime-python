"""
Test authorizer integration with SecurityManager.
"""

import pytest

from naylence.fame.delivery.default_delivery_tracker_factory import (
    DefaultDeliveryTrackerFactory,
)
from naylence.fame.security.auth.default_authorizer import DefaultAuthorizer
from naylence.fame.security.policy.default_security_policy import DefaultSecurityPolicy
from naylence.fame.security.security_manager_factory import SecurityManagerFactory
from naylence.fame.sentinel.sentinel import Sentinel
from naylence.fame.storage.in_memory_storage_provider import InMemoryStorageProvider


class TestAuthorizerIntegration:
    """Test the integration of authorizer with SecurityManager."""

    @pytest.mark.asyncio
    async def test_authorizer_via_node_security(self):
        """Test that authorizer can be provided through SecurityManager."""
        # Create a custom authorizer
        custom_authorizer = DefaultAuthorizer()

        # Create SecurityManager with the authorizer
        node_security = await SecurityManagerFactory.create_security_manager(
            policy=DefaultSecurityPolicy(), authorizer=custom_authorizer
        )

        # Verify the authorizer is in SecurityManager
        assert node_security.authorizer is custom_authorizer

        # Create a Sentinel with this SecurityManager
        storage_provider = InMemoryStorageProvider()
        delivery_tracker_factory = DefaultDeliveryTrackerFactory()
        delivery_tracker = await delivery_tracker_factory.create(storage_provider=storage_provider)

        sentinel = Sentinel(
            security_manager=node_security,
            storage_provider=storage_provider,
            delivery_tracker=delivery_tracker,
        )

        # Verify the Sentinel uses the authorizer from SecurityManager
        assert sentinel._security_manager.authorizer is custom_authorizer

    @pytest.mark.asyncio
    async def test_sentinel_without_authorizer_in_node_security(self):
        """Test that Sentinel works when SecurityManager automatically provides an authorizer."""
        # Create SecurityManager without explicit authorizer - should auto-provide one
        node_security = await SecurityManagerFactory.create_security_manager(DefaultSecurityPolicy())

        # Verify SecurityManager automatically provided an authorizer
        assert node_security.authorizer is not None
        assert isinstance(node_security.authorizer, DefaultAuthorizer)

        # Create a Sentinel with this NodeSecurity
        storage_provider = InMemoryStorageProvider()
        delivery_tracker_factory = DefaultDeliveryTrackerFactory()
        delivery_tracker = await delivery_tracker_factory.create(storage_provider=storage_provider)

        sentinel = Sentinel(
            security_manager=node_security,
            storage_provider=storage_provider,
            delivery_tracker=delivery_tracker,
        )

        # Verify the Sentinel uses the authorizer from NodeSecurity
        assert sentinel._security_manager.authorizer is node_security.authorizer
        assert isinstance(sentinel._security_manager.authorizer, DefaultAuthorizer)

    @pytest.mark.asyncio
    async def test_node_security_authorizer_fallback(self):
        """Test that SecurityManager properly handles authorizer fallback scenarios."""
        # Create a custom authorizer
        custom_authorizer = DefaultAuthorizer()

        # Test 1: SecurityManager with explicit authorizer
        node_security_with_auth = await SecurityManagerFactory.create_security_manager(
            policy=DefaultSecurityPolicy(), authorizer=custom_authorizer
        )

        storage_provider = InMemoryStorageProvider()
        delivery_tracker_factory = DefaultDeliveryTrackerFactory()
        delivery_tracker = await delivery_tracker_factory.create(storage_provider=storage_provider)

        sentinel_with_auth = Sentinel(
            security_manager=node_security_with_auth,
            storage_provider=storage_provider,
            delivery_tracker=delivery_tracker,
        )
        assert sentinel_with_auth._security_manager.authorizer is custom_authorizer

        # Test 2: SecurityManager without authorizer (should fallback to default)
        node_security_no_auth = await SecurityManagerFactory.create_security_manager(
            DefaultSecurityPolicy()
        )

        sentinel_no_auth = Sentinel(
            security_manager=node_security_no_auth,
            storage_provider=storage_provider,
            delivery_tracker=delivery_tracker,
        )
        assert sentinel_no_auth._security_manager.authorizer is not None
        assert isinstance(sentinel_no_auth._security_manager.authorizer, DefaultAuthorizer)

    @pytest.mark.asyncio
    async def test_node_security_includes_authorizer_field(self):
        """Test that SecurityManager properly includes the authorizer field."""
        # Test with explicit authorizer
        authorizer = DefaultAuthorizer()
        node_security_with_auth = await SecurityManagerFactory.create_security_manager(
            DefaultSecurityPolicy(), authorizer=authorizer
        )
        assert node_security_with_auth.authorizer is authorizer

        # Test without explicit authorizer - should auto-provide one due to policy
        node_security_auto_auth = await SecurityManagerFactory.create_security_manager(
            DefaultSecurityPolicy()
        )
        assert node_security_auto_auth.authorizer is not None
        assert isinstance(node_security_auto_auth.authorizer, DefaultAuthorizer)
