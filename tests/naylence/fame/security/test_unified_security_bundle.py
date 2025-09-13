#!/usr/bin/env python3
"""
Test the final unified security bundle approach.
"""

import pytest

from naylence.fame.delivery.default_delivery_tracker_factory import (
    DefaultDeliveryTrackerFactory,
)
from naylence.fame.security.auth.default_authorizer import DefaultAuthorizer
from naylence.fame.security.policy.default_security_policy import DefaultSecurityPolicy
from naylence.fame.security.security_manager_factory import SecurityManagerFactory
from naylence.fame.sentinel.sentinel import Sentinel
from naylence.fame.sentinel.sentinel_factory import SentinelConfig, SentinelFactory
from naylence.fame.storage.in_memory_storage_provider import InMemoryStorageProvider


@pytest.mark.asyncio
async def test_unified_security_bundle():
    """Test that the unified security bundle approach works correctly."""
    print("Testing unified security bundle approach...")

    # Test 1: Direct Sentinel creation with SecurityManager containing authorizer
    print("\n1. Testing direct Sentinel creation with SecurityManager...")

    custom_authorizer = DefaultAuthorizer()
    node_security = await SecurityManagerFactory.create_security_manager(
        policy=DefaultSecurityPolicy(), authorizer=custom_authorizer
    )

    storage_provider = InMemoryStorageProvider()
    delivery_tracker_factory = DefaultDeliveryTrackerFactory()
    delivery_tracker = await delivery_tracker_factory.create(storage_provider=storage_provider)
    
    sentinel = Sentinel(
        security_manager=node_security, 
        storage_provider=storage_provider,
        delivery_tracker=delivery_tracker,
    )
    assert sentinel._security_manager.authorizer is custom_authorizer
    print("✓ Direct Sentinel creation works with SecurityManager containing authorizer")

    # Test 2: Sentinel without explicit SecurityManager
    # (should automatically get no-op authorizer from NoSecurityManager)
    print("\n2. Testing Sentinel without explicit SecurityManager...")

    storage_provider2 = InMemoryStorageProvider()
    delivery_tracker_factory2 = DefaultDeliveryTrackerFactory()
    delivery_tracker2 = await delivery_tracker_factory2.create(storage_provider=storage_provider2)
    
    sentinel_default = Sentinel(
        storage_provider=storage_provider2,
        delivery_tracker=delivery_tracker2,
    )
    assert sentinel_default._security_manager.authorizer is not None
    # With NoSecurityManager as default, we get NoopAuthorizer
    from naylence.fame.security.auth.noop_authorizer import NoopAuthorizer

    assert isinstance(sentinel_default._security_manager.authorizer, NoopAuthorizer)
    print("✓ Sentinel without explicit SecurityManager gets no-op authorizer from NoSecurityManager")

    # Test 3: SecurityManager should automatically provide authorizer when policy requires it
    print("\n3. Testing SecurityManager automatic authorizer provision...")

    node_security_auto = await SecurityManagerFactory.create_security_manager(DefaultSecurityPolicy())
    assert node_security_auto.authorizer is not None
    assert isinstance(node_security_auto.authorizer, DefaultAuthorizer)
    print("✓ SecurityManager automatically provides authorizer when policy requires it")

    print("\n🎉 All unified security bundle tests passed!")


@pytest.mark.asyncio
async def test_unified_security_bundle_async():
    """Test that the unified security bundle approach works correctly with async factory."""
    print("Testing unified security bundle approach with async factory...")

    # Test SentinelFactory approach (async)
    print("\n1. Testing SentinelFactory approach...")

    factory = SentinelFactory()
    config = SentinelConfig()

    # This should create a Sentinel with SecurityManager containing authorizer
    sentinel_from_factory = await factory.create(config)

    assert sentinel_from_factory is not None
    assert sentinel_from_factory._security_manager.authorizer is not None
    assert isinstance(sentinel_from_factory._security_manager.authorizer, DefaultAuthorizer)
    print("✓ SentinelFactory creates Sentinel with SecurityManager containing authorizer")

    print("\n🎉 All async unified security bundle tests passed!")


if __name__ == "__main__":
    test_unified_security_bundle()

    # For async test, we need asyncio
    import asyncio

    asyncio.run(test_unified_security_bundle_async())
