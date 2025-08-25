"""
Test storage provider integration with nodes.

This test validates that:
1. FameNodeConfig accepts storage_provider configuration
2. FameNode gets storage_provider instance in constructor
3. NodeLike.storage_provider property works
4. Extension point registration works for InMemoryStorageProvider
"""

import pytest
from pydantic import BaseModel

from naylence.fame.node.node_config import FameNodeConfig
from naylence.fame.node.node_factory import NodeFactory


class TestModel(BaseModel):
    """Test model for storage provider testing."""

    name: str
    value: int


@pytest.mark.asyncio
async def test_storage_provider_integration():
    """Test that storage provider flows from config to node correctly."""

    # Create node config with storage_provider
    node_config = FameNodeConfig(
        type="Node",
        storage_provider={
            "type": "InMemoryStorageProvider",
        },
    )

    # Create the node using the factory
    factory = NodeFactory()
    node = await factory.create(node_config)

    assert node.storage_provider is not None, "Node should have storage provider"
    assert (
        node.storage_provider.__class__.__name__ == "InMemoryStorageProvider"
    ), "Should be InMemoryStorageProvider"

    # Test that we can get a key-value store
    kv_store = await node.storage_provider.get_kv_store(TestModel, namespace="test")
    assert kv_store is not None, "Should get KV store"

    # Test basic store operations
    test_obj = TestModel(name="test", value=42)
    await kv_store.set("key1", test_obj)

    retrieved = await kv_store.get("key1")
    assert retrieved == test_obj, "Should retrieve the same object that was stored"

    # Cleanup
    await node.stop()


@pytest.mark.asyncio
async def test_node_without_storage_provider():
    """Test that nodes always have a default storage provider when none is configured."""

    # Create node config without storage_provider
    node_config = FameNodeConfig(type="Node")

    factory = NodeFactory()
    node = await factory.create(node_config)

    # The factory always creates a default InMemoryStorageProvider
    assert (
        node.storage_provider is not None
    ), "Node should have default storage provider when none configured"
    assert (
        node.storage_provider.__class__.__name__ == "InMemoryStorageProvider"
    ), "Should default to InMemoryStorageProvider"

    # Cleanup
    await node.stop()


@pytest.mark.asyncio
async def test_storage_provider_kv_store_namespaces():
    """Test that different namespaces work independently."""

    node_config = FameNodeConfig(
        type="Node",
        storage_provider={
            "type": "InMemoryStorageProvider",
        },
    )

    factory = NodeFactory()
    node = await factory.create(node_config)

    # Get stores for different namespaces
    store1 = await node.storage_provider.get_kv_store(TestModel, namespace="ns1")
    store2 = await node.storage_provider.get_kv_store(TestModel, namespace="ns2")

    # Store different values in each namespace
    obj1 = TestModel(name="obj1", value=1)
    obj2 = TestModel(name="obj2", value=2)

    await store1.set("key", obj1)
    await store2.set("key", obj2)

    # Verify they're independent
    retrieved1 = await store1.get("key")
    retrieved2 = await store2.get("key")

    assert retrieved1 == obj1, "Namespace 1 should have obj1"
    assert retrieved2 == obj2, "Namespace 2 should have obj2"
    assert retrieved1 != retrieved2, "Different namespaces should have different values"

    # Cleanup
    await node.stop()


@pytest.mark.asyncio
async def test_storage_provider_multiple_model_types():
    """Test that different model types can be stored independently."""

    class AnotherModel(BaseModel):
        description: str
        count: int

    node_config = FameNodeConfig(
        type="Node",
        storage_provider={
            "type": "InMemoryStorageProvider",
        },
    )

    factory = NodeFactory()
    node = await factory.create(node_config)

    # Get stores for different model types
    test_store = await node.storage_provider.get_kv_store(TestModel, namespace="test")
    another_store = await node.storage_provider.get_kv_store(AnotherModel, namespace="test")

    # Store different model types
    test_obj = TestModel(name="test", value=42)
    another_obj = AnotherModel(description="another", count=10)

    await test_store.set("key1", test_obj)
    await another_store.set("key2", another_obj)

    # Verify they're stored correctly
    retrieved_test = await test_store.get("key1")
    retrieved_another = await another_store.get("key2")

    assert retrieved_test == test_obj, "TestModel should be retrieved correctly"
    assert retrieved_another == another_obj, "AnotherModel should be retrieved correctly"

    # Verify cross-type access doesn't work
    assert await test_store.get("key2") is None, "TestModel store shouldn't have AnotherModel key"
    assert await another_store.get("key1") is None, "AnotherModel store shouldn't have TestModel key"

    # Cleanup
    await node.stop()
