#!/usr/bin/env python3
"""
Test the integration of priority system with create_default_resource.
"""

import asyncio
from typing import Any, Optional

from naylence.fame.core.util.extension_manager import ExtensionManager
from naylence.fame.factory import (
    ResourceConfig,
    ResourceFactory,
    create_default_resource,
)


class TestResource:
    """Test resource type."""

    def __init__(self, name: str):
        self.name = name


class TestResourceFactory(ResourceFactory[TestResource, ResourceConfig]):
    """Base factory interface for test resources."""

    pass


class BasicTestFactory(TestResourceFactory):
    """Basic implementation with lower priority."""

    type = "basic"
    is_default = True
    priority = 10

    async def create(
        self, config: Optional[ResourceConfig | dict[str, Any]] = None, **kwargs: Any
    ) -> TestResource:
        return TestResource("basic")


class AdvancedTestFactory(TestResourceFactory):
    """Advanced implementation with higher priority."""

    type = "advanced"
    is_default = True
    priority = 100

    async def create(
        self, config: Optional[ResourceConfig | dict[str, Any]] = None, **kwargs: Any
    ) -> TestResource:
        return TestResource("advanced")


async def test_create_default_resource():
    """Test that create_default_resource uses priority-based selection."""

    # Set up the extension manager
    mgr = ExtensionManager.lazy_init(group="naylence.TestResourceFactory", base_type=TestResourceFactory)

    # Manually register our test factories (simulating entry point loading)
    mgr._registry["basic"] = BasicTestFactory
    mgr._registry["advanced"] = AdvancedTestFactory

    # Test the create_default_resource function
    resource = await create_default_resource(TestResourceFactory)

    if resource is None:
        print("❌ create_default_resource returned None")
        return False

    # Should select the advanced factory due to higher priority
    if resource.name == "advanced":
        print(
            f"✅ create_default_resource correctly selected advanced factory (resource.name: {
                resource.name
            })"
        )
        return True
    else:
        print(
            f"❌ create_default_resource selected wrong factory (resource.name: {
                resource.name
            }), expected 'advanced'"
        )
        return False


async def test_create_default_resource_with_config():
    """Test that create_default_resource works with additional config."""

    # Set up the extension manager
    mgr = ExtensionManager.lazy_init(
        group="naylence.TestResourceFactoryWithConfig", base_type=TestResourceFactory
    )

    # Manually register our test factories
    mgr._registry["basic"] = BasicTestFactory
    mgr._registry["advanced"] = AdvancedTestFactory

    # Test with config
    config = {"some_setting": "value"}
    resource = await create_default_resource(TestResourceFactory, config=config)

    if resource is None:
        print("❌ create_default_resource with config returned None")
        return False

    # Should still select the advanced factory
    if resource.name == "advanced":
        print(
            f"✅ create_default_resource with config correctly selected advanced factory (resource.name: {
                resource.name
            })"
        )
        return True
    else:
        print(
            f"❌ create_default_resource with config selected wrong factory (resource.name: {
                resource.name
            }), expected 'advanced'"
        )
        return False


async def main():
    print("Testing create_default_resource with priority system...")
    print()

    tests = [
        ("create_default_resource Priority Selection", test_create_default_resource),
        (
            "create_default_resource With Config",
            test_create_default_resource_with_config,
        ),
    ]

    passed = 0
    for test_name, test_func in tests:
        print(f"Running: {test_name}")
        if await test_func():
            passed += 1
        print()

    print(f"Results: {passed}/{len(tests)} tests passed")

    if passed == len(tests):
        print("🎉 All integration tests passed!")
    else:
        print("❌ Some integration tests failed")


if __name__ == "__main__":
    asyncio.run(main())
