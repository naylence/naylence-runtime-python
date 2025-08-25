from typing import Any, Optional

from naylence.fame.core import ExtensionManager, ResourceConfig, ResourceFactory


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


def test_priority_selection():
    """Test that the priority system selects the highest priority default."""

    # Create a test extension manager
    mgr = ExtensionManager(group="test.TestResourceFactory", base_type=TestResourceFactory)

    # Manually register our test factories (simulating entry point loading)
    mgr._registry["basic"] = BasicTestFactory
    mgr._registry["advanced"] = AdvancedTestFactory

    # Test the best default selection
    result = mgr.get_best_default_instance()

    if result is None:
        print("❌ No default found")
        return False

    factory_instance, factory_type = result

    # Should select the advanced factory due to higher priority
    if factory_type == "advanced":
        print(f"✅ Correctly selected advanced factory (type: {factory_type})")
        return True
    else:
        print(f"❌ Selected wrong factory (type: {factory_type}), expected 'advanced'")
        return False


def test_only_basic_available():
    """Test that basic factory is selected when advanced is not available."""

    # Create a test extension manager with only basic factory
    mgr = ExtensionManager(group="test.BasicOnlyFactory", base_type=TestResourceFactory)
    mgr._registry["basic"] = BasicTestFactory

    # Test the best default selection
    result = mgr.get_best_default_instance()

    if result is None:
        print("❌ No default found")
        return False

    factory_instance, factory_type = result

    # Should select the basic factory since it's the only one available
    if factory_type == "basic":
        print(f"✅ Correctly selected basic factory when only option (type: {factory_type})")
        return True
    else:
        print(f"❌ Selected wrong factory (type: {factory_type}), expected 'basic'")
        return False


def test_fallback_compatibility():
    """Test that the old method still works for backward compatibility."""

    # Create a test extension manager
    mgr = ExtensionManager(group="test.FallbackFactory", base_type=TestResourceFactory)
    mgr._registry["basic"] = BasicTestFactory
    mgr._registry["advanced"] = AdvancedTestFactory

    # Test the old default selection method
    result = mgr.get_default_instance()

    if result is None:
        print("❌ No default found via legacy method")
        return False

    factory_instance, factory_type = result

    # Should find a default (may warn about multiple)
    if factory_type in ["basic", "advanced"]:
        print(f"✅ Legacy method found default factory (type: {factory_type})")
        return True
    else:
        print(f"❌ Legacy method failed (type: {factory_type})")
        return False


if __name__ == "__main__":
    print("Testing priority-based default selection system...")
    print()

    tests = [
        ("Priority Selection", test_priority_selection),
        ("Basic Only Available", test_only_basic_available),
        ("Fallback Compatibility", test_fallback_compatibility),
    ]

    passed = 0
    for test_name, test_func in tests:
        print(f"Running: {test_name}")
        if test_func():
            passed += 1
        print()

    print(f"Results: {passed}/{len(tests)} tests passed")

    if passed == len(tests):
        print("🎉 All tests passed!")
    else:
        print("❌ Some tests failed")
