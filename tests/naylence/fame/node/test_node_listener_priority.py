"""
Test for node event listener priority sorting functionality.
"""

from naylence.fame.node.node_event_listener import NodeEventListener


class MockEventListener(NodeEventListener):
    """Mock implementation of NodeEventListener with configurable priority."""

    def __init__(self, name: str, priority: int = 1000):
        self.name = name
        self._priority = priority

    @property
    def priority(self) -> int:
        return self._priority

    def __str__(self) -> str:
        return f"MockEventListener({self.name}, priority={self.priority})"

    def __repr__(self) -> str:
        return self.__str__()


class MockFameNode:
    """
    Mock FameNode to test just the event listener sorting functionality.

    This mimics the exact sorting logic used in the real FameNode class.
    """

    def __init__(self, event_listeners=None):
        self._event_listeners = []

        # Add event listeners from parameter
        if event_listeners:
            self._event_listeners.extend(event_listeners)

        # Sort event listeners by priority (mimicking the real constructor)
        self._sort_event_listeners()

    def add_event_listener(self, listener: NodeEventListener) -> None:
        """Add an event listener to this node and maintain priority ordering."""
        if listener not in self._event_listeners:
            self._event_listeners.append(listener)
            # Re-sort to maintain priority ordering
            self._sort_event_listeners()

    def remove_event_listener(self, listener: NodeEventListener) -> None:
        """Remove an event listener from this node."""
        if listener in self._event_listeners:
            self._event_listeners.remove(listener)

    def _sort_event_listeners(self) -> None:
        """Sort event listeners by priority, maintaining stable ordering for equal priorities."""
        listeners_with_indices = list(enumerate(self._event_listeners))
        listeners_with_indices.sort(key=lambda item: (item[1].priority, item[0]))
        self._event_listeners = [listener for _, listener in listeners_with_indices]

    @property
    def event_listeners(self):
        return self._event_listeners.copy()


class TestNodeListenerPriority:
    """Test cases for node event listener priority system."""

    def test_default_priority_value(self):
        """Test that listeners get the default priority of 1000."""
        listener = MockEventListener("default")
        assert listener.priority == 1000

    def test_constructor_priority_sorting(self):
        """Test that event listeners are sorted by priority during construction."""
        # Create listeners with different priorities
        initial_listeners = [
            MockEventListener("A", 1000),  # default priority
            MockEventListener("B", 500),  # high priority
            MockEventListener("C", 1000),  # default priority (same as A)
            MockEventListener("D", 1500),  # low priority
            MockEventListener("E", 100),  # highest priority
        ]

        node = MockFameNode(initial_listeners)

        # Verify the expected order: E(100), B(500), A(1000), C(1000), D(1500)
        expected_names = ["E", "B", "A", "C", "D"]
        actual_names = [listener.name for listener in node.event_listeners]

        assert actual_names == expected_names

    def test_dynamic_addition_maintains_priority_order(self):
        """Test that dynamically adding listeners maintains priority ordering."""
        initial_listeners = [
            MockEventListener("A", 1000),
            MockEventListener("B", 500),
            MockEventListener("C", 1500),
        ]

        node = MockFameNode(initial_listeners)

        # Add a high priority listener dynamically
        new_listener = MockEventListener("D", 100)
        node.add_event_listener(new_listener)

        # D should be first due to highest priority
        expected_names = ["D", "B", "A", "C"]
        actual_names = [listener.name for listener in node.event_listeners]

        assert actual_names == expected_names

    def test_same_priority_maintains_original_order(self):
        """Test that listeners with same priority maintain their original order."""
        initial_listeners = [
            MockEventListener("A", 1000),
            MockEventListener("B", 1000),
            MockEventListener("C", 1000),
        ]

        node = MockFameNode(initial_listeners)

        # All have same priority, should maintain original order
        expected_names = ["A", "B", "C"]
        actual_names = [listener.name for listener in node.event_listeners]

        assert actual_names == expected_names

    def test_dynamic_addition_with_same_priority(self):
        """Test that dynamically added listeners with same priority
        go to the end of their priority group."""
        initial_listeners = [
            MockEventListener("A", 500),
            MockEventListener("B", 1000),
            MockEventListener("C", 1000),
            MockEventListener("D", 1500),
        ]

        node = MockFameNode(initial_listeners)

        # Add another listener with priority 1000
        new_listener = MockEventListener("E", 1000)
        node.add_event_listener(new_listener)

        # E should come after B and C (same priority group)
        expected_names = ["A", "B", "C", "E", "D"]
        actual_names = [listener.name for listener in node.event_listeners]

        assert actual_names == expected_names

    def test_remove_event_listener(self):
        """Test that removing listeners works correctly."""
        listeners = [
            MockEventListener("A", 100),
            MockEventListener("B", 500),
            MockEventListener("C", 1000),
        ]

        node = MockFameNode(listeners)

        # Remove the middle priority listener
        node.remove_event_listener(listeners[1])  # Remove B

        expected_names = ["A", "C"]
        actual_names = [listener.name for listener in node.event_listeners]

        assert actual_names == expected_names

    def test_priority_ranges(self):
        """Test various priority ranges to ensure sorting works correctly."""
        listeners = [
            MockEventListener("VeryLow", 10000),
            MockEventListener("Low", 2000),
            MockEventListener("Default", 1000),
            MockEventListener("High", 500),
            MockEventListener("VeryHigh", 1),
            MockEventListener("Zero", 0),
            MockEventListener("Negative", -100),
        ]

        node = MockFameNode(listeners)

        # Should be sorted from lowest to highest priority value
        expected_names = ["Negative", "Zero", "VeryHigh", "High", "Default", "Low", "VeryLow"]
        actual_names = [listener.name for listener in node.event_listeners]

        assert actual_names == expected_names

    def test_empty_initialization(self):
        """Test that node can be initialized with no listeners."""
        node = MockFameNode()
        assert len(node.event_listeners) == 0

    def test_duplicate_listener_not_added(self):
        """Test that adding the same listener instance twice doesn't duplicate it."""
        listener = MockEventListener("A", 500)
        node = MockFameNode([listener])

        # Try to add the same listener again
        node.add_event_listener(listener)

        # Should still only have one listener
        assert len(node.event_listeners) == 1
        assert node.event_listeners[0] is listener


def test_comprehensive_priority_system():
    """Legacy comprehensive test that can be run standalone."""
    # Create listeners with different priorities
    initial_listeners = [
        MockEventListener("A", 1000),  # default priority
        MockEventListener("B", 500),  # high priority
        MockEventListener("C", 1000),  # default priority (same as A)
        MockEventListener("D", 1500),  # low priority
        MockEventListener("E", 100),  # highest priority
    ]

    node = MockFameNode(initial_listeners)

    # Verify the expected order
    expected_names = ["E", "B", "A", "C", "D"]  # E(100), B(500), A(1000), C(1000), D(1500)
    actual_names = [listener.name for listener in node.event_listeners]

    assert actual_names == expected_names
