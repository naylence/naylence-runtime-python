#!/usr/bin/env python3
"""Test connector state management implementation."""

import asyncio

import pytest

from naylence.fame.core.connector.connector_state import ConnectorState


class MockConnector:
    """Mock connector for testing without transport dependencies."""

    def __init__(self):
        # Initialize the BaseAsyncConnector parts we need
        self._state = ConnectorState.INITIALIZED
        self._connector_flow_id = "mock-connector-123"

    @property
    def state(self) -> ConnectorState:
        return self._state

    @property
    def connector_state(self) -> ConnectorState:
        """Alias for backward compatibility."""
        return self._state

    def set_state(self, new_state: ConnectorState):
        """Helper method to change state for testing."""
        self._state = new_state


def test_connector_state_enum():
    """Test that ConnectorState enum has the expected values."""
    print("Testing ConnectorState enum...")

    # Test that all expected states exist
    expected_states = ["UNKNOWN", "INITIALIZED", "STARTED", "STOPPED", "CLOSED"]
    for state_name in expected_states:
        assert hasattr(ConnectorState, state_name), f"ConnectorState should have {state_name}"

    # Test state transitions
    state = ConnectorState.INITIALIZED
    assert state.name == "INITIALIZED"
    assert str(state) == "initialized"  # The actual string representation
    assert repr(state) == "ConnectorState.INITIALIZED"

    # Test that states are comparable
    assert ConnectorState.INITIALIZED != ConnectorState.STARTED
    assert ConnectorState.INITIALIZED == ConnectorState.INITIALIZED

    print("✓ ConnectorState enum is properly defined")


def test_connector_state_properties():
    """Test connector state properties and transitions."""
    print("Testing connector state properties...")

    connector = MockConnector()

    # Test initial state
    assert connector.state == ConnectorState.INITIALIZED
    assert connector.connector_state == ConnectorState.INITIALIZED
    print(f"✓ Initial state: {connector.state}")

    # Test state transitions
    connector.set_state(ConnectorState.STARTED)
    assert connector.state == ConnectorState.STARTED
    assert connector.connector_state == ConnectorState.STARTED
    print(f"✓ Started state: {connector.state}")

    connector.set_state(ConnectorState.STOPPED)
    assert connector.state == ConnectorState.STOPPED
    print(f"✓ Stopped state: {connector.state}")

    connector.set_state(ConnectorState.CLOSED)
    assert connector.state == ConnectorState.CLOSED
    print(f"✓ Closed state: {connector.state}")


def test_state_active_check():
    """Test the is_active property of connector states."""
    print("Testing state activity checks...")

    # Test active states (only STARTED is active)
    active_states = [ConnectorState.STARTED]
    for state in active_states:
        assert state.is_active, f"{state} should be active"
        print(f"✓ {state} is active")

    # Test inactive states
    inactive_states = [
        ConnectorState.UNKNOWN,
        ConnectorState.INITIALIZED,
        ConnectorState.STOPPED,
        ConnectorState.CLOSED,
    ]
    for state in inactive_states:
        assert not state.is_active, f"{state} should not be active"
        print(f"✓ {state} is not active")


def test_state_transition_capabilities():
    """Test state transition capability properties."""
    print("Testing state transition capabilities...")

    # Test can_start property
    can_start_states = [ConnectorState.INITIALIZED, ConnectorState.STOPPED]
    for state in can_start_states:
        assert state.can_start, f"{state} should be able to start"
        print(f"✓ {state} can start")

    # Test can_stop property
    can_stop_states = [ConnectorState.STARTED]
    for state in can_stop_states:
        assert state.can_stop, f"{state} should be able to stop"
        print(f"✓ {state} can stop")

    # Test can_close property
    can_close_states = [ConnectorState.INITIALIZED, ConnectorState.STARTED, ConnectorState.STOPPED]
    for state in can_close_states:
        assert state.can_close, f"{state} should be able to close"
        print(f"✓ {state} can close")


def test_connector_lifecycle():
    """Test a complete connector lifecycle."""
    print("Testing complete connector lifecycle...")

    connector = MockConnector()

    # Start with initialized
    assert connector.state == ConnectorState.INITIALIZED
    assert not connector.state.is_active  # INITIALIZED is not active, only STARTED is active
    assert connector.state.can_start  # Can start from INITIALIZED

    # Start the connector
    connector.set_state(ConnectorState.STARTED)
    assert connector.state == ConnectorState.STARTED
    assert connector.state.is_active  # STARTED is active
    assert connector.state.can_stop  # Can stop from STARTED

    # Stop the connector
    connector.set_state(ConnectorState.STOPPED)
    assert connector.state == ConnectorState.STOPPED
    assert not connector.state.is_active  # STOPPED is not active
    assert connector.state.is_inactive  # STOPPED is inactive

    # Close the connector
    connector.set_state(ConnectorState.CLOSED)
    assert connector.state == ConnectorState.CLOSED
    assert not connector.state.is_active  # CLOSED is not active
    assert connector.state.is_inactive  # CLOSED is inactive

    print("✓ Complete lifecycle test passed")


def test_backward_compatibility():
    """Test that connector_state property works for backward compatibility."""
    print("Testing backward compatibility...")

    connector = MockConnector()

    # Both properties should return the same value
    assert connector.state == connector.connector_state

    # Test through state changes
    for state in [ConnectorState.STARTED, ConnectorState.STOPPED, ConnectorState.CLOSED]:
        connector.set_state(state)
        assert connector.state == connector.connector_state
        print(f"✓ Both properties return {state}")


@pytest.mark.asyncio
async def test_async_state_transitions():
    """Test state transitions in async context."""
    print("Testing async state transitions...")

    connector = MockConnector()

    async def transition_states():
        """Simulate async state transitions."""
        await asyncio.sleep(0.01)
        connector.set_state(ConnectorState.STARTED)

        await asyncio.sleep(0.01)
        connector.set_state(ConnectorState.STOPPED)

        await asyncio.sleep(0.01)
        connector.set_state(ConnectorState.CLOSED)

    # Initial state
    assert connector.state == ConnectorState.INITIALIZED

    # Run async transitions
    await transition_states()

    # Final state
    assert connector.state == ConnectorState.CLOSED
    print("✓ Async state transitions work correctly")


if __name__ == "__main__":
    test_connector_state_enum()
    test_connector_state_properties()
    test_state_active_check()
    test_state_transition_capabilities()
    test_connector_lifecycle()
    test_backward_compatibility()

    # Run async test
    asyncio.run(test_async_state_transitions())

    print("\n✅ All connector state management tests passed!")
