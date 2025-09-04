#!/usr/bin/env python3
"""Test connector selection policy implementation."""

from unittest.mock import Mock

import pytest

from naylence.fame.connector.grant_selection_policy import (
    GrantSelectionContext,
    GrantSelectionPolicy,
)


def test_prefer_same_type_strategy():
    """Test that policy prefers connectors matching the inbound type."""
    print("Testing PreferSameTypeStrategy...")

    # Create mock NodeAttachFrame with HTTP and WebSocket connectors
    attach_frame = Mock()
    attach_frame.callback_grants = [
        {
            "config": {"port": 8080},
            "type": "HttpConnectionGrant",
            "url": "http://localhost:8080",
        },
        {
            "config": {"port": 8081},
            "type": "WebSocketConnectionGrant",
            "params": {"host": "localhost", "port": 8081},
        },
    ]

    policy = GrantSelectionPolicy()

    # Create mock node
    mock_node = Mock()

    # Test with HTTP inbound context
    http_context = GrantSelectionContext(
        child_id="test-child",
        callback_grant_type="HttpConnectionGrant",
        attach_frame=attach_frame,
        node=mock_node,
    )

    result = policy.select_callback_grant(http_context)

    # Should prefer HTTP since it matches inbound type
    assert result.grant.type == "HttpConnectionGrant"
    assert "Matching inbound connector type" in result.selection_reason
    assert not result.fallback_used

    print("✅ HTTP preference test passed")

    # Test with WebSocket inbound context
    ws_context = GrantSelectionContext(
        child_id="test-child",
        callback_grant_type="WebSocketConnectionGrant",
        attach_frame=attach_frame,
        node=mock_node,
    )

    result = policy.select_callback_grant(ws_context)

    # Should prefer WebSocket since it matches inbound type
    assert result.grant.type == "WebSocketConnectionGrant"
    assert "Matching inbound connector type" in result.selection_reason
    assert not result.fallback_used

    print("✅ WebSocket preference test passed")


def test_prefer_http_strategy():
    """Test that policy falls back when same type is not available."""
    print("Testing strategy fallback...")

    # Create mock NodeAttachFrame with only WebSocket
    attach_frame = Mock()
    attach_frame.callback_grants = [
        {
            "config": {"port": 8081},
            "type": "WebSocketConnectionGrant",
            "params": {"host": "localhost", "port": 8081},
        }
    ]

    policy = GrantSelectionPolicy()
    mock_node = Mock()

    # Test with HTTP inbound context (but only websocket available)
    http_context = GrantSelectionContext(
        child_id="test-child",
        callback_grant_type="HttpConnectionGrant",
        attach_frame=attach_frame,
        node=mock_node,
    )

    result = policy.select_callback_grant(http_context)

    # Should select websocket since that's all that's available
    assert result.grant.type == "WebSocketConnectionGrant"
    # Note: The actual implementation may not mark this as fallback
    # since it's the client's first preference

    print("✅ Fallback strategy test passed")


def test_client_preference_strategy():
    """Test that strategy can handle multiple connector options."""
    print("Testing multiple connector selection...")

    # Create mock NodeAttachFrame with multiple connectors
    attach_frame = Mock()
    attach_frame.callback_grants = [
        {
            "config": {"port": 8080},
            "type": "HttpConnectionGrant",
            "url": "http://localhost:8080",
        },
        {
            "config": {"port": 8081},
            "type": "WebSocketConnectionGrant",
            "params": {"host": "localhost", "port": 8081},
        },
    ]

    policy = GrantSelectionPolicy()
    mock_node = Mock()

    # Test with HTTP inbound context - should prefer HTTP
    context = GrantSelectionContext(
        child_id="test-child",
        callback_grant_type="HttpConnectionGrant",
        attach_frame=attach_frame,
        node=mock_node,
    )

    result = policy.select_callback_grant(context)

    # Should select HTTP since it matches inbound type
    assert result.grant.type == "HttpConnectionGrant"
    assert not result.fallback_used

    print("✅ Multiple connector selection test passed")


def test_no_suitable_connector():
    """Test error handling when no suitable connector is found."""
    print("Testing empty connector list scenario...")

    # Create mock NodeAttachFrame with empty connectors
    attach_frame = Mock()
    attach_frame.callback_grants = []

    policy = GrantSelectionPolicy()
    mock_node = Mock()

    context = GrantSelectionContext(
        child_id="test-child",
        callback_grant_type="HttpConnectionGrant",
        attach_frame=attach_frame,
        node=mock_node,
    )

    with pytest.raises(ValueError) as exc_info:
        policy.select_callback_grant(context)

    assert "No suitable connector found" in str(exc_info.value)
    assert "test-child" in str(exc_info.value)

    print("✅ Empty connector list error test passed")


def test_unknown_connector_type():
    """Test handling of unsupported connector configurations."""
    print("Testing unsupported connector type...")

    # Create mock NodeAttachFrame with unsupported connector type
    attach_frame = Mock()
    attach_frame.callback_grants = [{"config": {"port": 9999}, "type": "UnsupportedConnectorType"}]

    policy = GrantSelectionPolicy()
    mock_node = Mock()

    context = GrantSelectionContext(
        child_id="test-child",
        callback_grant_type="HttpConnectionGrant",
        attach_frame=attach_frame,
        node=mock_node,
    )

    # Should raise error since no strategy can handle the unsupported type
    with pytest.raises(ValueError) as exc_info:
        policy.select_callback_grant(context)

    assert "No suitable connector found" in str(exc_info.value)
    assert "UnsupportedConnectorType" in str(exc_info.value)

    print("✅ Unsupported connector type test passed")


if __name__ == "__main__":
    test_prefer_same_type_strategy()
    test_prefer_http_strategy()
    test_client_preference_strategy()
    test_no_suitable_connector()
    test_unknown_connector_type()
    print("\n✅ All connector selection policy tests passed!")
