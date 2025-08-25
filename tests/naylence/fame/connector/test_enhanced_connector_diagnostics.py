#!/usr/bin/env python3
"""Test enhanced FameConnector diagnostic capabilities."""

import asyncio
import logging

import pytest

from naylence.fame.connector.base_async_connector import BaseAsyncConnector
from naylence.fame.core.connector.connector_state import ConnectorState
from naylence.fame.errors.errors import FameTransportClose
from naylence.fame.node.admission.default_node_attach_client import (
    DefaultNodeAttachClient,
)

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class MockFailingConnector(BaseAsyncConnector):
    """Mock connector that fails during startup."""

    def __init__(self, fail_mode: str = "timeout", **kwargs):
        super().__init__(**kwargs)
        self.fail_mode = fail_mode

    async def _transport_send_bytes(self, data: bytes) -> None:
        if self.fail_mode == "send_error":
            raise FameTransportClose(1006, "Mock send failure")
        # For other modes, just ignore the send

    async def _transport_receive(self) -> bytes:
        if self.fail_mode == "immediate_close":
            raise FameTransportClose(1000, "Mock immediate close")
        elif self.fail_mode == "auth_failure":
            raise FameTransportClose(4001, "Authentication failed")
        elif self.fail_mode == "timeout":
            # Just hang indefinitely to trigger timeout
            await asyncio.sleep(100)

        return b"mock response"

    async def _transport_close(self, code: int, reason: str) -> None:
        logger.info(f"MockFailingConnector closing: {code} {reason}")


@pytest.mark.asyncio
async def test_diagnostic_properties():
    """Test that diagnostic properties are properly captured."""
    print("Testing diagnostic properties...")

    # Test immediate close scenario
    async def mock_handler(envelope):
        pass

    connector = MockFailingConnector(fail_mode="immediate_close")

    try:
        await connector.start(mock_handler)

        # Let the receive loop run and hit the failure
        await asyncio.sleep(0.1)

        # Check if state changed
        if connector.state == ConnectorState.STARTED:
            # Force shutdown to test diagnostic capture
            await connector._shutdown_with_error(FameTransportClose(1000, "Test close"))
    except Exception as e:
        print(f"Expected exception: {e}")

    # Check diagnostic properties
    print(f"State: {connector.state}")
    print(f"Close code: {connector.close_code}")
    print(f"Close reason: {connector.close_reason}")
    print(f"Last error: {connector.last_error}")

    assert connector.state == ConnectorState.CLOSED
    assert connector.close_code == 1000
    assert connector.close_reason in ["Mock immediate close", "Test close"]
    assert connector.last_error is not None

    print("✓ Diagnostic properties test passed")


@pytest.mark.asyncio
async def test_node_attach_error_reporting():
    """Test that DefaultNodeAttachClient provides better error messages."""
    print("\nTesting enhanced node attach error reporting...")

    # Test auth failure scenario
    async def mock_handler(envelope):
        pass

    connector = MockFailingConnector(fail_mode="auth_failure")

    # Create a minimal attach client
    client = DefaultNodeAttachClient(timeout_ms=1000)

    try:
        await connector.start(mock_handler)
        await client._await_ack(connector)
        print("Unexpected success!")
    except RuntimeError as e:
        error_msg = str(e)
        print(f"Enhanced error message: {error_msg}")

        # Verify the error message includes diagnostic information
        assert "Connector closed while waiting for NodeAttachAck" in error_msg
        assert "code=4001" in error_msg
        assert "Authentication failed" in error_msg

        print("✓ Enhanced error reporting test passed")
    except Exception as e:
        print(f"Unexpected exception type: {type(e).__name__}: {e}")
        raise


@pytest.mark.asyncio
async def test_multiple_failure_scenarios():
    """Test diagnostic properties with various failure scenarios."""
    print("\nTesting multiple failure scenarios...")

    async def mock_handler(envelope):
        pass

    # Test different failure modes
    failure_scenarios = [
        ("immediate_close", 1000, "Mock immediate close"),
        ("auth_failure", 4001, "Authentication failed"),
    ]

    for fail_mode, expected_code, expected_reason in failure_scenarios:
        print(f"Testing {fail_mode}...")

        connector = MockFailingConnector(fail_mode=fail_mode)

        try:
            await connector.start(mock_handler)
            await asyncio.sleep(0.1)  # Let failure occur
        except Exception:
            pass  # Expected

        # Check diagnostics
        assert connector.state == ConnectorState.CLOSED
        assert connector.close_code == expected_code
        assert connector.close_reason == expected_reason
        assert connector.last_error is not None

        print(f"✓ {fail_mode} scenario passed")


def test_diagnostic_properties_initialization():
    """Test that diagnostic properties are properly initialized."""
    print("\nTesting diagnostic properties initialization...")

    connector = MockFailingConnector()

    # Initially, diagnostic properties should be None
    assert connector.close_code is None
    assert connector.close_reason is None
    assert connector.last_error is None

    print("✓ Diagnostic properties properly initialized")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
