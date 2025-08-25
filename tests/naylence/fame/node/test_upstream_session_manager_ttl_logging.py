import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from naylence.fame.node.upstream_session_manager import UpstreamSessionManager


class MockNode:
    """Mock NodeLike object for testing."""

    def __init__(self, node_id: str = "test-id", sid: str = "test-sid"):
        self._id = node_id
        self._sid = sid
        self._envelope_factory = AsyncMock()
        self._security_manager = None
        self._physical_path = "/test/path"
        self._accepted_logicals = set()
        self._admission_client = AsyncMock()

    @property
    def id(self) -> str:
        return self._id

    @property
    def sid(self):
        return self._sid

    @property
    def physical_path(self) -> str:
        return self._physical_path

    @property
    def accepted_logicals(self):
        return self._accepted_logicals

    @property
    def envelope_factory(self):
        return self._envelope_factory

    @property
    def default_binding_path(self) -> str:
        return f"{self._physical_path}/default"

    @property
    def has_parent(self) -> bool:
        return True

    @property
    def security_manager(self):
        return self._security_manager

    @property
    def admission_client(self):
        return self._admission_client


@pytest.mark.asyncio
async def test_expiry_guard_logging():
    """Test that the expiry guard logs TTL expiration events."""
    # Create a mock connector
    connector = AsyncMock()

    # Create a mock welcome frame with expiry
    welcome = MagicMock()
    welcome.frame.expires_at = datetime.now(timezone.utc) + timedelta(seconds=1)

    # Create mock attach info
    attach_info = {}

    # Create stop event
    stop_evt = asyncio.Event()

    # Create mock node
    mock_node = MockNode()

    # Create a minimal upstream session manager
    upstream_manager = UpstreamSessionManager(
        node=mock_node,
        admission_client=AsyncMock(),
        attach_client=AsyncMock(),
        requested_logicals=["test"],
        outbound_origin_type="test",
        inbound_origin_type="test",
        inbound_handler=AsyncMock(),
        on_attach=AsyncMock(),
        on_epoch_change=AsyncMock(),
    )

    # Override the refresh safety to a very small value for testing
    upstream_manager.JWT_REFRESH_SAFETY = 0.1

    # Start the expiry guard
    task = asyncio.create_task(upstream_manager._expiry_guard(connector, welcome, attach_info, stop_evt))

    # Wait a bit longer than the expiry time
    await asyncio.sleep(1.2)

    # Check that the connector was stopped (indicating expiry was triggered)
    connector.stop.assert_called_once()

    # Clean up
    stop_evt.set()
    await task


@pytest.mark.asyncio
async def test_expiry_guard_no_expiry():
    """Test that the expiry guard handles no expiry case correctly."""
    # Create a mock connector
    connector = AsyncMock()

    # Create a mock welcome frame with NO expiry
    welcome = MagicMock()
    welcome.frame.expires_at = None

    # Create mock attach info with no expiry
    attach_info = {}

    # Create stop event
    stop_evt = asyncio.Event()

    # Create mock node
    mock_node = MockNode()

    # Create a minimal upstream session manager
    upstream_manager = UpstreamSessionManager(
        node=mock_node,
        admission_client=AsyncMock(),
        attach_client=AsyncMock(),
        requested_logicals=["test"],
        outbound_origin_type="test",
        inbound_origin_type="test",
        inbound_handler=AsyncMock(),
        on_attach=AsyncMock(),
        on_epoch_change=AsyncMock(),
    )

    # Start the expiry guard
    task = asyncio.create_task(upstream_manager._expiry_guard(connector, welcome, attach_info, stop_evt))

    # Wait a bit
    await asyncio.sleep(0.1)

    # Stop the guard
    stop_evt.set()
    await task

    # Check that the connector was NOT stopped (no expiry configured)
    connector.stop.assert_not_called()
