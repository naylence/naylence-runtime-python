"""
Tests for UpstreamSessionManager.

These tests cover the complex reconnection logic, TTL expiry handling,
and task cleanup scenarios that are critical for production reliability.
"""

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any, List, Optional
from unittest.mock import AsyncMock, Mock, patch

import pytest

from naylence.fame.constants.ttl_constants import TEST_LONG_TTL_SEC, TEST_SHORT_TTL_SEC
from naylence.fame.core import (
    DeliveryOriginType,
    EnvelopeFactory,
    FameEnvelope,
    NodeHeartbeatAckFrame,
    NodeWelcomeFrame,
)
from naylence.fame.errors.errors import FameConnectError, FameTransportClose
from naylence.fame.node.admission.node_attach_client import AttachInfo
from naylence.fame.node.upstream_session_manager import UpstreamSessionManager


class MockNode:
    """Mock NodeLike object for testing."""

    def __init__(
        self,
        node_id: str = "test-child",
        sid: str = "test-session",
        envelope_factory=None,
        security_manager=None,
        admission_client=None,
    ):
        self._id = node_id
        self._sid = sid
        self._envelope_factory = envelope_factory or Mock(spec=EnvelopeFactory)
        self._security_manager = security_manager
        self._admission_client = admission_client
        self._physical_path = "/test/path"
        self._accepted_logicals = set()
        self._event_listeners = []

    @property
    def id(self) -> str:
        return self._id

    @property
    def sid(self) -> Optional[str]:
        return self._sid

    @property
    def physical_path(self) -> str:
        return self._physical_path

    @property
    def accepted_logicals(self) -> set[str]:
        return self._accepted_logicals

    @property
    def envelope_factory(self) -> EnvelopeFactory:
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

    async def _dispatch_event(self, event_name: str, *args, **kwargs) -> None:
        """Mock implementation of _dispatch_event for testing."""
        # For testing purposes, we just simulate event dispatch without actual listeners
        # In real implementations, this would iterate through self._event_listeners
        pass

    def gather_supported_inbound_connectors(self) -> list[dict[str, Any]]:
        """Mock implementation that returns empty list of connectors."""
        # For test purposes, return empty list since mock nodes don't have real transport listeners
        return []


class MockConnector:
    """Mock connector that can simulate connection failures."""

    def __init__(self, fail_after: Optional[float] = None, fail_with: Optional[Exception] = None):
        self.fail_after = fail_after
        self.fail_with = fail_with or FameTransportClose("Connection closed")
        self.started = False
        self.stopped = False
        self.sent_messages: List[FameEnvelope] = []
        self._fail_task: Optional[asyncio.Task] = None
        self.handler = None
        self.authorization_context = None  # Add missing authorization_context attribute

    async def start(self, handler):
        self.started = True
        self.handler = handler
        if self.fail_after is not None:
            self._fail_task = asyncio.create_task(self._delayed_failure())

    async def stop(self):
        self.stopped = True
        if self._fail_task:
            self._fail_task.cancel()

    async def send(self, envelope: FameEnvelope):
        if self.stopped:
            raise FameTransportClose("Connection closed")
        self.sent_messages.append(envelope)

    async def _delayed_failure(self):
        """Simulate connection failure after delay."""
        await asyncio.sleep(self.fail_after)
        if not self.stopped:
            # Simulate connector failure by calling stop() which will trigger FameTransportClose
            # in the upstream session manager when it tries to send the next message
            await self.stop()
            # The manager will detect this when it tries to send the next heartbeat or message


class MockAdmissionClient:
    """Mock admission client."""

    def __init__(self, ttl_sec: int = TEST_LONG_TTL_SEC):
        self.ttl_sec = ttl_sec

    async def hello(self, system_id: str, instance_id: str, requested_logicals: List[str]):
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=self.ttl_sec)

        # Create mock welcome envelope
        welcome_frame = Mock(spec=NodeWelcomeFrame)
        welcome_frame.expires_at = expires_at
        welcome_frame.connector_directive = {
            "type": "WebSocketConnector",
            "params": {"url": "ws://test"},
        }
        welcome_frame.assigned_path = "/test/path"  # Add assigned_path for our new logic
        welcome_frame.accepted_logicals = requested_logicals
        welcome_frame.system_id = system_id  # Add system_id for certificate provisioning

        welcome_envelope = Mock()
        welcome_envelope.frame = welcome_frame

        return welcome_envelope

    async def close(self) -> None:
        """Mock close method."""
        pass


class MockAttachClient:
    """Mock attach client."""

    def __init__(self, ttl_sec: int = TEST_LONG_TTL_SEC):
        self.ttl_sec = ttl_sec

    async def attach(self, **kwargs) -> AttachInfo:
        attach_expires_at = datetime.now(timezone.utc) + timedelta(seconds=self.ttl_sec)

        return {
            "target_system_id": "test-parent",
            "assigned_path": "/test/path",
            "routing_epoch": "test-epoch-1",
            "attach_expires_at": attach_expires_at,
        }


class MockConnectorFactory:
    """Mock connector factory."""

    def __init__(self, connector: MockConnector):
        self.connector = connector

    async def create(self, directive):
        return self.connector


@pytest.fixture
def envelope_factory():
    """Mock envelope factory."""
    factory = Mock(spec=EnvelopeFactory)

    def create_envelope_side_effect(**kwargs):
        # Create a proper mock envelope with frame
        mock_envelope = Mock(spec=FameEnvelope)

        # If a frame is provided, use it; otherwise create a default one
        if "frame" in kwargs:
            mock_envelope.frame = kwargs["frame"]
        else:
            mock_envelope.frame = Mock()
            mock_envelope.corr_id = "test-corr-id"

        mock_envelope.id = "test-env-id"
        mock_envelope.reply_to = kwargs.get("reply_to")
        mock_envelope.to = kwargs.get("to")

        return mock_envelope

    factory.create_envelope.side_effect = create_envelope_side_effect
    return factory


@pytest.fixture
def mock_connector():
    """Basic mock connector."""
    return MockConnector()


@pytest.fixture
def upstream_session_manager(mock_connector, envelope_factory):
    """Create UpstreamSessionManager with mocked dependencies."""
    admission_client = MockAdmissionClient()
    attach_client = MockAttachClient()
    MockConnectorFactory(mock_connector)

    # Create mock node
    mock_node = MockNode(
        node_id="test-child",
        sid="test-session",
        envelope_factory=envelope_factory,
        admission_client=admission_client,
    )

    return UpstreamSessionManager(
        node=mock_node,
        # admission_client=admission_client,
        attach_client=attach_client,
        # connector_factory=connector_factory,
        requested_logicals=["test-logical"],
        outbound_origin_type=DeliveryOriginType.UPSTREAM,
        inbound_origin_type=DeliveryOriginType.DOWNSTREAM,
        inbound_handler=AsyncMock(),
        on_attach=AsyncMock(),
        on_epoch_change=AsyncMock(),
    )


@patch("naylence.fame.node.upstream_session_manager.create_resource")
class TestUpstreamSessionManager:
    """Test suite for UpstreamSessionManager."""

    def setup_create_resource_mock(self, mock_create_resource, connector=None):
        """Helper to set up create_resource mock to return a connector."""
        if connector is None:
            connector = MockConnector()
        mock_create_resource.return_value = connector
        return connector

    async def cleanup_manager(self, manager):
        """Helper method to properly cleanup a manager."""
        try:
            await manager.stop()
        except Exception:
            pass  # Ignore cleanup errors

    @pytest.mark.asyncio
    async def test_successful_connection_and_ready_signal(
        self, mock_create_resource, upstream_session_manager, mock_connector
    ):
        """Test that manager connects successfully and signals ready."""
        # Set up create_resource mock to return our mock connector
        self.setup_create_resource_mock(mock_create_resource, mock_connector)

        # Start the manager
        await upstream_session_manager.start(wait_until_ready=True)

        # Should be ready after successful connection
        assert upstream_session_manager.is_ready()
        assert upstream_session_manager.system_id == "test-parent"
        assert mock_connector.started

        # Clean shutdown
        await upstream_session_manager.stop()
        assert mock_connector.stopped

    @pytest.mark.asyncio
    async def test_ttl_expiry_triggers_reconnection(self, mock_create_resource, envelope_factory):
        """Test that TTL expiry triggers reconnection after JWT_REFRESH_SAFETY period."""
        # Use very short TTL to test expiry logic
        short_ttl = TEST_SHORT_TTL_SEC  # 2 seconds
        admission_client = MockAdmissionClient(ttl_sec=short_ttl)
        attach_client = MockAttachClient(ttl_sec=short_ttl)

        # Track reconnections
        connect_count = 0
        connectors = []

        def mock_create_resource_side_effect(*args, **kwargs):
            nonlocal connect_count
            connect_count += 1
            connector = MockConnector()
            connectors.append(connector)
            return connector

        mock_create_resource.side_effect = mock_create_resource_side_effect

        # Create mock node
        mock_node = MockNode(
            node_id="test-child",
            sid="test-session",
            envelope_factory=envelope_factory,
            admission_client=admission_client,
        )

        manager = UpstreamSessionManager(
            node=mock_node,
            attach_client=attach_client,
            # connector_factory=MockConnectorFactory(MockConnector()),  # Not used anymore but required
            # for constructor
            requested_logicals=["test-logical"],
            outbound_origin_type=DeliveryOriginType.UPSTREAM,
            inbound_origin_type=DeliveryOriginType.DOWNSTREAM,
            inbound_handler=AsyncMock(),
            on_attach=AsyncMock(),
            on_epoch_change=AsyncMock(),
        )

        # Override JWT_REFRESH_SAFETY to be very small for testing
        manager.JWT_REFRESH_SAFETY = 0.5  # 0.5 seconds

        try:
            # Start manager
            await manager.start(wait_until_ready=True)
            assert connect_count == 1

            # Wait for TTL expiry and reconnection
            # Should reconnect after (short_ttl - JWT_REFRESH_SAFETY) = 1.5 seconds
            await asyncio.sleep(2.5)

            # Should have reconnected
            assert connect_count >= 2, f"Expected reconnection, but connect_count={connect_count}"

            # Old connector should be stopped, new one should be started
            assert connectors[0].stopped
            assert connectors[1].started

        finally:
            await self.cleanup_manager(manager)

    @pytest.mark.asyncio
    async def test_heartbeat_failure_triggers_reconnection(self, mock_create_resource, envelope_factory):
        """Test that missed heartbeat triggers reconnection."""
        # Track reconnections
        connect_count = 0
        connectors = []

        def mock_create_resource_side_effect(*args, **kwargs):
            nonlocal connect_count
            connect_count += 1
            connector = MockConnector()
            connectors.append(connector)
            return connector

        mock_create_resource.side_effect = mock_create_resource_side_effect

        # Create mock node
        mock_node = MockNode(
            node_id="test-child",
            sid="test-session",
            envelope_factory=envelope_factory,
            admission_client=MockAdmissionClient(),
        )

        manager = UpstreamSessionManager(
            node=mock_node,
            attach_client=MockAttachClient(),
            # connector_factory=MockConnectorFactory(MockConnector()),  # Not used anymore but required
            # for constructor
            requested_logicals=["test-logical"],
            outbound_origin_type=DeliveryOriginType.UPSTREAM,
            inbound_origin_type=DeliveryOriginType.DOWNSTREAM,
            inbound_handler=AsyncMock(),
            on_attach=AsyncMock(),
            on_epoch_change=AsyncMock(),
        )

        # Use short heartbeat interval for testing
        manager.HEARTBEAT_INTERVAL = 0.1  # 100ms
        manager.HEARTBEAT_GRACE = 1.0  # 100ms grace period

        # Also reduce backoff for faster testing
        manager.BACKOFF_INITIAL = 0.1  # 100ms
        manager.BACKOFF_CAP = 0.2  # 200ms

        try:
            # Start manager
            await manager.start(wait_until_ready=True)
            assert connect_count == 1

            # Wait for heartbeat to be sent and timeout, plus backoff time
            # The heartbeat should timeout after HEARTBEAT_INTERVAL + HEARTBEAT_GRACE
            await asyncio.sleep(0.5)  # Should trigger heartbeat timeout + backoff

            # Should have attempted reconnection
            assert (
                connect_count >= 2
            ), f"Expected reconnection after heartbeat failure, but connect_count={connect_count}"

        finally:
            await self.cleanup_manager(manager)

    @pytest.mark.asyncio
    async def test_transport_close_triggers_reconnection(self, mock_create_resource, envelope_factory):
        """Test that transport closure triggers reconnection."""
        # Create connector that fails after short delay
        failing_connector = MockConnector(fail_after=0.1, fail_with=FameTransportClose("Connection lost"))

        # Track reconnections
        connect_count = 0
        connectors = []

        def mock_create_resource_side_effect(*args, **kwargs):
            nonlocal connect_count
            connect_count += 1
            if connect_count == 1:
                connectors.append(failing_connector)
                return failing_connector
            else:
                # Return working connector for reconnection
                connector = MockConnector()
                connectors.append(connector)
                return connector

        mock_create_resource.side_effect = mock_create_resource_side_effect

        # Create mock node
        mock_node = MockNode(
            node_id="test-child",
            sid="test-session",
            envelope_factory=envelope_factory,
            admission_client=MockAdmissionClient(),
        )

        manager = UpstreamSessionManager(
            node=mock_node,
            attach_client=MockAttachClient(),
            # connector_factory=MockConnectorFactory(MockConnector()),  # Not used anymore but required
            # for constructor
            requested_logicals=["test-logical"],
            outbound_origin_type=DeliveryOriginType.UPSTREAM,
            inbound_origin_type=DeliveryOriginType.DOWNSTREAM,
            inbound_handler=AsyncMock(),
            on_attach=AsyncMock(),
            on_epoch_change=AsyncMock(),
        )

        # Also reduce backoff for faster testing
        manager.BACKOFF_INITIAL = 0.1  # 100ms
        manager.BACKOFF_CAP = 0.2  # 200ms
        manager.HEARTBEAT_INTERVAL = 0.1  # 100ms to trigger heartbeat quickly

        try:
            # Start manager
            await manager.start(wait_until_ready=True)
            assert connect_count == 1

            # Wait for connection failure and reconnection
            # The connector fails after 0.1s, heartbeat should detect it within 0.1s
            await asyncio.sleep(0.5)

            # Should have reconnected
            assert (
                connect_count >= 2
            ), f"Expected reconnection after transport close, but connect_count={connect_count}"

        finally:
            await self.cleanup_manager(manager)

    @pytest.mark.asyncio
    async def test_fast_shutdown_responsiveness(
        self, mock_create_resource, upstream_session_manager, mock_connector
    ):
        """Test that manager shuts down quickly without waiting for heartbeat interval."""
        # Set up create_resource mock to return our mock connector
        self.setup_create_resource_mock(mock_create_resource, mock_connector)

        # Start manager
        await upstream_session_manager.start(wait_until_ready=True)

        # Measure shutdown time
        start_time = asyncio.get_event_loop().time()
        await upstream_session_manager.stop()
        shutdown_time = asyncio.get_event_loop().time() - start_time

        # Should shutdown much faster than heartbeat interval (15s)
        assert shutdown_time < 1.0, f"Shutdown took {shutdown_time}s, expected < 1s"
        assert mock_connector.stopped

    @pytest.mark.asyncio
    async def test_message_sending_and_queuing(
        self, mock_create_resource, upstream_session_manager, mock_connector
    ):
        """Test message sending and queue behavior."""
        # Set up create_resource mock to return our mock connector
        self.setup_create_resource_mock(mock_create_resource, mock_connector)

        # Start manager
        await upstream_session_manager.start(wait_until_ready=True)

        # Create test envelope
        test_envelope = Mock(spec=FameEnvelope)

        # Send message
        await upstream_session_manager.send(test_envelope)

        # Give message pump time to process
        await asyncio.sleep(0.1)

        # Message should have been sent via connector
        assert test_envelope in mock_connector.sent_messages

        await upstream_session_manager.stop()

    @pytest.mark.asyncio
    async def test_proper_task_cleanup_on_failure(self, mock_create_resource, envelope_factory):
        """Test that all tasks are properly cleaned up when connection fails."""
        # Create connector that fails immediately
        failing_connector = MockConnector(fail_after=0.1)

        # Set up the mock to return our failing connector
        self.setup_create_resource_mock(mock_create_resource, failing_connector)

        # Track task creation/cleanup
        created_tasks = []

        # Create mock node
        mock_node = MockNode(
            node_id="test-child",
            sid="test-session",
            envelope_factory=envelope_factory,
            admission_client=MockAdmissionClient(),
        )

        manager = UpstreamSessionManager(
            node=mock_node,
            attach_client=MockAttachClient(),
            # connector_factory=MockConnectorFactory(failing_connector),
            requested_logicals=["test-logical"],
            outbound_origin_type=DeliveryOriginType.UPSTREAM,
            inbound_origin_type=DeliveryOriginType.DOWNSTREAM,
            inbound_handler=AsyncMock(),
            on_attach=AsyncMock(),
            on_epoch_change=AsyncMock(),
        )

        # Override spawn to track tasks
        def track_spawn(coro, name=None):
            task = asyncio.create_task(coro, name=name)
            created_tasks.append(task)
            return task

        manager.spawn = track_spawn

        # Use fast heartbeat to trigger failure detection quickly
        manager.HEARTBEAT_INTERVAL = 0.05  # 50ms

        try:
            # Start manager (will fail after 0.1s)
            await manager.start(wait_until_ready=True)

            # Wait for failure and cleanup
            await asyncio.sleep(0.5)  # Give enough time for cleanup

            # All helper tasks should be cancelled/done
            helper_tasks = [
                t
                for t in created_tasks
                if t.get_name()
                and ("heartbeat" in t.get_name() or "pump" in t.get_name() or "expiry" in t.get_name())
            ]

            for task in helper_tasks:
                assert task.done(), f"Task {task.get_name()} was not cleaned up properly"

        finally:
            await self.cleanup_manager(manager)
            # Cancel any remaining tasks
            for task in created_tasks:
                if not task.done():
                    task.cancel()

    @pytest.mark.asyncio
    async def test_epoch_change_handling(
        self, mock_create_resource, upstream_session_manager, mock_connector
    ):
        """Test that epoch changes are properly handled."""
        # Set up create_resource mock to return our mock connector
        self.setup_create_resource_mock(mock_create_resource, mock_connector)

        epoch_changes = []

        async def track_epoch_change(epoch):
            epoch_changes.append(epoch)

        # Replace the epoch change handler
        upstream_session_manager._on_epoch_change = track_epoch_change

        # Start manager
        await upstream_session_manager.start(wait_until_ready=True)

        # Simulate epoch change via heartbeat ack
        ack_frame = Mock(spec=NodeHeartbeatAckFrame)
        ack_frame.routing_epoch = "new-epoch-123"
        ack_frame.corr_id = "test-corr-id"

        ack_envelope = Mock(spec=FameEnvelope)
        ack_envelope.frame = ack_frame
        ack_envelope.corr_id = "test-corr-id"
        ack_envelope.id = "test-env-id"
        ack_envelope.sec = None

        # Send heartbeat ack through the handler
        await upstream_session_manager._wrapped_handler(ack_envelope)

        # Give async handler time to execute
        await asyncio.sleep(0.1)

        # Should have recorded epoch change
        assert "new-epoch-123" in epoch_changes

        await upstream_session_manager.stop()

    @pytest.mark.asyncio
    async def test_fail_fast_on_first_connection_error(self, mock_create_resource, envelope_factory):
        """Test that manager fails fast on first connection attempt."""
        # Set up the mock (though it won't be called since admission client fails first)
        self.setup_create_resource_mock(mock_create_resource)

        # Create admission client that always fails
        class FailingAdmissionClient:
            async def hello(self, *args, **kwargs):
                raise FameConnectError("Connection failed")

        # Create mock node
        mock_node = MockNode(
            node_id="test-child",
            sid="test-session",
            envelope_factory=envelope_factory,
            admission_client=FailingAdmissionClient(),
        )

        manager = UpstreamSessionManager(
            node=mock_node,
            attach_client=MockAttachClient(),
            # connector_factory=MockConnectorFactory(MockConnector()),
            requested_logicals=["test-logical"],
            outbound_origin_type=DeliveryOriginType.UPSTREAM,
            inbound_origin_type=DeliveryOriginType.DOWNSTREAM,
            inbound_handler=AsyncMock(),
            on_attach=AsyncMock(),
            on_epoch_change=AsyncMock(),
        )

        # Should raise exception on first failure
        with pytest.raises(FameConnectError):
            await manager.start(wait_until_ready=True)

    @pytest.mark.asyncio
    async def test_backoff_and_retry_after_successful_connection(
        self, mock_create_resource, envelope_factory
    ):
        """Test that manager retries with backoff after successful initial connection."""
        # Track connection attempts
        attempt_count = 0

        class FlakyAdmissionClient:
            async def hello(self, *args, **kwargs):
                nonlocal attempt_count
                attempt_count += 1
                if attempt_count == 1:
                    # First attempt succeeds
                    return await MockAdmissionClient().hello(*args, **kwargs)
                elif attempt_count == 2:
                    # Second attempt fails (simulating reconnection failure)
                    raise FameConnectError("Reconnection failed")
                else:
                    # Subsequent attempts succeed
                    return await MockAdmissionClient().hello(*args, **kwargs)

        # Set up create_resource mock to return connector that fails after short time
        failing_connector = MockConnector(fail_after=0.1)
        self.setup_create_resource_mock(mock_create_resource, failing_connector)

        # Create mock node
        mock_node = MockNode(
            node_id="test-child",
            sid="test-session",
            envelope_factory=envelope_factory,
            admission_client=FlakyAdmissionClient(),
        )

        manager = UpstreamSessionManager(
            node=mock_node,
            attach_client=MockAttachClient(),
            # connector_factory=MockConnectorFactory(failing_connector),
            requested_logicals=["test-logical"],
            outbound_origin_type=DeliveryOriginType.UPSTREAM,
            inbound_origin_type=DeliveryOriginType.DOWNSTREAM,
            inbound_handler=AsyncMock(),
            on_attach=AsyncMock(),
            on_epoch_change=AsyncMock(),
        )

        # Use short backoff for testing
        manager.BACKOFF_INITIAL = 0.1
        manager.BACKOFF_CAP = 0.2
        manager.HEARTBEAT_INTERVAL = 0.05  # 50ms to trigger heartbeat quickly

        try:
            # Start manager (first connection succeeds)
            await manager.start(wait_until_ready=True)
            assert attempt_count == 1

            # Wait for connection failure and retry attempts
            await asyncio.sleep(0.8)  # Give enough time for backoff and retries

            # Should have attempted multiple connections
            assert attempt_count >= 3, f"Expected multiple retry attempts, got {attempt_count}"

        finally:
            await self.cleanup_manager(manager)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
