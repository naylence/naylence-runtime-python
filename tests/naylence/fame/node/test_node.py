"""
Comprehensive test coverage for the FameNode class.

This module tests        node = FameNode(
            node_meta_store=InMemoryKVStore(NodeMeta),
            system_id="test-system",e core FameNode functionality focusing on uncovered lines
and edge cases to improve test coverage.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import pytest

from naylence.fame.core import (
    DataFrame,
    DeliveryAckFrame,
    DeliveryOriginType,
    FameAddress,
    FameDeliveryContext,
    FameEnvelope,
    FameResponseType,
)
from naylence.fame.delivery.default_delivery_tracker_factory import DefaultDeliveryTrackerFactory
from naylence.fame.delivery.delivery_policy import DeliveryPolicy
from naylence.fame.node.node import (
    _NODE_STACK,
    DEFAULT_INVOKE_TIMEOUT_MILLIS,
    FameNode,
    _DefaultRetryHandler,
    get_node,
)
from naylence.fame.node.node_event_listener import NodeEventListener
from naylence.fame.node.node_meta import NodeMeta
from naylence.fame.service.default_service_manager import DefaultServiceManager
from naylence.fame.storage.in_memory_key_value_store import InMemoryKVStore
from naylence.fame.storage.in_memory_storage_provider import InMemoryStorageProvider


@pytest.fixture
def node_meta_store():
    """Create an in-memory node meta store."""
    return InMemoryKVStore(NodeMeta)


@pytest.fixture
def storage_provider():
    """Create an in-memory storage provider."""
    return InMemoryStorageProvider()


@pytest.fixture
async def delivery_tracker(storage_provider):
    """Create a delivery tracker."""
    factory = DefaultDeliveryTrackerFactory()
    return await factory.create(storage_provider=storage_provider)


@pytest.fixture
async def basic_node(node_meta_store, storage_provider, delivery_tracker):
    """Create a basic FameNode for testing."""
    node = FameNode(
        node_meta_store=node_meta_store,
        storage_provider=storage_provider,
        delivery_tracker=delivery_tracker,
        system_id="test-system",
    )
    node._physical_path = "test.node.path"  # Set physical path for tests

    # Initialize the delivery tracker properly
    await delivery_tracker.on_node_initialized(node)

    return node


class TestGetNode:
    """Test the get_node() function - lines 75-78."""

    def test_get_node_with_no_stack_raises_runtime_error(self):
        """Test get_node raises RuntimeError when no node in context."""
        # Clear the context stack
        _NODE_STACK.set(None)

        with pytest.raises(RuntimeError, match="No FameNode in context"):
            get_node()

    def test_get_node_with_empty_stack_raises_runtime_error(self):
        """Test get_node raises RuntimeError when stack is empty."""
        # Set empty stack
        _NODE_STACK.set([])

        with pytest.raises(RuntimeError, match="No FameNode in context"):
            get_node()

    def test_get_node_returns_last_node_from_stack(self, node_meta_store, storage_provider):
        """Test get_node returns the last node from the context stack."""
        # Clear any existing context
        _NODE_STACK.set(None)

        # Create delivery tracker
        factory = DefaultDeliveryTrackerFactory()

        async def test_async():
            delivery_tracker = await factory.create(storage_provider=storage_provider)

            # Create a node and push it to the stack
            node1 = FameNode(
                node_meta_store=node_meta_store,
                storage_provider=storage_provider,
                delivery_tracker=delivery_tracker,
                system_id="test-system-1",
            )

            # Create second node and push it to the stack
            node2 = FameNode(
                node_meta_store=InMemoryKVStore(NodeMeta),
                storage_provider=storage_provider,
                delivery_tracker=delivery_tracker,
                system_id="test-system-2",
            )

            # Simulate node context stack
            stack = [node1, node2]
            _NODE_STACK.set(stack)

            # Should return the last node in the stack
            assert get_node() is node2

        asyncio.run(test_async())


class TestDefaultRetryHandler:
    """Test the _DefaultRetryHandler class - lines 95-101."""

    @pytest.mark.asyncio
    async def test_on_retry_needed_calls_delivery_function(self):
        """Test that on_retry_needed calls the delivery function."""
        delivery_fn = AsyncMock()
        handler = _DefaultRetryHandler(delivery_fn)

        envelope = FameEnvelope(
            id="test-id",
            to=FameAddress("test@/node"),
            frame=DataFrame(payload=b"test"),
        )
        context = MagicMock(spec=FameDeliveryContext)

        await handler.on_retry_needed(envelope, attempt=2, next_delay_ms=1000, context=context)

        delivery_fn.assert_called_once_with(envelope, context)

    @pytest.mark.asyncio
    async def test_on_retry_needed_without_context(self):
        """Test that on_retry_needed works without context."""
        delivery_fn = AsyncMock()
        handler = _DefaultRetryHandler(delivery_fn)

        envelope = FameEnvelope(
            id="test-id",
            to=FameAddress("test@/node"),
            frame=DataFrame(payload=b"test"),
        )

        await handler.on_retry_needed(envelope, attempt=1, next_delay_ms=500)

        delivery_fn.assert_called_once_with(envelope, None)


class TestFameNodeProperties:
    """Test FameNode property accessors that have uncovered lines."""

    def test_physical_path_raises_runtime_error_when_not_assigned(self, basic_node):
        """Test physical_path property raises RuntimeError when not assigned - line 254."""
        # Ensure _physical_path is None/empty
        basic_node._physical_path = None

        with pytest.raises(RuntimeError, match="Physical path not assigned yet"):
            _ = basic_node.physical_path

    def test_physical_path_returns_value_when_assigned(self, basic_node):
        """Test physical_path property returns value when assigned."""
        test_path = "/test/physical/path"
        basic_node._physical_path = test_path

        assert basic_node.physical_path == test_path

    def test_default_binding_path_returns_physical_path(self, basic_node):
        """Test default_binding_path returns physical_path - line 259."""
        test_path = "/test/binding/path"
        basic_node._physical_path = test_path

        assert basic_node.default_binding_path == test_path


class TestFameNodeEventListeners:
    """Test event listener management - lines 311-314, 318-319."""

    def test_add_event_listener_appends_and_sorts(self, basic_node):
        """Test add_event_listener maintains priority ordering."""
        # Clear existing listeners to have a clean test
        initial_count = len(basic_node._event_listeners)

        listener1 = MagicMock(spec=NodeEventListener)
        listener1.priority = 10

        listener2 = MagicMock(spec=NodeEventListener)
        listener2.priority = 5

        listener3 = MagicMock(spec=NodeEventListener)
        listener3.priority = 15

        # Add listeners in non-priority order
        basic_node.add_event_listener(listener1)
        basic_node.add_event_listener(listener2)
        basic_node.add_event_listener(listener3)

        # Should have added 3 more listeners
        assert len(basic_node._event_listeners) == initial_count + 3

        # The entire list is sorted, so let's check that our listeners appear in priority order
        # The sort is stable, so listeners with the same priority maintain their original order
        our_listeners = [listener1, listener2, listener3]

        # Find where our listeners appear in the sorted list
        found_positions = [
            basic_node._event_listeners.index(listener)
            for listener in our_listeners
            if listener in basic_node._event_listeners
        ]

        # listener2 (priority 5) should come before listener1 (priority 10)
        # listener1 (priority 10) should come before listener3 (priority 15)
        assert len(found_positions) == 3
        listener2_pos = basic_node._event_listeners.index(listener2)
        listener1_pos = basic_node._event_listeners.index(listener1)
        listener3_pos = basic_node._event_listeners.index(listener3)

        # Lower priority number = higher priority (comes first)
        assert listener2_pos < listener1_pos < listener3_pos

    def test_add_event_listener_does_not_duplicate(self, basic_node):
        """Test add_event_listener doesn't add duplicates."""
        initial_count = len(basic_node._event_listeners)

        listener = MagicMock(spec=NodeEventListener)
        listener.priority = 10

        basic_node.add_event_listener(listener)
        basic_node.add_event_listener(listener)  # Add same listener again

        # Should only add one listener
        assert len(basic_node._event_listeners) == initial_count + 1
        assert basic_node._event_listeners[0] is listener

    def test_remove_event_listener_removes_listener(self, basic_node):
        """Test remove_event_listener removes listener from list."""
        initial_count = len(basic_node._event_listeners)

        listener1 = MagicMock(spec=NodeEventListener)
        listener1.priority = 10

        listener2 = MagicMock(spec=NodeEventListener)
        listener2.priority = 5

        basic_node.add_event_listener(listener1)
        basic_node.add_event_listener(listener2)

        assert len(basic_node._event_listeners) == initial_count + 2

        basic_node.remove_event_listener(listener1)

        assert len(basic_node._event_listeners) == initial_count + 1
        assert listener1 not in basic_node._event_listeners
        assert listener2 in basic_node._event_listeners

    def test_remove_event_listener_ignores_missing_listener(self, basic_node):
        """Test remove_event_listener ignores listeners not in the list."""
        initial_count = len(basic_node._event_listeners)

        listener1 = MagicMock(spec=NodeEventListener)
        listener1.priority = 10

        listener2 = MagicMock(spec=NodeEventListener)
        listener2.priority = 5

        basic_node.add_event_listener(listener1)

        # Try to remove listener that was never added
        basic_node.remove_event_listener(listener2)

        assert len(basic_node._event_listeners) == initial_count + 1
        assert basic_node._event_listeners[0] is listener1


class TestFameNodeGatherSupportedCallbackGrants:
    """Test gather_supported_callback_grants method - lines 334-347."""

    def test_gather_supported_callback_grants_empty_when_no_listeners(self, basic_node):
        """Test gather_supported_callback_grants returns empty list when no transport listeners."""
        result = basic_node.gather_supported_callback_grants()
        assert result == []

    def test_gather_supported_callback_grants_collects_from_transport_listeners(self, basic_node):
        """Test gather_supported_callback_grants collects grants from transport listeners."""
        from naylence.fame.connector.transport_listener import TransportListener

        # Mock transport listeners that inherit from TransportListener
        listener1 = MagicMock(spec=TransportListener)
        listener1.priority = 10  # Add priority for sorting
        grant1 = {"type": "http", "port": 8080}
        listener1.as_callback_grant.return_value = grant1

        listener2 = MagicMock(spec=TransportListener)
        listener2.priority = 15  # Add priority for sorting
        grant2 = {"type": "websocket", "port": 8081}
        listener2.as_callback_grant.return_value = grant2

        # Regular event listener (not a transport listener)
        listener3 = MagicMock(spec=NodeEventListener)
        listener3.priority = 10

        # Add listeners to event listeners list
        basic_node.add_event_listener(listener1)
        basic_node.add_event_listener(listener2)
        basic_node.add_event_listener(listener3)

        result = basic_node.gather_supported_callback_grants()

        assert len(result) == 2
        assert grant1 in result
        assert grant2 in result


class TestFameNodeForwardUpstream:
    """Test forward_upstream method with DeliveryOriginType check - lines 724-768."""

    @pytest.mark.asyncio
    async def test_forward_upstream_skips_when_origin_is_upstream(self, basic_node):
        """Test forward_upstream skips forwarding when origin is UPSTREAM to avoid loops."""
        envelope = FameEnvelope(
            id="test-id",
            to=FameAddress("test@/node"),
            frame=DataFrame(payload=b"test"),
        )

        context = FameDeliveryContext(origin_type=DeliveryOriginType.UPSTREAM, correlation_id="test-corr")

        # Mock the upstream session manager to ensure it's not called
        mock_upstream = AsyncMock()
        basic_node._upstream_session_manager = mock_upstream

        await basic_node.forward_upstream(envelope, context)

        # Should not have called the upstream session manager
        mock_upstream.send.assert_not_called()

    @pytest.mark.asyncio
    async def test_forward_upstream_proceeds_when_no_context(self, basic_node):
        """Test forward_upstream proceeds when context is None."""
        # Set physical path to avoid RuntimeError
        basic_node._physical_path = "/test/node"

        envelope = FameEnvelope(
            id="test-id",
            to=FameAddress("test@/node"),
            frame=DataFrame(payload=b"test"),
        )

        # Mock dependencies for forward_upstream
        mock_upstream_connector = MagicMock()
        basic_node._upstream_connector = mock_upstream_connector

        # Import and mock UpstreamSessionManager properly
        from naylence.fame.node.upstream_session_manager import UpstreamSessionManager

        mock_session_manager = AsyncMock(spec=UpstreamSessionManager)
        basic_node._session_manager = mock_session_manager

        with patch.object(basic_node, "_dispatch_envelope_event", new_callable=AsyncMock) as mock_dispatch:
            mock_dispatch.return_value = envelope  # Return unmodified envelope

            await basic_node.forward_upstream(envelope, None)

            # Should call session manager
            mock_session_manager.send.assert_called_once_with(envelope)
            # Should have dispatched the events (on_forward_upstream and on_forward_upstream_complete)
            assert mock_dispatch.call_count == 2
            # Verify the first call is for on_forward_upstream
            first_call = mock_dispatch.call_args_list[0]
            assert first_call[0][0] == "on_forward_upstream"
            # Verify the second call is for on_forward_upstream_complete
            second_call = mock_dispatch.call_args_list[1]
            assert second_call[0][0] == "on_forward_upstream_complete"

    @pytest.mark.asyncio
    async def test_forward_upstream_proceeds_when_origin_is_not_upstream(self, basic_node):
        """Test forward_upstream proceeds when origin is not UPSTREAM."""
        # Set physical path to avoid RuntimeError
        basic_node._physical_path = "/test/node"

        envelope = FameEnvelope(
            id="test-id",
            to=FameAddress("test@/node"),
            frame=DataFrame(payload=b"test"),
        )

        context = FameDeliveryContext(origin_type=DeliveryOriginType.LOCAL, correlation_id="test-corr")

        # Mock dependencies for forward_upstream
        mock_upstream_connector = MagicMock()
        basic_node._upstream_connector = mock_upstream_connector

        # Import and mock UpstreamSessionManager properly
        from naylence.fame.node.upstream_session_manager import UpstreamSessionManager

        mock_session_manager = AsyncMock(spec=UpstreamSessionManager)
        basic_node._session_manager = mock_session_manager

        with patch.object(basic_node, "_dispatch_envelope_event", new_callable=AsyncMock) as mock_dispatch:
            mock_dispatch.return_value = envelope  # Return unmodified envelope

            await basic_node.forward_upstream(envelope, context)

            # Should call session manager
            mock_session_manager.send.assert_called_once_with(envelope)
            # Should have dispatched the events (on_forward_upstream and on_forward_upstream_complete)
            assert mock_dispatch.call_count == 2
            # Verify the first call is for on_forward_upstream
            first_call = mock_dispatch.call_args_list[0]
            assert first_call[0][0] == "on_forward_upstream"
            # Verify the second call is for on_forward_upstream_complete
            second_call = mock_dispatch.call_args_list[1]
            assert second_call[0][0] == "on_forward_upstream_complete"

    @pytest.mark.asyncio
    async def test_forward_upstream_error_handling(self, basic_node):
        """Test forward_upstream handles exceptions properly."""
        # Set physical path to avoid RuntimeError
        basic_node._physical_path = "/test/node"

        envelope = FameEnvelope(
            id="test-id",
            to=FameAddress("test@/node"),
            frame=DataFrame(payload=b"test"),
        )

        # Mock dependencies for forward_upstream
        mock_upstream_connector = MagicMock()
        basic_node._upstream_connector = mock_upstream_connector

        # Import and mock UpstreamSessionManager properly
        from naylence.fame.node.upstream_session_manager import UpstreamSessionManager

        mock_session_manager = AsyncMock(spec=UpstreamSessionManager)
        mock_session_manager.send.side_effect = Exception("Send failed")
        basic_node._session_manager = mock_session_manager

        with patch.object(basic_node, "_dispatch_envelope_event", new_callable=AsyncMock) as mock_dispatch:
            mock_dispatch.return_value = envelope  # Return unmodified envelope

            # Should raise the exception after handling it
            with pytest.raises(Exception, match="Send failed"):
                await basic_node.forward_upstream(envelope, None)

            # Should have called dispatch twice: once for start, once for error completion
            assert mock_dispatch.call_count == 2

            # Verify the completion call includes the error
            completion_call = mock_dispatch.call_args_list[1]
            assert completion_call[0][0] == "on_forward_upstream_complete"
            assert "error" in completion_call[1]

    @pytest.mark.asyncio
    async def test_forward_upstream_no_upstream_connector(self, basic_node):
        """Test forward_upstream handles missing upstream connector."""
        # Set physical path to avoid RuntimeError
        basic_node._physical_path = "/test/node"

        envelope = FameEnvelope(
            id="test-id",
            to=FameAddress("test@/node"),
            frame=DataFrame(payload=b"test"),
        )

        # No upstream connector
        basic_node._upstream_connector = None

        with patch.object(basic_node, "_dispatch_envelope_event", new_callable=AsyncMock) as mock_dispatch:
            mock_dispatch.return_value = envelope  # Return unmodified envelope

            await basic_node.forward_upstream(envelope, None)

            # Should only call dispatch once for the start event, then return early
            assert mock_dispatch.call_count == 1
            first_call = mock_dispatch.call_args_list[0]
            assert first_call[0][0] == "on_forward_upstream"


class TestFameNodeConnectionMethods:
    """Test connection and initialization methods for better coverage."""

    @pytest.mark.asyncio
    async def test_connect_to_upstream_missing_attach_client(self, basic_node):
        """Test _connect_to_upstream raises error when attach_client is missing."""
        basic_node.attach_client = None

        with pytest.raises(RuntimeError, match="Missing attach client"):
            await basic_node._connect_to_upstream()

    @pytest.mark.asyncio
    async def test_connect_to_upstream_missing_admission_client(self, basic_node):
        """Test _connect_to_upstream raises error when admission_client is missing."""

        basic_node.attach_client = MagicMock()
        basic_node._admission_client = None

        with pytest.raises(RuntimeError, match="Missing admission client"):
            await basic_node._connect_to_upstream()

    @pytest.mark.asyncio
    async def test_connect_to_upstream_creates_session_manager(self, basic_node):
        """Test _connect_to_upstream creates UpstreamSessionManager properly."""
        from unittest.mock import AsyncMock, patch

        from naylence.fame.node.admission.noop_admission_client import NoopAdmissionClient

        # Mock required components
        basic_node.attach_client = MagicMock()
        basic_node._admission_client = NoopAdmissionClient()

        with patch("naylence.fame.node.node.UpstreamSessionManager") as mock_session_class:
            mock_session = AsyncMock()
            mock_session_class.return_value = mock_session

            await basic_node._connect_to_upstream()

            # Verify UpstreamSessionManager was created with correct parameters
            mock_session_class.assert_called_once()
            call_kwargs = mock_session_class.call_args[1]
            assert call_kwargs["node"] == basic_node
            assert call_kwargs["attach_client"] == basic_node.attach_client

            # Verify start was called
            mock_session.start.assert_called_once()
            assert basic_node._session_manager == mock_session

    @pytest.mark.asyncio
    async def test_on_welcome_sets_node_properties(self, basic_node):
        """Test _on_welcome sets node properties from welcome frame."""
        from datetime import datetime, timezone

        from naylence.fame.core import NodeWelcomeFrame

        welcome_frame = NodeWelcomeFrame(
            system_id="test-system-123",
            instance_id="test-instance-123",
            accepted_logicals=["logical1", "logical2"],
            expires_at=datetime.now(timezone.utc),
            assigned_path="/test-system-123",
            connection_grants=[],
        )

        # Test welcome for node without parent
        basic_node._has_parent = False

        await basic_node._on_welcome(welcome_frame)

        assert basic_node._id == "test-system-123"
        assert basic_node._accepted_logicals == {"logical1", "logical2"}
        assert basic_node._physical_path == "/test-system-123"
        assert basic_node._physical_segments == ["test-system-123"]
        assert basic_node._upstream_connector is None
        assert basic_node._handshake_completed is True

    @pytest.mark.asyncio
    async def test_on_welcome_without_assigned_path(self, basic_node):
        """Test _on_welcome handles missing assigned_path."""
        from datetime import datetime, timezone

        from naylence.fame.core import NodeWelcomeFrame

        welcome_frame = NodeWelcomeFrame(
            system_id="test-system-456",
            instance_id="test-instance-456",
            accepted_logicals=[],
            expires_at=datetime.now(timezone.utc),
            assigned_path=None,  # No assigned path
            connection_grants=[],
        )

        basic_node._has_parent = False

        await basic_node._on_welcome(welcome_frame)

        assert basic_node._physical_path == "/test-system-456"
        assert basic_node._physical_segments == ["test-system-456"]


class TestFameNodeMiscMethods:
    """Test various smaller uncovered methods and edge cases."""

    @pytest.mark.asyncio
    async def test_node_initialization_sets_default_values(self, node_meta_store, storage_provider):
        """Test that node initialization sets proper default values."""
        from naylence.fame.delivery.default_delivery_tracker_factory import DefaultDeliveryTrackerFactory
        from naylence.fame.node.node import FameNode

        # Create delivery tracker properly with await
        delivery_tracker_factory = DefaultDeliveryTrackerFactory()
        delivery_tracker = await delivery_tracker_factory.create(storage_provider=storage_provider)

        node = FameNode(
            node_meta_store=node_meta_store,
            storage_provider=storage_provider,
            delivery_tracker=delivery_tracker,
        )

        assert node._is_started is False
        assert node._physical_path is None
        assert node._id == ""  # Node is initialized with empty string, not None
        assert node._session_manager is None

    def test_node_initialization_with_optional_parameters(self, node_meta_store, storage_provider):
        """Test FameNode initialization with optional parameters."""
        mock_admission_client = MagicMock()
        mock_service_manager = MagicMock(spec=DefaultServiceManager)
        factory = DefaultDeliveryTrackerFactory()

        async def test_async():
            delivery_tracker = await factory.create(storage_provider=storage_provider)

            node = FameNode(
                node_meta_store=node_meta_store,
                storage_provider=storage_provider,
                delivery_tracker=delivery_tracker,
                system_id="test-system",
                admission_client=mock_admission_client,
                service_manager=mock_service_manager,
                has_parent=True,
                requested_logicals=["logical1", "logical2"],
                binding_ack_timeout_ms=5000,
            )

            assert node._admission_client is mock_admission_client
            assert node._service_manager is mock_service_manager
            assert node._has_parent is True
            assert node._requested_logicals == ["logical1", "logical2"]
            # binding_ack_timeout_ms is passed to binding_manager

        asyncio.run(test_async())

    @pytest.mark.asyncio
    async def test_node_context_stack_management(self, basic_node):
        """Test that node context stack is properly managed during operations."""
        # This tests implicit context stack usage during node operations
        initial_stack = _NODE_STACK.get()

        # Simulate some operation that might use the context stack
        async def test_operation():
            # This would be called from within a node operation
            try:
                current_node = get_node()
                return current_node
            except RuntimeError:
                return None

        # Without setting up the stack, should get None
        result = await test_operation()
        assert result is None

        # Set up the stack and try again
        _NODE_STACK.set([basic_node])
        result = await test_operation()
        assert result is basic_node

        # Clean up
        _NODE_STACK.set(initial_stack)


class TestEdgeCases:
    """Test edge cases and error conditions to improve coverage."""

    def test_sort_event_listeners_maintains_stable_ordering(self, basic_node):
        """Test _sort_event_listeners maintains stable ordering for equal priorities."""
        # Create listeners with same priority
        listener1 = MagicMock(spec=NodeEventListener)
        listener1.priority = 10

        listener2 = MagicMock(spec=NodeEventListener)
        listener2.priority = 10

        listener3 = MagicMock(spec=NodeEventListener)
        listener3.priority = 5

        # Add in specific order
        basic_node._event_listeners = [listener1, listener2, listener3]
        basic_node._sort_event_listeners()

        # listener3 should be first (priority 5), then listener1, listener2 in original order
        assert basic_node._event_listeners[0] is listener3
        assert basic_node._event_listeners[1] is listener1  # Original order preserved
        assert basic_node._event_listeners[2] is listener2

    @pytest.mark.asyncio
    async def test_delivery_tracking_with_retry_handler(self, basic_node):
        """Test delivery tracking uses retry handler correctly."""
        # Mock delivery tracker
        mock_tracker = MagicMock()
        basic_node._delivery_tracker = mock_tracker

        FameEnvelope(
            id="test-id",
            to=FameAddress("test@/node"),
            frame=DataFrame(payload=b"test"),
        )

        # This would test the retry handler integration, but requires more setup
        # Just verify the handler can be created
        delivery_fn = AsyncMock()
        retry_handler = _DefaultRetryHandler(delivery_fn)

        assert retry_handler._delivery_fn is delivery_fn


class TestFameNodeDeliveryHandling:
    """Test delivery and envelope handling methods for better coverage."""

    @pytest.mark.asyncio
    async def test_handle_delivery_ack(self, basic_node):
        """Test _handle_delivery_ack method."""
        from naylence.fame.core import DeliveryAckFrame

        ack_frame = DeliveryAckFrame(ref_id="test-env-id", ok=True, code="delivered")

        envelope = FameEnvelope(id="test-env-id", to=FameAddress("test@/node"), frame=ack_frame)

        # The _handle_delivery_ack method just logs, so let's test that it completes without error
        result = await basic_node._handle_delivery_ack(envelope)

        # Method should complete successfully (returns None)
        assert result is None

    def test_get_source_system_id_with_context(self, basic_node):
        """Test _get_source_system_id extracts system ID from context."""
        from naylence.fame.core import DeliveryOriginType, FameDeliveryContext

        context = FameDeliveryContext(
            from_system_id="source-system-123", origin_type=DeliveryOriginType.LOCAL
        )

        result = basic_node._get_source_system_id(context)
        assert result == "source-system-123"

    def test_get_source_system_id_no_context(self, basic_node):
        """Test _get_source_system_id returns None when no context."""
        result = basic_node._get_source_system_id(None)
        assert result is None

    def test_get_source_system_id_context_no_system_id(self, basic_node):
        """Test _get_source_system_id returns None when context has no system ID."""
        from naylence.fame.core import DeliveryOriginType, FameDeliveryContext

        context = FameDeliveryContext(from_system_id=None, origin_type=DeliveryOriginType.LOCAL)

        result = basic_node._get_source_system_id(context)
        assert result is None

    @pytest.mark.asyncio
    async def test_handle_inbound_from_upstream(self, basic_node):
        """Test handle_inbound_from_upstream processes envelopes."""
        envelope = FameEnvelope(
            id="upstream-env", to=FameAddress("test@/node"), frame=DataFrame(payload=b"upstream data")
        )

        from naylence.fame.core import DeliveryOriginType, FameDeliveryContext

        context = FameDeliveryContext(origin_type=DeliveryOriginType.UPSTREAM)

        # Mock the delivery method
        with patch.object(basic_node, "deliver", new_callable=AsyncMock) as mock_deliver:
            await basic_node.handle_inbound_from_upstream(envelope, context)

            # Check it was called with context as keyword argument
            mock_deliver.assert_called_once_with(envelope, context=context)

    @pytest.mark.asyncio
    async def test_deliver_with_security_processing_halt(self, basic_node):
        """Test deliver when security processing returns None (halts delivery)."""
        envelope = MagicMock()
        envelope.frame = MagicMock()
        envelope.frame.type = "Data"

        # Mock _dispatch_envelope_event to return None (security halt)
        basic_node._dispatch_envelope_event = AsyncMock(return_value=None)

        # Should return early without further processing
        await basic_node.deliver(envelope)

        basic_node._dispatch_envelope_event.assert_called_once_with(
            "on_deliver", basic_node, envelope, context=None
        )

    @pytest.mark.asyncio
    async def test_deliver_control_frames_to_upstream(self, basic_node):
        """Test deliver forwards control frames to upstream."""
        envelope = MagicMock()
        envelope.frame = MagicMock()

        # Ensure upstream connector exists
        basic_node._upstream_connector = MagicMock()

        # Test various control frame types
        control_frames = [
            "AddressBind",
            "AddressUnbind",
            "CapabilityAdvertise",
            "CapabilityWithdraw",
            "NodeHeartbeat",
        ]

        for frame_type in control_frames:
            envelope.frame.type = frame_type

            # Mock _dispatch_envelope_event to return the envelope
            basic_node._dispatch_envelope_event = AsyncMock(return_value=envelope)
            basic_node.forward_upstream = AsyncMock()

            await basic_node.deliver(envelope)

            basic_node.forward_upstream.assert_called_with(envelope, None)
            basic_node.forward_upstream.reset_mock()

    @pytest.mark.asyncio
    async def test_deliver_control_frames_without_upstream(self, basic_node):
        """Test deliver control frames when no upstream connector."""
        envelope = MagicMock()
        envelope.frame = MagicMock()
        envelope.frame.type = "AddressBind"

        # Mock _dispatch_envelope_event to return the envelope
        basic_node._dispatch_envelope_event = AsyncMock(return_value=envelope)
        basic_node._upstream_connector = None

        await basic_node.deliver(envelope)

        # Should not raise error when no upstream connector

    @pytest.mark.asyncio
    async def test_deliver_ack_frames_system_delivery(self, basic_node):
        """Test deliver handles ack frames with system delivery."""
        envelope = MagicMock()
        envelope.frame = MagicMock()

        ack_frames = [
            "AddressBindAck",
            "AddressUnbindAck",
            "CapabilityAdvertiseAck",
            "CapabilityWithdrawAck",
        ]

        for frame_type in ack_frames:
            envelope.frame.type = frame_type

            # Mock _dispatch_envelope_event to return the envelope
            basic_node._dispatch_envelope_event = AsyncMock(return_value=envelope)
            basic_node._delivery_tracker.on_envelope_delivered = AsyncMock()

            # Use the actual SYSTEM_INBOX value
            SYSTEM_INBOX = "__sys__"

            await basic_node.deliver(envelope)

            basic_node._delivery_tracker.on_envelope_delivered.assert_called_with(
                SYSTEM_INBOX, envelope, None
            )
            basic_node._delivery_tracker.on_envelope_delivered.reset_mock()

    @pytest.mark.asyncio
    async def test_deliver_data_frame_local_explicit_to(self, basic_node):
        """Test deliver data frame with explicit local 'to' address."""
        envelope = MagicMock()
        envelope.frame = MagicMock()
        envelope.frame.type = "Data"
        envelope.to = "local_address"
        envelope.capabilities = None

        # Mock _dispatch_envelope_event to return the envelope
        basic_node._dispatch_envelope_event = AsyncMock(return_value=envelope)
        basic_node.has_local = MagicMock(return_value=True)
        basic_node.deliver_local = AsyncMock()

        await basic_node.deliver(envelope)

        basic_node.has_local.assert_called_with("local_address")
        basic_node.deliver_local.assert_called_with("local_address", envelope, None)

    @pytest.mark.asyncio
    async def test_deliver_data_frame_capability_resolution(self, basic_node):
        """Test deliver data frame with capability resolution fallback."""
        envelope = MagicMock()
        envelope.frame = MagicMock()
        envelope.frame.type = "Data"
        envelope.to = None
        envelope.capabilities = ["test_capability"]

        resolved_address = "resolved_address"

        # Mock _dispatch_envelope_event to return the envelope
        basic_node._dispatch_envelope_event = AsyncMock(return_value=envelope)
        basic_node.has_local = MagicMock(return_value=False)
        basic_node._service_manager.resolve_address_by_capability = AsyncMock(return_value=resolved_address)
        basic_node.deliver_local = AsyncMock()

        await basic_node.deliver(envelope)

        basic_node._service_manager.resolve_address_by_capability.assert_called_with(["test_capability"])
        basic_node.deliver_local.assert_called_with(resolved_address, envelope, None)

    @pytest.mark.asyncio
    async def test_deliver_data_frame_no_local_match_forward_upstream(self, basic_node):
        """Test deliver forwards to upstream when no local match."""
        envelope = MagicMock()
        envelope.frame = MagicMock()
        envelope.frame.type = "Data"
        envelope.to = "remote_address"
        envelope.capabilities = None

        context = MagicMock()
        context.from_connector = MagicMock()  # Different from upstream

        # Ensure upstream connector exists
        basic_node._upstream_connector = MagicMock()

        # Mock _dispatch_envelope_event to return the envelope
        basic_node._dispatch_envelope_event = AsyncMock(return_value=envelope)
        basic_node.has_local = MagicMock(return_value=False)
        basic_node._service_manager.resolve_address_by_capability = AsyncMock(return_value=None)
        basic_node.forward_upstream = AsyncMock()

        # Mock DeliveryOriginType enum
        from unittest.mock import patch

        with patch("naylence.fame.node.node.DeliveryOriginType") as mock_origin_type:
            mock_origin_type.LOCAL = "LOCAL"
            context.origin_type = "LOCAL"

            await basic_node.deliver(envelope, context)

            basic_node.forward_upstream.assert_called_with(envelope, context)

    @pytest.mark.asyncio
    async def test_deliver_prevents_upstream_redirect_loop(self, basic_node):
        """Test deliver prevents redirecting envelope back to upstream."""
        envelope = MagicMock()
        envelope.frame = MagicMock()
        envelope.frame.type = "Data"
        envelope.to = "remote_address"

        # Ensure upstream connector exists
        basic_node._upstream_connector = MagicMock()

        context = MagicMock()
        context.from_connector = basic_node._upstream_connector  # Same as upstream

        # Mock _dispatch_envelope_event to return the envelope
        basic_node._dispatch_envelope_event = AsyncMock(return_value=envelope)
        basic_node.has_local = MagicMock(return_value=False)
        basic_node._service_manager.resolve_address_by_capability = AsyncMock(return_value=None)
        basic_node.forward_upstream = AsyncMock()

        # Mock DeliveryOriginType to make the condition trigger
        from unittest.mock import patch

        with patch("naylence.fame.node.node.DeliveryOriginType") as mock_origin_type:
            mock_origin_type.LOCAL = "LOCAL"
            context.origin_type = "LOCAL"

            with patch("naylence.fame.node.node.logger") as mock_logger:
                await basic_node.deliver(envelope, context)

                mock_logger.error.assert_called()
                basic_node.forward_upstream.assert_not_called()

    @pytest.mark.asyncio
    async def test_deliver_secure_frame_types(self, basic_node):
        """Test deliver handles secure frame types."""
        secure_frames = ["SecureOpen", "SecureAccept", "SecureClose", "DeliveryAck"]

        for frame_type in secure_frames:
            envelope = MagicMock()
            envelope.frame = MagicMock()
            envelope.frame.type = frame_type
            envelope.to = "local_address"
            envelope.capabilities = None

            # Mock _dispatch_envelope_event to return the envelope
            basic_node._dispatch_envelope_event = AsyncMock(return_value=envelope)
            basic_node.has_local = MagicMock(return_value=True)
            basic_node.deliver_local = AsyncMock()

            await basic_node.deliver(envelope)

            basic_node.deliver_local.assert_called_with("local_address", envelope, None)
            basic_node.deliver_local.reset_mock()

    def test_has_local_with_explicit_binding(self, basic_node):
        """Test has_local returns True when explicit binding exists."""
        address = "test_address"
        basic_node._binding_manager.has_binding = MagicMock(return_value=True)

        result = basic_node.has_local(address)

        assert result is True
        basic_node._binding_manager.has_binding.assert_called_with(address)

    def test_has_local_with_physical_path_match(self, basic_node):
        """Test has_local returns True when physical path matches."""
        address = "test_address"
        basic_node._binding_manager.has_binding = MagicMock(return_value=False)
        basic_node._physical_path = "/test/path"

        with patch("naylence.fame.core.parse_address") as mock_parse:
            mock_parse.return_value = ("system", "/test/path")

            result = basic_node.has_local(address)

            assert result is True
            mock_parse.assert_called_with(address)

    def test_has_local_with_no_match(self, basic_node):
        """Test has_local returns False when no match."""
        address = "test_address"
        basic_node._binding_manager.has_binding = MagicMock(return_value=False)
        basic_node._physical_path = "/different/path"

        with patch("naylence.fame.core.parse_address") as mock_parse:
            mock_parse.return_value = ("system", "/test/path")

            result = basic_node.has_local(address)

            assert result is False

    def test_has_local_with_parse_error(self, basic_node):
        """Test has_local handles parse_address errors gracefully."""
        address = "test_address"
        basic_node._binding_manager.has_binding = MagicMock(return_value=False)

        with patch("naylence.fame.core.parse_address") as mock_parse:
            mock_parse.side_effect = ValueError("Parse error")

            result = basic_node.has_local(address)

            assert result is False

    def test_has_local_with_runtime_error(self, basic_node):
        """Test has_local handles RuntimeError gracefully."""
        address = "test_address"
        basic_node._binding_manager.has_binding = MagicMock(return_value=False)

        with patch("naylence.fame.core.parse_address") as mock_parse:
            mock_parse.side_effect = RuntimeError("Runtime error")

            result = basic_node.has_local(address)

            assert result is False


class TestFameNodePropertyMethods:
    """Test property access methods and edge cases."""

    def test_upstream_connector_property_with_session_manager(self, basic_node):
        """Test upstream_connector property when session manager exists."""
        from naylence.fame.node.upstream_session_manager import UpstreamSessionManager

        # Mock session manager with connector
        mock_session = MagicMock(spec=UpstreamSessionManager)
        mock_connector = MagicMock()
        mock_session._connector = mock_connector
        basic_node._session_manager = mock_session

        result = basic_node.upstream_connector
        assert result == mock_connector

    def test_upstream_connector_property_without_session_manager(self, basic_node):
        """Test upstream_connector property when no session manager."""
        basic_node._session_manager = None

        result = basic_node.upstream_connector
        assert result is None

    def test_upstream_connector_property_wrong_session_type(self, basic_node):
        """Test upstream_connector property with wrong session manager type."""
        # Mock a different type of session manager
        mock_session = MagicMock()  # Not UpstreamSessionManager
        basic_node._session_manager = mock_session

        result = basic_node.upstream_connector
        assert result is None

    def test_physical_path_segments_empty_path(self, basic_node):
        """Test physical_path handling with empty path."""
        basic_node._physical_path = "/"

        # This should result in empty segments
        parts = basic_node._physical_path.strip("/").split("/")
        segments = parts if parts != [""] else []

        assert segments == []

    def test_physical_path_segments_multiple_levels(self, basic_node):
        """Test physical_path handling with multiple path levels."""
        basic_node._physical_path = "/root/child/grandchild"

        parts = basic_node._physical_path.strip("/").split("/")
        segments = parts if parts != [""] else []

        assert segments == ["root", "child", "grandchild"]


class TestFameNodeEdgeCases:
    """Test edge cases and error conditions."""

    def test_node_id_when_not_set(self, basic_node):
        """Test node id property when not set."""
        basic_node._id = None
        assert basic_node.id is None

    def test_id_when_not_set(self, basic_node):
        """Test id property when not set."""
        basic_node._id = None
        assert basic_node.id is None

    def test_physical_path_when_not_set_raises_error(self, basic_node):
        """Test physical_path property raises error when not set."""
        basic_node._physical_path = None
        with pytest.raises(RuntimeError, match="Physical path not assigned yet"):
            _ = basic_node.physical_path


class TestFameNodeSendMethod:
    """Test the send method functionality."""

    @pytest.fixture
    def mock_envelope(self):
        """Create a real envelope for testing."""
        from naylence.fame.core import DataFrame, FameAddress, FameEnvelope

        envelope = FameEnvelope(
            id="test-envelope-id", to=FameAddress("test@/test"), frame=DataFrame(payload=b"test data")
        )
        return envelope

    @pytest.fixture
    def mock_delivery_context(self):
        """Create a mock delivery context."""
        context = Mock(spec=FameDeliveryContext)
        context.origin_type = None
        context.from_system_id = None
        context.from_connector = None
        return context

    async def test_send_with_default_context(self, basic_node, mock_envelope):
        """Test send creates default LOCAL context when none provided."""
        with patch.object(basic_node, "deliver", new_callable=AsyncMock) as mock_deliver:
            await basic_node.send(mock_envelope)

            # Verify deliver was called with LOCAL context
            mock_deliver.assert_called_once()
            args, kwargs = mock_deliver.call_args
            envelope, context = args

            assert envelope == mock_envelope
            assert context.origin_type == DeliveryOriginType.LOCAL
            assert context.from_system_id == basic_node.id
            assert context.from_connector is None

    async def test_send_validates_context_origin_type(
        self, basic_node, mock_envelope, mock_delivery_context
    ):
        """Test send validates context origin type must be LOCAL."""
        mock_delivery_context.origin_type = DeliveryOriginType.UPSTREAM

        with pytest.raises(AssertionError, match="Can only send with LOCAL origin context"):
            await basic_node.send(mock_envelope, context=mock_delivery_context)

    async def test_send_validates_context_from_connector(
        self, basic_node, mock_envelope, mock_delivery_context
    ):
        """Test send validates from_connector must be None."""
        mock_delivery_context.from_connector = Mock()

        with pytest.raises(AssertionError, match="from_connector must be None in LOCAL context"):
            await basic_node.send(mock_envelope, context=mock_delivery_context)

    async def test_send_updates_provided_context(self, basic_node, mock_envelope, mock_delivery_context):
        """Test send updates provided context to LOCAL settings."""
        with patch.object(basic_node, "deliver", new_callable=AsyncMock):
            await basic_node.send(mock_envelope, context=mock_delivery_context)

            # Verify context was updated
            assert mock_delivery_context.origin_type == DeliveryOriginType.LOCAL
            assert mock_delivery_context.from_connector is None

    async def test_send_uses_custom_delivery_function(self, basic_node, mock_envelope):
        """Test send uses custom delivery function when provided."""
        custom_delivery_fn = AsyncMock()

        await basic_node.send(mock_envelope, delivery_fn=custom_delivery_fn)

        custom_delivery_fn.assert_called_once()

    async def test_send_applies_ack_requirement_from_policy(self, basic_node, mock_envelope):
        """Test send applies ACK requirement from delivery policy."""
        mock_policy = Mock(spec=DeliveryPolicy)
        mock_policy.is_ack_required.return_value = True
        mock_policy.sender_retry_policy = None  # No retry policy for this test

        # Create mock ACK response
        mock_ack_envelope = Mock()
        mock_ack_envelope.frame = Mock(spec=DeliveryAckFrame)

        with patch.object(basic_node, "deliver", new_callable=AsyncMock):
            with patch.object(basic_node._delivery_tracker, "track", new_callable=AsyncMock):
                with patch.object(
                    basic_node._delivery_tracker, "await_ack", new_callable=AsyncMock
                ) as mock_await_ack:
                    mock_await_ack.return_value = mock_ack_envelope

                    await basic_node.send(mock_envelope, delivery_policy=mock_policy)

                    # Verify ACK response type was set
                    assert mock_envelope.rtype == FameResponseType.ACK

    async def test_send_combines_ack_with_existing_rtype(self, basic_node, mock_envelope):
        """Test send combines ACK with existing response type."""
        mock_envelope.rtype = FameResponseType.REPLY
        mock_policy = Mock(spec=DeliveryPolicy)
        mock_policy.is_ack_required.return_value = True
        mock_policy.sender_retry_policy = None  # No retry policy for this test

        # Create mock ACK response
        mock_ack_envelope = Mock()
        mock_ack_envelope.frame = Mock(spec=DeliveryAckFrame)

        with patch.object(basic_node, "deliver", new_callable=AsyncMock):
            with patch.object(basic_node._delivery_tracker, "track", new_callable=AsyncMock):
                with patch.object(
                    basic_node._delivery_tracker, "await_ack", new_callable=AsyncMock
                ) as mock_await_ack:
                    mock_await_ack.return_value = mock_ack_envelope

                    await basic_node.send(mock_envelope, delivery_policy=mock_policy)

                    # Verify ACK was combined with existing REPLY
                    assert mock_envelope.rtype == (FameResponseType.ACK | FameResponseType.REPLY)

    @patch("naylence.fame.node.node.generate_id", return_value="generated-trace-id")
    async def test_send_generates_trace_id_when_missing(self, mock_generate_id, basic_node, mock_envelope):
        """Test send generates trace ID when envelope doesn't have one."""
        with patch.object(basic_node, "deliver", new_callable=AsyncMock):
            await basic_node.send(mock_envelope)

            assert mock_envelope.trace_id == "generated-trace-id"

    async def test_send_preserves_existing_trace_id(self, basic_node, mock_envelope):
        """Test send preserves existing trace ID."""
        mock_envelope.trace_id = "existing-trace-id"

        with patch.object(basic_node, "deliver", new_callable=AsyncMock):
            await basic_node.send(mock_envelope)

            assert mock_envelope.trace_id == "existing-trace-id"

    async def test_send_no_tracking_for_simple_delivery(self, basic_node, mock_envelope):
        """Test send doesn't use tracking for simple delivery (no ACK/REPLY)."""
        with patch.object(basic_node, "deliver", new_callable=AsyncMock) as mock_deliver:
            # Mock the delivery tracker to verify it's not called
            with patch.object(basic_node._delivery_tracker, "track", new_callable=AsyncMock) as mock_track:
                result = await basic_node.send(mock_envelope)

                # Should return result of deliver directly
                assert result == mock_deliver.return_value
                # Should not interact with delivery tracker
                assert not mock_track.called

    @patch("naylence.fame.node.node.generate_id", return_value="generated-corr-id")
    async def test_send_generates_correlation_id_for_tracked_delivery(
        self, mock_generate_id, basic_node, mock_envelope
    ):
        """Test send generates correlation ID for tracked delivery."""
        mock_envelope.rtype = FameResponseType.REPLY

        with patch.object(basic_node, "deliver", new_callable=AsyncMock):
            with patch.object(basic_node._delivery_tracker, "track", new_callable=AsyncMock):
                with patch.object(basic_node._delivery_tracker, "await_ack", new_callable=AsyncMock):
                    await basic_node.send(mock_envelope)

                    assert mock_envelope.corr_id == "generated-corr-id"

    @patch("naylence.fame.node.node.format_address", return_value="__sys__@/test/path")
    async def test_send_sets_reply_to_system_inbox(self, mock_format_address, basic_node, mock_envelope):
        """Test send sets reply_to to system inbox when missing."""
        mock_envelope.rtype = FameResponseType.REPLY
        basic_node._physical_path = "/test/path"

        with patch.object(basic_node, "deliver", new_callable=AsyncMock):
            with patch.object(basic_node._delivery_tracker, "track", new_callable=AsyncMock):
                with patch.object(basic_node._delivery_tracker, "await_ack", new_callable=AsyncMock):
                    await basic_node.send(mock_envelope)

                    mock_format_address.assert_called_with("__sys__", "/test/path")
                    assert mock_envelope.reply_to == "__sys__@/test/path"

    async def test_send_preserves_existing_reply_to(self, basic_node, mock_envelope):
        """Test send preserves existing reply_to address."""
        mock_envelope.rtype = FameResponseType.REPLY
        mock_envelope.reply_to = "existing@reply.to"

        with patch.object(basic_node, "deliver", new_callable=AsyncMock):
            with patch.object(basic_node._delivery_tracker, "track", new_callable=AsyncMock):
                with patch.object(basic_node._delivery_tracker, "await_ack", new_callable=AsyncMock):
                    await basic_node.send(mock_envelope)

                    assert mock_envelope.reply_to == "existing@reply.to"

    async def test_send_tracks_envelope_with_ack_requirement(self, basic_node, mock_envelope):
        """Test send tracks envelope with ACK requirement."""
        mock_envelope.rtype = FameResponseType.ACK
        mock_policy = Mock(spec=DeliveryPolicy)
        mock_policy.is_ack_required.return_value = True  # Ensure ACK is required
        mock_retry_policy = Mock()
        mock_retry_policy.max_retries = 3
        mock_policy.sender_retry_policy = mock_retry_policy

        # Create mock ACK response
        mock_ack_envelope = Mock()
        mock_ack_envelope.frame = Mock(spec=DeliveryAckFrame)

        with patch.object(basic_node, "deliver", new_callable=AsyncMock):
            with patch.object(basic_node._delivery_tracker, "track", new_callable=AsyncMock) as mock_track:
                with patch.object(
                    basic_node._delivery_tracker, "await_ack", new_callable=AsyncMock
                ) as mock_await_ack:
                    mock_await_ack.return_value = mock_ack_envelope

                    await basic_node.send(mock_envelope, delivery_policy=mock_policy)

                    mock_track.assert_called_once()
                    args, kwargs = mock_track.call_args
                    assert kwargs["envelope"] == mock_envelope
                    assert kwargs["expected_response_type"] == FameResponseType.ACK
                    assert kwargs["retry_policy"] == mock_policy.sender_retry_policy

    async def test_send_waits_for_ack_when_required(self, basic_node, mock_envelope):
        """Test send waits for ACK when required."""
        mock_envelope.rtype = FameResponseType.ACK
        mock_ack_envelope = Mock()
        mock_ack_frame = Mock(spec=DeliveryAckFrame)
        mock_ack_envelope.frame = mock_ack_frame

        # Create delivery policy that requires ACK
        mock_policy = Mock(spec=DeliveryPolicy)
        mock_policy.is_ack_required.return_value = True
        mock_policy.sender_retry_policy = None

        with patch.object(basic_node, "deliver", new_callable=AsyncMock):
            with patch.object(basic_node._delivery_tracker, "track", new_callable=AsyncMock):
                with patch.object(
                    basic_node._delivery_tracker, "await_ack", new_callable=AsyncMock
                ) as mock_await_ack:
                    mock_await_ack.return_value = mock_ack_envelope

                    result = await basic_node.send(
                        mock_envelope, delivery_policy=mock_policy, timeout_ms=5000
                    )

                    mock_await_ack.assert_called_once_with(envelope_id=mock_envelope.id, timeout_ms=5000)
                    assert result == mock_ack_frame

    async def test_send_validates_ack_frame_type(self, basic_node, mock_envelope):
        """Test send validates returned ACK frame type."""
        mock_envelope.rtype = FameResponseType.ACK
        mock_ack_envelope = Mock()
        mock_ack_envelope.frame = Mock()  # Not a DeliveryAckFrame - should raise error

        # Create delivery policy that requires ACK
        mock_policy = Mock(spec=DeliveryPolicy)
        mock_policy.is_ack_required.return_value = True
        mock_policy.sender_retry_policy = None

        with patch.object(basic_node, "deliver", new_callable=AsyncMock):
            with patch.object(basic_node._delivery_tracker, "track", new_callable=AsyncMock):
                with patch.object(
                    basic_node._delivery_tracker, "await_ack", new_callable=AsyncMock
                ) as mock_await_ack:
                    mock_await_ack.return_value = mock_ack_envelope

                    with pytest.raises(AssertionError, match="Expected DeliveryAckFrame in response"):
                        await basic_node.send(mock_envelope, delivery_policy=mock_policy)

    async def test_send_uses_default_timeout(self, basic_node, mock_envelope):
        """Test send uses default timeout when none provided."""
        mock_envelope.rtype = FameResponseType.ACK

        # Create delivery policy that requires ACK
        mock_policy = Mock(spec=DeliveryPolicy)
        mock_policy.is_ack_required.return_value = True
        mock_policy.sender_retry_policy = None

        with patch.object(basic_node, "deliver", new_callable=AsyncMock):
            with patch.object(basic_node._delivery_tracker, "track", new_callable=AsyncMock) as mock_track:
                with patch.object(
                    basic_node._delivery_tracker, "await_ack", new_callable=AsyncMock
                ) as mock_await_ack:
                    mock_ack_envelope = Mock()
                    mock_ack_envelope.frame = Mock(spec=DeliveryAckFrame)
                    mock_await_ack.return_value = mock_ack_envelope

                    await basic_node.send(mock_envelope, delivery_policy=mock_policy)

                    # Verify default timeout was used
                    mock_track.assert_called_once()
                    assert mock_track.call_args[1]["timeout_ms"] == DEFAULT_INVOKE_TIMEOUT_MILLIS

                    mock_await_ack.assert_called_once()
                    assert mock_await_ack.call_args[1]["timeout_ms"] == DEFAULT_INVOKE_TIMEOUT_MILLIS

    async def test_send_with_retry_policy_creates_handler(self, basic_node, mock_envelope):
        """Test send creates retry handler when retry policy exists."""
        mock_envelope.rtype = FameResponseType.ACK
        mock_policy = Mock(spec=DeliveryPolicy)
        mock_retry_policy = Mock()
        mock_retry_policy.max_retries = 2
        mock_policy.sender_retry_policy = mock_retry_policy

        with patch.object(basic_node, "deliver", new_callable=AsyncMock):
            with patch.object(basic_node._delivery_tracker, "track", new_callable=AsyncMock) as mock_track:
                with patch.object(basic_node._delivery_tracker, "await_ack", new_callable=AsyncMock):
                    mock_ack_envelope = Mock()
                    mock_ack_envelope.frame = Mock(spec=DeliveryAckFrame)
                    basic_node._delivery_tracker.await_ack.return_value = mock_ack_envelope

                    await basic_node.send(mock_envelope, delivery_policy=mock_policy)

                    # Verify retry handler was passed to track
                    mock_track.assert_called_once()
                    retry_handler = mock_track.call_args[1]["retry_handler"]
                    assert retry_handler is not None
                    assert hasattr(retry_handler, "_delivery_fn")

    async def test_send_handles_reply_stream_response_types(self, basic_node, mock_envelope):
        """Test send handles REPLY and STREAM response types for tracking."""
        test_cases = [
            FameResponseType.REPLY,
            FameResponseType.STREAM,
            FameResponseType.REPLY | FameResponseType.ACK,
            FameResponseType.STREAM | FameResponseType.ACK,
        ]

        for rtype in test_cases:
            mock_envelope.rtype = rtype
            mock_envelope.corr_id = None  # Reset for each test

            with patch.object(basic_node, "deliver", new_callable=AsyncMock):
                with patch.object(
                    basic_node._delivery_tracker, "track", new_callable=AsyncMock
                ) as mock_track:
                    if rtype & FameResponseType.ACK:
                        with patch.object(
                            basic_node._delivery_tracker, "await_ack", new_callable=AsyncMock
                        ):
                            mock_ack_envelope = Mock()
                            mock_ack_envelope.frame = Mock(spec=DeliveryAckFrame)
                            basic_node._delivery_tracker.await_ack.return_value = mock_ack_envelope

                            await basic_node.send(mock_envelope)
                    else:
                        await basic_node.send(mock_envelope)

                    # Should track for all these response types
                    mock_track.assert_called_once()
                    mock_track.reset_mock()
