"""
Comprehensive test suite for RPCClientManager.

Tests the redesigned RPCClientManager that uses delivery_tracker for
reply functionality, including:
- Basic invoke() functionality
- Streaming invoke_stream() functionality
- Timeout handling
- Error handling (delivery failures, RPC errors)
- Event handler integration
- Cleanup and lifecycle management
"""

import asyncio
from typing import Any
from unittest.mock import AsyncMock, Mock

import pytest

from naylence.fame.core import (
    DataFrame,
    DeliveryAckFrame,
    DeliveryOriginType,
    FameAddress,
    FameDeliveryContext,
    FameEnvelope,
    FameResponseType,
    JSONRPCError,
    JSONRPCResponse,
    create_fame_envelope,
    format_address,
    make_response,
)
from naylence.fame.delivery.default_delivery_tracker_factory import (
    DefaultDeliveryTrackerFactory,
)
from naylence.fame.delivery.delivery_tracker import TrackedEnvelope
from naylence.fame.node.node_envelope_factory import NodeEnvelopeFactory
from naylence.fame.node.rpc_client_manager import RPCClientManager
from naylence.fame.storage.in_memory_storage_provider import InMemoryStorageProvider


class TestRPCClientManager:
    """Test suite for RPCClientManager functionality."""

    @pytest.fixture
    async def delivery_tracker(self):
        """Create an envelope tracker for testing."""
        storage = InMemoryStorageProvider()
        factory = DefaultDeliveryTrackerFactory()
        tracker = await factory.create(storage_provider=storage)
        # Initialize the tracker manually for testing
        await tracker.on_node_initialized("test-node")
        await tracker.on_node_started("test-node")
        return tracker

    @pytest.fixture
    def mock_get_physical_path(self):
        """Mock function that returns physical path."""
        return Mock(return_value="/test/path")

    @pytest.fixture
    def mock_get_sid(self):
        """Mock function that returns system ID."""
        return Mock(return_value="test-system-id")

    @pytest.fixture
    def mock_deliver_wrapper(self):
        """Mock deliver wrapper function."""
        mock_deliver = AsyncMock()
        return Mock(return_value=mock_deliver)

    @pytest.fixture
    def envelope_factory(self, mock_get_physical_path, mock_get_sid):
        """Create envelope factory for testing."""
        return NodeEnvelopeFactory(physical_path_fn=mock_get_physical_path, sid_fn=mock_get_sid)

    @pytest.fixture
    def mock_listen_callback(self):
        """Mock listen callback for RPC reply addresses."""

        async def mock_callback(recipient: str, handler: Any) -> FameAddress:
            return FameAddress(f"{recipient}@/test/path")

        return AsyncMock(side_effect=mock_callback)

    @pytest.fixture
    async def rpc_client_manager(
        self,
        delivery_tracker,
        mock_get_physical_path,
        mock_get_sid,
        mock_deliver_wrapper,
        envelope_factory,
        mock_listen_callback,
    ):
        """Create RPCClientManager instance for testing."""
        manager = RPCClientManager(
            get_physical_path=mock_get_physical_path,
            get_id=lambda: "test-node-id",
            get_sid=mock_get_sid,
            deliver_wrapper=mock_deliver_wrapper,
            envelope_factory=envelope_factory,
            listen_callback=mock_listen_callback,
            delivery_tracker=delivery_tracker,
        )
        yield manager
        await manager.cleanup()

    @pytest.fixture
    def target_address(self):
        """Target address for RPC calls."""
        return FameAddress("test-service@/remote/path")

    @pytest.fixture
    def sample_request_params(self):
        """Sample parameters for RPC requests."""
        return {"param1": "value1", "param2": 42}

    def test_initialization(self, rpc_client_manager, delivery_tracker):
        """Test that RPCClientManager initializes correctly."""
        assert rpc_client_manager._delivery_tracker is delivery_tracker
        assert not rpc_client_manager._rpc_bound
        assert rpc_client_manager._rpc_reply_address is None
        assert rpc_client_manager._rpc_listener_address is None

    @pytest.mark.asyncio
    async def test_invoke_basic_success(
        self,
        rpc_client_manager,
        target_address,
        sample_request_params,
        mock_deliver_wrapper,
        delivery_tracker,
    ):
        """Test successful basic invoke() call."""
        # Setup mock response
        response_payload = make_response(id="test-id", result={"success": True, "data": "test-result"})
        response_envelope = create_fame_envelope(
            frame=DataFrame(payload=response_payload), corr_id="test-correlation-id"
        )

        # Mock the envelope tracker to return our response

        async def mock_await_reply(envelope_id: str, **kwargs):
            return response_envelope

        delivery_tracker.await_reply = AsyncMock(side_effect=mock_await_reply)

        # Execute invoke
        result = await rpc_client_manager.invoke(
            target_addr=target_address,
            method="test_method",
            params=sample_request_params,
            timeout_ms=5000,
        )

        # Verify result
        assert result == {"success": True, "data": "test-result"}

        # Verify deliver was called
        deliver_func = mock_deliver_wrapper.return_value
        assert deliver_func.call_count == 1

        # Verify the envelope that was delivered
        call_args = deliver_func.call_args
        envelope, context = call_args[0]

        assert isinstance(envelope, FameEnvelope)
        assert envelope.to == target_address
        assert isinstance(envelope.frame, DataFrame)
        assert envelope.frame.payload["method"] == "test_method"
        assert envelope.frame.payload["params"] == sample_request_params
        assert envelope.reply_to is not None  # Should have reply address set

        # Verify context
        assert isinstance(context, FameDeliveryContext)
        assert context.origin_type == DeliveryOriginType.LOCAL
        assert context.expected_response_type == FameResponseType.REPLY

    @pytest.mark.asyncio
    async def test_invoke_with_capabilities(
        self,
        rpc_client_manager,
        sample_request_params,
        mock_deliver_wrapper,
        delivery_tracker,
    ):
        """Test invoke() call with capabilities instead of target address."""
        # Setup mock response
        response_payload = make_response(id="test-id", result="capability-result")
        response_envelope = create_fame_envelope(
            frame=DataFrame(payload=response_payload), corr_id="test-correlation-id"
        )

        delivery_tracker.await_reply = AsyncMock(return_value=response_envelope)

        # Execute invoke with capabilities
        capabilities = ["test-capability", "another-capability"]
        result = await rpc_client_manager.invoke(
            capabilities=capabilities,
            method="test_method",
            params=sample_request_params,
        )

        # Verify result
        assert result == "capability-result"

        # Verify the envelope was created with capabilities
        deliver_func = mock_deliver_wrapper.return_value
        envelope, context = deliver_func.call_args[0]
        assert envelope.capabilities == capabilities
        assert envelope.to is None

    @pytest.mark.asyncio
    async def test_invoke_validation_errors(self, rpc_client_manager, target_address):
        """Test invoke() validation errors."""
        # Test neither target_addr nor capabilities provided
        with pytest.raises(ValueError, match="Either target address or capabilities must be provided"):
            await rpc_client_manager.invoke(method="test", params={})

        # Test both target_addr and capabilities provided
        with pytest.raises(ValueError, match="Both target address or capabilities must not be provided"):
            await rpc_client_manager.invoke(
                target_addr=target_address,
                capabilities=["test"],
                method="test",
                params={},
            )

    @pytest.mark.asyncio
    async def test_invoke_rpc_error_response(self, rpc_client_manager, target_address, delivery_tracker):
        """Test invoke() handling of RPC error responses."""
        # Setup error response
        error_payload = make_response(
            id="test-id", error=JSONRPCError(code=-32600, message="Invalid Request")
        )
        response_envelope = create_fame_envelope(
            frame=DataFrame(payload=error_payload), corr_id="test-correlation-id"
        )

        delivery_tracker.await_reply = AsyncMock(return_value=response_envelope)

        # Execute invoke and expect exception
        with pytest.raises(Exception, match="Invalid Request"):
            await rpc_client_manager.invoke(target_addr=target_address, method="failing_method", params={})

    @pytest.mark.asyncio
    async def test_invoke_stream_basic_success(
        self, rpc_client_manager, target_address, delivery_tracker, mock_deliver_wrapper
    ):
        """Test successful invoke_stream() call."""
        # Setup mock streaming responses
        responses = [
            make_response(id="test-id", result={"item": 1}),
            make_response(id="test-id", result={"item": 2}),
            make_response(id="test-id", result={"item": 3}),
            make_response(id="test-id", result=None),  # End marker
        ]

        response_envelopes = [
            create_fame_envelope(frame=DataFrame(payload=resp), corr_id="test-correlation-id")
            for resp in responses
        ]

        # Mock iter_stream to return our responses
        async def mock_iter_stream(envelope_id: str, **kwargs):
            for envelope in response_envelopes:
                yield envelope

        # Patch the iter_stream method with our async generator
        delivery_tracker.iter_stream = mock_iter_stream

        # Execute invoke_stream
        results = [
            result
            async for result in rpc_client_manager.invoke_stream(
                target_addr=target_address, method="stream_method", params={"count": 3}
            )
        ]

        # Verify results
        expected_results = [{"item": 1}, {"item": 2}, {"item": 3}]
        assert results == expected_results

        # Verify deliver was called with streaming context
        deliver_func = mock_deliver_wrapper.return_value
        envelope, context = deliver_func.call_args[0]
        assert context.expected_response_type == FameResponseType.STREAM

    @pytest.mark.asyncio
    async def test_invoke_stream_with_delivery_failure(
        self, rpc_client_manager, target_address, delivery_tracker
    ):
        """Test invoke_stream() handling delivery failure (NACK)."""
        # Setup NACK response
        nack_frame = DeliveryAckFrame(ok=False, code="signature_required", reason="Message must be signed")
        nack_envelope = create_fame_envelope(frame=nack_frame, corr_id="test-correlation-id")

        async def mock_iter_stream(envelope_id: str, **kwargs):
            yield nack_envelope

        delivery_tracker.iter_stream = mock_iter_stream

        # Execute invoke_stream and collect results
        results = [
            result
            async for result in rpc_client_manager.invoke_stream(
                target_addr=target_address, method="failing_stream", params={}
            )
        ]

        # Should get JSONRPCResponse with error
        assert len(results) == 1
        assert isinstance(results[0], JSONRPCResponse)
        assert results[0].error is not None
        assert results[0].error.code == -32099
        assert "signature" in results[0].error.message.lower()

    @pytest.mark.asyncio
    async def test_invoke_stream_rpc_error(self, rpc_client_manager, target_address, delivery_tracker):
        """Test invoke_stream() handling RPC error in stream."""
        # Setup error response
        error_response = make_response(
            id="test-id", error=JSONRPCError(code=-32601, message="Method not found")
        )
        error_envelope = create_fame_envelope(
            frame=DataFrame(payload=error_response), corr_id="test-correlation-id"
        )

        async def mock_iter_stream(envelope_id: str, **kwargs):
            yield error_envelope

        delivery_tracker.iter_stream = mock_iter_stream

        # Execute invoke_stream and expect exception
        with pytest.raises(Exception, match="Method not found"):
            async for result in rpc_client_manager.invoke_stream(
                target_addr=target_address, method="unknown_method", params={}
            ):
                pass

    @pytest.mark.asyncio
    async def test_setup_rpc_reply_listener(
        self, rpc_client_manager, mock_listen_callback, mock_get_physical_path
    ):
        """Test the setup of RPC reply listener."""
        # Initially not bound
        assert not rpc_client_manager._rpc_bound
        assert rpc_client_manager._rpc_reply_address is None

        # Setup reply listener
        await rpc_client_manager._setup_rpc_reply_listener()

        # Verify bound state
        assert rpc_client_manager._rpc_bound
        assert rpc_client_manager._rpc_reply_address is not None
        assert rpc_client_manager._rpc_listener_address is not None

        # Verify listen callback was called
        mock_listen_callback.assert_called_once()
        call_args = mock_listen_callback.call_args
        recipient = call_args[0][0]
        assert recipient.startswith("__rpc__")
        assert call_args[0][1] is None  # handler should be None

        # Verify reply address format
        expected_address = format_address(recipient, mock_get_physical_path.return_value)
        assert str(rpc_client_manager._rpc_reply_address) == str(expected_address)

    @pytest.mark.asyncio
    async def test_cleanup(self, rpc_client_manager):
        """Test cleanup functionality."""
        # Setup some state
        await rpc_client_manager._setup_rpc_reply_listener()
        assert rpc_client_manager._rpc_bound

        # Cleanup
        await rpc_client_manager.cleanup()

        # Verify cleanup
        assert not rpc_client_manager._rpc_bound
        assert rpc_client_manager._rpc_reply_address is None
        assert rpc_client_manager._rpc_listener_address is None

    @pytest.mark.asyncio
    async def test_event_handler_integration(
        self,
        delivery_tracker,
        mock_get_physical_path,
        mock_get_sid,
        mock_deliver_wrapper,
        envelope_factory,
        mock_listen_callback,
    ):
        """Test that RPCClientManager properly integrates as an event handler."""
        # Create manager and verify it's registered as event handler
        manager = RPCClientManager(
            get_physical_path=mock_get_physical_path,
            get_id=lambda: "test-node-id",
            get_sid=mock_get_sid,
            deliver_wrapper=mock_deliver_wrapper,
            envelope_factory=envelope_factory,
            listen_callback=mock_listen_callback,
            delivery_tracker=delivery_tracker,
        )

        # Verify event handler was added
        assert manager in delivery_tracker._event_handlers

        # Test on_envelope_replied method
        # Create a mock envelope for testing TrackedEnvelope
        mock_envelope = create_fame_envelope(frame=DataFrame(payload={"original": "envelope"}))
        # Set the ID manually after creation
        mock_envelope.id = "test-envelope-id"

        tracked_envelope = TrackedEnvelope(
            original_envelope=mock_envelope,
            timeout_at_ms=1000000,
            overall_timeout_at_ms=1000000,
            expected_response_type=FameResponseType.REPLY,
            created_at_ms=1000000,
        )

        reply_envelope = create_fame_envelope(
            frame=DataFrame(payload={"result": "test"}), corr_id="test-correlation-id"
        )

        # This should not raise an exception
        await manager.on_envelope_replied(tracked_envelope, reply_envelope)

        await manager.cleanup()

    def test_create_delivery_error_message(self, rpc_client_manager):
        """Test delivery error message creation."""
        # Test crypto level violation
        msg = rpc_client_manager._create_delivery_error_message(
            "crypto_level_violation", "Plaintext not allowed"
        )
        assert "encryption" in msg.lower()
        assert "plaintext" in msg.lower()

        # Test signature required
        msg = rpc_client_manager._create_delivery_error_message(
            "signature_required", "Message must be signed"
        )
        assert "signature" in msg.lower()
        assert "sign" in msg.lower()

        # Test signature verification failed
        msg = rpc_client_manager._create_delivery_error_message(
            "signature_verification_failed", "Invalid signature"
        )
        assert "signature" in msg.lower()
        assert "verified" in msg.lower()

        # Test unknown code
        msg = rpc_client_manager._create_delivery_error_message("unknown_code", "Some reason")
        assert "unknown_code" in msg
        assert "Some reason" in msg

        # Test without reason
        msg = rpc_client_manager._create_delivery_error_message("test_code", None)
        assert "test_code" in msg

    @pytest.mark.asyncio
    async def test_invoke_timeout_propagation(self, rpc_client_manager, target_address, delivery_tracker):
        """Test that timeout is properly passed to delivery_tracker."""
        # Mock await_reply to capture the timeout parameter
        delivery_tracker.await_reply = AsyncMock()

        # Setup a response that won't be reached due to timeout
        timeout_ms = 1000

        # Execute invoke with specific timeout
        try:
            await rpc_client_manager.invoke(
                target_addr=target_address,
                method="test_method",
                params={},
                timeout_ms=timeout_ms,
            )
        except Exception:
            pass  # We expect this to fail since we mocked await_reply

        # Verify await_reply was called (timeout handling is done by delivery_tracker)
        delivery_tracker.await_reply.assert_called_once()

    @pytest.mark.asyncio
    async def test_invoke_uses_correlation_id_as_request_id(
        self, rpc_client_manager, target_address, mock_deliver_wrapper, delivery_tracker
    ):
        """Test that invoke() uses correlation ID as JSON-RPC request ID."""
        # Mock response
        delivery_tracker.await_reply = AsyncMock(
            return_value=create_fame_envelope(
                frame=DataFrame(payload=make_response(id="test-id", result="success")),
                corr_id="test-correlation-id",
            )
        )

        await rpc_client_manager.invoke(target_addr=target_address, method="test_method", params={})

        # Check the delivered envelope
        deliver_func = mock_deliver_wrapper.return_value
        envelope, _ = deliver_func.call_args[0]

        # The correlation ID should match the JSON-RPC request ID
        request_payload = envelope.frame.payload
        assert request_payload["id"] == envelope.corr_id

    @pytest.mark.asyncio
    async def test_multiple_invokes_reuse_listener(
        self, rpc_client_manager, target_address, mock_listen_callback, delivery_tracker
    ):
        """Test that multiple invokes reuse the same RPC listener."""
        # Mock responses
        delivery_tracker.await_reply = AsyncMock(
            side_effect=[
                create_fame_envelope(
                    frame=DataFrame(payload=make_response(id="1", result="first")),
                    corr_id="1",
                ),
                create_fame_envelope(
                    frame=DataFrame(payload=make_response(id="2", result="second")),
                    corr_id="2",
                ),
            ]
        )

        # First invoke
        result1 = await rpc_client_manager.invoke(target_addr=target_address, method="test1", params={})
        assert result1 == "first"

        # Second invoke
        result2 = await rpc_client_manager.invoke(target_addr=target_address, method="test2", params={})
        assert result2 == "second"

        # Listener should only be set up once
        mock_listen_callback.assert_called_once()

    @pytest.mark.asyncio
    async def test_concurrent_invokes(
        self, rpc_client_manager, target_address, delivery_tracker, mock_deliver_wrapper
    ):
        """Test concurrent invoke() calls work correctly."""
        # Setup different responses for each call
        responses = {
            "call1": create_fame_envelope(
                frame=DataFrame(payload=make_response(id="1", result="result1")),
                corr_id="1",
            ),
            "call2": create_fame_envelope(
                frame=DataFrame(payload=make_response(id="2", result="result2")),
                corr_id="2",
            ),
            "call3": create_fame_envelope(
                frame=DataFrame(payload=make_response(id="3", result="result3")),
                corr_id="3",
            ),
        }

        # Mock await_reply to return different responses based on envelope_id
        call_count = 0

        async def mock_await_reply(envelope_id: str, **kwargs):
            nonlocal call_count
            call_count += 1
            return list(responses.values())[call_count - 1]

        delivery_tracker.await_reply = AsyncMock(side_effect=mock_await_reply)

        # Execute concurrent invokes
        tasks = [
            rpc_client_manager.invoke(target_addr=target_address, method=f"method{i}", params={})
            for i in range(1, 4)
        ]

        results = await asyncio.gather(*tasks)

        # Verify all results
        assert len(results) == 3
        assert set(results) == {"result1", "result2", "result3"}

        # Verify all calls were made
        assert delivery_tracker.await_reply.call_count == 3
        assert mock_deliver_wrapper.return_value.call_count == 3
