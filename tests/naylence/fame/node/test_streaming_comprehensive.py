#!/usr/bin/env python3
"""
Comprehensive test suite for RPC streaming functionality.
Tests both regular and streaming RPC calls with proper end-of-stream handling.
"""

import asyncio
from typing import Any, AsyncIterator, Optional

import pytest
import pytest_asyncio

from naylence.fame.core import (
    DataFrame,
    FameDeliveryContext,
    FameEnvelope,
    FameMessageResponse,
    FameRPCService,
    FameService,
    create_fame_envelope,
    make_response,
    parse_request,
)
from naylence.fame.fabric.in_process_fame_fabric import InProcessFameFabric


class ComprehensiveStreamingService(FameRPCService):
    """Test service that provides both streaming and non-streaming RPC methods."""

    @property
    def capabilities(self):
        return ["agent"]

    async def handle_rpc_request(self, method: str, params: Any) -> Any:
        """Handle various test methods."""
        if method == "add":
            # Simple non-streaming RPC
            x = params.get("x", 0) if params else 0
            y = params.get("y", 0) if params else 0
            return x + y

        elif method == "multiply":
            # Another non-streaming RPC
            x = params.get("x", 1) if params else 1
            y = params.get("y", 1) if params else 1
            return x * y

        elif method == "stream_numbers":
            # Basic streaming RPC that yields numbers
            count = params.get("count", 5) if params else 5
            return StreamingNumberGenerator(count)

        elif method == "fib_stream":
            # Fibonacci streaming with proper async generator
            n = params.get("n", 5) if params else 5
            return FibonacciGenerator(n)

        elif method == "empty_stream":
            # Empty stream test
            return EmptyGenerator()

        elif method == "error_stream":
            # Stream that produces an error
            return ErrorGenerator()

        else:
            raise ValueError(f"Unknown method: {method}")


class StreamingNumberGenerator:
    """Generator that yields numbers for streaming."""

    def __init__(self, count: int):
        self.count = count
        self.current = 0

    def __aiter__(self):
        return self

    async def __anext__(self):
        if self.current >= self.count:
            raise StopAsyncIteration
        result = self.current
        self.current += 1
        await asyncio.sleep(0.001)  # Tiny delay to simulate work
        return result


class FibonacciGenerator:
    """Generator that yields fibonacci numbers."""

    def __init__(self, count: int):
        self.count = count
        self.current = 0
        self.a, self.b = 0, 1

    def __aiter__(self):
        return self

    async def __anext__(self):
        if self.current >= self.count:
            raise StopAsyncIteration
        result = self.a
        self.a, self.b = self.b, self.a + self.b
        self.current += 1
        await asyncio.sleep(0.001)  # Tiny delay
        return result


class EmptyGenerator:
    """Generator that yields nothing (empty stream)."""

    def __aiter__(self):
        return self

    async def __anext__(self):
        raise StopAsyncIteration


class ErrorGenerator:
    """Generator that produces an error after a few items."""

    def __init__(self):
        self.count = 0

    def __aiter__(self):
        return self

    async def __anext__(self):
        if self.count >= 2:
            raise RuntimeError("Intentional error in stream")
        result = self.count
        self.count += 1
        return result


class CompleteStreamingService(FameService):
    """
    Service that demonstrates proper end-of-stream signaling
    using FameMessageResponse envelopes directly.
    """

    @property
    def name(self):
        return "complete-streaming-service"

    @property
    def capabilities(self):
        return ["agent"]

    async def handle_message(
        self, envelope: FameEnvelope, context: Optional[FameDeliveryContext] = None
    ) -> Optional[FameMessageResponse | AsyncIterator[FameMessageResponse]]:
        """Handle messages with proper end-of-stream signaling."""

        if not isinstance(envelope.frame, DataFrame):
            return None

        payload = envelope.frame.payload

        # Check if it's a JSON-RPC request
        if not (isinstance(payload, dict) and "jsonrpc" in payload and "method" in payload):
            return None

        request = parse_request(payload)
        method = request.method
        params = request.params
        request_id = request.id
        reply_to = envelope.reply_to

        if not reply_to:
            return None

        if method == "fib_stream_complete":
            # Streaming RPC with proper end-of-stream signaling
            n = params.get("n", 5) if params else 5

            async def _complete_response_generator():
                """Generate fibonacci values + final null response."""
                # Generate the fibonacci sequence
                a, b = 0, 1
                for i in range(n):
                    # Create JSON-RPC response for this value
                    rpc_response = make_response(id=request_id or "unknown", result=a)

                    # Create envelope
                    frame = DataFrame(
                        payload=rpc_response,
                        corr_id=str(request_id) if request_id is not None else None,
                    )
                    response_envelope = create_fame_envelope(
                        frame=frame,
                        to=reply_to,
                        trace_id=envelope.trace_id,
                        corr_id=str(request_id) if request_id is not None else None,
                    )

                    yield FameMessageResponse(envelope=response_envelope)

                    # Next fibonacci number
                    a, b = b, a + b
                    await asyncio.sleep(0.001)  # Small delay

                # Send final null response to signal end of stream
                final_response = make_response(id=request_id or "unknown", result=None)
                frame = DataFrame(
                    payload=final_response,
                    corr_id=str(request_id) if request_id is not None else None,
                )
                final_envelope = create_fame_envelope(
                    frame=frame,
                    to=reply_to,
                    trace_id=envelope.trace_id,
                    corr_id=str(request_id) if request_id is not None else None,
                )

                yield FameMessageResponse(envelope=final_envelope)

            return _complete_response_generator()

        else:
            # Error response
            error_response = make_response(
                id=request_id or "unknown",
                error={"code": -32601, "message": f"Method not found: {method}"},
            )

            frame = DataFrame(
                payload=error_response,
                corr_id=str(request_id) if request_id is not None else None,
            )
            response_envelope = create_fame_envelope(
                frame=frame,
                to=reply_to,
                trace_id=envelope.trace_id,
                corr_id=str(request_id) if request_id is not None else None,
            )

            return FameMessageResponse(envelope=response_envelope)


@pytest_asyncio.fixture
async def fabric():
    """Create and start an InProcessFameFabric for testing."""
    fabric = InProcessFameFabric()
    await fabric.start()
    yield fabric
    await fabric.stop()


@pytest_asyncio.fixture
async def streaming_service(fabric):
    """Register a comprehensive streaming test service and return its address."""
    service = ComprehensiveStreamingService()
    address = await fabric.serve(service, "streaming-test")
    return address


@pytest_asyncio.fixture
async def complete_service(fabric):
    """Register a complete streaming service and return its address."""
    service = CompleteStreamingService()
    address = await fabric.serve(service)
    return address


@pytest.mark.asyncio
async def test_basic_non_streaming_rpc(fabric, streaming_service):
    """Test that basic non-streaming RPC calls work correctly."""
    result = await fabric.invoke(streaming_service, "add", {"x": 5, "y": 3})
    assert result == 8, f"Expected 8, got {result}"

    result = await fabric.invoke(streaming_service, "multiply", {"x": 4, "y": 7})
    assert result == 28, f"Expected 28, got {result}"


@pytest.mark.asyncio
async def test_basic_streaming_rpc(fabric, streaming_service):
    """Test basic streaming RPC functionality."""
    stream = await fabric.invoke_stream(streaming_service, "stream_numbers", {"count": 3})

    results = [item async for item in stream]

    expected = [0, 1, 2]
    assert results == expected, f"Expected {expected}, got {results}"


@pytest.mark.asyncio
async def test_fibonacci_streaming(fabric, streaming_service):
    """Test fibonacci streaming functionality."""
    stream = await fabric.invoke_stream(streaming_service, "fib_stream", {"n": 6})

    results = [item async for item in stream]

    expected = [0, 1, 1, 2, 3, 5]
    assert results == expected, f"Expected {expected}, got {results}"


@pytest.mark.asyncio
async def test_empty_streaming_rpc(fabric, streaming_service):
    """Test streaming RPC with empty stream."""
    stream = await fabric.invoke_stream(streaming_service, "empty_stream", {})

    results = [item async for item in stream]

    assert results == [], f"Expected empty list, got {results}"


@pytest.mark.asyncio
async def test_streaming_rpc_zero_count(fabric, streaming_service):
    """Test streaming RPC with zero count."""
    stream = await fabric.invoke_stream(streaming_service, "stream_numbers", {"count": 0})

    results = [item async for item in stream]

    assert results == [], f"Expected empty list, got {results}"


@pytest.mark.asyncio
async def test_complete_end_of_stream_signaling(fabric, complete_service):
    """Test streaming with proper end-of-stream signaling."""
    # Use the node's invoke_stream method which handles null sentinels
    node = fabric.node
    stream = await node.invoke_stream(
        target_addr=complete_service,
        method="fib_stream_complete",
        params={"n": 5},
        timeout_ms=5000,
    )

    results = [result async for result in stream]

    expected = [0, 1, 1, 2, 3]
    assert results == expected, f"Expected {expected}, got {results}"


@pytest.mark.asyncio
async def test_streaming_error_handling(fabric, streaming_service):
    """Test that errors in streaming RPC are handled correctly."""
    with pytest.raises(Exception) as exc_info:
        stream = await fabric.invoke_stream(streaming_service, "unknown_method", {})
        async for item in stream:
            pass  # Should not reach here

    assert "Unknown method" in str(exc_info.value)


@pytest.mark.asyncio
async def test_streaming_with_runtime_error(fabric, streaming_service):
    """Test streaming that encounters a runtime error."""
    with pytest.raises(Exception) as exc_info:
        stream = await fabric.invoke_stream(streaming_service, "error_stream", {})
        async for item in stream:
            pass  # Should error after a couple items

    assert "Intentional error" in str(exc_info.value)


@pytest.mark.asyncio
async def test_concurrent_streaming_and_regular_rpc(fabric, streaming_service):
    """Test that streaming and regular RPC calls can work concurrently."""

    async def run_streaming():
        stream = await fabric.invoke_stream(streaming_service, "stream_numbers", {"count": 5})
        return [item async for item in stream]

    async def run_regular_rpcs():
        results = []
        for i in range(3):
            result = await fabric.invoke(streaming_service, "add", {"x": i, "y": i * 2})
            results.append(result)
        return results

    # Run both concurrently
    streaming_task = asyncio.create_task(run_streaming())
    regular_task = asyncio.create_task(run_regular_rpcs())

    streaming_results, regular_results = await asyncio.gather(streaming_task, regular_task)

    # Verify both worked correctly
    assert regular_results == [0, 3, 6], f"Regular RPC failed: {regular_results}"
    assert streaming_results == [
        0,
        1,
        2,
        3,
        4,
    ], f"Streaming RPC failed: {streaming_results}"


@pytest.mark.asyncio
async def test_multiple_concurrent_streams(fabric, streaming_service):
    """Test multiple concurrent streaming operations."""

    async def run_stream(method: str, params: dict):
        stream = await fabric.invoke_stream(streaming_service, method, params)
        return [item async for item in stream]

    # Start multiple streams concurrently
    tasks = [
        asyncio.create_task(run_stream("stream_numbers", {"count": 3})),
        asyncio.create_task(run_stream("fib_stream", {"n": 4})),
        asyncio.create_task(run_stream("stream_numbers", {"count": 2})),
    ]

    results = await asyncio.gather(*tasks)

    # Verify all streams worked correctly
    assert results[0] == [0, 1, 2], f"First stream failed: {results[0]}"
    assert results[1] == [0, 1, 1, 2], f"Second stream failed: {results[1]}"
    assert results[2] == [0, 1], f"Third stream failed: {results[2]}"


@pytest.mark.asyncio
async def test_large_streaming_rpc(fabric, streaming_service):
    """Test streaming RPC with a larger number of items."""
    count = 20
    stream = await fabric.invoke_stream(streaming_service, "stream_numbers", {"count": count})

    results = [item async for item in stream]

    expected = list(range(count))
    assert results == expected, f"Expected {expected}, got {results}"
    assert len(results) == count, f"Expected {count} items, got {len(results)}"


if __name__ == "__main__":
    # Allow running individual tests for debugging
    pytest.main([__file__, "-v"])
