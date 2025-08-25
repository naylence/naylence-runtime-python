#!/usr/bin/env python3
"""
Focused test suite for RPC streaming functionality.
This file contains the original, simpler streaming tests.
For comprehensive streaming tests, see test_streaming_comprehensive.py
"""

import asyncio
from typing import Any

import pytest
import pytest_asyncio

from naylence.fame.core import FameRPCService
from naylence.fame.fabric.in_process_fame_fabric import InProcessFameFabric


class SimpleStreamingService(FameRPCService):
    """Simple test service for basic streaming functionality."""

    @property
    def capabilities(self) -> list[str]:
        return ["stream_numbers", "simple_add"]

    async def handle_rpc_request(self, method: str, params: Any) -> Any:
        if method == "stream_numbers":
            # Return a generator that yields numbers
            count = params.get("count", 5) if params else 5
            return SimpleNumberGenerator(count)
        elif method == "simple_add":
            a = params.get("a", 0) if params else 0
            b = params.get("b", 0) if params else 0
            return a + b
        else:
            raise ValueError(f"Unknown method: {method}")


class SimpleNumberGenerator:
    """Simple generator that yields numbers for streaming."""

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
        await asyncio.sleep(0.001)  # Minimal delay
        return result


@pytest_asyncio.fixture
async def fabric():
    """Create and start an InProcessFameFabric for testing."""
    fabric = InProcessFameFabric()
    await fabric.start()
    yield fabric
    await fabric.stop()


@pytest_asyncio.fixture
async def simple_service_address(fabric):
    """Register a simple streaming test service and return its address."""
    service = SimpleStreamingService()
    address = await fabric.serve(service, "simple-streaming-test")
    return address


@pytest.mark.asyncio
async def test_non_streaming_rpc(fabric, simple_service_address):
    """Test that basic non-streaming RPC calls still work correctly."""
    # Debug: Check if envelope tracker is present
    node = fabric.node
    print(f"Node event listeners: {[type(listener).__name__ for listener in node.event_listeners]}")
    
    # Check if any listener is an envelope tracker
    for listener in node.event_listeners:
        if hasattr(listener, 'track'):
            print(f"Found envelope tracker: {type(listener).__name__}")
            break
    else:
        print("No envelope tracker found in event listeners!")
    
    result = await fabric.invoke(simple_service_address, "simple_add", {"a": 5, "b": 3})
    assert result == 8, f"Expected 8, got {result}"


@pytest.mark.asyncio
async def test_streaming_rpc_basic(fabric, simple_service_address):
    """Test basic streaming RPC functionality."""
    stream = await fabric.invoke_stream(simple_service_address, "stream_numbers", {"count": 3})

    results = [item async for item in stream]

    expected = [0, 1, 2]
    assert results == expected, f"Expected {expected}, got {results}"


@pytest.mark.asyncio
async def test_streaming_rpc_empty(fabric, simple_service_address):
    """Test streaming RPC with zero count (empty stream)."""
    stream = await fabric.invoke_stream(simple_service_address, "stream_numbers", {"count": 0})

    results = [item async for item in stream]

    assert results == [], f"Expected empty list, got {results}"


@pytest.mark.asyncio
async def test_streaming_rpc_error_handling(fabric, simple_service_address):
    """Test that errors in streaming RPC are handled correctly."""
    with pytest.raises(Exception) as exc_info:
        stream = await fabric.invoke_stream(simple_service_address, "unknown_method", {})
        async for item in stream:
            pass  # Should not reach here

    assert "Unknown method" in str(exc_info.value)
