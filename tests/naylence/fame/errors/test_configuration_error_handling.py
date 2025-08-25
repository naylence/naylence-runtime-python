#!/usr/bin/env python3
"""Test configuration error handling."""

import asyncio

import pytest

from naylence.fame.errors.errors import (
    FameConnectError,
    FameProtocolError,
    FameTransportClose,
)


@pytest.mark.asyncio
async def test_fame_connect_error():
    """Test FameConnectError usage."""
    print("Testing FameConnectError...")

    # Test that we can create and raise the exception
    try:
        raise FameConnectError("Test connection error")
    except FameConnectError as e:
        assert isinstance(e, FameConnectError), "Should be caught as FameConnectError"
        # Note: The actual message format depends on the implementation
        print("✅ FameConnectError test passed")


@pytest.mark.asyncio
async def test_fame_transport_close():
    """Test FameTransportClose error handling."""
    print("Testing FameTransportClose...")

    # Test creating transport close error with code and reason
    error = FameTransportClose(1006, "Connection lost")
    assert error.code == 1006
    assert error.reason == "Connection lost"

    # Test that it can be raised and caught
    try:
        raise error
    except FameTransportClose as e:
        assert e.code == 1006
        assert e.reason == "Connection lost"
        print("✅ FameTransportClose test passed")


@pytest.mark.asyncio
async def test_fame_protocol_error():
    """Test FameProtocolError handling."""
    print("Testing FameProtocolError...")

    # Test default values
    error = FameProtocolError()
    assert error.code == 1002
    assert error.reason == "protocol error"

    # Test custom values
    custom_error = FameProtocolError(1003, "unsupported data")
    assert custom_error.code == 1003
    assert custom_error.reason == "unsupported data"

    print("✅ FameProtocolError test passed")


@pytest.mark.asyncio
async def test_exception_handling_order():
    """Test that exception handling order is correct."""
    print("Testing exception handling order...")

    # Test that specific errors are caught before general ones
    try:
        raise FameTransportClose(1000, "Normal close")
    except FameTransportClose as e:
        assert e.code == 1000
        print("✓ FameTransportClose caught correctly")
    except Exception:
        pytest.fail("FameTransportClose should be caught before general Exception")


def test_error_message_format():
    """Test that error messages are properly formatted."""
    print("Testing error message format...")

    # Test FameTransportClose message
    error = FameTransportClose(1006, "Connection failed")
    # The string representation depends on the base class implementation
    assert hasattr(error, "code"), "Error should have code attribute"
    assert hasattr(error, "reason"), "Error should have reason attribute"

    print("✓ Error attributes properly set")


@pytest.mark.asyncio
async def test_errors_in_async_context():
    """Test errors in async context."""
    print("Testing errors in async context...")

    async def failing_operation():
        await asyncio.sleep(0.01)  # Simulate async work
        raise FameConnectError("Async operation failed")

    try:
        await failing_operation()
        pytest.fail("Should have raised FameConnectError")
    except FameConnectError as e:
        assert isinstance(e, FameConnectError)
        print("✓ FameConnectError works correctly in async context")


def test_multiple_error_types():
    """Test handling of multiple error types."""
    print("Testing multiple error types...")

    errors = []

    # Test different error types
    error_cases = [
        (FameConnectError, "Connection error"),
        (FameTransportClose, (1006, "Transport failed")),
        (FameProtocolError, (1002, "Protocol error")),
    ]

    for error_class, args in error_cases:
        try:
            if isinstance(args, tuple):
                error = error_class(*args)
            else:
                error = error_class(args)
            # Raise and catch the error to test handling
            raise error
        except error_class as e:
            errors.append((type(e).__name__, str(e)))
        except Exception as e:
            # Should not reach here if error classes work correctly
            errors.append((type(e).__name__, str(e)))

    # Verify all errors were captured
    assert len(errors) == 3
    assert errors[0][0] == "FameConnectError"
    assert errors[1][0] == "FameTransportClose"
    assert errors[2][0] == "FameProtocolError"
    print("✓ Multiple error types handled correctly")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
