"""Tests for NullKeyManagementHandler."""

from unittest.mock import Mock

import pytest

from naylence.fame.core import FameDeliveryContext, FameEnvelope
from naylence.fame.security.keys.key_management_handler_base import KeyManagementHandlerBase
from naylence.fame.security.keys.null_key_management_handler import NullKeyManagementHandler


class TestNullKeyManagementHandler:
    """Test the null key management handler."""

    def test_inheritance(self):
        """Test that NullKeyManagementHandler inherits from base class."""
        handler = NullKeyManagementHandler()
        assert isinstance(handler, KeyManagementHandlerBase)

    def test_initialization(self):
        """Test handler initialization."""
        handler = NullKeyManagementHandler()
        assert handler is not None
        # Should inherit _is_started from base class
        assert hasattr(handler, "_is_started")

    @pytest.mark.asyncio
    async def test_start(self):
        """Test starting the handler."""
        handler = NullKeyManagementHandler()

        # Should not be started initially
        assert not handler._is_started

        await handler.start()

        # Should be marked as started
        assert handler._is_started

    @pytest.mark.asyncio
    async def test_stop(self):
        """Test stopping the handler."""
        handler = NullKeyManagementHandler()

        # Start first
        await handler.start()
        assert handler._is_started

        await handler.stop()

        # Should be marked as stopped
        assert not handler._is_started

    @pytest.mark.asyncio
    async def test_start_stop_cycle(self):
        """Test multiple start/stop cycles."""
        handler = NullKeyManagementHandler()

        # Multiple start/stop cycles should work
        for _ in range(3):
            await handler.start()
            assert handler._is_started

            await handler.stop()
            assert not handler._is_started

    @pytest.mark.asyncio
    async def test_accept_key_announce_with_envelope_and_context(self):
        """Test accepting key announce with envelope and context."""
        handler = NullKeyManagementHandler()
        mock_envelope = Mock(spec=FameEnvelope)
        mock_context = Mock(spec=FameDeliveryContext)

        # Should not raise any exception (no-op)
        await handler.accept_key_announce(mock_envelope, mock_context)

    @pytest.mark.asyncio
    async def test_accept_key_announce_with_none_context(self):
        """Test accepting key announce with None context."""
        handler = NullKeyManagementHandler()
        mock_envelope = Mock(spec=FameEnvelope)

        # Should not raise any exception with None context
        await handler.accept_key_announce(mock_envelope, None)

    @pytest.mark.asyncio
    async def test_accept_key_announce_multiple_calls(self):
        """Test multiple calls to accept_key_announce."""
        handler = NullKeyManagementHandler()
        mock_envelope = Mock(spec=FameEnvelope)
        mock_context = Mock(spec=FameDeliveryContext)

        # Multiple calls should all be no-ops
        for _ in range(5):
            await handler.accept_key_announce(mock_envelope, mock_context)

    @pytest.mark.asyncio
    async def test_retry_pending_key_requests_after_attachment(self):
        """Test retrying pending key requests after attachment."""
        handler = NullKeyManagementHandler()

        # Should not raise any exception (no-op)
        await handler.retry_pending_key_requests_after_attachment()

    @pytest.mark.asyncio
    async def test_retry_pending_key_requests_multiple_calls(self):
        """Test multiple calls to retry pending key requests."""
        handler = NullKeyManagementHandler()

        # Multiple calls should all be no-ops
        for _ in range(3):
            await handler.retry_pending_key_requests_after_attachment()

    @pytest.mark.asyncio
    async def test_all_operations_when_not_started(self):
        """Test all operations work when handler is not started."""
        handler = NullKeyManagementHandler()
        mock_envelope = Mock(spec=FameEnvelope)
        mock_context = Mock(spec=FameDeliveryContext)

        # All operations should work even when not started
        await handler.accept_key_announce(mock_envelope, mock_context)
        await handler.retry_pending_key_requests_after_attachment()

    @pytest.mark.asyncio
    async def test_all_operations_after_start(self):
        """Test all operations work after handler is started."""
        handler = NullKeyManagementHandler()
        mock_envelope = Mock(spec=FameEnvelope)
        mock_context = Mock(spec=FameDeliveryContext)

        await handler.start()

        # All operations should work when started
        await handler.accept_key_announce(mock_envelope, mock_context)
        await handler.retry_pending_key_requests_after_attachment()

    @pytest.mark.asyncio
    async def test_all_operations_after_stop(self):
        """Test all operations work after handler is stopped."""
        handler = NullKeyManagementHandler()
        mock_envelope = Mock(spec=FameEnvelope)
        mock_context = Mock(spec=FameDeliveryContext)

        await handler.start()
        await handler.stop()

        # All operations should still work when stopped
        await handler.accept_key_announce(mock_envelope, mock_context)
        await handler.retry_pending_key_requests_after_attachment()
