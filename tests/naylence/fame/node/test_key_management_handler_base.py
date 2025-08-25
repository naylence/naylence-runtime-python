"""Tests for KeyManagementHandlerBase."""

from abc import ABC
from unittest.mock import Mock

import pytest

from naylence.fame.core import FameDeliveryContext, FameEnvelope
from naylence.fame.security.keys.key_management_handler_base import KeyManagementHandlerBase
from naylence.fame.util.task_spawner import TaskSpawner


class ConcreteKeyManagementHandler(KeyManagementHandlerBase):
    """Concrete implementation for testing."""

    def __init__(self):
        super().__init__()
        self.start_called = False
        self.stop_called = False
        self.accept_key_announce_called = False
        self.retry_pending_called = False

    async def start(self):
        """Concrete implementation of start."""
        self.start_called = True
        self._is_started = True

    async def stop(self):
        """Concrete implementation of stop."""
        self.stop_called = True
        self._is_started = False

    async def accept_key_announce(self, envelope: FameEnvelope, context):
        """Concrete implementation of accept_key_announce."""
        self.accept_key_announce_called = True

    async def retry_pending_key_requests_after_attachment(self):
        """Concrete implementation of retry_pending_key_requests_after_attachment."""
        self.retry_pending_called = True


class TestKeyManagementHandlerBase:
    """Test the key management handler base class."""

    def test_inheritance(self):
        """Test inheritance from TaskSpawner and ABC."""
        handler = ConcreteKeyManagementHandler()
        assert isinstance(handler, TaskSpawner)
        assert isinstance(handler, ABC)

    def test_initialization(self):
        """Test handler initialization."""
        handler = ConcreteKeyManagementHandler()
        assert hasattr(handler, "_is_started")
        assert handler._is_started is False

    def test_abstract_methods_must_be_implemented(self):
        """Test that abstract methods must be implemented."""
        # This should not raise an error since we provide concrete implementations
        handler = ConcreteKeyManagementHandler()
        assert handler is not None

    @pytest.mark.asyncio
    async def test_concrete_start_implementation(self):
        """Test that concrete start implementation works."""
        handler = ConcreteKeyManagementHandler()
        await handler.start()
        assert handler.start_called
        assert handler._is_started

    @pytest.mark.asyncio
    async def test_concrete_stop_implementation(self):
        """Test that concrete stop implementation works."""
        handler = ConcreteKeyManagementHandler()
        await handler.start()
        await handler.stop()
        assert handler.stop_called
        assert not handler._is_started

    @pytest.mark.asyncio
    async def test_concrete_accept_key_announce_implementation(self):
        """Test that concrete accept_key_announce implementation works."""
        handler = ConcreteKeyManagementHandler()
        mock_envelope = Mock(spec=FameEnvelope)
        mock_context = Mock(spec=FameDeliveryContext)

        await handler.accept_key_announce(mock_envelope, mock_context)
        assert handler.accept_key_announce_called

    @pytest.mark.asyncio
    async def test_concrete_retry_pending_implementation(self):
        """Test that concrete retry_pending implementation works."""
        handler = ConcreteKeyManagementHandler()
        await handler.retry_pending_key_requests_after_attachment()
        assert handler.retry_pending_called

    @pytest.mark.asyncio
    async def test_default_accept_key_request(self):
        """Test default accept_key_request implementation."""
        handler = ConcreteKeyManagementHandler()
        mock_envelope = Mock(spec=FameEnvelope)
        mock_context = Mock(spec=FameDeliveryContext)

        # Should not raise any exception (default is no-op)
        await handler.accept_key_request(mock_envelope, mock_context)

    @pytest.mark.asyncio
    async def test_default_process_envelope(self):
        """Test default process_envelope implementation."""
        handler = ConcreteKeyManagementHandler()
        mock_envelope = Mock(spec=FameEnvelope)
        mock_context = Mock(spec=FameDeliveryContext)

        # Should not raise any exception (default is no-op)
        await handler.process_envelope(mock_envelope, mock_context)

    @pytest.mark.asyncio
    async def test_default_should_process_envelope(self):
        """Test default should_process_envelope implementation."""
        handler = ConcreteKeyManagementHandler()
        mock_envelope = Mock(spec=FameEnvelope)
        mock_context = Mock(spec=FameDeliveryContext)

        result = await handler.should_process_envelope(mock_envelope, mock_context)
        assert result is False

    @pytest.mark.asyncio
    async def test_default_should_request_key(self):
        """Test default should_request_key implementation."""
        handler = ConcreteKeyManagementHandler()
        mock_envelope = Mock(spec=FameEnvelope)
        mock_context = Mock(spec=FameDeliveryContext)

        result = await handler.should_request_key(mock_envelope, mock_context)
        assert result is False

    @pytest.mark.asyncio
    async def test_default_should_request_encryption_key(self):
        """Test default should_request_encryption_key implementation."""
        handler = ConcreteKeyManagementHandler()
        mock_envelope = Mock(spec=FameEnvelope)
        mock_context = Mock(spec=FameDeliveryContext)

        result = await handler.should_request_encryption_key(mock_envelope, mock_context)
        assert result is False

    @pytest.mark.asyncio
    async def test_default_request_key(self):
        """Test default request_key implementation."""
        handler = ConcreteKeyManagementHandler()
        mock_envelope = Mock(spec=FameEnvelope)
        mock_context = Mock(spec=FameDeliveryContext)

        # Should not raise any exception (default is no-op)
        await handler.request_key(mock_envelope, mock_context)

    @pytest.mark.asyncio
    async def test_default_request_encryption_key(self):
        """Test default request_encryption_key implementation."""
        handler = ConcreteKeyManagementHandler()
        mock_envelope = Mock(spec=FameEnvelope)
        mock_context = Mock(spec=FameDeliveryContext)

        # Should not raise any exception (default is no-op)
        await handler.request_encryption_key(mock_envelope, mock_context)

    @pytest.mark.asyncio
    async def test_default_has_key(self):
        """Test default has_key implementation."""
        handler = ConcreteKeyManagementHandler()

        result = await handler.has_key("test-kid")
        assert result is False

    @pytest.mark.asyncio
    async def test_has_key_with_different_kids(self):
        """Test has_key with different key IDs."""
        handler = ConcreteKeyManagementHandler()

        # All should return False by default
        assert await handler.has_key("kid1") is False
        assert await handler.has_key("kid2") is False
        assert await handler.has_key("") is False
        assert await handler.has_key("very-long-key-id-123") is False

    @pytest.mark.asyncio
    async def test_accept_key_request_with_none_context(self):
        """Test accept_key_request with None context."""
        handler = ConcreteKeyManagementHandler()
        mock_envelope = Mock(spec=FameEnvelope)

        # Should handle None context gracefully
        await handler.accept_key_request(mock_envelope, None)

    @pytest.mark.asyncio
    async def test_multiple_operations_sequence(self):
        """Test sequence of multiple operations."""
        handler = ConcreteKeyManagementHandler()
        mock_envelope = Mock(spec=FameEnvelope)
        mock_context = Mock(spec=FameDeliveryContext)

        # Test a realistic sequence of operations
        await handler.start()
        assert handler._is_started

        await handler.accept_key_announce(mock_envelope, mock_context)
        await handler.process_envelope(mock_envelope, mock_context)

        should_process = await handler.should_process_envelope(mock_envelope, mock_context)
        assert should_process is False

        should_request = await handler.should_request_key(mock_envelope, mock_context)
        assert should_request is False

        has_key = await handler.has_key("test-key")
        assert has_key is False

        await handler.retry_pending_key_requests_after_attachment()
        await handler.stop()
        assert not handler._is_started
