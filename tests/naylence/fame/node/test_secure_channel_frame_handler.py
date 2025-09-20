"""Comprehensive tests for SecureChannelFrameHandler to achieve 85%+ coverage."""

from unittest.mock import AsyncMock, Mock, patch

import pytest

from naylence.fame.core import EnvelopeFactory, FameEnvelope
from naylence.fame.core.protocol.frames import (
    SecureAcceptFrame,
    SecureCloseFrame,
    SecureOpenFrame,
)
from naylence.fame.node.envelope_security_handler import EnvelopeSecurityHandler
from naylence.fame.node.secure_channel_frame_handler import SecureChannelFrameHandler
from naylence.fame.security.encryption.secure_channel_manager import SecureChannelManager


@pytest.fixture
def mock_secure_channel_manager():
    """Create a mock SecureChannelManager."""
    manager = Mock(spec=SecureChannelManager)
    manager.handle_open_frame = AsyncMock()
    manager.handle_accept_frame = AsyncMock()
    manager.handle_close_frame = Mock()
    return manager


@pytest.fixture
def mock_envelope_factory():
    """Create a mock EnvelopeFactory."""
    factory = Mock(spec=EnvelopeFactory)
    factory.create_envelope = Mock()
    return factory


@pytest.fixture
def mock_send_callback():
    """Create a mock send callback function."""
    return AsyncMock()


@pytest.fixture
def mock_envelope_security_handler():
    """Create a mock EnvelopeSecurityHandler."""
    handler = Mock(spec=EnvelopeSecurityHandler)
    handler.handle_channel_handshake_complete = AsyncMock()
    handler.handle_channel_handshake_failed = AsyncMock()
    return handler


@pytest.fixture
def secure_channel_frame_handler(mock_secure_channel_manager, mock_envelope_factory, mock_send_callback):
    """Create SecureChannelFrameHandler with basic mocks."""
    return SecureChannelFrameHandler(
        secure_channel_manager=mock_secure_channel_manager,
        envelope_factory=mock_envelope_factory,
        send_callback=mock_send_callback,
    )


@pytest.fixture
def secure_ch_fr_handler_with_sec(
    mock_secure_channel_manager,
    mock_envelope_factory,
    mock_send_callback,
    mock_envelope_security_handler,
):
    """Create SecureChannelFrameHandler with envelope security handler."""
    return SecureChannelFrameHandler(
        secure_channel_manager=mock_secure_channel_manager,
        envelope_factory=mock_envelope_factory,
        send_callback=mock_send_callback,
        envelope_security_handler=mock_envelope_security_handler,
    )


class TestSecureChannelFrameHandlerInit:
    """Test SecureChannelFrameHandler initialization."""

    def test_init_all_parameters(
        self,
        mock_secure_channel_manager,
        mock_envelope_factory,
        mock_send_callback,
        mock_envelope_security_handler,
    ):
        """Test initialization with all parameters."""
        handler = SecureChannelFrameHandler(
            secure_channel_manager=mock_secure_channel_manager,
            envelope_factory=mock_envelope_factory,
            send_callback=mock_send_callback,
            envelope_security_handler=mock_envelope_security_handler,
        )

        assert handler._secure_channel_manager == mock_secure_channel_manager
        assert handler._envelope_factory == mock_envelope_factory
        assert handler._send_callback == mock_send_callback
        assert handler._envelope_security_handler == mock_envelope_security_handler

    def test_init_without_security_handler(
        self, mock_secure_channel_manager, mock_envelope_factory, mock_send_callback
    ):
        """Test initialization without envelope security handler."""
        handler = SecureChannelFrameHandler(
            secure_channel_manager=mock_secure_channel_manager,
            envelope_factory=mock_envelope_factory,
            send_callback=mock_send_callback,
        )

        assert handler._secure_channel_manager == mock_secure_channel_manager
        assert handler._envelope_factory == mock_envelope_factory
        assert handler._send_callback == mock_send_callback
        assert handler._envelope_security_handler is None


class TestHandleSecureOpen:
    """Test handle_secure_open method to cover lines 39-100."""

    @pytest.mark.asyncio
    async def test_handle_secure_open_no_manager(self, mock_envelope_factory, mock_send_callback):
        """Test SecureOpen handling without SecureChannelManager."""
        handler = SecureChannelFrameHandler(
            secure_channel_manager=None,
            envelope_factory=mock_envelope_factory,
            send_callback=mock_send_callback,
        )

        frame = Mock(spec=SecureOpenFrame)
        envelope = Mock(spec=FameEnvelope)
        envelope.frame = frame

        with pytest.raises(RuntimeError, match="SecureChannelManager is not initialized"):
            await handler.handle_secure_open(envelope, None)

    @pytest.mark.asyncio
    async def test_handle_secure_open_wrong_frame_type(self, secure_channel_frame_handler):
        """Test SecureOpen handling with wrong frame type."""
        wrong_frame = Mock(spec=SecureAcceptFrame)  # Wrong type
        envelope = Mock(spec=FameEnvelope)
        envelope.frame = wrong_frame

        with pytest.raises(ValueError, match="Expected SecureOpenFrame"):
            await secure_channel_frame_handler.handle_secure_open(envelope, None)

    @pytest.mark.asyncio
    async def test_handle_secure_open_successful_channel(self, secure_channel_frame_handler):
        """Test SecureOpen handling with successful channel establishment."""
        # Mock frame
        frame = Mock(spec=SecureOpenFrame)
        frame.cid = "test-channel-123"
        frame.alg = "CHACHA20P1305"

        # Mock envelope
        envelope = Mock(spec=FameEnvelope)
        envelope.frame = frame
        envelope.reply_to = "sender-address"
        envelope.corr_id = "corr-123"
        envelope.sid = "session-456"

        # Mock successful accept frame
        accept_frame = Mock(spec=SecureAcceptFrame)
        accept_frame.ok = True
        secure_channel_frame_handler._secure_channel_manager.handle_open_frame.return_value = accept_frame

        # Mock response envelope
        response_envelope = Mock(spec=FameEnvelope)
        secure_channel_frame_handler._envelope_factory.create_envelope.return_value = response_envelope

        with patch("naylence.fame.node.secure_channel_frame_handler.logger"):
            await secure_channel_frame_handler.handle_secure_open(envelope, None)

            # Verify channel manager was called
            secure_channel_frame_handler._secure_channel_manager.handle_open_frame.assert_called_once_with(
                frame
            )

            # Verify response envelope creation
            secure_channel_frame_handler._envelope_factory.create_envelope.assert_called_once_with(
                to="sender-address", frame=accept_frame, corr_id="corr-123"
            )

            # Verify send callback was called (should use new signature path)
            secure_channel_frame_handler._send_callback.assert_called_once()
            args = secure_channel_frame_handler._send_callback.call_args[0]
            assert args[0] == response_envelope
            # Should have response context with stickiness for successful channel
            assert args[1] is not None
            assert args[1].stickiness_required is True

    @pytest.mark.asyncio
    async def test_handle_secure_open_failed_channel(self, secure_channel_frame_handler):
        """Test SecureOpen handling with failed channel establishment."""
        # Mock frame
        frame = Mock(spec=SecureOpenFrame)
        frame.cid = "test-channel-456"
        frame.alg = "CHACHA20P1305"

        # Mock envelope
        envelope = Mock(spec=FameEnvelope)
        envelope.frame = frame
        envelope.reply_to = "sender-address"
        envelope.corr_id = "corr-456"
        envelope.sid = "session-789"

        # Mock failed accept frame
        accept_frame = Mock(spec=SecureAcceptFrame)
        accept_frame.ok = False
        secure_channel_frame_handler._secure_channel_manager.handle_open_frame.return_value = accept_frame

        # Mock response envelope
        response_envelope = Mock(spec=FameEnvelope)
        secure_channel_frame_handler._envelope_factory.create_envelope.return_value = response_envelope

        with patch("naylence.fame.node.secure_channel_frame_handler.logger"):
            await secure_channel_frame_handler.handle_secure_open(envelope, None)

            # Verify send callback was called with no response context (failed channel)
            secure_channel_frame_handler._send_callback.assert_called_once()
            args = secure_channel_frame_handler._send_callback.call_args[0]
            assert args[0] == response_envelope
            assert args[1] is None  # No stickiness for failed channel

    @pytest.mark.asyncio
    async def test_handle_secure_open_backward_compatibility(self, secure_channel_frame_handler):
        """Test SecureOpen handling with old callback signature."""
        # Create a mock callback with old signature (only one parameter)
        old_callback = AsyncMock()

        # Mock signature inspection to return old signature
        with patch("inspect.signature") as mock_signature:
            mock_sig = Mock()
            mock_sig.parameters = {"envelope": Mock()}  # Only one parameter
            mock_signature.return_value = mock_sig

            # Replace callback with old-style one
            secure_channel_frame_handler._send_callback = old_callback

            # Mock frame and envelope
            frame = Mock(spec=SecureOpenFrame)
            frame.cid = "test-channel-old"
            frame.alg = "CHACHA20P1305"

            envelope = Mock(spec=FameEnvelope)
            envelope.frame = frame
            envelope.reply_to = "sender-address"
            envelope.corr_id = "corr-old"
            envelope.sid = "session-old"

            # Mock accept frame
            accept_frame = Mock(spec=SecureAcceptFrame)
            accept_frame.ok = True
            secure_channel_frame_handler._secure_channel_manager.handle_open_frame.return_value = (
                accept_frame
            )

            # Mock response envelope
            response_envelope = Mock(spec=FameEnvelope)
            secure_channel_frame_handler._envelope_factory.create_envelope.return_value = response_envelope

            with patch("naylence.fame.node.secure_channel_frame_handler.logger"):
                await secure_channel_frame_handler.handle_secure_open(envelope, None)

                # Should call old callback with None context
                old_callback.assert_called_once_with(response_envelope, None)

    @pytest.mark.asyncio
    async def test_handle_secure_open_method_signature_compatibility(self, secure_channel_frame_handler):
        """Test signature inspection filters out 'self' parameter correctly."""
        # Create a mock callback that's a method (has 'self' parameter)
        method_callback = AsyncMock()

        # Mock signature inspection to return method signature with 'self'
        with patch("inspect.signature") as mock_signature:
            mock_sig = Mock()
            # Method signature: self, envelope, context
            mock_sig.parameters = {"self": Mock(), "envelope": Mock(), "context": Mock()}
            mock_signature.return_value = mock_sig

            # Replace callback
            secure_channel_frame_handler._send_callback = method_callback

            # Mock frame and envelope
            frame = Mock(spec=SecureOpenFrame)
            frame.cid = "test-channel-method"
            frame.alg = "CHACHA20P1305"

            envelope = Mock(spec=FameEnvelope)
            envelope.frame = frame
            envelope.reply_to = "sender-address"
            envelope.corr_id = "corr-method"
            envelope.sid = "session-method"

            # Mock accept frame
            accept_frame = Mock(spec=SecureAcceptFrame)
            accept_frame.ok = True
            secure_channel_frame_handler._secure_channel_manager.handle_open_frame.return_value = (
                accept_frame
            )

            # Mock response envelope
            response_envelope = Mock(spec=FameEnvelope)
            secure_channel_frame_handler._envelope_factory.create_envelope.return_value = response_envelope

            with patch("naylence.fame.node.secure_channel_frame_handler.logger"):
                await secure_channel_frame_handler.handle_secure_open(envelope, None)

                # Should detect 2 parameters after filtering 'self' and use new signature
                method_callback.assert_called_once()
                args = method_callback.call_args[0]
                assert len(args) == 2  # envelope and context

    @pytest.mark.asyncio
    async def test_handle_secure_open_with_security_handler_channel_established(
        self, secure_ch_fr_handler_with_sec
    ):
        """Test SecureOpen with envelope security handler and successful channel."""
        # Mock frame with auto-pattern channel ID
        frame = Mock(spec=SecureOpenFrame)
        frame.cid = "auto-dest-node-12345"
        frame.alg = "CHACHA20P1305"

        # Mock envelope
        envelope = Mock(spec=FameEnvelope)
        envelope.frame = frame
        envelope.reply_to = "sender-address"
        envelope.corr_id = "corr-security"
        envelope.sid = "session-security"

        # Mock successful accept frame
        accept_frame = Mock(spec=SecureAcceptFrame)
        accept_frame.ok = True
        secure_ch_fr_handler_with_sec._secure_channel_manager.handle_open_frame.return_value = accept_frame

        # Mock response envelope
        response_envelope = Mock(spec=FameEnvelope)
        secure_ch_fr_handler_with_sec._envelope_factory.create_envelope.return_value = response_envelope

        with patch("naylence.fame.node.secure_channel_frame_handler.logger"):
            await secure_ch_fr_handler_with_sec.handle_secure_open(envelope, None)

            # Verify security handler was notified
            security_handler = secure_ch_fr_handler_with_sec._envelope_security_handler
            security_handler.handle_channel_handshake_complete.assert_called_once_with(
                "auto-dest-node-12345", "dest-node"
            )

    @pytest.mark.asyncio
    async def test_handle_secure_open_with_security_handler_non_auto_channel(
        self, secure_ch_fr_handler_with_sec
    ):
        """Test SecureOpen with non-auto channel ID pattern (no security handler notification)."""
        # Mock frame with non-auto channel ID
        frame = Mock(spec=SecureOpenFrame)
        frame.cid = "manual-channel-789"
        frame.alg = "CHACHA20P1305"

        # Mock envelope
        envelope = Mock(spec=FameEnvelope)
        envelope.frame = frame
        envelope.reply_to = "sender-address"
        envelope.corr_id = "corr-manual"
        envelope.sid = "session-manual"

        # Mock successful accept frame
        accept_frame = Mock(spec=SecureAcceptFrame)
        accept_frame.ok = True
        secure_ch_fr_handler_with_sec._secure_channel_manager.handle_open_frame.return_value = accept_frame

        # Mock response envelope
        response_envelope = Mock(spec=FameEnvelope)
        secure_ch_fr_handler_with_sec._envelope_factory.create_envelope.return_value = response_envelope

        with patch("naylence.fame.node.secure_channel_frame_handler.logger"):
            await secure_ch_fr_handler_with_sec.handle_secure_open(envelope, None)

            # Verify security handler was NOT notified (non-auto pattern)
            security_handler = secure_ch_fr_handler_with_sec._envelope_security_handler
            security_handler.handle_channel_handshake_complete.assert_not_called()


class TestHandleSecureAccept:
    """Test handle_secure_accept method to cover lines 106-144."""

    @pytest.mark.asyncio
    async def test_handle_secure_accept_no_manager(self, mock_envelope_factory, mock_send_callback):
        """Test SecureAccept handling without SecureChannelManager."""
        handler = SecureChannelFrameHandler(
            secure_channel_manager=None,
            envelope_factory=mock_envelope_factory,
            send_callback=mock_send_callback,
        )

        frame = Mock(spec=SecureAcceptFrame)
        envelope = Mock(spec=FameEnvelope)
        envelope.frame = frame

        with pytest.raises(RuntimeError, match="SecureChannelManager is not initialized"):
            await handler.handle_secure_accept(envelope, None)

    @pytest.mark.asyncio
    async def test_handle_secure_accept_wrong_frame_type(self, secure_channel_frame_handler):
        """Test SecureAccept handling with wrong frame type."""
        wrong_frame = Mock(spec=SecureOpenFrame)  # Wrong type
        envelope = Mock(spec=FameEnvelope)
        envelope.frame = wrong_frame

        with pytest.raises(ValueError, match="Expected SecureAcceptFrame"):
            await secure_channel_frame_handler.handle_secure_accept(envelope, None)

    @pytest.mark.asyncio
    async def test_handle_secure_accept_successful_handshake(self, secure_channel_frame_handler):
        """Test SecureAccept handling with successful handshake."""
        # Mock frame
        frame = Mock(spec=SecureAcceptFrame)
        frame.cid = "test-channel-success"
        frame.ok = True

        # Mock envelope
        envelope = Mock(spec=FameEnvelope)
        envelope.frame = frame

        # Mock successful handshake
        secure_channel_frame_handler._secure_channel_manager.handle_accept_frame.return_value = True

        with patch("naylence.fame.node.secure_channel_frame_handler.logger") as mock_logger:
            await secure_channel_frame_handler.handle_secure_accept(envelope, None)

            # Verify channel manager was called
            secure_channel_frame_handler._secure_channel_manager.handle_accept_frame.assert_called_once_with(
                frame
            )

            # Verify logging calls
            mock_logger.debug.assert_called()

    @pytest.mark.asyncio
    async def test_handle_secure_accept_failed_handshake(self, secure_channel_frame_handler):
        """Test SecureAccept handling with failed handshake."""
        # Mock frame
        frame = Mock(spec=SecureAcceptFrame)
        frame.cid = "test-channel-fail"
        frame.ok = True

        # Mock envelope
        envelope = Mock(spec=FameEnvelope)
        envelope.frame = frame

        # Mock failed handshake
        secure_channel_frame_handler._secure_channel_manager.handle_accept_frame.return_value = False

        with patch("naylence.fame.node.secure_channel_frame_handler.logger") as mock_logger:
            await secure_channel_frame_handler.handle_secure_accept(envelope, None)

            # Verify channel manager was called
            secure_channel_frame_handler._secure_channel_manager.handle_accept_frame.assert_called_once_with(
                frame
            )

            # Verify warning was logged
            mock_logger.warning.assert_called_once_with(
                "failed_to_complete_channel", cid="test-channel-fail"
            )

    @pytest.mark.asyncio
    async def test_handle_secure_accept_successful_with_security_handler(
        self, secure_ch_fr_handler_with_sec
    ):
        """Test SecureAccept with security handler and successful handshake."""
        # Mock frame with auto-pattern channel ID
        frame = Mock(spec=SecureAcceptFrame)
        frame.cid = "auto-target-system-67890"
        frame.ok = True

        # Mock envelope
        envelope = Mock(spec=FameEnvelope)
        envelope.frame = frame

        # Mock successful handshake
        secure_ch_fr_handler_with_sec._secure_channel_manager.handle_accept_frame.return_value = True

        with patch("naylence.fame.node.secure_channel_frame_handler.logger"):
            await secure_ch_fr_handler_with_sec.handle_secure_accept(envelope, None)

            # Verify security handler was notified of success
            security_handler = secure_ch_fr_handler_with_sec._envelope_security_handler
            security_handler.handle_channel_handshake_complete.assert_called_once_with(
                "auto-target-system-67890", "target-system"
            )

    @pytest.mark.asyncio
    async def test_handle_secure_accept_negative_with_security_handler(self, secure_ch_fr_handler_with_sec):
        """Test SecureAccept with negative ok flag and security handler."""
        # Mock frame with auto-pattern channel ID and negative ok
        frame = Mock(spec=SecureAcceptFrame)
        frame.cid = "auto-remote-node-99999"
        frame.ok = False  # Negative SecureAccept

        # Mock envelope
        envelope = Mock(spec=FameEnvelope)
        envelope.frame = frame

        # Mock failed handshake (though this shouldn't be called for negative frame)
        secure_ch_fr_handler_with_sec._secure_channel_manager.handle_accept_frame.return_value = False

        with patch("naylence.fame.node.secure_channel_frame_handler.logger") as mock_logger:
            await secure_ch_fr_handler_with_sec.handle_secure_accept(envelope, None)

            # Verify security handler was notified of failure
            security_handler = secure_ch_fr_handler_with_sec._envelope_security_handler
            security_handler.handle_channel_handshake_failed.assert_called_once_with(
                "auto-remote-node-99999", "remote-node", "negative_secure_accept"
            )

            # Verify debug logging for failure notification
            mock_logger.debug.assert_any_call(
                "notified_handshake_failure",
                cid="auto-remote-node-99999",
                destination="remote-node",
            )

    @pytest.mark.asyncio
    async def test_handle_secure_accept_malformed_channel_id(self, secure_ch_fr_handler_with_sec):
        """Test SecureAccept with malformed channel ID (insufficient parts)."""
        # Mock frame with malformed channel ID
        frame = Mock(spec=SecureAcceptFrame)
        frame.cid = "auto-onlyonepart"  # Not enough parts
        frame.ok = True

        # Mock envelope
        envelope = Mock(spec=FameEnvelope)
        envelope.frame = frame

        # Mock successful handshake
        secure_ch_fr_handler_with_sec._secure_channel_manager.handle_accept_frame.return_value = True

        with patch("naylence.fame.node.secure_channel_frame_handler.logger"):
            await secure_ch_fr_handler_with_sec.handle_secure_accept(envelope, None)

            # Verify security handler was NOT notified (malformed ID)
            security_handler = secure_ch_fr_handler_with_sec._envelope_security_handler
            security_handler.handle_channel_handshake_complete.assert_not_called()


class TestHandleSecureClose:
    """Test handle_secure_close method to cover lines 152-162."""

    @pytest.mark.asyncio
    async def test_handle_secure_close_no_manager(self, mock_envelope_factory, mock_send_callback):
        """Test SecureClose handling without SecureChannelManager."""
        handler = SecureChannelFrameHandler(
            secure_channel_manager=None,
            envelope_factory=mock_envelope_factory,
            send_callback=mock_send_callback,
        )

        frame = Mock(spec=SecureCloseFrame)
        envelope = Mock(spec=FameEnvelope)
        envelope.frame = frame

        with pytest.raises(RuntimeError, match="SecureChannelManager is not initialized"):
            await handler.handle_secure_close(envelope, None)

    @pytest.mark.asyncio
    async def test_handle_secure_close_wrong_frame_type(self, secure_channel_frame_handler):
        """Test SecureClose handling with wrong frame type."""
        wrong_frame = Mock(spec=SecureOpenFrame)  # Wrong type
        envelope = Mock(spec=FameEnvelope)
        envelope.frame = wrong_frame

        with pytest.raises(ValueError, match="Expected SecureCloseFrame"):
            await secure_channel_frame_handler.handle_secure_close(envelope, None)

    @pytest.mark.asyncio
    async def test_handle_secure_close_basic(self, secure_channel_frame_handler):
        """Test basic SecureClose handling."""
        # Mock frame
        frame = Mock(spec=SecureCloseFrame)
        frame.cid = "test-channel-close"
        frame.reason = "client_disconnect"

        # Mock envelope
        envelope = Mock(spec=FameEnvelope)
        envelope.frame = frame

        with patch("naylence.fame.node.secure_channel_frame_handler.logger") as mock_logger:
            await secure_channel_frame_handler.handle_secure_close(envelope, None)

            # Verify channel manager was called
            secure_channel_frame_handler._secure_channel_manager.handle_close_frame.assert_called_once_with(
                frame
            )

            # Verify debug logging
            mock_logger.debug.assert_called_once_with(
                "received_secure_close", cid="test-channel-close", reason="client_disconnect"
            )
