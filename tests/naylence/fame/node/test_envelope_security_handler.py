"""Comprehensive tests for EnvelopeSecurityHandler to achieve 85%+ coverage."""

from unittest.mock import AsyncMock, Mock, patch

import pytest

from naylence.fame.core import (
    DataFrame,
    DeliveryOriginType,
    FameAddress,
    FameDeliveryContext,
    FameEnvelope,
)
from naylence.fame.core.protocol.delivery_context import SecurityContext
from naylence.fame.core.protocol.frames import (
    KeyRequestFrame,
)
from naylence.fame.node.envelope_security_handler import EnvelopeSecurityHandler
from naylence.fame.node.node_like import NodeLike
from naylence.fame.security.encryption.encryption_manager import (
    EncryptionManager,
    EncryptionResult,
    EncryptionStatus,
)
from naylence.fame.security.keys.key_management_handler import KeyManagementHandler
from naylence.fame.security.policy import SecurityPolicy
from naylence.fame.security.policy.security_policy import CryptoLevel, SecurityAction
from naylence.fame.security.signing.envelope_signer import EnvelopeSigner
from naylence.fame.security.signing.envelope_verifier import EnvelopeVerifier

# Module-level fixtures available to all test classes


@pytest.fixture
def mock_node_like():
    """Create a mock NodeLike object."""
    node = Mock(spec=NodeLike)
    node.sid = "test-node-sid"
    node.physical_path = "/test/path"
    return node


@pytest.fixture
def mock_envelope_signer():
    """Create a mock EnvelopeSigner."""
    signer = Mock(spec=EnvelopeSigner)
    signer.sign_envelope = Mock()
    return signer


@pytest.fixture
def mock_envelope_verifier():
    """Create a mock EnvelopeVerifier."""
    verifier = Mock(spec=EnvelopeVerifier)
    verifier.verify_envelope = AsyncMock(return_value=True)
    return verifier


@pytest.fixture
def mock_encryption_manager():
    """Create a mock EncryptionManager."""
    manager = Mock(spec=EncryptionManager)
    manager.encrypt_envelope = AsyncMock()
    manager.decrypt_envelope = AsyncMock()
    return manager


@pytest.fixture
def mock_security_policy():
    """Create a mock SecurityPolicy."""
    policy = Mock(spec=SecurityPolicy)
    policy.should_sign_envelope = AsyncMock(return_value=False)
    policy.should_encrypt_envelope = AsyncMock(return_value=False)
    policy.should_decrypt_envelope = AsyncMock(return_value=False)
    policy.get_encryption_options = AsyncMock(return_value=None)
    policy.decide_outbound_crypto_level = AsyncMock(return_value=CryptoLevel.PLAINTEXT)
    policy.decide_response_crypto_level = AsyncMock(return_value=CryptoLevel.PLAINTEXT)
    policy.classify_message_crypto_level = Mock(return_value=CryptoLevel.PLAINTEXT)
    policy.is_signature_required = Mock(return_value=False)
    policy.get_unsigned_violation_action = Mock(return_value=SecurityAction.ALLOW)
    return policy


@pytest.fixture
def mock_key_management_handler():
    """Create a mock KeyManagementHandler."""
    handler = Mock(spec=KeyManagementHandler)
    handler.has_key = AsyncMock(return_value=True)
    handler._pending_envelopes = {}
    handler._pending_encryption_envelopes = {}
    handler._maybe_request_signing_key = AsyncMock()
    handler._maybe_request_encryption_key = AsyncMock()
    handler._maybe_request_encryption_key_by_address = AsyncMock()
    return handler


@pytest.fixture
def envelope_security_handler(
    mock_node_like,
    mock_envelope_signer,
    mock_envelope_verifier,
    mock_encryption_manager,
    mock_security_policy,
    mock_key_management_handler,
):
    """Create an EnvelopeSecurityHandler with all mocks."""
    return EnvelopeSecurityHandler(
        node_like=mock_node_like,
        envelope_signer=mock_envelope_signer,
        envelope_verifier=mock_envelope_verifier,
        encryption_manager=mock_encryption_manager,
        security_policy=mock_security_policy,
        key_management_handler=mock_key_management_handler,
    )


@pytest.fixture
def test_envelope():
    """Create a test envelope."""
    return FameEnvelope(
        id="test-envelope-123",
        to=FameAddress("test@/destination"),
        frame=DataFrame(type="Data", payload={"message": "test"}),
    )


@pytest.fixture
def test_context():
    """Create a test delivery context."""
    context = FameDeliveryContext(origin_type=DeliveryOriginType.LOCAL)
    context.meta = {"message-type": "request"}
    context.from_system_id = "test-system"
    return context


@pytest.fixture
def signed_envelope():
    """Create a signed envelope for testing."""
    from naylence.fame.core.protocol.security_header import SecurityHeader, SignatureHeader

    envelope = FameEnvelope(
        id="signed-envelope-123",
        to=FameAddress("test@/destination"),
        frame=DataFrame(type="Data", payload={"message": "signed"}),
    )
    envelope.sec = SecurityHeader()
    envelope.sec.sig = SignatureHeader(kid="test-key-id", val="test-signature")
    return envelope


@pytest.fixture
def dataframe_envelope():
    """Create an envelope with DataFrame for encryption testing."""
    return FameEnvelope(
        id="dataframe-envelope-123",
        to=FameAddress("test@/destination"),
        frame=DataFrame(type="Data", payload={"message": "encrypt me"}),
    )


@pytest.fixture
def non_dataframe_envelope():
    """Create an envelope with non-DataFrame for testing encryption skipping."""
    return FameEnvelope(
        id="key-request-envelope-123",
        to=FameAddress("test@/destination"),
        frame=KeyRequestFrame(kid="test-key", physical_path="/test"),
    )


@pytest.fixture
def encrypted_envelope():
    """Create an encrypted envelope for testing."""
    from naylence.fame.core.protocol.security_header import EncryptionHeader, SecurityHeader

    envelope = FameEnvelope(
        id="encrypted-envelope-123",
        to=FameAddress("test@/destination"),
        frame=DataFrame(type="Data", payload={"encrypted": True}),
    )
    envelope.sec = SecurityHeader()
    envelope.sec.enc = EncryptionHeader(val="encrypted-data")
    return envelope


class TestEnvelopeSecurityHandler:
    """Test cases for EnvelopeSecurityHandler."""

    async def test_init_with_all_components(
        self,
        mock_node_like,
        mock_envelope_signer,
        mock_envelope_verifier,
        mock_encryption_manager,
        mock_security_policy,
        mock_key_management_handler,
    ):
        """Test initialization with all components."""
        handler = EnvelopeSecurityHandler(
            node_like=mock_node_like,
            envelope_signer=mock_envelope_signer,
            envelope_verifier=mock_envelope_verifier,
            encryption_manager=mock_encryption_manager,
            security_policy=mock_security_policy,
            key_management_handler=mock_key_management_handler,
        )

        assert handler._node_like is mock_node_like
        assert handler._envelope_signer is mock_envelope_signer
        assert handler._envelope_verifier is mock_envelope_verifier
        assert handler._encryption_manager is mock_encryption_manager
        assert handler._security_policy is mock_security_policy
        assert handler._key_management_handler is mock_key_management_handler

    async def test_init_with_optional_none(
        self, mock_node_like, mock_security_policy, mock_key_management_handler
    ):
        """Test initialization with optional components as None."""
        handler = EnvelopeSecurityHandler(
            node_like=mock_node_like,
            envelope_signer=None,
            envelope_verifier=None,
            encryption_manager=None,
            security_policy=mock_security_policy,
            key_management_handler=mock_key_management_handler,
        )

        assert handler._envelope_signer is None
        assert handler._envelope_verifier is None
        assert handler._encryption_manager is None

    async def test_handle_outbound_security_no_signing_or_encryption(
        self, envelope_security_handler, test_envelope, test_context
    ):
        """Test outbound security when no signing or encryption is needed."""
        result = await envelope_security_handler.handle_outbound_security(test_envelope, test_context)

        assert result is True
        assert test_envelope.sec is None or test_envelope.sec.sig is None
        assert test_envelope.sec is None or test_envelope.sec.enc is None

    async def test_handle_outbound_security_signing_required_no_signer(
        self, envelope_security_handler, test_envelope, test_context, mock_security_policy
    ):
        """Test outbound security when signing is required but no signer is configured."""
        mock_security_policy.should_sign_envelope.return_value = True
        envelope_security_handler._envelope_signer = None

        with pytest.raises(RuntimeError, match="EnvelopeSigner is not configured"):
            await envelope_security_handler.handle_outbound_security(test_envelope, test_context)

    async def test_handle_outbound_security_signing_success(
        self,
        envelope_security_handler,
        test_envelope,
        test_context,
        mock_security_policy,
        mock_envelope_signer,
    ):
        """Test successful outbound signing."""
        mock_security_policy.should_sign_envelope.return_value = True

        result = await envelope_security_handler.handle_outbound_security(test_envelope, test_context)

        assert result is True
        assert test_envelope.sid == "test-node-sid"  # Should be set from node_like
        mock_envelope_signer.sign_envelope.assert_called_once_with(
            test_envelope, physical_path="/test/path"
        )

    async def test_is_signed_true(self, envelope_security_handler, test_envelope, test_context):
        """Test is_signed returns True for signed envelope."""
        # Create a mock signature
        from naylence.fame.core.protocol.security_header import SecurityHeader, SignatureHeader

        test_envelope.sec = SecurityHeader()
        test_envelope.sec.sig = SignatureHeader(kid="test-kid", val="test-signature")

        result = envelope_security_handler.is_signed(test_envelope, test_context)
        assert result is True

    async def test_is_signed_false_no_sec(self, envelope_security_handler, test_envelope, test_context):
        """Test is_signed returns False when no security section."""
        result = envelope_security_handler.is_signed(test_envelope, test_context)
        assert result is False

    async def test_is_signed_false_no_context(self, envelope_security_handler, test_envelope):
        """Test is_signed returns False when no context."""
        from naylence.fame.core.protocol.security_header import SecurityHeader, SignatureHeader

        test_envelope.sec = SecurityHeader()
        test_envelope.sec.sig = SignatureHeader(kid="test-kid", val="test-signature")

        result = envelope_security_handler.is_signed(test_envelope, None)
        assert result is False


class TestHandleSignedEnvelope:
    """Test cases for handle_signed_envelope method covering lines 163, 173-207."""

    async def test_handle_signed_envelope_key_available_verification_success(
        self,
        envelope_security_handler,
        signed_envelope,
        test_context,
        mock_key_management_handler,
        mock_envelope_verifier,
    ):
        """Test handle_signed_envelope when key is available and verification succeeds."""
        mock_key_management_handler.has_key.return_value = True
        mock_envelope_verifier.verify_envelope.return_value = True

        result = await envelope_security_handler.handle_signed_envelope(signed_envelope, test_context)

        assert result is True
        mock_key_management_handler.has_key.assert_called_once_with("test-key-id")
        mock_envelope_verifier.verify_envelope.assert_called_once_with(signed_envelope, check_payload=False)

    async def test_handle_signed_envelope_key_available_verification_failure(
        self,
        envelope_security_handler,
        signed_envelope,
        test_context,
        mock_key_management_handler,
        mock_envelope_verifier,
    ):
        """Test handle_signed_envelope when key is available but verification fails."""
        mock_key_management_handler.has_key.return_value = True
        mock_envelope_verifier.verify_envelope.return_value = False

        with pytest.raises(ValueError, match="Envelope signature verification failed for kid=test-key-id"):
            await envelope_security_handler.handle_signed_envelope(signed_envelope, test_context)

    async def test_handle_signed_envelope_key_missing_queues_envelope(
        self, envelope_security_handler, signed_envelope, test_context, mock_key_management_handler
    ):
        """Test handle_signed_envelope when key is missing - should queue envelope and request key."""
        mock_key_management_handler.has_key.return_value = False
        mock_key_management_handler._pending_envelopes = {}

        result = await envelope_security_handler.handle_signed_envelope(signed_envelope, test_context)

        assert result is False
        # Check that envelope was queued
        assert "test-key-id" in mock_key_management_handler._pending_envelopes
        assert (signed_envelope, test_context) in mock_key_management_handler._pending_envelopes[
            "test-key-id"
        ]
        # Check that key request was made
        mock_key_management_handler._maybe_request_signing_key.assert_called_once_with(
            "test-key-id", DeliveryOriginType.LOCAL, "test-system"
        )

    async def test_handle_signed_envelope_no_from_system_id_during_attachment(
        self, envelope_security_handler, signed_envelope, mock_key_management_handler
    ):
        """Test handle_signed_envelope with missing from_system_id (during node attachment)."""
        # Create context without from_system_id
        context = FameDeliveryContext(origin_type=DeliveryOriginType.LOCAL)
        context.meta = {"message-type": "request"}
        # from_system_id is None (simulating attachment phase)

        mock_key_management_handler.has_key.return_value = False
        mock_key_management_handler._pending_envelopes = {}

        result = await envelope_security_handler.handle_signed_envelope(signed_envelope, context)

        assert result is False
        # Check that key request was made with "pending-attachment"
        mock_key_management_handler._maybe_request_signing_key.assert_called_once_with(
            "test-key-id", DeliveryOriginType.LOCAL, "pending-attachment"
        )

    async def test_handle_signed_envelope_no_context_assertion(
        self, envelope_security_handler, signed_envelope
    ):
        """Test handle_signed_envelope raises assertion error when context is None."""
        with pytest.raises(AssertionError):
            await envelope_security_handler.handle_signed_envelope(signed_envelope, None)

    async def test_handle_signed_envelope_no_origin_type_assertion(
        self, envelope_security_handler, signed_envelope
    ):
        """Test handle_signed_envelope raises assertion error when origin_type is None."""
        context = FameDeliveryContext(origin_type=None)
        with pytest.raises(AssertionError):
            await envelope_security_handler.handle_signed_envelope(signed_envelope, context)

    async def test_handle_signed_envelope_no_signature_assertion(
        self, envelope_security_handler, test_envelope, test_context
    ):
        """Test handle_signed_envelope raises assertion error when envelope is not signed."""
        with pytest.raises(AssertionError):
            await envelope_security_handler.handle_signed_envelope(test_envelope, test_context)

    async def test_handle_signed_envelope_no_verifier_assertion(
        self, envelope_security_handler, signed_envelope, test_context
    ):
        """Test handle_signed_envelope raises assertion error when no verifier is configured."""
        envelope_security_handler._envelope_verifier = None
        with pytest.raises(AssertionError):
            await envelope_security_handler.handle_signed_envelope(signed_envelope, test_context)


class TestEncryptionMethods:
    """Test cases for encryption methods covering lines 224-288, 303-365."""

    async def test_handle_to_be_encrypted_envelope_non_local_origin_rejected(
        self, envelope_security_handler, dataframe_envelope, mock_encryption_manager, mock_security_policy
    ):
        """Test encryption rejection for non-LOCAL origin envelopes."""
        context = FameDeliveryContext(origin_type=DeliveryOriginType.UPSTREAM)

        result = await envelope_security_handler._handle_to_be_encrypted_envelope(
            dataframe_envelope, context
        )

        assert result is True  # Continue without encryption
        mock_encryption_manager.encrypt_envelope.assert_not_called()

    async def test_handle_to_be_encrypted_envelope_non_dataframe_skipped(
        self, envelope_security_handler, non_dataframe_envelope, test_context, mock_encryption_manager
    ):
        """Test encryption skipping for non-DataFrame envelopes."""
        result = await envelope_security_handler._handle_to_be_encrypted_envelope(
            non_dataframe_envelope, test_context
        )

        assert result is True  # Continue without encryption
        mock_encryption_manager.encrypt_envelope.assert_not_called()

    async def test_handle_to_be_encrypted_envelope_no_encryption_options(
        self,
        envelope_security_handler,
        dataframe_envelope,
        test_context,
        mock_encryption_manager,
        mock_security_policy,
    ):
        """Test encryption when security policy returns no encryption options."""
        mock_security_policy.get_encryption_options.return_value = None

        result = await envelope_security_handler._handle_to_be_encrypted_envelope(
            dataframe_envelope, test_context
        )

        assert result is True  # Continue without encryption
        mock_encryption_manager.encrypt_envelope.assert_not_called()

    async def test_handle_to_be_encrypted_envelope_encryption_ok(
        self,
        envelope_security_handler,
        dataframe_envelope,
        test_context,
        mock_encryption_manager,
        mock_security_policy,
    ):
        """Test successful encryption."""
        encryption_opts = {"recip_kid": "test-recipient-key"}
        mock_security_policy.get_encryption_options.return_value = encryption_opts

        # Create a result envelope with encrypted content
        encrypted_envelope = FameEnvelope(
            id="encrypted-envelope",
            to=dataframe_envelope.to,
            frame=DataFrame(type="Data", payload={"encrypted": True}),
        )
        result = EncryptionResult(status=EncryptionStatus.OK, envelope=encrypted_envelope)
        mock_encryption_manager.encrypt_envelope.return_value = result

        result_bool = await envelope_security_handler._handle_to_be_encrypted_envelope(
            dataframe_envelope, test_context
        )

        assert result_bool is True
        mock_encryption_manager.encrypt_envelope.assert_called_once_with(
            dataframe_envelope, opts=encryption_opts
        )
        # Envelope should be updated with encrypted content
        assert dataframe_envelope.frame == encrypted_envelope.frame

    async def test_handle_to_be_encrypted_envelope_encryption_skipped(
        self,
        envelope_security_handler,
        dataframe_envelope,
        test_context,
        mock_encryption_manager,
        mock_security_policy,
    ):
        """Test encryption skipped status."""
        encryption_opts = {"recip_kid": "test-recipient-key"}
        mock_security_policy.get_encryption_options.return_value = encryption_opts

        result = EncryptionResult(status=EncryptionStatus.SKIPPED, envelope=None)
        mock_encryption_manager.encrypt_envelope.return_value = result

        result_bool = await envelope_security_handler._handle_to_be_encrypted_envelope(
            dataframe_envelope, test_context
        )

        assert result_bool is True
        mock_encryption_manager.encrypt_envelope.assert_called_once_with(
            dataframe_envelope, opts=encryption_opts
        )

    async def test_handle_to_be_encrypted_envelope_encryption_queued(
        self,
        envelope_security_handler,
        dataframe_envelope,
        test_context,
        mock_encryption_manager,
        mock_security_policy,
    ):
        """Test encryption queued status."""
        encryption_opts = {"recip_kid": "test-recipient-key"}
        mock_security_policy.get_encryption_options.return_value = encryption_opts

        result = EncryptionResult(status=EncryptionStatus.QUEUED, envelope=None)
        mock_encryption_manager.encrypt_envelope.return_value = result

        with patch.object(envelope_security_handler, "_handle_encryption_queueing") as mock_queueing:
            result_bool = await envelope_security_handler._handle_to_be_encrypted_envelope(
                dataframe_envelope, test_context
            )

        assert result_bool is False  # Don't continue delivery
        mock_queueing.assert_called_once_with(dataframe_envelope, test_context, encryption_opts)

    async def test_handle_to_be_encrypted_envelope_unknown_status(
        self,
        envelope_security_handler,
        dataframe_envelope,
        test_context,
        mock_encryption_manager,
        mock_security_policy,
    ):
        """Test unknown encryption status."""
        encryption_opts = {"recip_kid": "test-recipient-key"}
        mock_security_policy.get_encryption_options.return_value = encryption_opts

        # Create a result with unknown status (using a different enum value or mock)
        result = Mock()
        result.status = "UNKNOWN_STATUS"
        result.envelope = None
        mock_encryption_manager.encrypt_envelope.return_value = result

        result_bool = await envelope_security_handler._handle_to_be_encrypted_envelope(
            dataframe_envelope, test_context
        )

        assert result_bool is True  # Continue as fallback

    async def test_handle_to_be_encrypted_envelope_exception_fallback(
        self,
        envelope_security_handler,
        dataframe_envelope,
        test_context,
        mock_encryption_manager,
        mock_security_policy,
    ):
        """Test encryption exception handling with fallback."""
        encryption_opts = {"recip_kid": "test-recipient-key"}
        mock_security_policy.get_encryption_options.return_value = encryption_opts

        mock_encryption_manager.encrypt_envelope.side_effect = Exception("Encryption failed")

        result_bool = await envelope_security_handler._handle_to_be_encrypted_envelope(
            dataframe_envelope, test_context
        )

        assert result_bool is True  # Continue as fallback

    async def test_handle_to_be_encrypted_envelope_with_options_forced_options(
        self, envelope_security_handler, dataframe_envelope, test_context, mock_encryption_manager
    ):
        """Test _handle_to_be_encrypted_envelope_with_options with forced encryption options."""
        encryption_opts = {"recip_kid": "forced-key"}

        result = EncryptionResult(status=EncryptionStatus.OK, envelope=dataframe_envelope)
        mock_encryption_manager.encrypt_envelope.return_value = result

        result_bool = await envelope_security_handler._handle_to_be_encrypted_envelope_with_options(
            dataframe_envelope, test_context, encryption_opts
        )

        assert result_bool is True
        # Should use forced options, not call security policy
        mock_encryption_manager.encrypt_envelope.assert_called_once_with(
            dataframe_envelope, opts=encryption_opts
        )

    async def test_handle_to_be_encrypted_envelope_with_options_no_options(
        self, envelope_security_handler, dataframe_envelope, test_context, mock_encryption_manager
    ):
        """Test _handle_to_be_encrypted_envelope_with_options with no encryption options."""
        result_bool = await envelope_security_handler._handle_to_be_encrypted_envelope_with_options(
            dataframe_envelope, test_context, None
        )

        assert result_bool is True
        mock_encryption_manager.encrypt_envelope.assert_not_called()

        assert result_bool is True
        mock_encryption_manager.encrypt_envelope.assert_not_called()


class TestEncryptionQueueing:
    """Test cases for _handle_encryption_queueing method covering lines 380-428."""

    async def test_handle_encryption_queueing_with_recip_kid(
        self, envelope_security_handler, test_envelope, test_context, mock_key_management_handler
    ):
        """Test encryption queueing with recipient key ID."""
        encryption_opts = {"recip_kid": "test-recipient-key"}

        await envelope_security_handler._handle_encryption_queueing(
            test_envelope, test_context, encryption_opts
        )

        # Check that envelope was queued under the key ID
        assert "test-recipient-key" in mock_key_management_handler._pending_encryption_envelopes
        assert (test_envelope, test_context) in mock_key_management_handler._pending_encryption_envelopes[
            "test-recipient-key"
        ]

        # Check that key request was made
        mock_key_management_handler._maybe_request_encryption_key.assert_called_once_with(
            "test-recipient-key", DeliveryOriginType.LOCAL, "test-system"
        )

    async def test_handle_encryption_queueing_with_request_address(
        self, envelope_security_handler, test_envelope, test_context, mock_key_management_handler
    ):
        """Test encryption queueing with request address."""
        test_address = FameAddress("target@/node")
        encryption_opts = {"request_address": test_address}

        await envelope_security_handler._handle_encryption_queueing(
            test_envelope, test_context, encryption_opts
        )

        # Check that envelope was queued under the address string
        address_key = str(test_address)
        assert address_key in mock_key_management_handler._pending_encryption_envelopes
        assert (test_envelope, test_context) in mock_key_management_handler._pending_encryption_envelopes[
            address_key
        ]

        # Check that key request by address was made
        mock_key_management_handler._maybe_request_encryption_key_by_address.assert_called_once_with(
            test_address, DeliveryOriginType.LOCAL, "test-system"
        )

    async def test_handle_encryption_queueing_channel_encryption(
        self, envelope_security_handler, test_envelope, test_context, mock_key_management_handler
    ):
        """Test encryption queueing for channel encryption (should be handled internally)."""
        encryption_opts = {"encryption_type": "channel", "destination": FameAddress("channel@/destination")}

        await envelope_security_handler._handle_encryption_queueing(
            test_envelope, test_context, encryption_opts
        )

        # Channel encryption queueing is handled internally by the manager
        # So no key management handler calls should be made
        mock_key_management_handler._maybe_request_encryption_key.assert_not_called()
        mock_key_management_handler._maybe_request_encryption_key_by_address.assert_not_called()

    async def test_handle_encryption_queueing_unknown_options(
        self, envelope_security_handler, test_envelope, test_context, mock_key_management_handler
    ):
        """Test encryption queueing with unknown options (should log warning)."""
        encryption_opts = {"unknown_option": "unknown_value"}

        await envelope_security_handler._handle_encryption_queueing(
            test_envelope, test_context, encryption_opts
        )

        # Unknown options should not trigger any key requests
        mock_key_management_handler._maybe_request_encryption_key.assert_not_called()
        mock_key_management_handler._maybe_request_encryption_key_by_address.assert_not_called()

    async def test_handle_encryption_queueing_no_from_system_id(
        self, envelope_security_handler, test_envelope, mock_key_management_handler
    ):
        """Test encryption queueing when context has no from_system_id."""
        context = FameDeliveryContext(origin_type=DeliveryOriginType.LOCAL)
        context.meta = {"message-type": "request"}
        # from_system_id is None

        encryption_opts = {"recip_kid": "test-recipient-key"}

        await envelope_security_handler._handle_encryption_queueing(test_envelope, context, encryption_opts)

        # Should use "unknown" as fallback for from_system_id
        mock_key_management_handler._maybe_request_encryption_key.assert_called_once_with(
            "test-recipient-key", DeliveryOriginType.LOCAL, "unknown"
        )


class TestDecryptionMethods:
    """Test cases for decryption methods covering lines 439-453, 460-462, 466."""

    async def test_should_decrypt_envelope_standard_encryption_true(
        self, envelope_security_handler, encrypted_envelope, test_context, mock_security_policy
    ):
        """Test should_decrypt_envelope returns True for standard encryption."""
        mock_security_policy.should_decrypt_envelope.return_value = True

        result = await envelope_security_handler.should_decrypt_envelope(encrypted_envelope, test_context)

        assert result is True
        mock_security_policy.should_decrypt_envelope.assert_called_once_with(
            encrypted_envelope, test_context, envelope_security_handler._node_like
        )

    async def test_should_decrypt_envelope_standard_encryption_false(
        self, envelope_security_handler, encrypted_envelope, test_context, mock_security_policy
    ):
        """Test should_decrypt_envelope returns False when standard policy says no."""
        mock_security_policy.should_decrypt_envelope.return_value = False
        mock_security_policy.classify_message_crypto_level.return_value = CryptoLevel.PLAINTEXT

        result = await envelope_security_handler.should_decrypt_envelope(encrypted_envelope, test_context)

        assert result is False

    async def test_should_decrypt_envelope_channel_encryption_true(
        self, envelope_security_handler, encrypted_envelope, test_context, mock_security_policy
    ):
        """Test should_decrypt_envelope returns True for channel encryption."""
        mock_security_policy.should_decrypt_envelope.return_value = False
        mock_security_policy.classify_message_crypto_level.return_value = CryptoLevel.CHANNEL

        result = await envelope_security_handler.should_decrypt_envelope(encrypted_envelope, test_context)

        assert result is True

    async def test_should_decrypt_envelope_no_encryption_manager(
        self, envelope_security_handler, encrypted_envelope, test_context, mock_security_policy
    ):
        """Test should_decrypt_envelope when no encryption manager is available."""
        envelope_security_handler._encryption_manager = None
        mock_security_policy.classify_message_crypto_level.return_value = CryptoLevel.PLAINTEXT

        result = await envelope_security_handler.should_decrypt_envelope(encrypted_envelope, test_context)

        assert result is False

    async def test_should_decrypt_envelope_no_sec_section(
        self, envelope_security_handler, test_envelope, test_context, mock_security_policy
    ):
        """Test should_decrypt_envelope with envelope that has no security section."""
        mock_security_policy.should_decrypt_envelope.return_value = False
        mock_security_policy.classify_message_crypto_level.return_value = CryptoLevel.PLAINTEXT

        result = await envelope_security_handler.should_decrypt_envelope(test_envelope, test_context)

        assert result is False

    async def test_decrypt_envelope_success(
        self, envelope_security_handler, encrypted_envelope, mock_encryption_manager
    ):
        """Test successful envelope decryption."""
        decrypted_envelope = FameEnvelope(
            id="decrypted-envelope",
            to=encrypted_envelope.to,
            frame=DataFrame(type="Data", payload={"decrypted": True}),
        )
        mock_encryption_manager.decrypt_envelope.return_value = decrypted_envelope

        result = await envelope_security_handler.decrypt_envelope(encrypted_envelope)

        assert result is decrypted_envelope
        mock_encryption_manager.decrypt_envelope.assert_called_once_with(encrypted_envelope, opts=None)

    async def test_decrypt_envelope_with_options(
        self, envelope_security_handler, encrypted_envelope, mock_encryption_manager
    ):
        """Test envelope decryption with options."""
        decryption_opts = {"decryption_key": "test-key"}
        decrypted_envelope = FameEnvelope(
            id="decrypted-envelope",
            to=encrypted_envelope.to,
            frame=DataFrame(type="Data", payload={"decrypted": True}),
        )
        mock_encryption_manager.decrypt_envelope.return_value = decrypted_envelope

        result = await envelope_security_handler.decrypt_envelope(encrypted_envelope, decryption_opts)

        assert result is decrypted_envelope
        mock_encryption_manager.decrypt_envelope.assert_called_once_with(
            encrypted_envelope, opts=decryption_opts
        )

    async def test_decrypt_envelope_no_encryption_manager(
        self, envelope_security_handler, encrypted_envelope
    ):
        """Test decrypt_envelope raises error when no encryption manager is available."""
        envelope_security_handler._encryption_manager = None

        with pytest.raises(RuntimeError, match="No encryption manager available for decryption"):
            await envelope_security_handler.decrypt_envelope(encrypted_envelope)


class TestHandleEnvelopeSecurity:
    """Test cases for handle_envelope_security method covering lines 487-601."""

    async def test_handle_envelope_security_local_origin_no_processing(
        self, envelope_security_handler, test_envelope, test_context
    ):
        """Test handle_envelope_security with LOCAL origin - should skip inbound processing."""
        result_envelope, should_continue = await envelope_security_handler.handle_envelope_security(
            test_envelope, test_context
        )

        assert result_envelope is test_envelope
        assert should_continue is True

    async def test_handle_envelope_security_crypto_level_classification(
        self, envelope_security_handler, test_envelope, mock_security_policy
    ):
        """Test crypto level classification and storage in context."""
        context = FameDeliveryContext(origin_type=DeliveryOriginType.UPSTREAM)
        context.meta = {"message-type": "request"}
        context.from_system_id = "test-system"

        mock_security_policy.classify_message_crypto_level.return_value = CryptoLevel.SEALED

        result_envelope, should_continue = await envelope_security_handler.handle_envelope_security(
            test_envelope, context
        )

        assert result_envelope is test_envelope
        assert should_continue is True
        assert context.security is not None
        assert context.security.inbound_crypto_level == CryptoLevel.SEALED

    async def test_handle_envelope_security_preserve_existing_crypto_level(
        self, envelope_security_handler, test_envelope, mock_security_policy
    ):
        """Test preserving existing crypto level when it's more secure."""
        context = FameDeliveryContext(origin_type=DeliveryOriginType.UPSTREAM)
        context.meta = {"message-type": "request"}
        context.from_system_id = "test-system"
        context.security = SecurityContext()
        context.security.inbound_crypto_level = CryptoLevel.SEALED  # More secure existing level

        mock_security_policy.classify_message_crypto_level.return_value = (
            CryptoLevel.PLAINTEXT
        )  # Less secure

        result_envelope, should_continue = await envelope_security_handler.handle_envelope_security(
            test_envelope, context
        )

        # Should preserve the more secure existing level
        assert context.security.inbound_crypto_level == CryptoLevel.SEALED

    async def test_handle_envelope_security_upgrade_crypto_level(
        self, envelope_security_handler, test_envelope, mock_security_policy
    ):
        """Test upgrading crypto level when envelope suggests higher security."""
        context = FameDeliveryContext(origin_type=DeliveryOriginType.UPSTREAM)
        context.meta = {"message-type": "request"}
        context.from_system_id = "test-system"
        context.security = SecurityContext()
        context.security.inbound_crypto_level = CryptoLevel.PLAINTEXT  # Less secure existing level

        mock_security_policy.classify_message_crypto_level.return_value = CryptoLevel.SEALED  # More secure

        result_envelope, should_continue = await envelope_security_handler.handle_envelope_security(
            test_envelope, context
        )

        # Should upgrade to the more secure level
        assert context.security.inbound_crypto_level == CryptoLevel.SEALED

    async def test_handle_envelope_security_signed_envelope_success(
        self,
        envelope_security_handler,
        mock_security_policy,
        mock_key_management_handler,
        mock_envelope_verifier,
    ):
        """Test handle_envelope_security with signed envelope that verifies successfully."""
        from naylence.fame.core.protocol.security_header import SecurityHeader, SignatureHeader

        signed_envelope = FameEnvelope(
            id="signed-envelope-123",
            to=FameAddress("test@/destination"),
            frame=DataFrame(type="Data", payload={"message": "signed"}),
        )
        signed_envelope.sec = SecurityHeader()
        signed_envelope.sec.sig = SignatureHeader(kid="test-key-id", val="test-signature")

        context = FameDeliveryContext(origin_type=DeliveryOriginType.UPSTREAM)
        context.meta = {"message-type": "request"}
        context.from_system_id = "test-system"

        mock_security_policy.classify_message_crypto_level.return_value = CryptoLevel.PLAINTEXT
        mock_key_management_handler.has_key.return_value = True
        mock_envelope_verifier.verify_envelope.return_value = True

        result_envelope, should_continue = await envelope_security_handler.handle_envelope_security(
            signed_envelope, context
        )

        assert result_envelope is signed_envelope
        assert should_continue is True
        assert context.security is not None
        assert context.security.inbound_was_signed is True

    async def test_handle_envelope_security_signed_envelope_queued(
        self, envelope_security_handler, mock_security_policy, mock_key_management_handler
    ):
        """Test handle_envelope_security with signed envelope that gets queued for missing key."""
        from naylence.fame.core.protocol.security_header import SecurityHeader, SignatureHeader

        signed_envelope = FameEnvelope(
            id="signed-envelope-123",
            to=FameAddress("test@/destination"),
            frame=DataFrame(type="Data", payload={"message": "signed"}),
        )
        signed_envelope.sec = SecurityHeader()
        signed_envelope.sec.sig = SignatureHeader(kid="test-key-id", val="test-signature")

        context = FameDeliveryContext(origin_type=DeliveryOriginType.UPSTREAM)
        context.meta = {"message-type": "request"}
        context.from_system_id = "test-system"

        mock_security_policy.classify_message_crypto_level.return_value = CryptoLevel.PLAINTEXT
        mock_key_management_handler.has_key.return_value = False
        mock_key_management_handler._pending_envelopes = {}

        result_envelope, should_continue = await envelope_security_handler.handle_envelope_security(
            signed_envelope, context
        )

        assert result_envelope is signed_envelope
        assert should_continue is False  # Envelope was queued
        assert context.security is not None
        assert context.security.inbound_was_signed is True

    async def test_handle_envelope_security_unsigned_envelope_not_required(
        self, envelope_security_handler, test_envelope, mock_security_policy
    ):
        """Test handle_envelope_security with unsigned envelope when signature not required."""
        context = FameDeliveryContext(origin_type=DeliveryOriginType.UPSTREAM)
        context.meta = {"message-type": "request"}
        context.from_system_id = "test-system"

        mock_security_policy.classify_message_crypto_level.return_value = CryptoLevel.PLAINTEXT
        mock_security_policy.is_signature_required.return_value = False

        result_envelope, should_continue = await envelope_security_handler.handle_envelope_security(
            test_envelope, context
        )

        assert result_envelope is test_envelope
        assert should_continue is True
        assert context.security is not None
        assert context.security.inbound_was_signed is False

    async def test_handle_envelope_security_unsigned_critical_frame_rejected(
        self, envelope_security_handler, mock_security_policy
    ):
        """Test handle_envelope_security rejects unsigned critical frames."""
        critical_envelope = FameEnvelope(
            id="critical-envelope-123",
            to=FameAddress("test@/destination"),
            frame=KeyRequestFrame(kid="test-key", physical_path="/test"),
        )

        context = FameDeliveryContext(origin_type=DeliveryOriginType.UPSTREAM)
        context.meta = {"message-type": "request"}
        context.from_system_id = "test-system"

        mock_security_policy.classify_message_crypto_level.return_value = CryptoLevel.PLAINTEXT
        mock_security_policy.is_signature_required.return_value = True

        result_envelope, should_continue = await envelope_security_handler.handle_envelope_security(
            critical_envelope, context
        )

        assert result_envelope is critical_envelope
        assert should_continue is False  # Critical frames must be rejected if unsigned

    async def test_handle_envelope_security_unsigned_violation_action_reject(
        self, envelope_security_handler, test_envelope, mock_security_policy
    ):
        """Test handle_envelope_security with unsigned violation action REJECT."""
        context = FameDeliveryContext(origin_type=DeliveryOriginType.UPSTREAM)
        context.meta = {"message-type": "request"}
        context.from_system_id = "test-system"

        mock_security_policy.classify_message_crypto_level.return_value = CryptoLevel.PLAINTEXT
        mock_security_policy.is_signature_required.return_value = True
        mock_security_policy.get_unsigned_violation_action.return_value = SecurityAction.REJECT

        result_envelope, should_continue = await envelope_security_handler.handle_envelope_security(
            test_envelope, context
        )

        assert result_envelope is test_envelope
        assert should_continue is False  # Should halt delivery

    async def test_handle_envelope_security_unsigned_violation_action_nack(
        self, envelope_security_handler, test_envelope, mock_security_policy
    ):
        """Test handle_envelope_security with unsigned violation action NACK."""
        context = FameDeliveryContext(origin_type=DeliveryOriginType.UPSTREAM)
        context.meta = {"message-type": "request"}
        context.from_system_id = "test-system"

        mock_security_policy.classify_message_crypto_level.return_value = CryptoLevel.PLAINTEXT
        mock_security_policy.is_signature_required.return_value = True
        mock_security_policy.get_unsigned_violation_action.return_value = SecurityAction.NACK

        result_envelope, should_continue = await envelope_security_handler.handle_envelope_security(
            test_envelope, context
        )

        assert result_envelope is test_envelope
        assert should_continue is False  # Should drop envelope

    async def test_handle_envelope_security_unsigned_violation_action_allow(
        self, envelope_security_handler, test_envelope, mock_security_policy
    ):
        """Test handle_envelope_security with unsigned violation action ALLOW."""
        context = FameDeliveryContext(origin_type=DeliveryOriginType.UPSTREAM)
        context.meta = {"message-type": "request"}
        context.from_system_id = "test-system"

        mock_security_policy.classify_message_crypto_level.return_value = CryptoLevel.PLAINTEXT
        mock_security_policy.is_signature_required.return_value = True
        mock_security_policy.get_unsigned_violation_action.return_value = SecurityAction.ALLOW

        result_envelope, should_continue = await envelope_security_handler.handle_envelope_security(
            test_envelope, context
        )

        assert result_envelope is test_envelope
        assert should_continue is True  # Should continue processing


class TestChannelHandshake:
    """Test cases for channel handshake methods covering lines 610-619, 636-667."""

    async def test_handle_channel_handshake_complete_with_encryption_manager(
        self, envelope_security_handler, mock_encryption_manager
    ):
        """Test channel handshake completion with encryption manager that supports notification."""
        mock_encryption_manager.notify_channel_established = AsyncMock()

        await envelope_security_handler.handle_channel_handshake_complete(
            "test-channel-123", "test@/destination"
        )

        mock_encryption_manager.notify_channel_established.assert_called_once_with("test-channel-123")

    async def test_handle_channel_handshake_complete_without_notification_method(
        self, envelope_security_handler, mock_encryption_manager
    ):
        """Test channel handshake completion with encryption manager that lacks notification method."""
        # Don't add the notify_channel_established method

        await envelope_security_handler.handle_channel_handshake_complete(
            "test-channel-123", "test@/destination"
        )

        # Should not raise an error, just skip notification

    async def test_handle_channel_handshake_complete_no_encryption_manager(self, envelope_security_handler):
        """Test channel handshake completion with no encryption manager."""
        envelope_security_handler._encryption_manager = None

        await envelope_security_handler.handle_channel_handshake_complete(
            "test-channel-123", "test@/destination"
        )

        # Should not raise an error

    async def test_handle_channel_handshake_failed_with_notification_method(
        self, envelope_security_handler, mock_encryption_manager
    ):
        """Test channel handshake failure with encryption manager that supports failure notification."""
        mock_encryption_manager.notify_channel_failed = AsyncMock()

        await envelope_security_handler.handle_channel_handshake_failed(
            "test-channel-123", "test@/destination", "handshake_timeout"
        )

        mock_encryption_manager.notify_channel_failed.assert_called_once_with(
            "test-channel-123", "handshake_timeout"
        )

    async def test_handle_channel_handshake_failed_without_notification_method(
        self, envelope_security_handler, mock_encryption_manager, mock_key_management_handler
    ):
        """Test channel handshake failure with encryption manager that lacks failure notification."""
        # Don't add the notify_channel_failed method - encryption manager exists but lacks the method

        await envelope_security_handler.handle_channel_handshake_failed(
            "test-channel-123", "test@/destination", "handshake_timeout"
        )

        # When encryption manager exists but lacks notify_channel_failed method,
        # no cleanup is called - it just logs and continues

    async def test_handle_channel_handshake_failed_no_encryption_manager(
        self, envelope_security_handler, mock_key_management_handler
    ):
        """Test channel handshake failure with no encryption manager."""
        envelope_security_handler._encryption_manager = None

        with patch.object(
            envelope_security_handler, "_handle_failed_channel_envelope_cleanup"
        ) as mock_cleanup:
            await envelope_security_handler.handle_channel_handshake_failed(
                "test-channel-123", "test@/destination", "handshake_timeout"
            )

        mock_cleanup.assert_called_once_with("test@/destination", "handshake_timeout")

    async def test_handle_failed_channel_envelope_cleanup(self, envelope_security_handler):
        """Test _handle_failed_channel_envelope_cleanup method."""
        # This method currently just logs, so we test it doesn't raise errors
        await envelope_security_handler._handle_failed_channel_envelope_cleanup(
            "test@/destination", "handshake_failed"
        )

        # Should complete without error


class TestEncryptionLevelHandlers:
    """Test cases for encryption level handlers covering lines 677-686, 697-751, 761-774."""

    async def test_handle_sealed_encryption_no_destination(self, envelope_security_handler, test_context):
        """Test _handle_sealed_encryption with envelope that has no destination."""
        envelope_no_dest = FameEnvelope(
            id="no-dest-envelope",
            to=None,
            frame=DataFrame(type="Data", payload={"message": "test"}),
        )

        result = await envelope_security_handler._handle_sealed_encryption(envelope_no_dest, test_context)

        assert result is True  # Continue without encryption as fallback

    async def test_handle_sealed_encryption_policy_returns_channel_options(
        self, envelope_security_handler, test_envelope, test_context, mock_security_policy
    ):
        """Test _handle_sealed_encryption when policy returns channel options."""
        channel_opts = {"encryption_type": "channel", "destination": test_envelope.to}
        mock_security_policy.get_encryption_options.return_value = channel_opts

        with patch.object(
            envelope_security_handler, "_handle_to_be_encrypted_envelope_with_options"
        ) as mock_handle:
            mock_handle.return_value = True

            result = await envelope_security_handler._handle_sealed_encryption(test_envelope, test_context)

        assert result is True
        # Should force key request by address for sealed encryption
        expected_opts = {"request_address": test_envelope.to}
        mock_handle.assert_called_once_with(test_envelope, test_context, expected_opts)

    async def test_handle_sealed_encryption_policy_returns_sealed_options(
        self, envelope_security_handler, test_envelope, test_context, mock_security_policy
    ):
        """Test _handle_sealed_encryption when policy returns sealed options."""
        sealed_opts = {"recip_kid": "recipient-key-123"}
        mock_security_policy.get_encryption_options.return_value = sealed_opts

        with patch.object(
            envelope_security_handler, "_handle_to_be_encrypted_envelope_with_options"
        ) as mock_handle:
            mock_handle.return_value = True

            result = await envelope_security_handler._handle_sealed_encryption(test_envelope, test_context)

        assert result is True
        mock_handle.assert_called_once_with(test_envelope, test_context, sealed_opts)

    async def test_handle_sealed_encryption_no_options_from_policy(
        self, envelope_security_handler, test_envelope, test_context, mock_security_policy
    ):
        """Test _handle_sealed_encryption when policy returns no options."""
        mock_security_policy.get_encryption_options.return_value = None

        with patch.object(
            envelope_security_handler, "_handle_to_be_encrypted_envelope_with_options"
        ) as mock_handle:
            mock_handle.return_value = True

            result = await envelope_security_handler._handle_sealed_encryption(test_envelope, test_context)

        assert result is True
        # Should request key by address
        expected_opts = {"request_address": test_envelope.to}
        mock_handle.assert_called_once_with(test_envelope, test_context, expected_opts)

    async def test_handle_sealed_encryption_policy_exception(
        self, envelope_security_handler, test_envelope, test_context, mock_security_policy
    ):
        """Test _handle_sealed_encryption when policy raises exception."""
        mock_security_policy.get_encryption_options.side_effect = Exception("Policy error")

        with patch.object(
            envelope_security_handler, "_handle_to_be_encrypted_envelope_with_options"
        ) as mock_handle:
            mock_handle.return_value = True

            result = await envelope_security_handler._handle_sealed_encryption(test_envelope, test_context)

        assert result is True
        # Should fallback to key request by address
        expected_opts = {"request_address": test_envelope.to}
        mock_handle.assert_called_once_with(test_envelope, test_context, expected_opts)

    async def test_handle_channel_encryption_no_destination(self, envelope_security_handler, test_context):
        """Test _handle_channel_encryption with envelope that has no destination."""
        envelope_no_dest = FameEnvelope(
            id="no-dest-envelope",
            to=None,
            frame=DataFrame(type="Data", payload={"message": "test"}),
        )

        result = await envelope_security_handler._handle_channel_encryption(envelope_no_dest, test_context)

        assert result is True  # Continue without encryption as fallback

    async def test_handle_channel_encryption_success(
        self, envelope_security_handler, test_envelope, test_context
    ):
        """Test _handle_channel_encryption success."""
        with patch.object(
            envelope_security_handler, "_handle_to_be_encrypted_envelope_with_options"
        ) as mock_handle:
            mock_handle.return_value = True

            result = await envelope_security_handler._handle_channel_encryption(test_envelope, test_context)

        assert result is True
        expected_opts = {
            "encryption_type": "channel",
            "destination": test_envelope.to,
        }
        mock_handle.assert_called_once_with(test_envelope, test_context, expected_opts)


class TestOutboundSecurityCryptoLevels:
    """Test cases for outbound security crypto level handling covering remaining lines."""

    async def test_handle_outbound_security_already_encrypted_skip(
        self,
        envelope_security_handler,
        test_envelope,
        test_context,
        mock_encryption_manager,
        mock_security_policy,
    ):
        """Test outbound security skips encryption if envelope is already encrypted."""
        from naylence.fame.core.protocol.security_header import EncryptionHeader, SecurityHeader

        # Set up envelope as already encrypted
        test_envelope.sec = SecurityHeader()
        test_envelope.sec.enc = EncryptionHeader(val="already-encrypted")

        mock_security_policy.should_encrypt_envelope.return_value = True
        mock_security_policy.decide_outbound_crypto_level.return_value = CryptoLevel.SEALED

        result = await envelope_security_handler.handle_outbound_security(test_envelope, test_context)

        assert result is True
        mock_encryption_manager.encrypt_envelope.assert_not_called()

    async def test_handle_outbound_security_response_crypto_level(
        self, envelope_security_handler, test_envelope, mock_encryption_manager, mock_security_policy
    ):
        """Test outbound security with response envelope using response crypto policy."""
        context = FameDeliveryContext(origin_type=DeliveryOriginType.LOCAL)
        context.meta = {"message-type": "response", "response-to-id": "original-request-123"}
        context.security = SecurityContext()
        context.security.inbound_crypto_level = CryptoLevel.CHANNEL

        mock_security_policy.should_encrypt_envelope.return_value = False
        mock_security_policy.decide_response_crypto_level.return_value = CryptoLevel.SEALED

        with patch.object(envelope_security_handler, "_handle_sealed_encryption") as mock_sealed:
            mock_sealed.return_value = True

            result = await envelope_security_handler.handle_outbound_security(test_envelope, context)

        assert result is True
        mock_security_policy.decide_response_crypto_level.assert_called_once_with(
            CryptoLevel.CHANNEL, test_envelope, context
        )
        mock_sealed.assert_called_once_with(test_envelope, context)

    async def test_handle_outbound_security_plaintext_level(
        self,
        envelope_security_handler,
        test_envelope,
        test_context,
        mock_encryption_manager,
        mock_security_policy,
    ):
        """Test outbound security with plaintext crypto level."""
        mock_security_policy.should_encrypt_envelope.return_value = False
        mock_security_policy.decide_outbound_crypto_level.return_value = CryptoLevel.PLAINTEXT

        result = await envelope_security_handler.handle_outbound_security(test_envelope, test_context)

        assert result is True
        mock_encryption_manager.encrypt_envelope.assert_not_called()
