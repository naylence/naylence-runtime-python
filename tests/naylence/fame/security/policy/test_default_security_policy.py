"""
Comprehensive tests for DefaultSecurityPolicy covering largest coverage gaps systematically.

This test suite follows the proven largest-gap-first methodology used successfully
for logicals_util and key_management_handler coverage improvements.

Current coverage: 58.54% (202/326 statements)
Target gaps (largest first):
1. Lines 297-346 (50 lines) - _lookup_recipient_encryption_key method
2. Lines 237-267 (31 lines) - get_encryption_options method
3. Lines 406-435 (30 lines) - decide_outbound_crypto_level method
4. Lines 495-518 (24 lines) - _should_sign_response method
5. Remaining smaller gaps for comprehensive coverage
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from naylence.fame.core import (
    DataFrame,
    DeliveryOriginType,
    FameAddress,
)
from naylence.fame.core.protocol.frames import (
    KeyAnnounceFrame,
    KeyRequestFrame,
    NodeAttachFrame,
    NodeHeartbeatFrame,
    SecureOpenFrame,
)
from naylence.fame.security.policy.default_security_policy import DefaultSecurityPolicy
from naylence.fame.security.policy.security_policy import (
    CryptoLevel,
    EncryptionConfig,
    SignaturePolicy,
    SigningConfig,
    SigningMaterial,
)


class TestDefaultSecurityPolicyLargestGaps:
    """Test the largest coverage gaps in DefaultSecurityPolicy - lines 297-346 (50 lines)"""

    @pytest.fixture
    def mock_key_provider(self):
        """Create mock key provider for testing."""
        provider = MagicMock()
        provider.get_keys_for_path = AsyncMock(return_value=[])
        return provider

    @pytest.fixture
    def policy_with_key_provider(self, mock_key_provider):
        """Create policy with mock key provider."""
        return DefaultSecurityPolicy(key_provider=mock_key_provider)

    @pytest.fixture
    def mock_node_like(self):
        """Create mock node_like object."""
        node = MagicMock()
        node.physical_path = "/test/node/path"
        node.has_local = MagicMock(return_value=False)
        return node

    @pytest.fixture
    def test_address(self):
        """Create test FameAddress."""
        return FameAddress("testparticipant@/path/to/service")

    @pytest.mark.asyncio
    async def test_lookup_recipient_encryption_key_no_address(self, policy_with_key_provider):
        """Test _lookup_recipient_encryption_key with no address - covers lines 297-299"""
        with pytest.raises(ValueError, match="No recipient address in envelope"):
            await policy_with_key_provider._lookup_recipient_encryption_key(None, "/test/path")

    @pytest.mark.asyncio
    async def test_lookup_recipient_encryption_key_no_key_provider(self):
        """Test _lookup_recipient_encryption_key without key provider - covers line 301"""
        policy = DefaultSecurityPolicy()  # No key provider
        test_address = FameAddress("testparticipant@/path")

        with pytest.raises(AssertionError, match="Key provider must be set"):
            await policy._lookup_recipient_encryption_key(test_address, "/test/path")

    @pytest.mark.asyncio
    async def test_lookup_recipient_encryption_key_parsing_and_logging(
        self, policy_with_key_provider, test_address
    ):
        """Test address parsing and initial logging - covers lines 304-314"""
        with patch("naylence.fame.core.address.address.parse_address") as mock_parse:
            mock_parse.return_value = ("test.participant", "/path/to/service")

            # Should fail because no keys found, but covers parsing logic
            with pytest.raises(ValueError, match="No encryption key found"):
                await policy_with_key_provider._lookup_recipient_encryption_key(
                    test_address, "/test/node/path"
                )

            mock_parse.assert_called_once_with(str(test_address))

    @pytest.mark.asyncio
    async def test_lookup_recipient_encryption_key_no_participant(
        self, policy_with_key_provider, test_address
    ):
        """Test handling of addresses with no participant - covers lines 315-317"""
        with patch("naylence.fame.core.address.address.parse_address") as mock_parse:
            mock_parse.return_value = (None, "/path/to/service")  # No participant

            with pytest.raises(ValueError, match="Cannot determine participant from address"):
                await policy_with_key_provider._lookup_recipient_encryption_key(
                    test_address, "/test/node/path"
                )

    @pytest.mark.asyncio
    async def test_lookup_recipient_encryption_key_local_address_crypto_provider(
        self, policy_with_key_provider, test_address
    ):
        """Test key provider path when address doesn't match node path - covers lines 274-346"""
        # This test covers the case where we go through key provider instead of crypto provider
        # Since our mocks show get_crypto_provider is NOT called, we're testing the key provider branch

        mock_key = {
            "kid": "test-crypto-kid",
            "kty": "OKP",
            "crv": "X25519",
            "use": "enc",
            "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",  # Base64 for 32 zero bytes
        }

        # Mock the key provider to return our test key
        mock_key_provider = AsyncMock()
        mock_key_provider.get_keys_for_path.return_value = iter([mock_key])
        policy_with_key_provider._key_provider = mock_key_provider

        with patch("naylence.fame.security.crypto.jwk_validation.validate_encryption_key") as mock_validate:
            # Make validation pass
            mock_validate.return_value = None

            kid, pub_bytes = await policy_with_key_provider._lookup_recipient_encryption_key(
                test_address, "/different/node/path"
            )

            # Should get the key from the key provider path
            assert kid == "test-crypto-kid"
            assert len(pub_bytes) == 32  # X25519 key should be 32 bytes

    @pytest.mark.asyncio
    async def test_lookup_recipient_encryption_key_local_address_crypto_error(
        self, policy_with_key_provider, test_address
    ):
        """Test local address crypto provider extraction error - covers lines 346-348"""
        with patch("naylence.fame.core.address.address.parse_address") as mock_parse:
            with patch(
                "naylence.fame.security.crypto.providers.crypto_provider.get_crypto_provider"
            ) as mock_get_crypto:
                mock_parse.return_value = ("test.participant", "/test/node/path")

                mock_crypto = MagicMock()
                mock_crypto.encryption_public_pem = "invalid_pem_data"
                mock_get_crypto.return_value = mock_crypto

                # Mock cryptography to raise error
                with patch(
                    "cryptography.hazmat.primitives.serialization.load_pem_public_key"
                ) as mock_load_pem:
                    mock_load_pem.side_effect = Exception("Invalid PEM")

                    # Should fall through to key store lookup, which will fail
                    with pytest.raises(ValueError, match="No encryption key found"):
                        await policy_with_key_provider._lookup_recipient_encryption_key(
                            test_address, "/test/node/path"
                        )

    @pytest.mark.asyncio
    async def test_lookup_recipient_encryption_key_address_keys_found(
        self, policy_with_key_provider, test_address
    ):
        """Test finding keys by address string - covers lines 354-360"""
        # Mock key provider to return encryption key
        encryption_key = {
            "kid": "test-encryption-key",
            "use": "enc",
            "kty": "OKP",
            "crv": "X25519",
            "x": "test_x_value_with_padding",  # Will be padded
        }
        policy_with_key_provider._key_provider.get_keys_for_path.return_value = [encryption_key]

        with patch("naylence.fame.core.address.address.parse_address") as mock_parse:
            with patch(
                "naylence.fame.security.crypto.jwk_validation.validate_encryption_key"
            ) as mock_validate:
                with patch("base64.urlsafe_b64decode") as mock_b64decode:
                    mock_parse.return_value = ("test.participant", "/different/path")  # Not local
                    mock_b64decode.return_value = b"decoded_public_key"

                    kid, pub_bytes = await policy_with_key_provider._lookup_recipient_encryption_key(
                        test_address, "/test/node/path"
                    )

                    assert kid == "test-encryption-key"
                    assert pub_bytes == b"decoded_public_key"

                    # Should call get_keys_for_path with address string
                    policy_with_key_provider._key_provider.get_keys_for_path.assert_called_with(
                        str(test_address)
                    )
                    mock_validate.assert_called_once_with(encryption_key)

    @pytest.mark.asyncio
    async def test_lookup_recipient_encryption_key_path_fallback(
        self, policy_with_key_provider, test_address
    ):
        """Test fallback to path keys when address keys not found - covers lines 362-367"""
        # First call (by address) returns empty, second call (by path) returns key
        encryption_key = {
            "kid": "path-encryption-key",
            "use": "enc",
            "kty": "OKP",
            "crv": "X25519",
            "x": "path_key_x_value",
        }

        async def mock_get_keys_side_effect(path):
            if path == str(test_address):
                return []  # No keys for full address
            elif path == "/path/to/service":
                return [encryption_key]  # Key found for path
            return []

        policy_with_key_provider._key_provider.get_keys_for_path.side_effect = mock_get_keys_side_effect

        with patch("naylence.fame.core.address.address.parse_address") as mock_parse:
            with patch("naylence.fame.security.crypto.jwk_validation.validate_encryption_key"):
                with patch("base64.urlsafe_b64decode", return_value=b"path_key_bytes"):
                    mock_parse.return_value = ("test.participant", "/path/to/service")

                    kid, pub_bytes = await policy_with_key_provider._lookup_recipient_encryption_key(
                        test_address, "/test/node/path"
                    )

                    assert kid == "path-encryption-key"
                    assert pub_bytes == b"path_key_bytes"

    @pytest.mark.asyncio
    async def test_lookup_recipient_encryption_key_participant_fallback(
        self, policy_with_key_provider, test_address
    ):
        """Test fallback to participant keys - covers lines 369-376"""
        participant_key = {
            "kid": "participant-key",
            "use": "enc",
            "kty": "OKP",
            "crv": "X25519",
            "x": "participant_x_value",
        }

        async def mock_get_keys_side_effect(path):
            if path == "test.participant":
                return [participant_key]
            return []

        policy_with_key_provider._key_provider.get_keys_for_path.side_effect = mock_get_keys_side_effect

        with patch("naylence.fame.core.address.address.parse_address") as mock_parse:
            with patch("naylence.fame.security.crypto.jwk_validation.validate_encryption_key"):
                with patch("base64.urlsafe_b64decode", return_value=b"participant_key_bytes"):
                    mock_parse.return_value = ("test.participant", "/path/to/service")

                    kid, pub_bytes = await policy_with_key_provider._lookup_recipient_encryption_key(
                        test_address, "/test/node/path"
                    )

                    assert kid == "participant-key"
                    assert pub_bytes == b"participant_key_bytes"

    @pytest.mark.asyncio
    async def test_lookup_recipient_encryption_key_invalid_key_validation(
        self, policy_with_key_provider, test_address
    ):
        """Test handling of invalid encryption keys - covers lines 389-392"""
        invalid_key = {"kid": "invalid-key", "use": "enc", "kty": "OKP", "crv": "X25519", "x": "invalid_x"}
        policy_with_key_provider._key_provider.get_keys_for_path.return_value = [invalid_key]

        with patch("naylence.fame.core.address.address.parse_address") as mock_parse:
            with patch(
                "naylence.fame.security.crypto.jwk_validation.validate_encryption_key"
            ) as mock_validate:
                from naylence.fame.security.crypto.jwk_validation import JWKValidationError

                mock_parse.return_value = ("test.participant", "/different/path")
                mock_validate.side_effect = JWKValidationError("Invalid key")

                with pytest.raises(ValueError, match="No encryption key found"):
                    await policy_with_key_provider._lookup_recipient_encryption_key(
                        test_address, "/test/node/path"
                    )

    @pytest.mark.asyncio
    async def test_lookup_recipient_encryption_key_missing_x_parameter(
        self, policy_with_key_provider, test_address
    ):
        """Test handling of encryption key missing x parameter - covers lines 395-398"""
        key_missing_x = {
            "kid": "key-no-x",
            "use": "enc",
            "kty": "OKP",
            "crv": "X25519",
            # Missing "x" parameter
        }
        policy_with_key_provider._key_provider.get_keys_for_path.return_value = [key_missing_x]

        with patch("naylence.fame.core.address.address.parse_address") as mock_parse:
            with patch("naylence.fame.security.crypto.jwk_validation.validate_encryption_key"):
                mock_parse.return_value = ("test.participant", "/different/path")

                with pytest.raises(ValueError, match="No encryption key found"):
                    await policy_with_key_provider._lookup_recipient_encryption_key(
                        test_address, "/test/node/path"
                    )

    @pytest.mark.asyncio
    async def test_lookup_recipient_encryption_key_unsupported_key_type(
        self, policy_with_key_provider, test_address
    ):
        """Test handling of unsupported key types - covers lines 406-413"""
        unsupported_key = {
            "kid": "unsupported-key",
            "use": "enc",
            "kty": "RSA",  # Not OKP
            "crv": "P-256",  # Not X25519
        }
        policy_with_key_provider._key_provider.get_keys_for_path.return_value = [unsupported_key]

        with patch("naylence.fame.core.address.address.parse_address") as mock_parse:
            with patch("naylence.fame.security.crypto.jwk_validation.validate_encryption_key"):
                mock_parse.return_value = ("test.participant", "/different/path")

                with pytest.raises(ValueError, match="No encryption key found"):
                    await policy_with_key_provider._lookup_recipient_encryption_key(
                        test_address, "/test/node/path"
                    )

    @pytest.mark.asyncio
    async def test_lookup_recipient_encryption_key_non_encryption_use(
        self, policy_with_key_provider, test_address
    ):
        """Test skipping keys not marked for encryption - covers lines 416-417"""
        signing_key = {
            "kid": "signing-key",
            "use": "sig",  # Not "enc"
            "kty": "OKP",
            "crv": "Ed25519",
        }
        policy_with_key_provider._key_provider.get_keys_for_path.return_value = [signing_key]

        with patch("naylence.fame.core.address.address.parse_address") as mock_parse:
            mock_parse.return_value = ("test.participant", "/different/path")

            with pytest.raises(ValueError, match="No encryption key found"):
                await policy_with_key_provider._lookup_recipient_encryption_key(
                    test_address, "/test/node/path"
                )

    @pytest.mark.asyncio
    async def test_lookup_recipient_encryption_key_final_error_handling(
        self, policy_with_key_provider, test_address
    ):
        """Test final error handling and re-raising - covers lines 418-435"""
        with patch("naylence.fame.core.address.address.parse_address") as mock_parse:
            mock_parse.side_effect = Exception("Address parsing failed")

            with pytest.raises(ValueError, match="Failed to lookup recipient key"):
                await policy_with_key_provider._lookup_recipient_encryption_key(
                    test_address, "/test/node/path"
                )


class TestGetEncryptionOptionsLargestGap:
    """Test get_encryption_options method - second largest gap (lines 237-267, 31 lines)"""

    @pytest.fixture
    def policy(self):
        """Create default security policy."""
        return DefaultSecurityPolicy()

    @pytest.fixture
    def mock_node_like(self):
        """Create mock node_like."""
        node = MagicMock()
        node.physical_path = "/test/node/path"
        return node

    @pytest.fixture
    def test_envelope(self):
        """Create test envelope with recipient."""
        envelope = MagicMock()
        envelope.id = "test-env-id"
        envelope.to = FameAddress("recipient@test.com/service")
        return envelope

    @pytest.fixture
    def test_context(self):
        """Create test delivery context."""
        context = MagicMock()
        context.meta = {"message-type": "request"}
        context.security = MagicMock()
        context.security.inbound_crypto_level = CryptoLevel.PLAINTEXT
        context.origin_type = DeliveryOriginType.LOCAL
        return context

    @pytest.mark.asyncio
    async def test_get_encryption_options_no_recipient(self, policy):
        """Test get_encryption_options with no recipient - covers lines 237-240"""
        envelope = MagicMock()
        envelope.id = "test-env-id"
        envelope.to = None  # No recipient

        result = await policy.get_encryption_options(envelope, None, None)
        assert result is None

    @pytest.mark.asyncio
    async def test_get_encryption_options_channel_encryption(
        self, policy, test_envelope, test_context, mock_node_like
    ):
        """Test get_encryption_options with channel encryption - covers lines 242-259"""
        with patch.object(policy, "_should_use_channel_encryption_internal", return_value=True):
            result = await policy.get_encryption_options(test_envelope, test_context, mock_node_like)

            expected = {"encryption_type": "channel", "destination": test_envelope.to}
            assert result == expected

    @pytest.mark.asyncio
    async def test_get_encryption_options_successful_key_lookup(
        self, policy, test_envelope, test_context, mock_node_like
    ):
        """Test successful encryption key lookup - covers lines 261-267"""
        with patch.object(policy, "_should_use_channel_encryption_internal", return_value=False):
            with patch.object(
                policy, "_lookup_recipient_encryption_key", return_value=("test-kid", b"test_key_bytes")
            ):
                result = await policy.get_encryption_options(test_envelope, test_context, mock_node_like)

                # EncryptionOptions is a TypedDict, check the structure instead
                assert isinstance(result, dict)
                assert result["recip_kid"] == "test-kid"
                assert result["recip_pub"] == b"test_key_bytes"

    @pytest.mark.asyncio
    async def test_get_encryption_options_key_lookup_failure(
        self, policy, test_envelope, test_context, mock_node_like
    ):
        """Test encryption key lookup failure - returns address-based request - covers lines 268-275"""
        with patch.object(policy, "_should_use_channel_encryption_internal", return_value=False):
            with patch.object(
                policy, "_lookup_recipient_encryption_key", side_effect=Exception("Key not found")
            ):
                result = await policy.get_encryption_options(test_envelope, test_context, mock_node_like)

                expected = {"request_address": test_envelope.to}
                assert result == expected


class TestDecideOutboundCryptoLevelLargestGap:
    """Test decide_outbound_crypto_level method - third largest gap (lines 406-435, 30 lines)"""

    @pytest.fixture
    def policy(self):
        """Create policy with outbound encryption config."""
        encryption_config = EncryptionConfig.for_development()
        encryption_config.outbound.default_level = CryptoLevel.PLAINTEXT
        encryption_config.outbound.escalate_if_peer_supports = False
        encryption_config.outbound.prefer_sealed_for_sensitive = False

        return DefaultSecurityPolicy(encryption=encryption_config)

    @pytest.fixture
    def data_envelope(self):
        """Create DataFrame envelope."""
        envelope = MagicMock()
        envelope.frame = DataFrame(payload=b"test data")
        envelope.to = FameAddress("recipient@test.com")
        return envelope

    @pytest.fixture
    def non_data_envelope(self):
        """Create non-DataFrame envelope."""
        envelope = MagicMock()
        envelope.frame = MagicMock()
        envelope.frame.type = "Control"
        return envelope

    @pytest.mark.asyncio
    async def test_decide_outbound_crypto_level_non_data_frame(self, policy, non_data_envelope):
        """Test outbound crypto level for non-DataFrame - covers lines 406-408"""
        result = await policy.decide_outbound_crypto_level(non_data_envelope, None, None)
        assert result == CryptoLevel.PLAINTEXT

    @pytest.mark.asyncio
    async def test_decide_outbound_crypto_level_default_level(self, policy, data_envelope):
        """Test using default outbound crypto level - covers lines 410-413"""
        result = await policy.decide_outbound_crypto_level(data_envelope, None, None)
        assert result == CryptoLevel.PLAINTEXT  # Default configured level

    @pytest.mark.asyncio
    async def test_decide_outbound_crypto_level_escalate_if_peer_supports(self, policy, data_envelope):
        """Test escalation when peer supports encryption - covers lines 415-424"""
        # Configure policy to escalate if peer supports
        policy.encryption.outbound.escalate_if_peer_supports = True

        mock_node = MagicMock()
        mock_node.physical_path = "/test/path"

        with patch.object(
            policy, "_lookup_recipient_encryption_key", return_value=("key-id", b"key_bytes")
        ):
            result = await policy.decide_outbound_crypto_level(data_envelope, None, mock_node)
            assert result == CryptoLevel.SEALED  # Escalated due to peer support

    @pytest.mark.asyncio
    async def test_decide_outbound_crypto_level_escalate_peer_no_key(self, policy, data_envelope):
        """Test escalation attempt when peer has no key - covers lines 415-427"""
        # Configure policy to escalate if peer supports
        policy.encryption.outbound.escalate_if_peer_supports = True

        mock_node = MagicMock()
        mock_node.physical_path = "/test/path"

        with patch.object(policy, "_lookup_recipient_encryption_key", side_effect=Exception("No key")):
            result = await policy.decide_outbound_crypto_level(data_envelope, None, mock_node)
            assert result == CryptoLevel.PLAINTEXT  # Fallback to default

    @pytest.mark.asyncio
    async def test_decide_outbound_crypto_level_prefer_sealed_for_sensitive(self, policy, data_envelope):
        """Test preferring sealed for sensitive operations - covers lines 429-435"""
        # Configure policy to prefer sealed for sensitive operations
        policy.encryption.outbound.prefer_sealed_for_sensitive = True

        with patch.object(policy, "_is_sensitive_operation", return_value=True):
            result = await policy.decide_outbound_crypto_level(data_envelope, None, None)
            assert result == CryptoLevel.SEALED  # Escalated due to sensitive operation

    @pytest.mark.asyncio
    async def test_decide_outbound_crypto_level_not_sensitive_operation(self, policy, data_envelope):
        """Test non-sensitive operations maintain default level - covers lines 429-435"""
        # Configure policy to prefer sealed for sensitive operations
        policy.encryption.outbound.prefer_sealed_for_sensitive = True

        with patch.object(policy, "_is_sensitive_operation", return_value=False):
            result = await policy.decide_outbound_crypto_level(data_envelope, None, None)
            assert result == CryptoLevel.PLAINTEXT  # Default level maintained


class TestShouldSignResponseLargestGap:
    """Test _should_sign_response method gaps - fourth largest gap (lines 495-518, 24 lines)"""

    @pytest.fixture
    def policy(self):
        """Create policy with response signing config."""
        signing_config = SigningConfig.for_development()
        signing_config.response.always_sign_responses = False
        signing_config.response.sign_error_responses = False
        signing_config.response.mirror_request_signing = False

        return DefaultSecurityPolicy(signing=signing_config)

    @pytest.fixture
    def test_envelope(self):
        """Create test envelope."""
        envelope = MagicMock()
        envelope.id = "response-env-id"
        return envelope

    @pytest.fixture
    def test_context_with_security(self):
        """Create context with security information."""
        context = MagicMock()
        context.security = MagicMock()
        context.security.inbound_was_signed = True
        context.security.inbound_crypto_level = CryptoLevel.SEALED
        return context

    def test_should_sign_response_always_sign_enabled(self, policy, test_envelope):
        """Test always sign responses setting - covers lines 495-497"""
        policy.signing.response.always_sign_responses = True

        result = policy._should_sign_response(test_envelope, None, None)
        assert result is True

    def test_should_sign_response_sign_error_responses_enabled(self, policy, test_envelope):
        """Test sign error responses setting - covers lines 499-503"""
        policy.signing.response.sign_error_responses = True

        with patch.object(policy, "_is_error_response", return_value=True):
            result = policy._should_sign_response(test_envelope, None, None)
            assert result is True

    def test_should_sign_response_not_error_response(self, policy, test_envelope):
        """Test non-error response with sign_error_responses enabled - covers lines 499-503"""
        policy.signing.response.sign_error_responses = True

        with patch.object(policy, "_is_error_response", return_value=False):
            result = policy._should_sign_response(test_envelope, None, None)
            assert result is False

    def test_should_sign_response_mirror_request_signing_explicit_flag(
        self, policy, test_envelope, test_context_with_security
    ):
        """Test mirroring when explicit inbound_was_signed flag is set - covers lines 505-518"""
        policy.signing.response.mirror_request_signing = True

        result = policy._should_sign_response(test_envelope, test_context_with_security, None)
        assert result is True

    def test_should_sign_response_mirror_request_signing_crypto_fallback(self, policy, test_envelope):
        """Test mirroring fallback to crypto level when explicit flag unavailable - covers lines 505-518"""
        policy.signing.response.mirror_request_signing = True

        context = MagicMock()
        context.security = MagicMock()
        # No inbound_was_signed attribute, fallback to crypto level
        context.security.inbound_crypto_level = CryptoLevel.SEALED  # Non-plaintext indicates security

        # Remove inbound_was_signed to test fallback
        del context.security.inbound_was_signed

        result = policy._should_sign_response(test_envelope, context, None)
        assert result is True

    def test_should_sign_response_mirror_plaintext_request(self, policy, test_envelope):
        """Test mirroring plaintext request doesn't require signing - covers lines 505-518"""
        policy.signing.response.mirror_request_signing = True

        context = MagicMock()
        context.security = MagicMock()
        context.security.inbound_crypto_level = CryptoLevel.PLAINTEXT
        del context.security.inbound_was_signed  # Test fallback path

        result = policy._should_sign_response(test_envelope, context, None)
        assert result is False

    def test_should_sign_response_no_context_security(self, policy, test_envelope):
        """Test behavior with no context security - covers lines 505-518"""
        policy.signing.response.mirror_request_signing = True

        context = MagicMock()
        context.security = None  # No security context

        result = policy._should_sign_response(test_envelope, context, None)
        assert result is False

    def test_should_sign_response_no_context(self, policy, test_envelope):
        """Test behavior with no context at all - covers lines 505-518"""
        policy.signing.response.mirror_request_signing = True

        result = policy._should_sign_response(test_envelope, None, None)
        assert result is False


class TestRemainingSmallGaps:
    """Test remaining smaller coverage gaps for comprehensive coverage."""

    @pytest.fixture
    def policy(self):
        """Create default security policy."""
        return DefaultSecurityPolicy()

    def test_is_sensitive_operation_default_implementation(self, policy):
        """Test _is_sensitive_operation default implementation - covers lines 458-463"""
        envelope = MagicMock()
        result = policy._is_sensitive_operation(envelope)
        assert result is False  # Default implementation returns False

    def test_is_error_response_error_frame_type(self, policy):
        """Test _is_error_response with Error frame type - covers lines 467-468"""
        envelope = MagicMock()
        envelope.frame = MagicMock()
        envelope.frame.type = "Error"

        result = policy._is_error_response(envelope)
        assert result is True

    def test_is_error_response_non_error_frame(self, policy):
        """Test _is_error_response with non-error frame - covers lines 474"""
        envelope = MagicMock()
        envelope.frame = MagicMock()
        envelope.frame.type = "Data"

        result = policy._is_error_response(envelope)
        assert result is False

    def test_is_error_response_no_frame(self, policy):
        """Test _is_error_response with no frame - covers lines 474"""
        envelope = MagicMock()
        envelope.frame = None

        result = policy._is_error_response(envelope)
        assert result is False


class TestAdditionalCoverage:
    """Test additional methods for comprehensive coverage improvement."""

    @pytest.fixture
    def policy(self):
        """Create policy with custom configurations."""
        encryption_config = EncryptionConfig.for_development()
        signing_config = SigningConfig.for_development()
        return DefaultSecurityPolicy(encryption=encryption_config, signing=signing_config)

    def test_should_sign_envelope_already_signed(self, policy):
        """Test should_sign_envelope when envelope already signed."""
        envelope = MagicMock()
        envelope.sec = MagicMock()
        envelope.sec.sig = MagicMock()  # Already has signature

        result = asyncio.run(policy.should_sign_envelope(envelope, None, None))
        assert result is False

    def test_should_encrypt_envelope_non_local_origin(self, policy):
        """Test should_encrypt_envelope security check for non-local origins."""
        envelope = MagicMock()
        context = MagicMock()
        context.origin_type = DeliveryOriginType.UPSTREAM  # Not LOCAL

        result = asyncio.run(policy.should_encrypt_envelope(envelope, context, None))
        assert result is False

    def test_should_encrypt_envelope_already_encrypted(self, policy):
        """Test should_encrypt_envelope when already encrypted."""
        envelope = MagicMock()
        envelope.sec = MagicMock()
        envelope.sec.enc = MagicMock()  # Already encrypted

        context = MagicMock()
        context.origin_type = DeliveryOriginType.LOCAL

        result = asyncio.run(policy.should_encrypt_envelope(envelope, context, None))
        assert result is False

    def test_classify_message_crypto_level_channel_algorithm(self, policy):
        """Test classify_message_crypto_level with channel algorithm."""
        envelope = MagicMock()
        envelope.id = "test-env"
        envelope.sec = MagicMock()
        envelope.sec.enc = MagicMock()
        envelope.sec.enc.alg = "ChaCha20Poly1305"  # Channel algorithm

        # Configure policy to recognize this as channel algorithm
        policy.encryption.supported_channel_algorithms = ["ChaCha20Poly1305"]
        policy.encryption.supported_sealed_algorithms = ["X25519"]

        result = policy.classify_message_crypto_level(envelope, None)
        assert result == CryptoLevel.CHANNEL

    def test_classify_message_crypto_level_unknown_algorithm(self, policy):
        """Test classify_message_crypto_level with unknown algorithm."""
        envelope = MagicMock()
        envelope.id = "test-env"
        envelope.sec = MagicMock()
        envelope.sec.enc = MagicMock()
        envelope.sec.enc.alg = "UnknownAlgorithm"

        policy.encryption.supported_channel_algorithms = ["ChaCha20Poly1305"]
        policy.encryption.supported_sealed_algorithms = ["X25519"]

        result = policy.classify_message_crypto_level(envelope, None)
        assert result == CryptoLevel.SEALED  # Defaults to sealed for safety

    def test_is_signature_required_critical_security_frames(self, policy):
        """Test is_signature_required for critical security frames."""
        # Test KeyRequestFrame
        envelope = MagicMock()
        envelope.frame = KeyRequestFrame(kid="test-kid")

        result = policy.is_signature_required(envelope, None)
        assert result is True

        # Test KeyAnnounceFrame
        envelope.frame = KeyAnnounceFrame(physical_path="/test", keys=[])
        result = policy.is_signature_required(envelope, None)
        assert result is True

        # Test SecureOpenFrame
        envelope.frame = SecureOpenFrame(cid="test-cid", ephPub=b"x" * 32)  # 32 bytes minimum
        result = policy.is_signature_required(envelope, None)
        assert result is True

    def test_is_signature_required_node_frames_no_requirement(self, policy):
        """Test is_signature_required for node frames that don't require signatures."""
        envelope = MagicMock()
        envelope.frame = NodeAttachFrame(systemId="test-system", instanceId="test-instance")

        result = policy.is_signature_required(envelope, None)
        assert result is False

        envelope.frame = NodeHeartbeatFrame()
        result = policy.is_signature_required(envelope, None)
        assert result is False

    def test_requirements_comprehensive_analysis(self, policy):
        """Test requirements method comprehensive analysis."""
        # Configure policy to require various capabilities
        policy.signing.outbound.default_signing = True
        policy.signing.inbound.signature_policy = SignaturePolicy.REQUIRED
        policy.encryption.outbound.default_level = CryptoLevel.SEALED
        policy.encryption.inbound.allow_sealed = True
        policy.encryption.inbound.allow_plaintext = False  # Disable plaintext to change minimum level
        policy.signing.signing_material = SigningMaterial.X509_CHAIN

        requirements = policy.requirements()

        assert requirements.signing_required is True
        assert requirements.verification_required is True
        assert requirements.encryption_required is True
        assert requirements.decryption_required is True
        assert requirements.require_key_exchange is True
        assert requirements.require_signing_key_exchange is True
        assert requirements.require_encryption_key_exchange is True
        assert requirements.require_certificates is True
        assert requirements.minimum_crypto_level != CryptoLevel.PLAINTEXT
