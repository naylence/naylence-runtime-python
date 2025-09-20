"""Tests for DefaultCryptoProvider focusing on uncovered lines and functionality."""

import base64
from unittest.mock import Mock, patch

import pytest

from naylence.fame.security.crypto.providers.default_crypto_provider import (
    DefaultCryptoProvider,
)


class TestDefaultCryptoProviderInitialization:
    """Test initialization paths and key generation."""

    def test_initialization_with_rsa_algorithm(self):
        """Test RSA key generation path (lines 59-66)."""
        with (
            patch("os.getenv", return_value="RSA"),
            patch(
                "naylence.fame.security.crypto.key_factories.rsa_key_factory.create_rsa_keypair"
            ) as mock_rsa,
        ):
            mock_keypair = Mock()
            mock_keypair.private_pem = "-----BEGIN PRIVATE KEY-----\nRSA_PRIVATE\n-----END PRIVATE KEY-----"
            mock_keypair.public_pem = "-----BEGIN PUBLIC KEY-----\nRSA_PUBLIC\n-----END PUBLIC KEY-----"
            mock_rsa.return_value = mock_keypair

            provider = DefaultCryptoProvider(algorithm="RSA")

            assert provider.signing_private_pem == mock_keypair.private_pem
            assert provider.signing_public_pem == mock_keypair.public_pem
            mock_rsa.assert_called_once()

    def test_initialization_with_invalid_algorithm(self):
        """Test invalid algorithm error path (line 96)."""
        with pytest.raises(ValueError, match="Invalid key algorithm: INVALID"):
            DefaultCryptoProvider(algorithm="INVALID")

    def test_initialization_with_user_provided_signature_keys(self):
        """Test initialization with user-provided signature keys."""
        sig_private = "-----BEGIN PRIVATE KEY-----\nUSER_PRIVATE\n-----END PRIVATE KEY-----"
        sig_public = "-----BEGIN PUBLIC KEY-----\nUSER_PUBLIC\n-----END PUBLIC KEY-----"

        provider = DefaultCryptoProvider(signature_private_pem=sig_private, signature_public_pem=sig_public)

        assert provider.signing_private_pem == sig_private
        assert provider.signing_public_pem == sig_public

    def test_initialization_with_user_provided_encryption_keys(self):
        """Test initialization with user-provided encryption keys."""
        enc_private = "-----BEGIN PRIVATE KEY-----\nENC_PRIVATE\n-----END PRIVATE KEY-----"
        enc_public = "-----BEGIN PUBLIC KEY-----\nENC_PUBLIC\n-----END PUBLIC KEY-----"

        provider = DefaultCryptoProvider(
            encryption_private_pem=enc_private, encryption_public_pem=enc_public
        )

        assert provider.encryption_private_pem == enc_private
        assert provider.encryption_public_pem == enc_public

    def test_initialization_with_user_provided_hmac_secret(self):
        """Test initialization with user-provided HMAC secret."""
        hmac_secret = "user_provided_secret"

        provider = DefaultCryptoProvider(hmac_secret=hmac_secret)

        assert provider.hmac_secret == hmac_secret

    def test_initialization_generates_random_hmac_secret(self):
        """Test automatic HMAC secret generation when not provided."""
        with patch("secrets.token_bytes", return_value=b"random_bytes"):
            provider = DefaultCryptoProvider()

            expected_secret = base64.b64encode(b"random_bytes").decode("utf-8")
            assert provider.hmac_secret == expected_secret


class TestDefaultCryptoProviderProperties:
    """Test property getters (lines 118-119, 123-124, 128, 132, 136, 140)."""

    def test_encryption_public_pem_property(self):
        """Test encryption_public_pem property."""
        enc_public = "-----BEGIN PUBLIC KEY-----\nENC_PUBLIC\n-----END PUBLIC KEY-----"
        enc_private = "-----BEGIN PRIVATE KEY-----\nENC_PRIVATE\n-----END PRIVATE KEY-----"

        provider = DefaultCryptoProvider(
            encryption_public_pem=enc_public, encryption_private_pem=enc_private
        )

        assert provider.encryption_public_pem == enc_public

    def test_hmac_secret_property(self):
        """Test hmac_secret property."""
        secret = "test_secret"

        provider = DefaultCryptoProvider(hmac_secret=secret)

        assert provider.hmac_secret == secret

    def test_issuer_property(self):
        """Test issuer property."""
        issuer = "test-issuer"

        provider = DefaultCryptoProvider(issuer=issuer)

        assert provider.issuer == issuer

    def test_signature_key_id_property(self):
        """Test signature_key_id property."""
        key_id = "test-sig-key-id"

        provider = DefaultCryptoProvider(signature_key_id=key_id)

        assert provider.signature_key_id == key_id

    def test_encryption_key_id_property(self):
        """Test encryption_key_id property."""
        key_id = "test-enc-key-id"

        provider = DefaultCryptoProvider(encryption_key_id=key_id)

        assert provider.encryption_key_id == key_id


class TestDefaultCryptoProviderTokenMethods:
    """Test token issuer and verifier creation (lines 151-153, 161-163)."""

    def test_get_token_issuer(self):
        """Test token issuer creation."""
        with patch("naylence.fame.security.auth.jwt_token_issuer.JWTTokenIssuer") as mock_issuer:
            provider = DefaultCryptoProvider(
                signature_key_id="test-key", issuer="test-issuer", ttl_sec=3600
            )

            provider.get_token_issuer()

            mock_issuer.assert_called_once_with(
                signing_key_pem=provider.signing_private_pem,
                kid="test-key",
                issuer="test-issuer",
                ttl_sec=3600,
            )

    def test_get_token_verifier(self):
        """Test token verifier creation."""
        with patch("naylence.fame.security.auth.jwt_token_verifier.JWTTokenVerifier") as mock_verifier:
            provider = DefaultCryptoProvider(issuer="test-issuer")

            provider.get_token_verifier()

            mock_verifier.assert_called_once_with(key=provider.signing_public_pem, issuer="test-issuer")


class TestDefaultCryptoProviderJWKS:
    """Test JWKS creation and error handling (lines 170->179, 179->185, 197)."""

    def test_get_jwks_with_both_keys(self):
        """Test JWKS generation with both signing and encryption keys."""
        with (
            patch(
                "naylence.fame.security.crypto.providers.default_crypto_provider.jwk_from_pem"
            ) as mock_jwk,
            patch(
                "naylence.fame.security.crypto.providers.default_crypto_provider.detect_alg",
                return_value="EdDSA",
            ),
        ):
            mock_signing_jwk = {"kid": "sig-key", "use": "sig"}
            mock_jwk.return_value = mock_signing_jwk

            with patch.object(DefaultCryptoProvider, "_create_encryption_jwk") as mock_enc_jwk:
                mock_encryption_jwk = {"kid": "enc-key", "use": "enc"}
                mock_enc_jwk.return_value = mock_encryption_jwk

                provider = DefaultCryptoProvider(signature_key_id="sig-key", encryption_key_id="enc-key")

                jwks = provider.get_jwks()

                assert jwks == {"keys": [mock_signing_jwk, mock_encryption_jwk]}

    def test_create_encryption_jwk_with_invalid_key(self):
        """Test _create_encryption_jwk with non-X25519 key (line 197)."""
        with patch("cryptography.hazmat.primitives.serialization.load_pem_public_key") as mock_load:
            # Mock a non-X25519 key
            mock_key = Mock()
            mock_key.__class__.__name__ = "Ed25519PublicKey"  # Not X25519
            mock_load.return_value = mock_key

            provider = DefaultCryptoProvider()

            with pytest.raises(ValueError, match="Expected X25519 public key"):
                provider._create_encryption_jwk("invalid_pem", "test-kid")

    def test_create_encryption_jwk_success(self):
        """Test successful _create_encryption_jwk."""
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

        with patch("cryptography.hazmat.primitives.serialization.load_pem_public_key") as mock_load:
            mock_key = Mock(spec=X25519PublicKey)
            mock_key.public_bytes.return_value = b"raw_bytes"
            mock_load.return_value = mock_key

            with patch("base64.urlsafe_b64encode", return_value=b"encoded_bytes"):
                provider = DefaultCryptoProvider()

                result = provider._create_encryption_jwk("test_pem", "test-kid")

                expected = {
                    "kty": "OKP",
                    "crv": "X25519",
                    "x": "encoded_bytes",
                    "kid": "test-kid",
                    "use": "enc",
                    "alg": "ECDH-ES",
                }
                assert result == expected


class TestDefaultCryptoProviderNodeContext:
    """Test node context methods (lines 230-243, 259-269, 287-300)."""

    def test_set_node_context(self):
        """Test set_node_context method."""
        with patch("naylence.fame.util.util.secure_digest", return_value="computed_sid"):
            provider = DefaultCryptoProvider()

            provider.set_node_context(
                node_id="test-node",
                physical_path="/test/path",
                logicals=["logical1", "logical2"],
                parent_path="/parent",
            )

            context = provider.get_certificate_context()
            assert context == {
                "node_id": "test-node",
                "node_sid": "computed_sid",
                "physical_path": "/test/path",
                "logicals": ["logical1", "logical2"],
            }

    def test_set_node_context_from_nodelike(self):
        """Test set_node_context_from_nodelike method."""
        from unittest.mock import Mock

        node_like = Mock()
        node_like.id = "test-node"
        node_like.physical_path = "/test/path"
        node_like.sid = "provided_sid"
        node_like.accepted_logicals = {"logical1", "logical2"}

        with patch("naylence.fame.util.util.secure_digest", return_value="computed_sid"):
            provider = DefaultCryptoProvider()

            provider.set_node_context_from_nodelike(node_like)

            context = provider.get_certificate_context()
            # Compare sorted logicals since sets are unordered and list() conversion is non-deterministic
            expected_context = {
                "node_id": "test-node",
                "node_sid": "provided_sid",  # Should use provided SID
                "physical_path": "/test/path",
                "logicals": ["logical1", "logical2"],
            }
            assert context["node_id"] == expected_context["node_id"]
            assert context["node_sid"] == expected_context["node_sid"]
            assert context["physical_path"] == expected_context["physical_path"]
            assert sorted(context["logicals"]) == sorted(expected_context["logicals"])

    def test_set_node_context_from_nodelike_without_sid(self):
        """Test set_node_context_from_nodelike when NodeLike has no SID."""
        from unittest.mock import Mock

        node_like = Mock()
        node_like.id = "test-node"
        node_like.physical_path = "/test/path"
        node_like.sid = None
        node_like.accepted_logicals = {"logical1", "logical2"}

        with patch("naylence.fame.util.util.secure_digest", return_value="computed_sid"):
            provider = DefaultCryptoProvider()

            provider.set_node_context_from_nodelike(node_like)

            context = provider.get_certificate_context()
            assert context["node_sid"] == "computed_sid"  # Should use computed SID

    def test_prepare_for_attach(self):
        """Test prepare_for_attach method."""
        with patch("naylence.fame.util.util.secure_digest", return_value="computed_sid"):
            provider = DefaultCryptoProvider()

            provider.prepare_for_attach(
                node_id="test-node", physical_path="/test/path", logicals=["logical1", "logical2"]
            )

            context = provider.get_certificate_context()
            assert context == {
                "node_id": "test-node",
                "node_sid": "computed_sid",
                "physical_path": "/test/path",
                "logicals": ["logical1", "logical2"],
            }


class TestDefaultCryptoProviderCertificateContext:
    """Test certificate context methods (lines 310, 314, 318)."""

    def test_get_certificate_context_when_none(self):
        """Test get_certificate_context when no context is set."""
        provider = DefaultCryptoProvider()

        context = provider.get_certificate_context()

        assert context is None

    def test_get_certificate_context_returns_copy(self):
        """Test get_certificate_context returns a copy."""
        provider = DefaultCryptoProvider()
        provider._cert_context = {"test": "value"}

        context = provider.get_certificate_context()

        assert context == {"test": "value"}
        assert context is not provider._cert_context

    def test_has_node_context_false(self):
        """Test has_node_context when no context is set."""
        provider = DefaultCryptoProvider()

        assert not provider.has_node_context()

    def test_has_node_context_true(self):
        """Test has_node_context when context is set."""
        provider = DefaultCryptoProvider()
        provider._cert_context = {"test": "value"}

        assert provider.has_node_context()


class TestDefaultCryptoProviderNodeJWK:
    """Test node_jwk with certificate chains (lines 323-411)."""

    def test_node_jwk_without_certificate(self):
        """Test node_jwk when no certificate is available."""
        with patch.object(DefaultCryptoProvider, "get_jwks") as mock_jwks:
            mock_jwks.return_value = {
                "keys": [
                    {"kid": "sig-key", "use": "sig", "kty": "OKP"},
                    {"kid": "enc-key", "use": "enc", "kty": "OKP"},
                ]
            }

            provider = DefaultCryptoProvider(signature_key_id="sig-key")

            result = provider.node_jwk()

            expected = {"kid": "sig-key", "use": "sig", "kty": "OKP"}
            assert result == expected

    def test_node_jwk_with_certificate_chain(self):
        """Test node_jwk with certificate and chain processing."""
        provider = DefaultCryptoProvider(signature_key_id="sig-key")

        # Mock the get_jwks method to return a key that matches
        with patch.object(provider, "get_jwks") as mock_jwks:
            mock_jwks.return_value = {"keys": [{"kid": "sig-key", "kty": "OKP", "use": "sig"}]}

            # Test without certificate (should return key without x5c)
            result = provider.node_jwk()
            assert result == {"kid": "sig-key", "kty": "OKP", "use": "sig"}
            assert "x5c" not in result

    def test_node_jwk_certificate_error_handling(self):
        """Test node_jwk error handling during certificate processing."""
        with patch("cryptography.x509.load_pem_x509_certificate", side_effect=Exception("Cert error")):
            with patch.object(DefaultCryptoProvider, "get_jwks") as mock_jwks:
                mock_jwks.return_value = {"keys": [{"kid": "sig-key", "kty": "OKP"}]}

                provider = DefaultCryptoProvider(signature_key_id="sig-key")
                provider._node_cert_pem = "invalid_cert"

                result = provider.node_jwk()

                # Should return JWK without x5c on error
                assert "x5c" not in result
                assert result["kid"] == "sig-key"

    def test_node_jwk_no_matching_signing_key(self):
        """Test node_jwk when no matching signing key is found."""
        with patch.object(DefaultCryptoProvider, "get_jwks") as mock_jwks:
            mock_jwks.return_value = {"keys": [{"kid": "different-key", "use": "sig"}]}

            provider = DefaultCryptoProvider(signature_key_id="sig-key")

            result = provider.node_jwk()

            assert result == {}


class TestDefaultCryptoProviderSetLogicals:
    """Test set_logicals method (lines 423-427)."""

    def test_set_logicals_with_context(self):
        """Test set_logicals when context exists."""
        provider = DefaultCryptoProvider()
        provider._cert_context = {"node_id": "test-node", "logicals": ["old1", "old2"]}

        provider.set_logicals(["new1", "new2", "new3"])

        assert provider._cert_context["logicals"] == ["new1", "new2", "new3"]

    def test_set_logicals_without_context(self):
        """Test set_logicals when no context exists."""
        provider = DefaultCryptoProvider()

        # Should not raise an error
        provider.set_logicals(["logical1", "logical2"])

        # Context should still be None
        assert provider._cert_context is None


class TestDefaultCryptoProviderCSR:
    """Test CSR creation (lines 457-542)."""

    def test_create_csr_with_non_ed25519_key(self):
        """Test create_csr error when key is not Ed25519."""
        with patch(
            "naylence.fame.security.crypto.providers.default_crypto_provider.detect_alg", return_value="RSA"
        ):
            provider = DefaultCryptoProvider()

            with pytest.raises(ValueError, match="CSR creation only supported for Ed25519 keys"):
                provider.create_csr(node_id="test-node", physical_path="/test/path", logicals=["logical1"])

    def test_create_csr_with_non_ed25519_private_key(self):
        """Test create_csr error when private key is not Ed25519."""
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

        mock_rsa_key = Mock(spec=RSAPrivateKey)

        with (
            patch(
                "naylence.fame.security.crypto.providers.default_crypto_provider.detect_alg",
                return_value="EdDSA",
            ),
            patch(
                "cryptography.hazmat.primitives.serialization.load_pem_private_key",
                return_value=mock_rsa_key,
            ),
        ):
            provider = DefaultCryptoProvider()

            with pytest.raises(ValueError, match="CSR creation only supported for Ed25519 keys"):
                provider.create_csr(node_id="test-node", physical_path="/test/path", logicals=["logical1"])

    def test_create_csr_success(self):
        """Test successful CSR creation."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        mock_ed25519_key = Mock(spec=Ed25519PrivateKey)
        mock_csr = Mock()
        mock_csr.public_bytes.return_value = (
            b"-----BEGIN CERTIFICATE REQUEST-----\nCSR\n-----END CERTIFICATE REQUEST-----"
        )

        with (
            patch(
                "naylence.fame.security.crypto.providers.default_crypto_provider.detect_alg",
                return_value="EdDSA",
            ),
            patch(
                "cryptography.hazmat.primitives.serialization.load_pem_private_key",
                return_value=mock_ed25519_key,
            ),
            patch("cryptography.x509.CertificateSigningRequestBuilder") as mock_builder_class,
            patch("naylence.fame.util.util.secure_digest", return_value="test_sid"),
        ):
            mock_builder = Mock()
            mock_builder.subject_name.return_value = mock_builder
            mock_builder.add_extension.return_value = mock_builder
            mock_builder.sign.return_value = mock_csr
            mock_builder_class.return_value = mock_builder

            provider = DefaultCryptoProvider()

            result = provider.create_csr(
                node_id="test-node",
                physical_path="/test/path",
                logicals=["logical1", "logical2"],
                subject_name="Custom Subject",
            )

            assert result == "-----BEGIN CERTIFICATE REQUEST-----\nCSR\n-----END CERTIFICATE REQUEST-----"
            mock_builder.sign.assert_called_once_with(mock_ed25519_key, None)

    def test_create_csr_with_default_subject_name(self):
        """Test CSR creation with default subject name (node_id)."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        mock_ed25519_key = Mock(spec=Ed25519PrivateKey)
        mock_csr = Mock()
        mock_csr.public_bytes.return_value = b"CSR_BYTES"

        with (
            patch(
                "naylence.fame.security.crypto.providers.default_crypto_provider.detect_alg",
                return_value="EdDSA",
            ),
            patch(
                "cryptography.hazmat.primitives.serialization.load_pem_private_key",
                return_value=mock_ed25519_key,
            ),
            patch("cryptography.x509.CertificateSigningRequestBuilder") as mock_builder_class,
            patch("cryptography.x509.Name") as mock_name_class,
            patch("naylence.fame.util.util.secure_digest", return_value="test_sid"),
        ):
            mock_builder = Mock()
            mock_builder.subject_name.return_value = mock_builder
            mock_builder.add_extension.return_value = mock_builder
            mock_builder.sign.return_value = mock_csr
            mock_builder_class.return_value = mock_builder

            provider = DefaultCryptoProvider()

            provider.create_csr(node_id="test-node", physical_path="/test/path", logicals=["logical1"])

            # Verify subject was created with node_id as CN
            mock_name_class.assert_called_once()

    def test_create_csr_exception_handling(self):
        """Test CSR creation exception handling."""
        with (
            patch(
                "naylence.fame.security.crypto.providers.default_crypto_provider.detect_alg",
                return_value="EdDSA",
            ),
            patch(
                "cryptography.hazmat.primitives.serialization.load_pem_private_key",
                side_effect=Exception("Key error"),
            ),
        ):
            provider = DefaultCryptoProvider()

            with pytest.raises(Exception, match="Key error"):
                provider.create_csr(node_id="test-node", physical_path="/test/path", logicals=["logical1"])


class TestDefaultCryptoProviderAdditionalCoverage:
    """Additional tests to cover remaining edge cases."""

    def test_get_jwks_error_handling(self):
        """Test JWKS creation error handling (lines 170->179, 179->185)."""
        provider = DefaultCryptoProvider()

        # Mock jwk_from_pem to raise an exception
        with patch(
            "naylence.fame.security.crypto.providers.default_crypto_provider.jwk_from_pem",
            side_effect=Exception("JWK error"),
        ):
            with patch(
                "naylence.fame.security.crypto.providers.default_crypto_provider.detect_alg",
                return_value="EdDSA",
            ):
                # Should propagate the exception since there's no error handling
                with pytest.raises(Exception, match="JWK error"):
                    provider.get_jwks()

    def test_node_jwk_certificate_chain_parsing_edge_cases(self):
        """Test node_jwk certificate chain parsing edge cases (lines 343-401)."""
        provider = DefaultCryptoProvider(signature_key_id="sig-key")

        # Set up certificate with malformed chain
        cert_pem = "-----BEGIN CERTIFICATE-----\nCERT\n-----END CERTIFICATE-----"
        malformed_chain = "-----BEGIN CERTIFICATE-----\nMALFORMED CERT\n-----END CERTIFICATE-----"

        with patch.object(provider, "get_jwks") as mock_jwks:
            mock_jwks.return_value = {"keys": [{"kid": "sig-key", "kty": "OKP", "use": "sig"}]}

            # Mock successful cert loading but failed chain cert loading
            with patch("cryptography.x509.load_pem_x509_certificate") as mock_load:
                mock_cert = Mock()
                mock_cert.public_bytes.return_value = b"cert_der_bytes"
                mock_load.side_effect = [mock_cert, Exception("Invalid cert")]

                with patch("base64.b64encode", return_value=b"cert_b64"):
                    provider._node_cert_pem = cert_pem
                    provider._node_cert_chain_pem = malformed_chain

                    result = provider.node_jwk()

                    # Should still work with just the end-entity cert
                    assert "x5c" in result
                    assert result["x5c"] == ["cert_b64"]

    def test_create_csr_rsa_key_error(self):
        """Test create_csr with non-Ed25519 private key loaded (lines 500->507)."""
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

        mock_rsa_key = Mock(spec=RSAPrivateKey)

        with (
            patch(
                "naylence.fame.security.crypto.providers.default_crypto_provider.detect_alg",
                return_value="EdDSA",
            ),
            patch(
                "cryptography.hazmat.primitives.serialization.load_pem_private_key",
                return_value=mock_rsa_key,
            ),
        ):
            provider = DefaultCryptoProvider()

            with pytest.raises(ValueError, match="CSR creation only supported for Ed25519 keys"):
                provider.create_csr(node_id="test-node", physical_path="/test/path", logicals=["logical1"])

    def test_create_csr_general_exception(self):
        """Test create_csr general exception handling (lines 512, 525)."""
        with (
            patch(
                "naylence.fame.security.crypto.providers.default_crypto_provider.detect_alg",
                return_value="EdDSA",
            ),
            patch(
                "cryptography.hazmat.primitives.serialization.load_pem_private_key",
                side_effect=Exception("Key loading error"),
            ),
        ):
            provider = DefaultCryptoProvider()

            # Should reraise the exception
            with pytest.raises(Exception, match="Key loading error"):
                provider.create_csr(node_id="test-node", physical_path="/test/path", logicals=["logical1"])


class TestDefaultCryptoProviderCertificateStorage:
    """Test certificate storage methods (lines 554-560, 568, 572)."""

    def test_store_signed_certificate_with_chain(self):
        """Test storing signed certificate with chain."""
        provider = DefaultCryptoProvider()

        cert_pem = "-----BEGIN CERTIFICATE-----\nCERT\n-----END CERTIFICATE-----"
        chain_pem = "-----BEGIN CERTIFICATE-----\nCHAIN\n-----END CERTIFICATE-----"

        provider.store_signed_certificate(cert_pem, chain_pem)

        assert provider.node_certificate_pem() == cert_pem
        assert provider.certificate_chain_pem() == chain_pem

    def test_store_signed_certificate_without_chain(self):
        """Test storing signed certificate without chain."""
        provider = DefaultCryptoProvider()

        cert_pem = "-----BEGIN CERTIFICATE-----\nCERT\n-----END CERTIFICATE-----"

        provider.store_signed_certificate(cert_pem)

        assert provider.node_certificate_pem() == cert_pem
        assert provider.certificate_chain_pem() is None

    def test_has_certificate_false(self):
        """Test has_certificate when no certificate is stored."""
        provider = DefaultCryptoProvider()

        assert not provider.has_certificate()

    def test_has_certificate_true(self):
        """Test has_certificate when certificate is stored."""
        provider = DefaultCryptoProvider()
        provider._node_cert_pem = "cert"

        assert provider.has_certificate()

    def test_node_certificate_pem_none(self):
        """Test node_certificate_pem when no certificate is stored."""
        provider = DefaultCryptoProvider()

        assert provider.node_certificate_pem() is None

    def test_certificate_chain_pem_none(self):
        """Test certificate_chain_pem when no chain is stored."""
        provider = DefaultCryptoProvider()

        assert provider.certificate_chain_pem() is None
