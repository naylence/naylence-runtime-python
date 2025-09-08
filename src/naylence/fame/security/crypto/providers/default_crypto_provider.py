from __future__ import annotations

import base64
import os
import secrets
from typing import TYPE_CHECKING, Any, Dict, Optional

from naylence.fame.core import generate_id
from naylence.fame.security.auth.token_issuer import TokenIssuer
from naylence.fame.security.auth.token_verifier import TokenVerifier
from naylence.fame.security.crypto.providers.crypto_provider import CryptoProvider

if TYPE_CHECKING:
    from naylence.fame.node.node_like import NodeLike
from naylence.fame.util.crypto_util import detect_alg, jwk_from_pem
from naylence.fame.util.logging import getLogger

logger = getLogger(__name__)

ENV_VAR_CRYPTO_ALGORITHM = "FAME_CRYPTO_ALGORITHM"

DEFAULT_CRYPTO_ALGORITHM = "EdDSA"


class DefaultCryptoProvider(CryptoProvider):
    """
    Default crypto utility for dev or single-node environments.
    Uses a provided PEM keypair or falls back to ephemeral in-memory RSA/Ed25519 keys.
    Also generates X25519 keys for encryption operations.

    Certificate generation is handled via external CA service - use certificate_provisioner.
    """

    def __init__(
        self,
        *,
        signature_private_pem: Optional[str] = None,
        signature_public_pem: Optional[str] = None,
        signature_key_id: Optional[str] = None,
        encryption_private_pem: Optional[str] = None,
        encryption_public_pem: Optional[str] = None,
        encryption_key_id: Optional[str] = None,
        hmac_secret: Optional[str] = None,
        issuer: str = "dev.naylence.ai",
        audience: str = "router-dev",
        algorithm: Optional[str] = None,
        ttl_sec: int = 3600,
    ):
        self._signature_key_id = signature_key_id or generate_id()
        self._encryption_key_id = encryption_key_id or generate_id()
        algorithm = algorithm or os.getenv(ENV_VAR_CRYPTO_ALGORITHM, DEFAULT_CRYPTO_ALGORITHM)
        if not (signature_private_pem and signature_public_pem):
            if not algorithm or algorithm == "EdDSA":
                from naylence.fame.security.crypto.key_factories.ed25519_key_factory import (
                    create_ed25519_keypair,
                )

                dev_key_pair = create_ed25519_keypair(self._signature_key_id)
            elif algorithm == "RSA":
                from naylence.fame.security.crypto.key_factories.rsa_key_factory import (
                    create_rsa_keypair,
                )

                dev_key_pair = create_rsa_keypair()
            else:
                raise ValueError(f"Invalid key algorithm: {algorithm}")

            self._signature_private_pem = dev_key_pair.private_pem
            self._signature_public_pem = dev_key_pair.public_pem
        else:
            # user provided PEM(s)
            self._signature_private_pem = signature_private_pem
            self._signature_public_pem = signature_public_pem

        # Generate X25519 keys for encryption if not provided

        if not (encryption_private_pem and encryption_public_pem):
            from naylence.fame.security.crypto.key_factories.x25519_key_factory import (
                create_x25519_keypair,
            )

            x25519_keypair = create_x25519_keypair(self._encryption_key_id)
            self._encryption_private_pem = x25519_keypair.private_pem
            self._encryption_public_pem = x25519_keypair.public_pem
        else:
            # user provided encryption PEM(s)
            self._encryption_private_pem = encryption_private_pem
            self._encryption_public_pem = encryption_public_pem

        # Generate HMAC secret if not provided
        if hmac_secret is None:
            # Generate a 256-bit (32 bytes) random secret and base64 encode it
            random_bytes = secrets.token_bytes(32)
            self._hmac_secret = base64.b64encode(random_bytes).decode("utf-8")
        else:
            self._hmac_secret = hmac_secret

        assert self._signature_private_pem
        assert self._signature_public_pem

        self._issuer = issuer
        self._audience = audience
        self._ttl = ttl_sec

        # Certificate storage (from external CA service)
        self._node_cert_pem: Optional[str] = None
        self._node_cert_chain_pem: Optional[str] = None  # Full certificate chain
        self._cert_context: Optional[Dict[str, Any]] = None  # Store context for certificate generation

        logger.debug(
            "default_crypto_provider_initialized",
            signature_key_id=self._signature_key_id,
            encryption_key_id=self._encryption_key_id,
        )

    @property
    def signing_private_pem(self) -> str:
        assert self._signature_private_pem
        return self._signature_private_pem

    @property
    def signing_public_pem(self) -> str:
        assert self._signature_public_pem
        return self._signature_public_pem

    @property
    def encryption_private_pem(self) -> Optional[str]:
        return self._encryption_private_pem

    @property
    def encryption_public_pem(self) -> Optional[str]:
        return self._encryption_public_pem

    @property
    def hmac_secret(self) -> Optional[str]:
        return self._hmac_secret

    @property
    def issuer(self) -> str:
        return self._issuer

    @property
    def signature_key_id(self) -> str:
        return self._signature_key_id

    @property
    def encryption_key_id(self) -> str:
        return self._encryption_key_id

    def get_token_issuer(self) -> TokenIssuer:
        from naylence.fame.security.auth.jwt_token_issuer import JWTTokenIssuer

        return JWTTokenIssuer(
            signing_key_pem=self.signing_private_pem,  # type: ignore
            kid=self._signature_key_id,
            issuer=self._issuer,
            ttl_sec=self._ttl,
        )

    def get_token_verifier(self) -> TokenVerifier:
        from naylence.fame.security.auth.jwt_token_verifier import JWTTokenVerifier

        return JWTTokenVerifier(key=self.signing_public_pem, issuer=self._issuer)

    def get_jwks(self) -> Dict[str, Any]:
        """Return JWKS with both signing and encryption keys."""
        keys = []

        # Add signing key
        if self._signature_public_pem:
            signing_jwk = jwk_from_pem(
                self._signature_public_pem,
                algorithm=detect_alg(self._signature_public_pem),
                kid=self._signature_key_id,
            )
            keys.append(signing_jwk)

        # Add encryption key
        if self._encryption_public_pem:
            encryption_jwk = self._create_encryption_jwk(
                self._encryption_public_pem, kid=self._encryption_key_id
            )
            keys.append(encryption_jwk)

        return {"keys": keys}

    def _create_encryption_jwk(self, public_pem: str, kid: str) -> Dict[str, Any]:
        """Convert X25519 public key PEM to JWK format for encryption."""
        from base64 import urlsafe_b64encode

        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

        # Load the public key
        public_key = serialization.load_pem_public_key(public_pem.encode())
        if not isinstance(public_key, X25519PublicKey):
            raise ValueError("Expected X25519 public key")

        # Get raw bytes
        raw_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )

        # Create JWK in OKP format for X25519
        return {
            "kty": "OKP",
            "crv": "X25519",
            "x": urlsafe_b64encode(raw_bytes).decode().rstrip("="),
            "kid": kid,
            "use": "enc",
            "alg": "ECDH-ES",
        }

    def set_node_context(
        self,
        node_id: str,
        physical_path: str,
        logicals: list[str],
        parent_path: Optional[str] = None,
    ) -> None:
        """
        Set node context and generate certificate.

        Args:
            node_id: Node identifier
            physical_path: Physical path of the node
            logicals: List of host-like logical addresses this node will serve
            parent_path: Optional parent path (unused in current implementation)
        """
        from naylence.fame.util.util import secure_digest

        # Compute SID from physical path (standard behavior)
        node_sid = secure_digest(physical_path)

        # Store context for later use
        self._cert_context = {
            "node_id": node_id,
            "node_sid": node_sid,  # Use computed SID from physical path
            "physical_path": physical_path,
            "logicals": logicals,
        }

        logger.debug(
            "node_context_set",
            node_id=node_id,
            physical_path=physical_path,
            logicals=logicals,
            message="Certificate generation via external CA service required",
        )

    def set_node_context_from_nodelike(self, node_like: NodeLike) -> None:
        """
        Set node context from NodeLike object and generate certificate.

        Args:
            node_like: Node object with id, physical_path, sid, accepted_logicals, etc.
        """
        # Convert NodeLike to individual parameters and call legacy method
        logicals = list(node_like.accepted_logicals)
        self.set_node_context(
            node_id=node_like.id,
            physical_path=node_like.physical_path,
            logicals=logicals,
        )

        # Update the SID if NodeLike provides one that's different from computed
        if self._cert_context and node_like.sid and node_like.sid != self._cert_context.get("node_sid"):
            self._cert_context["node_sid"] = node_like.sid
            logger.debug(
                "node_context_updated_with_nodelike_sid",
                node_id=node_like.id,
                provided_sid=node_like.sid,
                message="Certificate generation via external CA service required",
            )

    def prepare_for_attach(self, node_id: str, physical_path: str, logicals: list[str]) -> None:
        """
        Prepare certificate for direct attach scenario.

        For direct attach, the node needs to generate its certificate before
        the handshake, using the known physical path.

        Args:
            physical_path: The node's physical path
            logicals: Host-like logical addresses this node will serve
        """
        from naylence.fame.util.util import secure_digest

        # Compute SID from physical path
        node_sid = secure_digest(physical_path)

        # Store context for certificate generation
        self._cert_context = {
            "node_id": node_id,
            "node_sid": node_sid,
            "physical_path": physical_path,
            "logicals": logicals,
        }

        logger.debug(
            "prepared_context_for_attach",
            physical_path=physical_path,
            node_id=node_id,
            node_sid=node_sid,
            message="Certificate generation via external CA service required",
        )

    def node_certificate_pem(self) -> Optional[str]:
        """Return signed node certificate if available."""
        return self._node_cert_pem

    def get_certificate_context(self) -> Optional[Dict[str, Any]]:
        """Return the current certificate context if available."""
        return self._cert_context.copy() if self._cert_context else None

    def has_node_context(self) -> bool:
        """Check if node context has been set."""
        return self._cert_context is not None

    def node_jwk(self) -> Dict[str, Any]:
        """Return JWK with x5c certificate chain if available."""
        # Get base signing JWK
        jwks = self.get_jwks()
        signing_jwk = None
        for key in jwks["keys"]:
            if key.get("kid") == self._signature_key_id and key.get("use") != "enc":
                signing_jwk = key.copy()
                break

        if not signing_jwk:
            return {}

        # Add x5c if certificate is available
        if self._node_cert_pem:
            try:
                from cryptography import x509
                from cryptography.hazmat.primitives import serialization

                x5c_chain = []

                # Add the end-entity certificate first
                cert = x509.load_pem_x509_certificate(self._node_cert_pem.encode())
                cert_der = cert.public_bytes(serialization.Encoding.DER)
                x5c_chain.append(base64.b64encode(cert_der).decode())

                # Add intermediate certificates from the chain (but exclude root CA)
                if self._node_cert_chain_pem:
                    # Parse the certificate chain
                    chain_parts = []
                    current_cert = ""
                    in_cert = False

                    for line in self._node_cert_chain_pem.split("\n"):
                        if "-----BEGIN CERTIFICATE-----" in line:
                            in_cert = True
                            current_cert = line + "\n"
                        elif "-----END CERTIFICATE-----" in line:
                            current_cert += line + "\n"
                            chain_parts.append(current_cert.strip())
                            current_cert = ""
                            in_cert = False
                        elif in_cert:
                            current_cert += line + "\n"

                    # Skip the first certificate (end-entity) since we already added it
                    # Add intermediate certificates but exclude self-signed root CAs
                    intermediate_count = 0
                    for cert_pem in chain_parts[1:]:
                        try:
                            chain_cert = x509.load_pem_x509_certificate(cert_pem.encode())

                            # Check if this is a self-signed root CA (issuer == subject)
                            if chain_cert.issuer == chain_cert.subject:
                                logger.debug(
                                    "excluded_root_ca_from_x5c",
                                    reason="self_signed_root_ca",
                                    subject=str(chain_cert.subject),
                                )
                                continue

                            # Add intermediate CA to the chain
                            chain_cert_der = chain_cert.public_bytes(serialization.Encoding.DER)
                            x5c_chain.append(base64.b64encode(chain_cert_der).decode())
                            intermediate_count += 1

                        except Exception as cert_e:
                            logger.debug(
                                "Failed to add certificate to x5c chain",
                                error=str(cert_e),
                                cert_pem_preview=cert_pem[:100],
                            )

                    logger.debug(
                        "processed_certificate_chain_for_x5c",
                        total_chain_parts=len(chain_parts),
                        intermediate_added=intermediate_count,
                        excluded_root_ca=True,
                    )

                signing_jwk["x5c"] = x5c_chain
                logger.debug(
                    "added_certificate_chain_to_x5c",
                    chain_length=len(x5c_chain),
                    has_full_chain=self._node_cert_chain_pem is not None,
                    excludes_root_ca=True,
                )

            except Exception as e:
                logger.debug("Failed to add x5c to JWK", error=str(e))

        return signing_jwk

    def set_logicals(self, logicals: list[str]) -> None:
        """
        Update logical addresses for certificate generation.

        Can be called after set_node_context() to update logical addresses
        and regenerate the certificate if needed.

        Args:
            logicals: List of host-like logical addresses this node will serve
        """
        if self._cert_context:
            # Update the stored context
            self._cert_context["logicals"] = logicals

            logger.debug(
                "logicals_updated",
                node_id=self._cert_context["node_id"],
                logicals=logicals,
                message="Certificate regeneration via external CA service required",
            )

    def create_csr(
        self,
        node_id: str,
        physical_path: str,
        logicals: list[str],
        subject_name: Optional[str] = None,
    ) -> str:
        """
        Create a Certificate Signing Request (CSR) for this node.

        Args:
            node_id: Node identifier
            physical_path: Physical path of the node
            logicals: List of host-like logical addresses this node will serve
            subject_name: Optional subject name (defaults to node_id)

        Returns:
            CSR in PEM format

        Raises:
            ValueError: If the signing key is not Ed25519
        """
        # Only support Ed25519 for now
        if detect_alg(self._signature_public_pem) != "EdDSA":
            raise ValueError("CSR creation only supported for Ed25519 keys")

        try:
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.x509.oid import NameOID

            from naylence.fame.util.util import secure_digest

            # Load the private key
            private_key = serialization.load_pem_private_key(
                self._signature_private_pem.encode(), password=None
            )

            # Verify it's Ed25519
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PrivateKey,
            )

            if not isinstance(private_key, Ed25519PrivateKey):
                raise ValueError("CSR creation only supported for Ed25519 keys")

            # Create subject
            subject_name = subject_name or node_id
            subject = x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, subject_name),
                ]
            )

            # Create CSR builder
            builder = x509.CertificateSigningRequestBuilder()
            builder = builder.subject_name(subject)

            # Add Subject Alternative Names (SANs) for logical addresses
            san_names = []

            # Logical address URIs
            san_names.extend(
                x509.UniformResourceIdentifier(f"naylence://{logical}") for logical in logicals
            )

            if san_names:
                builder = builder.add_extension(
                    x509.SubjectAlternativeName(san_names),
                    critical=False,
                )

            # Add SID as an extension (using a custom OID)
            secure_digest(physical_path)
            try:
                # Add SID as OtherName extension (similar to what ca_service does)
                # For now, we'll skip this complex extension in CSR - the CA service will add it
                pass
            except Exception:
                # SID extension is optional in CSR, CA service will add it
                pass

            # Sign the CSR
            # For Ed25519 keys, algorithm must be None
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PrivateKey,
            )

            if isinstance(private_key, Ed25519PrivateKey):
                csr = builder.sign(private_key, None)
            else:
                csr = builder.sign(private_key, hashes.SHA256())

            # Return PEM-encoded CSR
            csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()

            logger.debug(
                "csr_created",
                node_id=node_id,
                physical_path=physical_path,
                logicals=logicals,
                subject_name=subject_name,
            )

            return csr_pem

        except Exception as e:
            logger.error("csr_creation_failed", node_id=node_id, error=str(e), exc_info=True)
            raise

    def store_signed_certificate(
        self, certificate_pem: str, certificate_chain_pem: Optional[str] = None
    ) -> None:
        """
        Store a signed certificate (and optional chain) received from the CA service.

        Args:
            certificate_pem: The signed certificate in PEM format
            certificate_chain_pem: Optional full certificate chain in PEM format
        """
        self._node_cert_pem = certificate_pem

        # Store chain if provided (for future use)
        if certificate_chain_pem:
            self._node_cert_chain_pem = certificate_chain_pem

        logger.debug(
            "certificate_stored",
            has_certificate=bool(certificate_pem),
            has_chain=bool(certificate_chain_pem),
        )

    def has_certificate(self) -> bool:
        """Check if a node certificate is available."""
        return self._node_cert_pem is not None

    def certificate_chain_pem(self) -> Optional[str]:
        """Return the full certificate chain if available."""
        return self._node_cert_chain_pem
