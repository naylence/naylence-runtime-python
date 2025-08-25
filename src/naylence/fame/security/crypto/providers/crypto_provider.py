from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, Dict, Optional

if TYPE_CHECKING:
    from naylence.fame.node.node_like import NodeLike

# No auth imports here to avoid heavy dependency loading


class CryptoProvider(ABC):
    """
    Abstract interface for cryptographic operations in Naylence Fame.

    Core Methods (must be implemented):
    - signing_private_pem, signing_public_pem: Signing key pair
    - issuer, signature_key_id, encryption_key_id: Identity properties
    - get_token_issuer, get_token_verifier: Token operations
    - get_jwks: Public key set for wire transfer

    Certificate Methods (optional, with default implementations):
    - node_certificate_pem, node_jwk: Certificate access
    - has_certificate: Certificate availability check
    - create_csr, store_signed_certificate: External CA integration
    - set_node_context, prepare_for_attach: Context management

    Encryption Methods (optional):
    - encryption_private_pem, encryption_public_pem: Encryption key pair

    HMAC Methods (optional):
    - hmac_secret: Secret for HMAC-based JWT signing/verification
    """

    @property
    @abstractmethod
    def signing_private_pem(self) -> str:
        """Private key for signing operations."""
        ...

    @property
    @abstractmethod
    def signing_public_pem(self) -> str:
        """Public key for signature verification operations."""
        ...

    @property
    def encryption_private_pem(self) -> Optional[str]:
        """Private key for decryption operations."""
        return None

    @property
    def encryption_public_pem(self) -> Optional[str]:
        """Public key for encryption operations."""
        return None

    @property
    def hmac_secret(self) -> Optional[str]:
        """HMAC secret for symmetric JWT signing/verification operations."""
        return None

    @property
    @abstractmethod
    def issuer(self) -> str: ...

    @property
    @abstractmethod
    def signature_key_id(self) -> str: ...

    @property
    @abstractmethod
    def encryption_key_id(self) -> str: ...

    @abstractmethod
    def get_token_issuer(self) -> Any:
        """Returns a TokenIssuer implementation."""
        ...

    @abstractmethod
    def get_token_verifier(self) -> Any:
        """Returns a TokenVerifier implementation."""
        ...

    @abstractmethod
    def get_jwks(self) -> Dict[str, Any]: ...

    # Certificate support (optional, non-breaking)
    def node_certificate_pem(self) -> Optional[str]:
        """Signed node certificate (PEM). None if certificates not used."""
        return None

    def node_jwk(self) -> Dict[str, Any]:
        """Public JWK for wire transfer. Includes x5c when certificate available."""
        # Default implementation without certificates
        return self.get_jwks()["keys"][0] if self.get_jwks()["keys"] else {}

    # Node context management (optional, for certificate lifecycle)
    def set_node_context(
        self,
        node_id: str,
        physical_path: str,
        logicals: list[str],
        parent_path: Optional[str] = None,
    ) -> None:
        """
        Set node context for certificate generation.

        Optional method - providers that don't support certificates can ignore this.

        Args:
            node_id: Node identifier
            physical_path: Physical path of the node
            logicals: List of host-like logical addresses this node will serve
            parent_path: Optional parent path (unused in current implementation)
        """
        pass

    def set_node_context_from_nodelike(self, node_like: NodeLike) -> None:
        """
        Set node context from NodeLike object for certificate generation.

        Optional method - providers that don't support certificates can ignore this.

        Args:
            node_like: Node object with id, physical_path, sid, accepted_logicals, etc.
        """
        pass

    def prepare_for_attach(self, node_id: str, physical_path: str, logicals: list[str]) -> None:
        """
        Prepare certificate for direct attach scenario.

        Optional method - providers that don't support certificates can ignore this.

        Args:
            physical_path: The node's physical path
            logicals: Host-like logical addresses this node will serve
        """
        pass

    def has_node_context(self) -> bool:
        """Check if node context has been set."""
        return False

    # Certificate signing request support (optional, for external CA flow)
    def create_csr(
        self,
        node_id: str,
        physical_path: str,
        logicals: list[str],
        subject_name: Optional[str] = None,
    ) -> str:
        """
        Create a Certificate Signing Request (CSR) for this node.

        Optional method - only implemented by providers that support external CA flow.

        Args:
            node_id: Node identifier
            physical_path: Physical path of the node
            logicals: List of host-like logical addresses this node will serve
            subject_name: Optional subject name (defaults to node_id)

        Returns:
            CSR in PEM format

        Raises:
            NotImplementedError: If provider doesn't support CSR creation
        """
        raise NotImplementedError("CSR creation not supported by this crypto provider")

    def store_signed_certificate(
        self, certificate_pem: str, certificate_chain_pem: Optional[str] = None
    ) -> None:
        """
        Store a signed certificate received from an external CA service.

        Optional method - only implemented by providers that support external CA flow.

        Args:
            certificate_pem: The signed certificate in PEM format
            certificate_chain_pem: Optional full certificate chain in PEM format
        """
        # Default implementation does nothing
        pass

    def has_certificate(self) -> bool:
        """
        Check if a node certificate is available.

        Returns:
            True if certificate is available, False otherwise
        """
        return self.node_certificate_pem() is not None


_instance: Optional[CryptoProvider] = None


def get_crypto_provider() -> CryptoProvider:
    global _instance
    if _instance is None:
        from naylence.fame.security.crypto.providers.default_crypto_provider import (
            DefaultCryptoProvider,
        )

        _instance = DefaultCryptoProvider()

    return _instance
