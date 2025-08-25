"""
Interface for attachment key validation during node handshake.

This module provides the abstract interface for validating keys during the attachment
handshake between nodes, ensuring both sides trust each other's keys/certificates
before establishing the connection.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Tuple

from pydantic import BaseModel


class KeyInfo(BaseModel):
    """Metadata about a validated key/certificate."""

    kid: Optional[str] = None
    expires_at: Optional[datetime] = None
    not_before: Optional[datetime] = None
    has_certificate: bool = False
    cert_subject: Optional[str] = None
    cert_issuer: Optional[str] = None


class KeyValidationError(Exception):
    """Raised when a key fails validation."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        kid: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.kid = kid
        self.details = details or {}


class AttachmentKeyValidator(ABC):
    """
    Abstract interface for validating keys during attachment handshake.

    This interface defines the contract for validating keys and certificates
    during the attachment process between nodes.
    """

    @abstractmethod
    async def validate_key(self, key: Dict[str, Any]) -> KeyInfo:
        """
        Validate a single JWK and return KeyInfo.

        Implementations must raise KeyValidationError on failure.

        Args:
            key: JWK dictionary (may contain x5c certificate chains)

        Returns:
            KeyInfo with metadata about the validated key

        Raises:
            KeyValidationError: When validation fails
        """
        raise NotImplementedError

    async def validate_keys(self, keys: Optional[Iterable[Dict[str, Any]]]) -> List[KeyInfo]:
        """
        Validate multiple keys and return KeyInfo for each valid one.

        Args:
            keys: Iterable of JWK dictionaries

        Returns:
            List of KeyInfo for each successfully validated key

        Raises:
            KeyValidationError: When any key validation fails
        """
        infos: List[KeyInfo] = []
        if not keys:
            return infos
        for key in keys:
            info = await self.validate_key(key)
            infos.append(info)
        return infos

    @abstractmethod
    async def validate_child_attachment_logicals(
        self,
        child_keys: Optional[List[Dict[str, Any]]],
        authorized_logicals: Optional[List[str]],
        child_id: str,
    ) -> Tuple[bool, str]:
        """
        Validate that child certificate logicals match authorized paths from welcome token.

        Args:
            child_keys: Keys provided by the child node
            authorized_logicals: Logicals authorized by welcome token
            child_id: Child node identifier

        Returns:
            Tuple of (is_valid, error_message)
        """
        pass
