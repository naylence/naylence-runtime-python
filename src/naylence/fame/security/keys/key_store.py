"""
Generic public-key storage / lookup interface.

Nothing in here is algorithm-specific; a KeyStore just maps **kid → JWK**.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Iterable, Optional

from naylence.fame.security.keys.key_provider import KeyProvider
from naylence.fame.util import logging
from naylence.fame.util.util import secure_digest

logger = logging.getLogger(__name__)


class KeyStore(ABC, KeyProvider):
    """Simple CRUD for public keys identified by their `kid` value."""

    @abstractmethod
    async def add_key(self, kid: str, jwk: dict[str, Any]) -> None:  # noqa: D401
        """Store (or replace) a JWK under the given key-id."""
        raise NotImplementedError

    @abstractmethod
    async def get_key(self, kid: str) -> dict[str, Any]:  # noqa: D401
        """Return the JWK for *kid* or raise ``ValueError`` if missing."""
        raise NotImplementedError

    @abstractmethod
    async def has_key(self, kid: str) -> bool:  # noqa: D401
        """Store (or replace) a JWK under the given key-id."""
        raise NotImplementedError

    @abstractmethod
    async def get_keys(self) -> Iterable[dict[str, Any]]:
        pass

    @abstractmethod
    async def get_keys_for_path(self, physical_path: str) -> Iterable[dict[str, Any]]:
        """
        Return **all** JWKs that originated from the same _physical path_
        (identified by the SHA-256-based `sid` we store alongside each key).
        """
        raise NotImplementedError

    @abstractmethod
    async def get_keys_grouped_by_path(self) -> dict[str, list[dict[str, Any]]]:
        """
        Return a mapping **sid → list[JWK]** where *sid* is the secure-digest
        that corresponds to a physical message path.  Concrete implementations
        may choose to keep only the digest, not the raw path, for privacy.
        """
        raise NotImplementedError

    @abstractmethod
    async def remove_keys_for_path(self, physical_path: str) -> int:
        """
        Remove all keys associated with the given physical path.
        Returns the number of keys removed.
        """
        raise NotImplementedError

    @abstractmethod
    async def remove_key(self, kid: str) -> bool:
        """
        Remove a specific key by its key ID.
        Returns True if the key was found and removed, False if not found.
        """
        raise NotImplementedError

    async def add_keys(self, keys: list[dict], physical_path: str) -> None:
        from ..crypto.jwk_validation import JWKValidationError, validate_jwk_complete

        logger.debug(
            "adding_keys",
            from_physical_path=physical_path,
            key_ids=[key["kid"] for key in keys if "kid" in key],
        )
        sid = secure_digest(physical_path)
        for key_info in keys:
            # Validate JWK structure and use field
            try:
                validate_jwk_complete(key_info)
            except JWKValidationError as e:
                logger.warning(
                    "rejected_invalid_jwk",
                    kid=key_info.get("kid", "unknown"),
                    from_physical_path=physical_path,
                    error=str(e),
                )
                continue  # Skip invalid keys

            kid: str = key_info["kid"]
            key_info_ext = dict(key_info)
            key_info_ext["sid"] = sid
            key_info_ext["physical_path"] = physical_path
            await self.add_key(kid, key_info_ext)
            logger.debug(
                "added_key",
                kid=kid,
                from_physical_path=physical_path,
                use=key_info.get("use", "unknown"),
            )


_instance: Optional[KeyStore] = None


def get_key_store() -> KeyStore:
    global _instance
    if _instance is None:
        # raise RuntimeError(
        #     "KeyStore singleton not initialized! "
        #     "Did you forget to call KeyStoreFactory.create()?"
        # )
        from naylence.fame.security.keys.in_memory_key_store import InMemoryKeyStore

        _instance = InMemoryKeyStore()
    return _instance
