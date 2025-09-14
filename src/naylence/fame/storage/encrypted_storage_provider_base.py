"""
Base abstract class for encrypted storage providers.

This module provides a base class that handles encryption/decryption transparently
using a configurable master key, so individual storage provider implementations
don't need to implement encryption logic separately.
"""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from typing import Callable, Dict, Generic, Optional, Type, TypeVar

from pydantic import BaseModel

from naylence.fame.security.credential.credential_provider import CredentialProvider
from naylence.fame.storage.key_value_store import KeyValueStore
from naylence.fame.storage.storage_provider import StorageProvider

V = TypeVar("V", bound=BaseModel)

# Type alias for master key provider function
MasterKeyProvider = Callable[[], bytes]


class EncryptionManager(ABC):
    """Abstract interface for encryption/decryption operations."""

    @abstractmethod
    async def encrypt(self, plaintext: bytes, key: bytes) -> bytes:
        """Encrypt plaintext using the provided key."""
        raise NotImplementedError

    @abstractmethod
    async def decrypt(self, ciphertext: bytes, key: bytes) -> bytes:
        """Decrypt ciphertext using the provided key."""
        raise NotImplementedError


class AESEncryptionManager(EncryptionManager):
    """AES-GCM encryption manager implementation."""

    async def encrypt(self, plaintext: bytes, key: bytes) -> bytes:
        """Encrypt using AES-GCM."""
        try:
            import os

            from cryptography.hazmat.primitives.ciphers.aead import AESGCM

            # Generate a random 96-bit IV for GCM
            iv = os.urandom(12)

            # Use first 32 bytes of key for AES-256
            aes_key = key[:32] if len(key) >= 32 else key.ljust(32, b"\x00")

            aesgcm = AESGCM(aes_key)
            ciphertext = aesgcm.encrypt(iv, plaintext, None)

            # Prepend IV to ciphertext
            return iv + ciphertext

        except ImportError:
            raise RuntimeError(
                "AES encryption requires the 'cryptography' package. "
                "Install it with: pip install cryptography"
            )

    async def decrypt(self, ciphertext: bytes, key: bytes) -> bytes:
        """Decrypt using AES-GCM."""
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM

            if len(ciphertext) < 12:
                raise ValueError("Ciphertext too short to contain IV")

            # Extract IV and ciphertext
            iv = ciphertext[:12]
            actual_ciphertext = ciphertext[12:]

            # Use first 32 bytes of key for AES-256
            aes_key = key[:32] if len(key) >= 32 else key.ljust(32, b"\x00")

            aesgcm = AESGCM(aes_key)
            return aesgcm.decrypt(iv, actual_ciphertext, None)

        except ImportError:
            raise RuntimeError(
                "AES decryption requires the 'cryptography' package. "
                "Install it with: pip install cryptography"
            )


class EncryptedKeyValueStore(KeyValueStore[V], Generic[V]):
    """
    A key-value store wrapper that encrypts/decrypts values transparently.
    """

    def __init__(
        self,
        underlying_store: KeyValueStore[EncryptedValue],
        master_key_provider: CredentialProvider,
        encryption_manager: EncryptionManager,
        model_cls: Type[V],
        enable_caching: bool = False,
    ):
        self._underlying_store = underlying_store
        self._master_key_provider = master_key_provider
        self._encryption_manager = encryption_manager
        self._model_cls = model_cls
        self._enable_caching = enable_caching

        # Cache for decrypted values
        self._cache: Dict[str, V] = {} if enable_caching else {}
        self._cache_enabled = enable_caching
        self._cache_lock: Optional[asyncio.Lock] = asyncio.Lock() if enable_caching else None

    async def _clear_cache(self) -> None:
        """Clear the entire cache."""
        if self._cache_enabled and self._cache_lock:
            async with self._cache_lock:
                self._cache.clear()

    async def _cache_get(self, key: str) -> Optional[V]:
        """Get a value from cache if caching is enabled."""
        if not self._cache_enabled or not self._cache_lock:
            return None
        async with self._cache_lock:
            return self._cache.get(key)

    async def _cache_set(self, key: str, value: V) -> None:
        """Set a value in cache if caching is enabled."""
        if self._cache_enabled and self._cache_lock:
            async with self._cache_lock:
                self._cache[key] = value

    async def _cache_delete(self, key: str) -> None:
        """Delete a value from cache if caching is enabled."""
        if self._cache_enabled and self._cache_lock:
            async with self._cache_lock:
                self._cache.pop(key, None)

    async def set(self, key: str, value: V) -> None:
        # Serialize to JSON
        json_data = value.model_dump_json(by_alias=True, exclude_none=True)
        plaintext = json_data.encode("utf-8")

        # Encrypt
        master_key = await self._master_key_provider.get()
        if not master_key:
            raise ValueError("Master key provider must return a valid key")

        if isinstance(master_key, str):
            master_key = master_key.encode("utf-8")
        ciphertext = await self._encryption_manager.encrypt(plaintext, master_key)

        # Create encrypted wrapper model (use static key_id since we simplified)
        encrypted_value = EncryptedValue(
            key_id="default",
            ciphertext=ciphertext.hex(),  # Store as hex string
            algorithm="AES-GCM",
        )

        # Store the encrypted wrapper
        await self._underlying_store.set(key, encrypted_value)

        # Update cache with the new value and clear other entries on write
        if self._cache_enabled:
            await self._cache_set(key, value)
            # Note: We could implement more sophisticated cache invalidation
            # For now, we keep the updated value but could clear all on any write

    async def get(self, key: str) -> Optional[V]:
        # Check cache first
        cached_value = await self._cache_get(key)
        if cached_value is not None:
            return cached_value

        # Get encrypted wrapper
        encrypted_value = await self._underlying_store.get(key)
        if encrypted_value is None:
            return None

        if not isinstance(encrypted_value, EncryptedValue):
            raise ValueError(f"Expected EncryptedValue, got {type(encrypted_value)}")

        # Decrypt
        master_key = await self._master_key_provider.get()
        assert master_key is not None, "Master key provider must return a valid key"
        if isinstance(master_key, str):
            master_key = master_key.encode("utf-8")
        ciphertext = bytes.fromhex(encrypted_value.ciphertext)
        plaintext = await self._encryption_manager.decrypt(ciphertext, master_key)

        # Deserialize from JSON
        json_data = plaintext.decode("utf-8")
        result = self._model_cls.model_validate_json(json_data)

        # Cache the result
        await self._cache_set(key, result)

        return result

    async def delete(self, key: str) -> None:
        await self._underlying_store.delete(key)

        # Remove from cache
        await self._cache_delete(key)

    async def list(self) -> Dict[str, V]:
        encrypted_items = await self._underlying_store.list()
        result = {}

        master_key = await self._master_key_provider.get()
        assert master_key is not None, "Master key provider must return a valid key"
        if isinstance(master_key, str):
            master_key = master_key.encode("utf-8")

        for k, encrypted_value in encrypted_items.items():
            if not isinstance(encrypted_value, EncryptedValue):
                continue

            # Check cache first
            cached_value = await self._cache_get(k)
            if cached_value is not None:
                result[k] = cached_value
                continue

            try:
                # Decrypt each item
                ciphertext = bytes.fromhex(encrypted_value.ciphertext)
                plaintext = await self._encryption_manager.decrypt(ciphertext, master_key)
                json_data = plaintext.decode("utf-8")
                decrypted_value = self._model_cls.model_validate_json(json_data)
                result[k] = decrypted_value

                # Cache the result
                await self._cache_set(k, decrypted_value)
            except Exception:
                # Skip corrupted entries
                continue

        return result


class EncryptedValue(BaseModel):
    """Model for storing encrypted values with metadata."""

    key_id: str  # Identifier of the key used for encryption
    ciphertext: str  # Hex-encoded ciphertext
    algorithm: str  # Encryption algorithm used (e.g., "AES-GCM")


class EncryptedStorageProviderBase(StorageProvider, ABC):
    """
    Abstract base class for encrypted storage providers.

    This class handles encryption/decryption transparently using a configurable
    master key, so subclasses only need to implement the underlying storage logic.
    Encryption can be toggled on/off with the is_encrypted parameter.
    Caching can be enabled to improve read performance.
    """

    def __init__(
        self,
        is_encrypted: bool = True,
        master_key_provider: Optional[CredentialProvider] = None,
        encryption_manager: Optional[EncryptionManager] = None,
        enable_caching: bool = False,
    ):
        self._is_encrypted = is_encrypted
        self._enable_caching = enable_caching

        if is_encrypted:
            if master_key_provider is None:
                raise ValueError("master_key_provider is required when is_encrypted=True")
            self._master_key_provider = master_key_provider
            self._encryption_manager = encryption_manager or AESEncryptionManager()
        else:
            self._master_key_provider = None
            self._encryption_manager = None

    async def get_kv_store(
        self,
        model_cls: Type[V],
        namespace: str,
    ) -> KeyValueStore[V]:
        """
        Get a key-value store for the given model class and namespace.

        If encryption is enabled, this method creates an encrypted wrapper around
        the underlying storage. If encryption is disabled, it returns the underlying
        storage directly.
        """
        if not self._is_encrypted:
            # Return the underlying store directly (no encryption)
            return await self._get_underlying_kv_store(model_cls, namespace)

        # Encryption is enabled - wrap the underlying store
        underlying_store = await self._get_underlying_kv_store(
            EncryptedValue,  # type: ignore - Store encrypted values
            namespace,
        )

        # Wrap it with encryption
        return EncryptedKeyValueStore(
            underlying_store=underlying_store,  # type: ignore - We know this is KeyValueStore[EncryptedValue]
            master_key_provider=self._master_key_provider,  # type: ignore - checked above
            encryption_manager=self._encryption_manager,  # type: ignore - checked above
            model_cls=model_cls,
            enable_caching=self._enable_caching,
        )

    @abstractmethod
    async def _get_underlying_kv_store(
        self,
        model_cls: Type[V],
        namespace: str,
    ) -> KeyValueStore[V]:
        """
        Get the underlying key-value store.

        Subclasses must implement this to provide the actual storage mechanism
        (e.g., file system, database, cloud storage, etc.).

        The model_cls parameter will be:
        - EncryptedValue when encryption is enabled (to store encrypted data)
        - The actual model class when encryption is disabled (to store plain data)
        """
        raise NotImplementedError
