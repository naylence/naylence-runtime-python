"""
Test the encrypted storage provider functionality.
"""

import hashlib
from typing import Optional, Type, TypeVar

import pytest
from pydantic import BaseModel

from naylence.fame.security.credential.credential_provider import CredentialProvider
from naylence.fame.storage.encrypted_storage_provider_base import (
    EncryptedStorageProviderBase,
)
from naylence.fame.storage.in_memory_storage_provider import InMemoryStorageProvider
from naylence.fame.storage.key_value_store import KeyValueStore

V = TypeVar("V", bound=BaseModel)


class StaticCredentialProvider(CredentialProvider):
    """Simple credential provider that returns a static key."""

    def __init__(self, key: bytes, key_id: str = "static-key"):
        self._key = key
        self._key_id = key_id

    async def get(self) -> bytes:
        return self._key

    def get_key_id(self) -> str:
        return self._key_id


class EncryptedInMemoryStorageProvider(EncryptedStorageProviderBase):
    """
    Test encrypted storage provider using in-memory storage as the backend.
    """

    def __init__(self, master_password: Optional[str] = None, is_encrypted: bool = True):
        if is_encrypted:
            if master_password is None:
                raise ValueError("master_password is required when is_encrypted=True")
            # Derive a 32-byte key from the password using PBKDF2
            master_key = self._derive_key_from_password(master_password)
            master_key_provider = StaticCredentialProvider(master_key, "memory-key-v1")
        else:
            master_key_provider = None

        # Initialize the encrypted base
        super().__init__(is_encrypted=is_encrypted, master_key_provider=master_key_provider)

        # Create underlying storage
        self._underlying_provider = InMemoryStorageProvider()

    def _derive_key_from_password(self, password: str) -> bytes:
        """Derive a cryptographic key from a password."""
        # Use a fixed salt for simplicity (in production, use a random salt)
        salt = b"naylence-fame-encrypted-storage"
        return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100000)

    async def _get_underlying_kv_store(
        self,
        model_cls: Type[V],
        namespace: str,
    ) -> KeyValueStore[V]:
        """Get the underlying storage for the encrypted wrapper."""
        return await self._underlying_provider.get_kv_store(model_cls, namespace)


class StorageTestData(BaseModel):
    """Test model for storage."""

    id: str
    name: str
    secret: str
    count: int = 0


@pytest.mark.asyncio
async def test_encrypted_storage():
    """Test basic encrypted storage functionality."""
    # Create encrypted storage with a master password
    provider = EncryptedInMemoryStorageProvider("my-secret-password-123")

    # Get a key-value store for our test data
    kv_store = await provider.get_kv_store(StorageTestData, namespace="test")

    # Test data
    test_item = StorageTestData(id="test-1", name="Test Item", secret="This is sensitive data!", count=42)

    # Store the data (should be encrypted)
    await kv_store.set("item1", test_item)

    # Retrieve the data (should be decrypted automatically)
    retrieved = await kv_store.get("item1")
    assert retrieved is not None, "Should retrieve stored item"
    assert retrieved.id == "test-1", "ID should match"
    assert retrieved.name == "Test Item", "Name should match"
    assert retrieved.secret == "This is sensitive data!", "Secret should be decrypted correctly"
    assert retrieved.count == 42, "Count should match"


@pytest.mark.asyncio
async def test_encrypted_storage_missing_keys():
    """Test that non-existent keys return None."""
    provider = EncryptedInMemoryStorageProvider("my-secret-password-123")
    kv_store = await provider.get_kv_store(StorageTestData, namespace="test")

    # Test that non-existent keys return None
    missing = await kv_store.get("nonexistent")
    assert missing is None, "Non-existent key should return None"


@pytest.mark.asyncio
async def test_encrypted_storage_different_types():
    """Test storing different types of data."""
    provider = EncryptedInMemoryStorageProvider("test-password")
    kv_store = await provider.get_kv_store(StorageTestData, namespace="types")

    # Test with various data values
    test_cases = [
        StorageTestData(id="empty", name="", secret="", count=0),
        StorageTestData(
            id="special",
            name="Special Chars: !@#$%^&*()",
            secret="Unicode: café ñoño",
            count=-1,
        ),
        StorageTestData(id="large", name="Large Data", secret="x" * 1000, count=999999),
    ]

    for i, test_item in enumerate(test_cases):
        key = f"item_{i}"
        await kv_store.set(key, test_item)
        retrieved = await kv_store.get(key)

        assert retrieved is not None, f"Should retrieve item {i}"
        assert retrieved.id == test_item.id, f"ID should match for item {i}"
        assert retrieved.name == test_item.name, f"Name should match for item {i}"
        assert retrieved.secret == test_item.secret, f"Secret should match for item {i}"
        assert retrieved.count == test_item.count, f"Count should match for item {i}"


@pytest.mark.asyncio
async def test_encrypted_storage_multiple_namespaces():
    """Test that different namespaces are isolated."""
    provider = EncryptedInMemoryStorageProvider("test-password")

    # Get stores for different namespaces
    store1 = await provider.get_kv_store(StorageTestData, namespace="ns1")
    store2 = await provider.get_kv_store(StorageTestData, namespace="ns2")

    # Store data in both namespaces using the same key
    data1 = StorageTestData(id="1", name="Namespace 1", secret="Secret 1", count=1)
    data2 = StorageTestData(id="2", name="Namespace 2", secret="Secret 2", count=2)

    await store1.set("shared_key", data1)
    await store2.set("shared_key", data2)

    # Retrieve and verify they're different
    retrieved1 = await store1.get("shared_key")
    retrieved2 = await store2.get("shared_key")

    assert retrieved1 is not None and retrieved1.id == "1", "Namespace 1 should have its own data"
    assert retrieved2 is not None and retrieved2.id == "2", "Namespace 2 should have its own data"
    assert retrieved1.secret != retrieved2.secret, "Namespaces should be isolated"


@pytest.mark.asyncio
async def test_encrypted_storage_update_operations():
    """Test updating existing items."""
    provider = EncryptedInMemoryStorageProvider("test-password")
    kv_store = await provider.get_kv_store(StorageTestData, namespace="updates")

    # Store initial data
    original = StorageTestData(id="update_test", name="Original", secret="Original Secret", count=1)
    await kv_store.set("update_key", original)

    # Update the data
    updated = StorageTestData(id="update_test", name="Updated", secret="Updated Secret", count=2)
    await kv_store.set("update_key", updated)

    # Retrieve and verify update
    retrieved = await kv_store.get("update_key")
    assert retrieved is not None, "Should retrieve updated item"
    assert retrieved.name == "Updated", "Name should be updated"
    assert retrieved.secret == "Updated Secret", "Secret should be updated"
    assert retrieved.count == 2, "Count should be updated"
