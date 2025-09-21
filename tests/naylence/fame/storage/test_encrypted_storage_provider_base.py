"""Tests for encrypted_storage_provider_base.py coverage improvement."""

from typing import Dict, Optional, Type, TypeVar
from unittest.mock import AsyncMock, patch

import pytest
from pydantic import BaseModel

from naylence.fame.security.credential.credential_provider import CredentialProvider
from naylence.fame.storage.encrypted_storage_provider_base import (
    AESEncryptionManager,
    EncryptedKeyValueStore,
    EncryptedStorageProviderBase,
    EncryptedValue,
    EncryptionManager,
)
from naylence.fame.storage.key_value_store import KeyValueStore

V = TypeVar("V", bound=BaseModel)


class TestData(BaseModel):
    """Test model for storage."""

    id: str
    name: str
    value: int = 0


# Prevent pytest from collecting this as a test class
TestData.__test__ = False


class MockCredentialProvider(CredentialProvider):
    """Mock credential provider for testing."""

    def __init__(self, key: bytes):
        self.key = key

    async def get(self) -> bytes:
        return self.key


class MockKeyValueStore(KeyValueStore[V]):
    """Mock key-value store for testing."""

    def __init__(self):
        self.data: Dict[str, V] = {}

    async def set(self, key: str, value: V) -> None:
        self.data[key] = value

    async def get(self, key: str) -> Optional[V]:
        return self.data.get(key)

    async def delete(self, key: str) -> None:
        self.data.pop(key, None)

    async def list(self) -> Dict[str, V]:
        return self.data.copy()


class TestEncryptionManager(EncryptionManager):
    """Test encryption manager for testing edge cases."""

    def __init__(self, should_fail: bool = False):
        self.should_fail = should_fail

    async def encrypt(self, plaintext: bytes, key: bytes) -> bytes:
        if self.should_fail:
            raise Exception("Encryption failed")
        # Simple "encryption" for testing
        return b"encrypted:" + plaintext

    async def decrypt(self, ciphertext: bytes, key: bytes) -> bytes:
        if self.should_fail:
            raise Exception("Decryption failed")
        # Simple "decryption" for testing
        if ciphertext.startswith(b"encrypted:"):
            return ciphertext[10:]
        raise ValueError("Invalid ciphertext")


# Prevent pytest from collecting this as a test class
TestEncryptionManager.__test__ = False


class TestStorageProvider(EncryptedStorageProviderBase):
    """Test storage provider implementation."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.stores: Dict[str, KeyValueStore] = {}

    async def _get_underlying_kv_store(
        self,
        model_cls: Type[V],
        namespace: str,
    ) -> KeyValueStore[V]:
        key = f"{model_cls.__name__}:{namespace}"
        if key not in self.stores:
            self.stores[key] = MockKeyValueStore()
        return self.stores[key]


# Prevent pytest from collecting this as a test class
TestStorageProvider.__test__ = False


class TestAESEncryptionManager:
    """Test the AESEncryptionManager class - covers lines 63-64, 75, 87-88."""

    @pytest.mark.asyncio
    async def test_encrypt_success(self):
        """Test successful AES encryption."""
        manager = AESEncryptionManager()
        plaintext = b"test message"
        key = b"0" * 32  # 32-byte key

        # Should not raise and should return bytes
        result = await manager.encrypt(plaintext, key)
        assert isinstance(result, bytes)
        assert len(result) > len(plaintext)  # Should be longer due to IV

    @pytest.mark.asyncio
    async def test_encrypt_short_key(self):
        """Test encryption with short key (gets padded)."""
        manager = AESEncryptionManager()
        plaintext = b"test message"
        short_key = b"short"  # Less than 32 bytes

        # Should pad key and work
        result = await manager.encrypt(plaintext, short_key)
        assert isinstance(result, bytes)

    @pytest.mark.asyncio
    async def test_encrypt_import_error(self):
        """Test encryption when cryptography package is missing - line 63-64."""
        manager = AESEncryptionManager()

        with patch("builtins.__import__", side_effect=ImportError("No module named 'cryptography'")):
            with pytest.raises(RuntimeError, match="AES encryption requires the 'cryptography' package"):
                await manager.encrypt(b"test", b"key" * 8)

    @pytest.mark.asyncio
    async def test_decrypt_success(self):
        """Test successful AES decryption."""
        manager = AESEncryptionManager()
        plaintext = b"test message"
        key = b"0" * 32

        # Encrypt then decrypt
        ciphertext = await manager.encrypt(plaintext, key)
        result = await manager.decrypt(ciphertext, key)

        assert result == plaintext

    @pytest.mark.asyncio
    async def test_decrypt_short_ciphertext(self):
        """Test decryption with ciphertext too short for IV - line 75."""
        manager = AESEncryptionManager()
        key = b"0" * 32
        short_ciphertext = b"short"  # Less than 12 bytes

        with pytest.raises(ValueError, match="Ciphertext too short to contain IV"):
            await manager.decrypt(short_ciphertext, key)

    @pytest.mark.asyncio
    async def test_decrypt_import_error(self):
        """Test decryption when cryptography package is missing - line 87-88."""
        manager = AESEncryptionManager()

        with patch("builtins.__import__", side_effect=ImportError("No module named 'cryptography'")):
            with pytest.raises(RuntimeError, match="AES decryption requires the 'cryptography' package"):
                await manager.decrypt(b"0" * 20, b"key" * 8)


class TestEncryptedKeyValueStore:
    """Test the EncryptedKeyValueStore class - covers lines 120-122, 128-129, 134-135, 139-141."""

    @pytest.fixture
    async def encrypted_store(self):
        """Create an encrypted key-value store for testing."""
        underlying_store = MockKeyValueStore()
        key_provider = MockCredentialProvider(b"test_key" * 4)
        encryption_manager = TestEncryptionManager()

        return EncryptedKeyValueStore(
            underlying_store=underlying_store,
            master_key_provider=key_provider,
            encryption_manager=encryption_manager,
            model_cls=TestData,
            enable_caching=True,
        )

    @pytest.fixture
    async def encrypted_store_no_cache(self):
        """Create an encrypted key-value store without caching."""
        underlying_store = MockKeyValueStore()
        key_provider = MockCredentialProvider(b"test_key" * 4)
        encryption_manager = TestEncryptionManager()

        return EncryptedKeyValueStore(
            underlying_store=underlying_store,
            master_key_provider=key_provider,
            encryption_manager=encryption_manager,
            model_cls=TestData,
            enable_caching=False,
        )

    @pytest.mark.asyncio
    async def test_clear_cache_enabled(self, encrypted_store):
        """Test _clear_cache when caching is enabled - lines 120-122."""
        # Add something to cache first
        await encrypted_store._cache_set("test_key", TestData(id="1", name="test"))
        assert len(encrypted_store._cache) == 1

        # Clear cache
        await encrypted_store._clear_cache()
        assert len(encrypted_store._cache) == 0

    @pytest.mark.asyncio
    async def test_clear_cache_disabled(self, encrypted_store_no_cache):
        """Test _clear_cache when caching is disabled."""
        # Should not raise error even with no caching
        await encrypted_store_no_cache._clear_cache()

    @pytest.mark.asyncio
    async def test_cache_get_enabled(self, encrypted_store):
        """Test _cache_get when caching is enabled - lines 128-129."""
        test_data = TestData(id="1", name="test")
        await encrypted_store._cache_set("test_key", test_data)

        result = await encrypted_store._cache_get("test_key")
        assert result == test_data

    @pytest.mark.asyncio
    async def test_cache_get_disabled(self, encrypted_store_no_cache):
        """Test _cache_get when caching is disabled."""
        result = await encrypted_store_no_cache._cache_get("test_key")
        assert result is None

    @pytest.mark.asyncio
    async def test_cache_set_enabled(self, encrypted_store):
        """Test _cache_set when caching is enabled - lines 134-135."""
        test_data = TestData(id="1", name="test")
        await encrypted_store._cache_set("test_key", test_data)

        assert encrypted_store._cache["test_key"] == test_data

    @pytest.mark.asyncio
    async def test_cache_set_disabled(self, encrypted_store_no_cache):
        """Test _cache_set when caching is disabled."""
        test_data = TestData(id="1", name="test")
        # Should not raise error even with no caching
        await encrypted_store_no_cache._cache_set("test_key", test_data)

    @pytest.mark.asyncio
    async def test_cache_delete_enabled(self, encrypted_store):
        """Test _cache_delete when caching is enabled - lines 139-141."""
        test_data = TestData(id="1", name="test")
        await encrypted_store._cache_set("test_key", test_data)
        assert "test_key" in encrypted_store._cache

        await encrypted_store._cache_delete("test_key")
        assert "test_key" not in encrypted_store._cache

    @pytest.mark.asyncio
    async def test_cache_delete_disabled(self, encrypted_store_no_cache):
        """Test _cache_delete when caching is disabled."""
        # Should not raise error even with no caching
        await encrypted_store_no_cache._cache_delete("test_key")

    @pytest.mark.asyncio
    async def test_set_string_master_key(self, encrypted_store_no_cache):
        """Test set method with string master key - line 151."""
        # Create store with string key provider
        key_provider = MockCredentialProvider(b"string_key")
        # Mock to return string instead of bytes
        key_provider.get = AsyncMock(return_value="string_key")

        encrypted_store_no_cache._master_key_provider = key_provider

        test_data = TestData(id="1", name="test")
        await encrypted_store_no_cache.set("test_key", test_data)

        # Should work - string gets encoded to bytes
        stored_encrypted = await encrypted_store_no_cache._underlying_store.get("test_key")
        assert isinstance(stored_encrypted, EncryptedValue)

    @pytest.mark.asyncio
    async def test_set_none_master_key(self, encrypted_store_no_cache):
        """Test set method with None master key - line 154."""
        # Mock to return None
        encrypted_store_no_cache._master_key_provider.get = AsyncMock(return_value=None)

        test_data = TestData(id="1", name="test")
        with pytest.raises(ValueError, match="Master key provider must return a valid key"):
            await encrypted_store_no_cache.set("test_key", test_data)

    @pytest.mark.asyncio
    async def test_get_cache_hit(self, encrypted_store):
        """Test get method with cache hit - line 169."""
        test_data = TestData(id="1", name="test")
        await encrypted_store._cache_set("test_key", test_data)

        # Should return from cache without hitting underlying store
        result = await encrypted_store.get("test_key")
        assert result == test_data

    @pytest.mark.asyncio
    async def test_get_not_found(self, encrypted_store_no_cache):
        """Test get method when key not found - line 177."""
        result = await encrypted_store_no_cache.get("nonexistent_key")
        assert result is None

    @pytest.mark.asyncio
    async def test_get_invalid_encrypted_value(self, encrypted_store_no_cache):
        """Test get method with invalid EncryptedValue type - line 185."""
        # Store something that's not an EncryptedValue
        await encrypted_store_no_cache._underlying_store.set("test_key", "not_encrypted_value")

        with pytest.raises(ValueError, match="Expected EncryptedValue, got"):
            await encrypted_store_no_cache.get("test_key")

    @pytest.mark.asyncio
    async def test_get_string_master_key_get(self, encrypted_store_no_cache):
        """Test get method with string master key - line 191."""
        # First set a value normally
        test_data = TestData(id="1", name="test")
        await encrypted_store_no_cache.set("test_key", test_data)

        # Then mock to return string for get
        key_provider = MockCredentialProvider(b"string_key")
        key_provider.get = AsyncMock(return_value="string_key")
        encrypted_store_no_cache._master_key_provider = key_provider

        # Should work - string gets encoded to bytes
        result = await encrypted_store_no_cache.get("test_key")
        assert result.id == "1"

    @pytest.mark.asyncio
    async def test_list_cache_hits(self, encrypted_store):
        """Test list method with cache hits - lines 205-208."""
        # Set up test data
        test_data1 = TestData(id="1", name="test1")
        test_data2 = TestData(id="2", name="test2")

        # Store normally first
        await encrypted_store.set("key1", test_data1)
        await encrypted_store.set("key2", test_data2)

        # Clear cache and add one item back to cache
        await encrypted_store._clear_cache()
        await encrypted_store._cache_set("key1", test_data1)

        # List should use cache for key1 and decrypt key2
        result = await encrypted_store.list()

        assert len(result) == 2
        assert result["key1"] == test_data1
        assert result["key2"] == test_data2

    @pytest.mark.asyncio
    async def test_list_non_encrypted_values(self, encrypted_store_no_cache):
        """Test list method with non-EncryptedValue items - lines 211-243."""
        # Mix valid and invalid items in underlying store
        # hex for encrypted:{"id":"1","name":"test","value":0}
        hex_data = (
            "656e637279707465643a7b226964223a2231222c226e616d65223a2274657374222c2276616c7565223a307d"
        )
        encrypted_value = EncryptedValue(key_id="test", ciphertext=hex_data, algorithm="test")

        await encrypted_store_no_cache._underlying_store.set("valid_key", encrypted_value)
        await encrypted_store_no_cache._underlying_store.set("invalid_key", "not_encrypted_value")

        result = await encrypted_store_no_cache.list()

        # Should only include valid encrypted values
        assert len(result) == 1
        assert "valid_key" in result
        assert "invalid_key" not in result

    @pytest.mark.asyncio
    async def test_list_corrupted_entries(self, encrypted_store_no_cache):
        """Test list method with corrupted entries that cause exceptions."""
        # Create store with failing encryption manager for decrypt
        failing_encryption = TestEncryptionManager(should_fail=True)
        encrypted_store_no_cache._encryption_manager = failing_encryption

        # Add encrypted value that will fail to decrypt
        encrypted_value = EncryptedValue(key_id="test", ciphertext="invalid_hex_data", algorithm="test")

        await encrypted_store_no_cache._underlying_store.set("corrupted_key", encrypted_value)

        # Should skip corrupted entries and continue
        result = await encrypted_store_no_cache.list()
        assert len(result) == 0  # Corrupted entry should be skipped

    @pytest.mark.asyncio
    async def test_list_string_master_key(self, encrypted_store_no_cache):
        """Test list method with string master key - line 276."""
        # Mock to return string
        key_provider = MockCredentialProvider(b"string_key")
        key_provider.get = AsyncMock(return_value="string_key")
        encrypted_store_no_cache._master_key_provider = key_provider

        # Add some test data first
        hex_data = (
            "656e637279707465643a7b226964223a2231222c226e616d65223a2274657374222c2276616c7565223a307d"
        )
        encrypted_value = EncryptedValue(key_id="test", ciphertext=hex_data, algorithm="test")

        await encrypted_store_no_cache._underlying_store.set("test_key", encrypted_value)

        # Should work - string gets encoded to bytes
        result = await encrypted_store_no_cache.list()
        assert len(result) == 1


class TestEncryptedStorageProviderBase:
    """Test the EncryptedStorageProviderBase class - additional coverage."""

    @pytest.mark.asyncio
    async def test_get_kv_store_not_encrypted(self):
        """Test get_kv_store when encryption is disabled."""
        provider = TestStorageProvider(is_encrypted=False)

        store = await provider.get_kv_store(TestData, "test_namespace")

        # Should return underlying store directly
        assert isinstance(store, MockKeyValueStore)

    @pytest.mark.asyncio
    async def test_get_kv_store_encrypted_with_caching(self):
        """Test get_kv_store when encryption is enabled with caching."""
        key_provider = MockCredentialProvider(b"test_key" * 4)
        provider = TestStorageProvider(
            is_encrypted=True, master_key_provider=key_provider, enable_caching=True
        )

        store = await provider.get_kv_store(TestData, "test_namespace")

        # Should return encrypted wrapper
        assert isinstance(store, EncryptedKeyValueStore)
        assert store._enable_caching is True
        assert store._cache_enabled is True

    def test_init_encrypted_no_key_provider(self):
        """Test initialization with encryption enabled but no key provider."""
        with pytest.raises(ValueError, match="master_key_provider is required when is_encrypted=True"):
            TestStorageProvider(is_encrypted=True, master_key_provider=None)

    def test_init_not_encrypted_defaults(self):
        """Test initialization with encryption disabled."""
        provider = TestStorageProvider(is_encrypted=False)

        assert provider._is_encrypted is False
        assert provider._master_key_provider is None
        assert provider._encryption_manager is None

    def test_init_encrypted_custom_encryption_manager(self):
        """Test initialization with custom encryption manager."""
        key_provider = MockCredentialProvider(b"test_key")
        custom_encryption = TestEncryptionManager()

        provider = TestStorageProvider(
            is_encrypted=True, master_key_provider=key_provider, encryption_manager=custom_encryption
        )

        assert provider._encryption_manager is custom_encryption

    def test_init_encrypted_default_encryption_manager(self):
        """Test initialization with default AES encryption manager."""
        key_provider = MockCredentialProvider(b"test_key")

        provider = TestStorageProvider(is_encrypted=True, master_key_provider=key_provider)

        assert isinstance(provider._encryption_manager, AESEncryptionManager)
