"""
SQLite storage provider implementation based on EncryptedStorageProviderBase.

This provider stores data in SQLite databases with optional encryption support.
"""

from __future__ import annotations

import asyncio
import sqlite3
from pathlib import Path
from typing import Dict, Generic, Optional, Type, TypeVar

from pydantic import BaseModel

from naylence.fame.security.credential.credential_provider import CredentialProvider
from naylence.fame.storage.encrypted_storage_provider_base import (
    EncryptedStorageProviderBase,
)
from naylence.fame.storage.key_value_store import KeyValueStore
from naylence.fame.util.util import camel_to_snake_case

V = TypeVar("V", bound=BaseModel)


class SQLiteKeyValueStore(KeyValueStore[V], Generic[V]):
    """
    SQLite-based key-value store implementation.
    """

    def __init__(self, db_path: str, table_name: str, model_cls: Type[V]):
        self._db_path = db_path
        self._table_name = table_name
        self._model_cls = model_cls
        self._lock = asyncio.Lock()
        self._init_db()

    def _init_db(self) -> None:
        """Initialize the SQLite database and table."""
        # Ensure directory exists
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)

        with sqlite3.connect(self._db_path) as conn:
            conn.execute(
                f"""
                CREATE TABLE IF NOT EXISTS {self._table_name} (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """
            )

            # Create trigger to update the updated_at timestamp
            conn.execute(
                f"""
                CREATE TRIGGER IF NOT EXISTS update_{self._table_name}_timestamp 
                AFTER UPDATE ON {self._table_name}
                BEGIN
                    UPDATE {self._table_name} SET updated_at = CURRENT_TIMESTAMP WHERE key = NEW.key;
                END
            """
            )

            conn.commit()

    async def set(self, key: str, value: V) -> None:
        """Store a value in the SQLite database."""
        json_data = value.model_dump_json(by_alias=True, exclude_none=True)

        async with self._lock:
            with sqlite3.connect(self._db_path) as conn:
                conn.execute(
                    f"INSERT OR REPLACE INTO {self._table_name} (key, value) VALUES (?, ?)",
                    (key, json_data),
                )
                conn.commit()

    async def update(self, key: str, value: V) -> None:
        """Store a value in the SQLite database."""
        json_data = value.model_dump_json(by_alias=True, exclude_none=True)

        async with self._lock:
            with sqlite3.connect(self._db_path) as conn:
                cursor = conn.execute(
                    f"UPDATE {self._table_name} SET value = ? WHERE key = ?",
                    (json_data, key),
                )
                updated_count = cursor.rowcount
                if updated_count == 0:
                    raise KeyError(f"Key '{key}' not found for update.")
                conn.commit()

    async def get(self, key: str) -> Optional[V]:
        """Retrieve a value from the SQLite database."""
        async with self._lock:
            with sqlite3.connect(self._db_path) as conn:
                cursor = conn.execute(f"SELECT value FROM {self._table_name} WHERE key = ?", (key,))
                row = cursor.fetchone()

                if row is None:
                    return None

                return self._model_cls.model_validate_json(row[0])

    async def delete(self, key: str) -> None:
        """Delete a value from the SQLite database."""
        async with self._lock:
            with sqlite3.connect(self._db_path) as conn:
                conn.execute(f"DELETE FROM {self._table_name} WHERE key = ?", (key,))
                conn.commit()

    async def list(self) -> Dict[str, V]:
        """List all key-value pairs from the SQLite database."""
        async with self._lock:
            with sqlite3.connect(self._db_path) as conn:
                cursor = conn.execute(f"SELECT key, value FROM {self._table_name}")
                rows = cursor.fetchall()

                result = {}
                for key, value_json in rows:
                    try:
                        result[key] = self._model_cls.model_validate_json(value_json)
                    except Exception:
                        # Skip corrupted entries
                        continue

                return result


class SQLiteStorageProvider(EncryptedStorageProviderBase):
    """
    SQLite storage provider with optional encryption support.

    This provider stores data in SQLite databases on disk. When encryption is enabled,
    the data is encrypted before being stored in the database.
    """

    def __init__(
        self,
        db_directory: str,
        is_encrypted: bool = False,
        master_key_provider: Optional[CredentialProvider] = None,
        is_cached: bool = False,
    ):
        """
        Initialize the SQLite storage provider.

        Args:
            db_directory: Directory where SQLite database files will be stored
            is_encrypted: Whether to encrypt stored data
            master_key_provider: Provider for encryption keys (required if is_encrypted=True)
            is_cached: Whether to enable in-memory caching of decrypted values
        """
        super().__init__(
            is_encrypted=is_encrypted,
            master_key_provider=master_key_provider,
            enable_caching=is_cached,
        )

        self._db_directory = Path(db_directory)
        self._db_directory.mkdir(parents=True, exist_ok=True)

        # Cache for store instances
        self._stores: Dict[tuple, SQLiteKeyValueStore] = {}

    async def _get_underlying_kv_store(
        self,
        model_cls: Type[V],
        *,
        namespace: str | None = None,
    ) -> KeyValueStore[V]:
        """
        Get the underlying SQLite key-value store for the given model class and namespace.
        """
        # Convert class name to snake_case
        snake_case_name = camel_to_snake_case(model_cls.__name__)

        # Create a unique cache key
        cache_key = (snake_case_name, namespace)

        if cache_key not in self._stores:
            # Generate database file name based on namespace and model class
            if namespace:
                db_name = f"{namespace}_{snake_case_name}.db"
            else:
                db_name = f"{snake_case_name}.db"

            db_path = str(self._db_directory / db_name)

            # Generate table name (already in snake_case)
            table_name = f"kv_{snake_case_name}"

            # Create the store
            self._stores[cache_key] = SQLiteKeyValueStore(
                db_path=db_path, table_name=table_name, model_cls=model_cls
            )

        return self._stores[cache_key]
