"""
SQLite storage provider implementation based on EncryptedStorageProviderBase.

This provider stores data in SQLite databases with optional encryption support.
"""

from __future__ import annotations

import asyncio
import datetime
import re
import sqlite3
from pathlib import Path
from typing import Any, Callable, Dict, Generic, Optional, Type, TypeVar

from pydantic import BaseModel

from naylence.fame.security.credential.credential_provider import CredentialProvider
from naylence.fame.storage.encrypted_storage_provider_base import (
    EncryptedStorageProviderBase,
)
from naylence.fame.storage.key_value_store import KeyValueStore
from naylence.fame.util.logging import getLogger
from naylence.fame.util.util import camel_to_snake_case

V = TypeVar("V", bound=BaseModel)

logger = getLogger(__name__)


class SQLiteKeyValueStore(KeyValueStore[V], Generic[V]):
    """
    SQLite-based key-value store implementation.
    """

    def __init__(self, db_path: str, table_name: str, model_cls: Type[V], *, auto_recover: bool = True):
        self._db_path = db_path
        self._table_name = table_name
        self._model_cls = model_cls
        self._lock = asyncio.Lock()
        self._auto_recover = auto_recover
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        """
        Open a connection with pragmatic defaults for resilience.
        """
        conn = sqlite3.connect(self._db_path, timeout=30)
        # Improve durability and reduce corruption likelihood
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _is_corruption_error(self, exc: Exception) -> bool:
        """Check if an exception indicates SQLite database corruption."""
        if not isinstance(exc, sqlite3.DatabaseError):
            return False
        msg = str(exc).lower()
        return any(
            phrase in msg
            for phrase in (
                "database disk image is malformed",
                "file is not a database",
                "file is encrypted or is not a database",
            )
        )

    def _quarantine_corrupted_files(self) -> None:
        """
        Move the DB and its sidecar files (-wal, -shm) aside with a timestamp suffix.
        """
        ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        base = Path(self._db_path)
        candidates = [base, Path(str(base) + "-wal"), Path(str(base) + "-shm")]
        for p in candidates:
            if p.exists():
                try:
                    p.rename(p.with_name(p.name + f".corrupt.{ts}"))
                except Exception:
                    logger.exception("Failed to quarantine file: %s", p)
        logger.warning("quarantined_corrupted_db", path=self._db_path)

    def _recover_corrupted_db(self) -> None:
        """Quarantine corrupted files and recreate the database schema."""
        self._quarantine_corrupted_files()
        # Recreate empty DB and schema
        try:
            with self._connect() as conn:
                self._create_schema(conn)
        except Exception:
            logger.exception("Failed to recreate SQLite schema after corruption at %s", self._db_path)
            raise

    def _execute_with_recovery(self, op: Callable[[sqlite3.Connection], Any]) -> Any:
        """
        Execute an operation, and if corruption is detected, quarantine, rebuild, and retry once.
        """
        try:
            with self._connect() as conn:
                return op(conn)
        except Exception as exc:
            if self._auto_recover and self._is_corruption_error(exc):
                self._recover_corrupted_db()
                with self._connect() as conn:
                    return op(conn)
            raise

    def _create_schema(self, conn: sqlite3.Connection) -> None:
        """Create the table schema and triggers."""
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

    def _init_db(self) -> None:
        """Initialize the SQLite database and table."""
        # Ensure directory exists
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)

        try:
            with self._connect() as conn:
                self._create_schema(conn)
        except Exception as exc:
            if self._auto_recover and self._is_corruption_error(exc):
                logger.warning("detected_corrupted_db", path=self._db_path)
                self._recover_corrupted_db()
            else:
                raise

    async def set(self, key: str, value: V) -> None:
        """Store a value in the SQLite database."""
        json_data = value.model_dump_json(by_alias=True, exclude_none=True)

        async with self._lock:

            def op(conn: sqlite3.Connection) -> None:
                conn.execute(
                    f"INSERT OR REPLACE INTO {self._table_name} (key, value) VALUES (?, ?)",
                    (key, json_data),
                )
                conn.commit()

            self._execute_with_recovery(op)

    async def update(self, key: str, value: V) -> None:
        """Store a value in the SQLite database."""
        json_data = value.model_dump_json(by_alias=True, exclude_none=True)

        async with self._lock:

            def op(conn: sqlite3.Connection) -> None:
                cursor = conn.execute(
                    f"UPDATE {self._table_name} SET value = ? WHERE key = ?",
                    (json_data, key),
                )
                updated_count = cursor.rowcount
                if updated_count == 0:
                    raise KeyError(f"Key '{key}' not found for update.")
                conn.commit()

            self._execute_with_recovery(op)

    async def get(self, key: str) -> Optional[V]:
        """Retrieve a value from the SQLite database."""
        async with self._lock:

            def op(conn: sqlite3.Connection) -> Optional[V]:
                cursor = conn.execute(f"SELECT value FROM {self._table_name} WHERE key = ?", (key,))
                row = cursor.fetchone()

                if row is None:
                    return None

                return self._model_cls.model_validate_json(row[0])

            return self._execute_with_recovery(op)

    async def delete(self, key: str) -> None:
        """Delete a value from the SQLite database."""
        async with self._lock:

            def op(conn: sqlite3.Connection) -> None:
                conn.execute(f"DELETE FROM {self._table_name} WHERE key = ?", (key,))
                conn.commit()

            self._execute_with_recovery(op)

    async def list(self) -> Dict[str, V]:
        """List all key-value pairs from the SQLite database."""
        async with self._lock:

            def op(conn: sqlite3.Connection) -> Dict[str, V]:
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

            return self._execute_with_recovery(op)


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
        self._stores: dict[str, SQLiteKeyValueStore] = {}

    def _sanitize_namespace(self, ns: str) -> str:
        """
        Produce a filesystem/SQLite-friendly name.
        Allows [A-Za-z0-9._-], replaces others with '_', trims/limits length.
        """
        safe = re.sub(r"[^A-Za-z0-9._-]+", "_", ns)
        safe = safe.strip("._-")
        if not safe:
            safe = "ns"
        # keep it reasonably short for filenames
        return safe[:120]

    async def _get_underlying_kv_store(self, model_cls: Type[V], namespace: str) -> KeyValueStore[V]:
        """
        Get the underlying SQLite key-value store for the given model class and namespace.
        """

        cache_key = namespace

        if cache_key not in self._stores:
            # Generate database file name based on namespace and model class
            db_name = f"{namespace}.db"
            db_path = str(self._db_directory / db_name)

            snake_case_name = camel_to_snake_case(model_cls.__name__)
            # Generate table name (already in snake_case)
            table_name = f"kv_{snake_case_name}"

            # Create the store
            self._stores[cache_key] = SQLiteKeyValueStore(
                db_path=db_path, table_name=table_name, model_cls=model_cls
            )

        return self._stores[cache_key]
