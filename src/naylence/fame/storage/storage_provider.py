from __future__ import annotations

from abc import abstractmethod
from typing import Protocol, Type, TypeVar

from pydantic import BaseModel

from naylence.fame.storage.key_value_store import KeyValueStore

V = TypeVar("V", bound=BaseModel)


class StorageProvider(Protocol):
    """
    Umbrella persistence gateway.

    A provider returns **namespaced** `KeyValueStore` instances.  The exact KV
    implementation (Redis, SQLite, S3…) is opaque to callers.
    """

    @abstractmethod
    async def get_kv_store(
        self,
        model_cls: Type[V],
        namespace: str,
    ) -> KeyValueStore[V]:
        """Return (or create) a KV-store bound to *model_cls* in *namespace*."""
