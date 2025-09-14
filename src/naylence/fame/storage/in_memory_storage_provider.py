from typing import Dict, Tuple, Type, TypeVar

from pydantic import BaseModel

from naylence.fame.storage.in_memory_key_value_store import (
    InMemoryKVStore,
)  # existing impl

V = TypeVar("V", bound=BaseModel)


class InMemoryStorageProvider:
    """
    Process-local, non-durable provider
    """

    def __init__(self) -> None:
        # (namespace, model_cls) → store
        self._stores: Dict[Tuple[str, Type], InMemoryKVStore] = {}

    async def get_kv_store(self, model_cls: Type[V], namespace: str):
        key = (namespace, model_cls)
        if key not in self._stores:
            self._stores[key] = InMemoryKVStore(model_cls)
        return self._stores[key]
