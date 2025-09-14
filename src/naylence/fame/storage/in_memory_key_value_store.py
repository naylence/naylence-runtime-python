from __future__ import annotations

from typing import Dict, Generic, Optional, Type, TypeVar

from pydantic import BaseModel

from naylence.fame.storage.key_value_store import KeyValueStore

V = TypeVar("V", bound=BaseModel)


class InMemoryKVStore(KeyValueStore[V], Generic[V]):
    """
    A simple in-memory JSON-backed KV store for Pydantic models of type V.
    """

    def __init__(self, model_cls: Type[V]) -> None:
        # model_cls is *exactly* the V type, not just BaseModel
        self._model_cls: Type[V] = model_cls
        self._data: Dict[str, str] = {}

    async def set(self, key: str, value: V) -> None:
        # `value` is known to be a V → we can call model_dump_json()
        self._data[key] = value.model_dump_json(by_alias=True, exclude_none=True)

    async def update(self, key: str, value: V) -> None:
        if key not in self._data:
            raise KeyError(f"Key '{key}' not found for update.")
        self._data[key] = value.model_dump_json(by_alias=True, exclude_none=True)

    async def get(self, key: str) -> Optional[V]:
        raw = self._data.get(key)
        if raw is None:
            return None
        # model_validate_json on Type[V] returns V
        return self._model_cls.model_validate_json(raw)

    async def delete(self, key: str) -> None:
        self._data.pop(key, None)

    async def list(self) -> Dict[str, V]:
        return {k: self._model_cls.model_validate_json(v) for k, v in self._data.items()}
