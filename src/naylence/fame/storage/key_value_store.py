from __future__ import annotations

from typing import Dict, Generic, Optional, Protocol, TypeVar

from pydantic import BaseModel

V = TypeVar("V", bound=BaseModel)


class KeyValueStore(Protocol, Generic[V]):
    """
    A simple async key→value store.
    Values of type V are serialized/deserialized by the impl.
    """

    async def set(self, key: str, value: V) -> None: ...
    async def update(self, key: str, value: V) -> None: ...
    async def get(self, key: str) -> Optional[V]: ...
    async def delete(self, key: str) -> None: ...
    async def list(self) -> Dict[str, V]: ...
