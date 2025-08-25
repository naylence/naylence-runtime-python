from typing import Any, Iterable, Protocol


class KeyProvider(Protocol):
    async def get_key(self, kid: str) -> dict[str, Any]: ...

    async def get_keys_for_path(self, physical_path: str) -> Iterable[dict[str, Any]]: ...


def get_key_provider() -> KeyProvider:
    """Get the key provider instance (returns the key store)."""
    from naylence.fame.security.keys.key_store import get_key_store

    return get_key_store()
