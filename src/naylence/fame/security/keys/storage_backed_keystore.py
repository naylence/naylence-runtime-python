from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Iterable

from pydantic import BaseModel, Field

from naylence.fame.security.keys.key_store import KeyStore
from naylence.fame.storage.key_value_store import KeyValueStore
from naylence.fame.storage.storage_provider import StorageProvider
from naylence.fame.util import logging

logger = logging.getLogger(__name__)


class JWKEntry(BaseModel):
    kid: str
    jwk: dict[str, Any]  # as received
    sid: str | None = None
    physical_path: str | None = None
    inserted_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class StorageBackedKeyStore(KeyStore):
    def __init__(self, kv_store: KeyValueStore[JWKEntry], **kwargs):
        super().__init__(**kwargs)
        self._kv: KeyValueStore[JWKEntry] = kv_store
        logger.debug("created_storage_backed_keystore")

    @classmethod
    async def create(cls, storage: StorageProvider, *, namespace: str):
        kv_store = await storage.get_kv_store(JWKEntry, namespace=namespace)
        return cls(kv_store)

    # --- CRUD ----------------------------------------------------------

    async def add_key(self, kid: str, jwk: dict[str, Any]) -> None:
        from ..crypto.jwk_validation import JWKValidationError, validate_jwk_complete

        # Validate JWK structure and use field
        try:
            validate_jwk_complete(jwk)
        except JWKValidationError as e:
            logger.warning("rejected_invalid_jwk_individual", kid=kid, error=str(e))
            return  # Don't add invalid keys

        # Check if this key has a physical_path and use field
        physical_path = jwk.get("physical_path")
        use = jwk.get("use")

        if physical_path and use:
            # Remove any existing keys for the same physical_path and use
            # This prevents stale key issues when nodes rebind with new keys
            all_entries = await self._kv.list()
            stale_entries = [
                entry
                for entry in all_entries.values()
                if (
                    entry.jwk.get("physical_path") == physical_path
                    and entry.jwk.get("use") == use
                    and entry.kid != kid
                )  # Don't remove the key we're about to add
            ]

            if stale_entries:
                stale_key_ids = [entry.kid for entry in stale_entries]
                logger.debug(
                    "removing_stale_keys_before_adding_new_key",
                    new_kid=kid,
                    physical_path=physical_path,
                    use=use,
                    stale_key_ids=stale_key_ids,
                    count=len(stale_key_ids),
                )

                for entry in stale_entries:
                    await self._kv.delete(entry.kid)

        await self._kv.set(kid, JWKEntry(kid=kid, jwk=jwk, physical_path=physical_path))

    async def get_key(self, kid: str) -> dict[str, Any]:
        entry = await self._kv.get(kid)
        if entry is None:
            raise ValueError(f"Unknown key id: {kid}")
        return entry.jwk

    async def has_key(self, kid: str) -> bool:
        return (await self._kv.get(kid)) is not None

    async def get_keys(self) -> Iterable[dict[str, Any]]:
        return (e.jwk for e in (await self._kv.list()).values())

    # --- helpers -------------------------------------------------------

    async def get_keys_for_path(self, physical_path: str):
        return (e.jwk for e in (await self._kv.list()).values() if e.physical_path == physical_path)

    async def get_keys_grouped_by_path(self):
        out: dict[str, list[dict]] = defaultdict(list)
        for e in (await self._kv.list()).values():
            if e.physical_path:
                out[e.physical_path].append(e.jwk)
        return out

    async def remove_keys_for_path(self, physical_path: str) -> int:
        removed = [e.kid for e in (await self._kv.list()).values() if e.physical_path == physical_path]
        for kid in removed:
            await self._kv.delete(kid)

        if removed:
            logger.debug(
                "removed_keys_for_path",
                physical_path=physical_path,
                removed_key_ids=removed,
                count=len(removed),
            )

        return len(removed)

    async def remove_key(self, kid: str) -> bool:
        existed = (await self._kv.get(kid)) is not None
        if existed:
            await self._kv.delete(kid)
            logger.debug("removed_individual_key", kid=kid)
        return existed
