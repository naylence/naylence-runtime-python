"""
In-memory key store plus its factory registration.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Iterable, Mapping, Optional

from .key_store import KeyStore


class InMemoryKeyStore(KeyStore):
    """Thread-safe enough for async single-process use-cases."""

    def __init__(self, initial_keys: Optional[Mapping[str, dict[str, Any]]] = None, **kwargs) -> None:
        super().__init__(**kwargs)
        self._keys: dict[str, dict[str, Any]] = dict(initial_keys or {})

    async def add_key(self, kid: str, jwk: dict[str, Any]) -> None:
        from ..crypto.jwk_validation import JWKValidationError, validate_jwk_complete

        # Validate JWK structure and use field
        try:
            validate_jwk_complete(jwk)
        except JWKValidationError as e:
            from naylence.fame.util import logging

            logger = logging.getLogger(__name__)
            logger.warning("rejected_invalid_jwk_individual", kid=kid, error=str(e))
            return  # Don't add invalid keys

        # Check if this key has a physical_path and use field
        physical_path = jwk.get("physical_path")
        use = jwk.get("use")

        if physical_path and use:
            # Remove any existing keys for the same physical_path and use
            # This prevents stale key issues when nodes rebind with new keys
            stale_keys = [
                existing_kid
                for existing_kid, existing_jwk in self._keys.items()
                if (
                    existing_jwk.get("physical_path") == physical_path
                    and existing_jwk.get("use") == use
                    and existing_kid != kid
                )  # Don't remove the key we're about to add
            ]

            if stale_keys:
                from naylence.fame.util import logging

                logger = logging.getLogger(__name__)
                logger.debug(
                    "removing_stale_keys_before_adding_new_key",
                    new_kid=kid,
                    physical_path=physical_path,
                    use=use,
                    stale_key_ids=stale_keys,
                    count=len(stale_keys),
                )

                for stale_kid in stale_keys:
                    del self._keys[stale_kid]

        self._keys[kid] = jwk

    async def get_key(self, kid: str) -> dict[str, Any]:
        try:
            return self._keys[kid]
        except KeyError:
            raise ValueError(f"Unknown key id: {kid}") from None

    async def has_key(self, kid: str) -> bool:
        return kid in self._keys

    async def get_keys(self) -> Iterable[dict[str, Any]]:
        return self._keys.values()

    async def get_keys_for_path(self, physical_path: str) -> Iterable[dict[str, Any]]:
        """Select keys whose stored `sid` matches the path's digest."""
        return (jwk for jwk in self._keys.values() if jwk.get("physical_path") == physical_path)

    async def get_keys_grouped_by_path(self) -> dict[str, list[dict[str, Any]]]:
        grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for jwk in self._keys.values():
            physical_path = jwk.get("physical_path")
            if physical_path is not None:
                grouped[physical_path].append(jwk)
        return dict(grouped)

    async def remove_keys_for_path(self, physical_path: str) -> int:
        """Remove all keys associated with the given physical path."""
        keys_to_remove = [
            kid for kid, jwk in self._keys.items() if jwk.get("physical_path") == physical_path
        ]

        for kid in keys_to_remove:
            del self._keys[kid]

        from naylence.fame.util import logging

        logger = logging.getLogger(__name__)
        if keys_to_remove:
            logger.debug(
                "removed_keys_for_path",
                physical_path=physical_path,
                removed_key_ids=keys_to_remove,
                count=len(keys_to_remove),
            )

        return len(keys_to_remove)

    async def remove_key(self, kid: str) -> bool:
        """Remove a specific key by its key ID."""
        if kid in self._keys:
            del self._keys[kid]

            from naylence.fame.util import logging

            logger = logging.getLogger(__name__)
            logger.debug("removed_individual_key", kid=kid)
            return True
        return False
