"""
Default implementation of KeyManager.
"""

import asyncio
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, Any, Iterable, Optional

from naylence.fame.core import (
    DeliveryOriginType,
    EnvelopeFactory,
    KeyAnnounceFrame,
    local_delivery_context,
)
from naylence.fame.security.keys.key_store import KeyStore
from naylence.fame.util.envelope_context import current_trace_id
from naylence.fame.util.logging import getLogger
from naylence.fame.util.util import secure_digest

from .key_manager import KeyManager

if TYPE_CHECKING:
    from naylence.fame.node.node_like import NodeLike
    from naylence.fame.node.routing_node_like import RoutingNodeLike

logger = getLogger(__name__)


class DefaultKeyManager(KeyManager):
    """Default implementation of KeyManager with certificate expiry management."""

    def __init__(
        self,
        *,
        key_store: KeyStore,
    ) -> None:
        KeyManager.__init__(self)
        self._key_store: KeyStore = key_store

        # Context - populated by on_node_started
        self._node: Optional[NodeLike] = None
        self._routing_node: Optional[RoutingNodeLike] = None

    async def on_node_started(self, node: "NodeLike") -> None:
        """Called when a node has been started and is ready for operation.

        This replaces the deprecated update_context() method and also starts
        the background certificate purging task.
        """
        self._node = node

        # Check if this is a routing node for additional capabilities
        try:
            from naylence.fame.node.routing_node_like import RoutingNodeLike

            if isinstance(node, RoutingNodeLike):
                self._routing_node = node
        except ImportError:
            # RoutingNodeLike not available, skip routing-specific features
            pass

        logger.debug(
            "key_manager_started",
            node_id=self._node_id,
            physical_path=self._physical_path,
            has_upstream=self._has_upstream,
        )

        # Start background certificate purging task

    async def on_node_stopped(self, node: "NodeLike") -> None:
        """Called when a node is being stopped and should clean up resources."""
        logger.debug("key_manager_stopped", node_id=self._node_id)

    @property
    def _has_upstream(self) -> bool:
        return self._node.has_parent if self._node else False

    @property
    def _physical_path(self) -> str:
        """Get the node's physical path."""
        return str(getattr(self._node, "physical_path", "/")) if self._node else "/"

    @property
    def _node_id(self) -> str:
        """Get the node's ID."""
        return str(getattr(self._node, "_id", "")) if self._node else ""

    @property
    def _node_sid(self) -> str:
        """Get the node's secure ID."""
        return str(getattr(self._node, "_sid", "")) if self._node else ""

    @property
    def _envelope_factory(self) -> Optional[EnvelopeFactory]:
        """Get the node's envelope factory."""
        return getattr(self._node, "_envelope_factory", None) if self._node else None

    async def get_key(self, kid: str) -> dict[str, Any]:
        return await self._key_store.get_key(kid)

    async def has_key(self, kid: str) -> bool:
        return await self._key_store.has_key(kid)

    async def add_keys(
        self,
        *,
        keys: list[dict],
        sid: Optional[str] = None,
        physical_path: str,
        system_id: str,
        origin: DeliveryOriginType,
        skip_sid_validation: bool = False,  # New parameter for correlation routing
    ):
        from naylence.fame.security.crypto.jwk_validation import (
            JWKValidationError,
            validate_jwk_complete,
        )

        # Pre-validate all keys before processing
        valid_keys = []
        rejected_count = 0  # Get trust store configuration if available

        for key in keys:
            try:
                # First, basic JWK validation
                validate_jwk_complete(key)

                valid_keys.append(key)

            except JWKValidationError as e:
                logger.warning(
                    "rejected_invalid_jwk_in_announce",
                    kid=key.get("kid", "unknown"),
                    from_system_id=system_id,
                    from_physical_path=physical_path,
                    error=str(e),
                )
                rejected_count += 1
        if not valid_keys:
            logger.warning(
                "no_valid_keys_in_announce",
                from_system_id=system_id,
                from_physical_path=physical_path,
                total_keys=len(keys),
                rejected_count=rejected_count,
            )
            return

        logger.debug(
            "adding_keys",
            key_ids=[key["kid"] for key in valid_keys],
            source_system_id=system_id,
            from_physical_path=physical_path,
            trace_id=current_trace_id(),
            origin=origin,
            valid_count=len(valid_keys),
            rejected_count=rejected_count,
        )

        if origin == DeliveryOriginType.LOCAL:
            await self._key_store.add_keys(valid_keys, physical_path=physical_path)
            return

        self_physical_path = self._physical_path

        # Accept key announcements signed by direct links only
        # Skip SID validation for correlation-routed KeyAnnounce messages
        if sid and not skip_sid_validation:
            key_path = None

            if origin == DeliveryOriginType.DOWNSTREAM:
                key_path = str(PurePosixPath(self_physical_path) / system_id)
            elif origin == DeliveryOriginType.UPSTREAM:
                key_path = str(PurePosixPath(self_physical_path).parent)
            elif origin == DeliveryOriginType.PEER:
                key_path = f"/{system_id}"

            assert key_path

            expected_sid = secure_digest(key_path)
            if sid != expected_sid:
                # TODO: security: disconnect the downstream that sent the announcement?
                raise ValueError(f"Invalid downstream sid: {sid}")

        # For downstream origins, ensure the physical path is downstream
        if origin == DeliveryOriginType.DOWNSTREAM:
            normalized_frame_path = physical_path.rstrip("/")
            expected_path_prefix = str(PurePosixPath(self_physical_path) / system_id / "")
            if not (normalized_frame_path + "/").startswith(expected_path_prefix):
                raise ValueError(
                    f"Frame physical path {normalized_frame_path} "
                    f"does not match expected prefix {expected_path_prefix}"
                )

        await self._key_store.add_keys(valid_keys, physical_path=physical_path)

        if origin == DeliveryOriginType.DOWNSTREAM:
            await self._announce_path_keys(valid_keys, physical_path, origin)
        else:
            logger.debug(
                "skip_announcing_keys_to_upstream",
                key_ids=[key["kid"] for key in keys if "kid" in key],
                from_physical_path=physical_path,
                has_upsteam=self._has_upstream,
            )

    async def _announce_path_keys(
        self,
        keys: list[dict[str, Any]],
        from_physical_path: str,
        origin: DeliveryOriginType,
    ):
        # Only announce if we have somewhere to announce to
        if not (
            self._has_upstream or (self._routing_node and hasattr(self._routing_node, "forward_to_peers"))
        ):
            logger.debug(
                "skip_announcing_keys_no_destination",
                key_ids=[key["kid"] for key in keys if "kid" in key],
                from_physical_path=from_physical_path,
                has_upstream=self._has_upstream,
                has_routing_node=self._routing_node is not None,
            )
            return

        logger.debug(
            "announcing_keys_to_upstream",
            key_ids=[key["kid"] for key in keys if "kid" in key],
            from_physical_path=from_physical_path,
        )

        envelope_factory = self._envelope_factory
        if not envelope_factory:
            raise RuntimeError("Envelope factory not available - key manager not properly initialized")

        env = envelope_factory.create_envelope(
            frame=KeyAnnounceFrame(keys=keys, physical_path=from_physical_path)
        )

        if self._has_upstream:
            node_id = self._node_id
            if not node_id:
                raise RuntimeError("Node ID not available - key manager not properly initialized")
            if not self._node:
                raise RuntimeError("Node not available - key manager not properly initialized")
            await self._node.forward_upstream(env, local_delivery_context(node_id))

        if self._routing_node and hasattr(self._routing_node, "forward_to_peers"):
            node_id = self._node_id
            if not node_id:
                raise RuntimeError("Node ID not available - key manager not properly initialized")
            await self._routing_node.forward_to_peers(env, None, None, local_delivery_context(node_id))

    async def announce_keys_to_upstream(self):
        if not self._has_upstream:
            return

        self_physical_path = self._physical_path

        logger.debug("reannouncing_keys_upstream")

        sem = asyncio.Semaphore(16)  # throttle burst to 16 in-flight

        async def _announce(path: str, keys_per_sid: list[dict[str, Any]]) -> None:
            if not path.startswith(self_physical_path):
                return
            async with sem:
                try:
                    await self._announce_path_keys(keys_per_sid, path, DeliveryOriginType.DOWNSTREAM)
                except Exception as e:
                    logger.error("announce_key_failed", error=e, exc_info=True)

        # TODO: get keys relevant to the origin
        await asyncio.gather(
            *(
                _announce(path, keys)
                for path, keys in (await self._key_store.get_keys_grouped_by_path()).items()
            )
        )

        logger.debug("reannounce_keys_upstream_completed")

    def _get_keys_to_announce_upstream(self) -> list[list[dict[str, Any]]]: ...

    def _should_announce_upsteam(self, key: dict[str, Any]) -> bool:
        return False

    async def handle_key_request(
        self,
        kid: str,
        from_seg: str,
        *,
        physical_path: str | None,
        origin: DeliveryOriginType,
        corr_id: Optional[str] = None,
        original_client_sid: Optional[str] = None,
    ) -> None:
        """
        Answer a KeyRequest with a signed KeyAnnounce.

        Parameters
        ----------
        kid : str
            The requested key-id.
        from_seg : str
            The segment we received the request *from* (so we can target the reply
            if it came from downstream).
        physical_path : str | None
            Optional path filter for bulk requests.
        origin : DeliveryOriginType
            UPSTREAM if the request travelled down from our parent,
            DOWNSTREAM if it came up from a child.
        corr_id : str | None
            Optional correlation ID for the request.
        original_client_sid : str | None
            Original client session ID for sticky routing.
        """

        logger.trace("handling_key_request", kid=kid, corr_id=corr_id)

        jwk = None
        # 1) Gather the key(s)
        try:
            jwk = await self._key_store.get_key(kid)
            keys = [jwk]
        except ValueError:
            if physical_path is None:
                logger.trace(
                    "handling_key_request_failed",
                    kid=kid,
                    corr_id=corr_id,
                    reason="key_not_found",
                )
                raise  # we really have nothing suitable
            keys = list(await self._key_store.get_keys_for_path(physical_path))

        assert jwk

        # 2) Build & sign the KeyAnnounce
        envelope_factory = self._envelope_factory
        if not envelope_factory:
            raise RuntimeError("Envelope factory not available - key manager not properly initialized")

        env = envelope_factory.create_envelope(
            frame=KeyAnnounceFrame(
                keys=keys,
                physical_path=jwk["physical_path"],
            ),
            corr_id=corr_id,
        )

        # 3) Send it the right way with proper delivery context
        node_id = self._node_id
        if not node_id:
            raise RuntimeError("Node ID not available - key manager not properly initialized")

        delivery_context = local_delivery_context(node_id)

        # Request stickiness for encryption keys
        if jwk.get("use") == "enc":
            delivery_context.stickiness_required = True
            delivery_context.sticky_sid = original_client_sid  # Set original client SID for AFT
            logger.debug(
                "key_announce_stickiness_set",
                kid=kid,
                corr_id=corr_id,
                key_use=jwk.get("use"),
                original_client_sid=original_client_sid,
            )

        if origin is DeliveryOriginType.DOWNSTREAM:
            if not self._routing_node:
                raise RuntimeError(
                    "Forward downstream not available - routing functionality not initialized"
                )
            # The child that asked lives on `from_seg`
            await self._routing_node.forward_to_route(from_seg, env, delivery_context)
        else:  # origin == UPSTREAM
            if not self._node:
                raise RuntimeError("Node not available - key manager not properly initialized")
            await self._node.forward_upstream(env, delivery_context)

    async def remove_keys_for_path(self, physical_path: str) -> int:
        """Remove all keys associated with the given physical path.

        This is useful when a system reconnects with new keys - we want to
        remove all old keys for that system before adding the new ones.

        Returns the number of keys removed.
        """
        removed_count = await self._key_store.remove_keys_for_path(physical_path)
        logger.debug(
            "removed_keys_for_path",
            physical_path=physical_path,
            removed_count=removed_count,
        )
        return removed_count

    async def get_keys_for_path(self, physical_path: str) -> Iterable[dict[str, Any]]:
        """Get all keys associated with the given physical path."""
        return await self._key_store.get_keys_for_path(physical_path)
