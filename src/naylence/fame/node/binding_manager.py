from __future__ import annotations

import asyncio
from collections import defaultdict
from typing import Awaitable, Callable, Dict, Iterable, Optional

from pydantic import BaseModel

from naylence.fame.channel.in_memory.in_memory_binding import InMemoryBinding
from naylence.fame.core import (
    AddressBindAckFrame,
    AddressBindFrame,
    AddressUnbindAckFrame,
    AddressUnbindFrame,
    Binding,
    CapabilityAdvertiseAckFrame,
    CapabilityAdvertiseFrame,
    CapabilityWithdrawAckFrame,
    CapabilityWithdrawFrame,
    DeliveryAckFrame,
    EnvelopeFactory,
    FameAddress,
    FameDeliveryContext,
    FameEnvelope,
    FameResponseType,
    format_address,
    format_address_from_components,
    generate_id,
    local_delivery_context,
    parse_address,
    parse_address_components,
)
from naylence.fame.delivery.delivery_tracker import DeliveryTracker
from naylence.fame.storage.in_memory_key_value_store import InMemoryKVStore
from naylence.fame.storage.key_value_store import KeyValueStore
from naylence.fame.util.envelope_context import current_trace_id
from naylence.fame.util.logging import getLogger
from naylence.fame.util.logicals_util import is_pool_logical, matches_pool_logical

logger = getLogger(__name__)

SYSTEM_INBOX = "__sys__"
DEFAULT_ACK_TIMEOUT_MS = 20000


class FameEnvironmentContext:
    """Placeholder for Fame system context (e.g., metrics, tracing)."""

    pass


class BindingStoreEntry(BaseModel):
    """Model for persisting binding entries in a key-value store."""

    address: str  # Store as string to avoid FameAddress validation for logical addresses
    encryption_key_id: Optional[str] = None
    physical_path: Optional[str] = None


class BindingManager:
    """
    Tracks local address bindings, persists them, and manages upstream bind/unbind communications.

    Responsibilities:
      - Maintain an in-memory map of active bindings and persist them for recovery.
      - Support pool-based logical claims (wildcard prefixes), exact logical, and physical-path bindings.
      - Send AddressBindFrame/AddressUnbindFrame to an upstream handler and await ACK responses.
      - Restore persisted bindings at initialization.
    """

    def __init__(
        self,
        *,
        has_upstream: bool,
        get_id: Callable[[], str],
        get_sid: Callable[[], str],
        get_physical_path: Callable[[], str],
        forward_upstream: Callable[[FameEnvelope, Optional[FameDeliveryContext]], Awaitable[None]],
        get_accepted_logicals: Callable[[], set[str]],
        get_encryption_key_id: Optional[Callable[[], Optional[str]]] = None,
        binding_store: Optional[KeyValueStore[BindingStoreEntry]] = None,
        binding_factory: Optional[Callable[[FameAddress], Binding]] = None,
        envelope_factory: EnvelopeFactory,
        delivery_tracker: DeliveryTracker,
        ack_timeout_ms: int = DEFAULT_ACK_TIMEOUT_MS,
    ):
        """
        :param has_upstream: whether to propagate binds upstream
        :param get_id: function returning the system's ID (used for pool instance binds)
        :param get_physical_path: function returning the system's physical path for default binds
        :param forward_upstream: coroutine function to send a FameEnvelope upstream
        :param get_accepted_logicals: function returning the set of accepted logicals
        :param get_encryption_key_id: function returning the encryption key ID for this node
        :param binding_store: optional KV store for persisting bindings
        :param binding_factory: factory to create Binding instances for addresses
        :param binding_ack_timeout_ms: timeout for bind ACK in milliseconds
        """
        self._has_upstream = has_upstream
        self._get_id = get_id
        self._get_sid = get_sid
        self._get_accepted_logicals = get_accepted_logicals
        self._get_physical_path = get_physical_path
        self._get_encryption_key_id = get_encryption_key_id
        self._forward_upstream = forward_upstream
        # Default to in-memory channel for local binding
        self._binding_factory = binding_factory or (lambda address: InMemoryBinding(address))

        # In-memory map: full address -> Binding
        self._bindings: Dict[FameAddress, Binding] = {}
        # Persistent store for recovering bindings
        self._binding_store = binding_store or InMemoryKVStore(BindingStoreEntry)
        # Pending correlation: request ID -> Future awaiting ACK
        self._ack_timeout_sec = ack_timeout_ms / 1000.0
        self._ack_timeout_ms = ack_timeout_ms

        self._capabilities_by_address: dict[FameAddress, set[str]] = defaultdict(set)

        self._envelope_factory = envelope_factory

        self._delivery_tracker = delivery_tracker

    def get_binding(self, address: FameAddress) -> Optional[Binding]:
        """Return the Binding for a given address, or None if not bound."""
        # ① fast-path: exact hit
        binding = self._bindings.get(address)
        if binding:
            return binding

        # ② slow-path: pool pattern lookup
        return self._match_pool(address)

    def _match_pool(self, address: FameAddress) -> Optional[Binding]:
        name, location = parse_address(address)

        # Only check host-like pool patterns - no wildcards in physical addresses
        try:
            _, host, path = parse_address_components(address)
            if host:
                # Host-like address - check against host-like pool patterns
                return self._match_host_pool(name, host, path)
        except Exception:
            pass

        # No pool matching for non-host addresses
        return None

    def _match_host_pool(self, name: str, host: str, path: Optional[str]) -> Optional[Binding]:
        """Match host-like addresses against host-like pool patterns."""
        candidates: list[tuple[int, Binding]] = []

        for patt, binding in self._bindings.items():
            pn, plocation = parse_address(patt)
            if pn != name:
                continue

            try:
                _, phost, ppath = parse_address_components(patt)
                if not phost:
                    continue  # Skip non-host patterns

                # Check if this is a pool pattern and matches
                if is_pool_logical(phost):
                    if matches_pool_logical(host, phost):
                        # Calculate specificity based on pool pattern depth
                        specificity = len(phost.split("."))
                        candidates.append((specificity, binding))
            except Exception:
                continue

        if not candidates:
            return None

        # Most specific (deepest) pattern wins
        candidates.sort(key=lambda t: t[0], reverse=True)
        return candidates[0][1]

    def get_addresses(self) -> Iterable[FameAddress]:
        """Return all currently bound addresses."""
        return self._bindings.keys()

    def has_binding(self, address: FameAddress) -> bool:
        """Return True if the given address is currently bound locally."""
        return address in self._bindings or self._match_pool(address) is not None

    async def restore(self) -> None:
        """
        Recreate Binding objects from persisted entries.
        Invoke during initialization to recover previous state.
        """
        persisted = await self._binding_store.list()
        for entry in persisted.values():
            # Convert stored string back to FameAddress
            addr = FameAddress(entry.address)
            if addr not in self._bindings:
                self._bindings[addr] = self._binding_factory(addr)
                logger.debug("restored_binding", address=addr)

        # ── now that we’re back in business, re-advertise everything upstream ──
        if self._has_upstream:
            await self.rebind_addresses_upstream()
            await self.readvertise_capabilities_upstream()

    async def bind(
        self,
        participant: str,
        *,
        capabilities: list[str] | None = None,
    ) -> Binding:
        """
        Create local Binding(s) for a participant and send an upstream bind request if applicable.

        Args:
          participant: either a bare name (uses the provided physical path) or 'name@path'
                       to specify target path.

        Behavior:
          - If the path matches a wildcard logical (starting with '*.'), two bindings are created:
            1) logical binding at that path
            2) instance binding at '<id>.<logical>'.
          - Otherwise, if the path is an exact logical prefix or equals the physical path,
            only one binding is created.

        After creating and persisting local bindings, sends an AddressBindFrame upstream and awaits ACK,
        rolling back local state on failure.

        Returns:
          The Binding corresponding to the logical prefix address.
        """

        logger.debug("binding_participant", participant=participant)

        # Resolve participant into name and location
        if "@" in participant:
            name, location = parse_address(participant)
        else:
            name = participant
            location = self._get_physical_path()

        base_addr = format_address(name, location)

        # Check if location is host-like or path-based
        try:
            _, host, path = parse_address_components(base_addr)
            is_host_based = host is not None
        except Exception:
            is_host_based = False
            host = None

        # Get accepted logicals (these should now be in host-like notation)
        accepted_logicals = self._get_accepted_logicals()

        # Determine logical and pool claim based on address type
        if is_host_based and host:
            # Host-based address - check exact logical first, then pool patterns
            logical = host
            # First check if it's an exact accepted logical
            if self._is_accepted_logical_host(logical):
                pool_claim = None  # Use exact logical, not pool
            else:
                # Then check for pool patterns
                pool_claim = self._find_host_pool_claim(accepted_logicals, host)
        else:
            # Physical address - only allow if it's the physical path
            logical = None
            pool_claim = None

        if pool_claim:
            # Pool claim found - create pool pattern address and instance address
            prefix_addr = format_address_from_components(
                name, host=pool_claim
            )  # Wildcards now supported in regular format
            # Extract instance host from the pool claim pattern
            if host and "*" in host:
                instance_host = host.replace("*", self._get_id(), 1)  # Replace first * with instance ID
            else:
                # Create instance host from pool claim
                instance_host = pool_claim.replace("*", self._get_id(), 1)
            instance_addr = format_address_from_components(name, host=instance_host)
        elif logical and self._is_accepted_logical_host(logical):
            # Host-based logical address that's accepted
            prefix_addr = base_addr
            instance_addr = None  # No additional instance address for host-based logicals
        elif location == self._get_physical_path():
            # Physical path binding
            prefix_addr = base_addr
            instance_addr = None
        else:
            raise ValueError(f"Cannot bind '{participant}': location '{location}' not permitted")

        # Create and persist local bindings
        addrs = {prefix_addr}
        if instance_addr:
            addrs.add(instance_addr)

        # ── 1. create local bindings (in-memory only for now) ───────────────
        for addr in addrs:
            if addr not in self._bindings:
                self._bindings[addr] = self._binding_factory(addr)
                logger.debug("bound_address", address=addr, participant=participant)

        # ── 2. propagate bind upstream if required ──────────────────────────
        propagate_addr = self._has_upstream and (
            pool_claim or (logical and self._is_accepted_logical_host(logical))
        )
        bind_addr = None
        if propagate_addr:
            if pool_claim:
                # For pool claims, send the host-like pattern upstream
                bind_addr = format_address_from_components(name, host=pool_claim)
            else:
                bind_addr = prefix_addr
            try:
                await self._bind_address_upstream(bind_addr)
            except Exception:
                # roll back *in-memory* map; nothing is yet persisted
                for addr in addrs:
                    self._bindings.pop(addr, None)
                raise

        # ensure we propagate caps only when we have an upstream
        cap_addr = instance_addr or prefix_addr
        propagate_caps = self._has_upstream and capabilities and cap_addr is not None

        # ── 2b. advertise capabilities (rolls back like bind) ───────────────
        if propagate_caps:
            assert cap_addr is not None  # Type narrowing for Pylance
            try:
                await self._advertise_capabilities(cap_addr, capabilities or [])
            except Exception:
                # if caps fail we also roll back the address bind we just did
                if propagate_addr and bind_addr:
                    try:
                        await self._unbind_address_upstream(bind_addr)
                    except Exception:
                        logger.error("bind_rollback_failed", address=bind_addr, exc_info=True)
                for addr in addrs:
                    self._bindings.pop(addr, None)
                raise

        # ── 3. persistence only after success (or when no upstream) ────────
        for addr in addrs:
            await self._binding_store.set(addr, BindingStoreEntry(address=str(addr)))

        logger.debug(
            "bind_success",
            participant=participant,
            address=prefix_addr,
            capabilities=capabilities,
            total_bindings=len(self._bindings),
        )
        return self._bindings[prefix_addr]

    async def _bind_address_upstream(self, addr: FameAddress) -> None:
        """
        Send AddressBindFrame upstream and await the corresponding ACK.
        Raises on timeout or negative ACK.
        """
        corr_id = generate_id()

        frame = AddressBindFrame(
            address=addr,
            physical_path=self._get_physical_path(),
            encryption_key_id=(self._get_encryption_key_id() if self._get_encryption_key_id else None),
        )
        reply_to = format_address(SYSTEM_INBOX, self._get_physical_path())
        env = self._envelope_factory.create_envelope(
            trace_id=current_trace_id(),
            frame=frame,
            reply_to=reply_to,
            corr_id=corr_id,
        )

        try:
            ok = await self._send_and_wait_for_ack(env, timeout_ms=self._ack_timeout_ms)
        except asyncio.TimeoutError:
            raise RuntimeError(f"Timeout waiting for bind ack for {addr!r}")

        if not ok:
            raise RuntimeError(f"Bind to {addr!r} was rejected")

    async def unbind(self, participant: str) -> None:
        """
        Unbind a participant locally after confirming upstream unbind.

        Mirrors bind(): compute addresses to unbind, send AddressUnbindFrame,
        await ACK, then remove local state and persistence.
        """
        if "@" in participant:
            name, location = parse_address(participant)
        else:
            name = participant
            location = self._get_physical_path()

        base_addr = format_address(name, location)

        # Check if location is host-like or path-based
        try:
            _, host, path = parse_address_components(base_addr)
            is_host_based = host is not None
        except Exception:
            is_host_based = False
            host = None

        # Get accepted logicals (these should now be in host-like notation)
        accepted_logicals = self._get_accepted_logicals()

        # Determine logical and pool claim based on address type
        if is_host_based and host:
            # Host-based address - check for pool patterns
            logical = host
            pool_claim = self._find_host_pool_claim(accepted_logicals, host)
        else:
            # Physical address - no pool logic for these
            logical = None
            pool_claim = None

        if pool_claim:
            # Host-based pool
            prefix_addr = format_address_from_components(
                name, host=pool_claim
            )  # Wildcards now supported in regular format
            if host and "*" in host:
                instance_host = host.replace("*", self._get_id(), 1)
            else:
                # Create instance host from pool claim
                instance_host = pool_claim.replace("*", self._get_id(), 1)
            instance_addr = format_address_from_components(name, host=instance_host)
            unprop_addr = prefix_addr
            addrs = {prefix_addr, instance_addr}
        elif logical and self._is_accepted_logical_host(logical):
            prefix_addr = base_addr
            unprop_addr = prefix_addr
            addrs = {prefix_addr}
        elif location == self._get_physical_path():
            prefix_addr = base_addr
            unprop_addr = None
            addrs = {prefix_addr}
        else:
            raise ValueError(f"Cannot unbind '{participant}': location '{location}' not permitted")

        if self._has_upstream and unprop_addr:
            await self._unbind_address_upstream(unprop_addr)

        for addr in addrs:
            if addr in self._bindings:
                self._bindings.pop(addr)
                await self._binding_store.delete(addr)

    async def _unbind_address_upstream(self, addr: FameAddress) -> None:
        """
        Send AddressUnbindFrame upstream and await the corresponding ACK.
        Raises on timeout or negative ACK.
        """
        corr_id = generate_id()

        frame = AddressUnbindFrame(address=addr)  # , corr_id=corr_id)
        reply_to = format_address(SYSTEM_INBOX, self._get_physical_path())
        env = self._envelope_factory.create_envelope(
            trace_id=current_trace_id(), frame=frame, reply_to=reply_to, corr_id=corr_id
        )

        try:
            ok = await self._send_and_wait_for_ack(env, timeout_ms=self._ack_timeout_ms)
        except asyncio.TimeoutError:
            raise RuntimeError(f"Timeout waiting for unbind ack for {addr!r}")

        if not ok:
            raise RuntimeError(f"Unbind of {addr!r} was rejected")

    async def handle_ack(
        self, envelope: FameEnvelope, context: Optional[FameDeliveryContext] = None
    ) -> None:
        """
        Handle AddressBindAckFrame, AddressUnbindAckFrame,
        CapabilityAdvertiseAckFrame and CapabilityWithdrawAckFrame by matching
        on envelope.id and fulfilling the pending Future.
        """
        assert isinstance(
            envelope.frame,
            AddressBindAckFrame
            | AddressUnbindAckFrame
            | CapabilityAdvertiseAckFrame
            | CapabilityWithdrawAckFrame,
        )
        logger.debug("received_ack", frame=envelope.frame)
        from naylence.fame.node.node import SYSTEM_INBOX

        await self._delivery_tracker.on_envelope_delivered(SYSTEM_INBOX, envelope, context)

    def _is_physical_path_prefix(self, path):
        return (path + "/").startswith(self._get_physical_path() + "/")

    def _should_rebind(self, address: FameAddress) -> bool:
        name, location = parse_address(address)

        # Check if this is a host-based or path-based address
        try:
            _, host, path = parse_address_components(address)
            is_host_based = host is not None
        except Exception:
            is_host_based = False
            host = None

        if is_host_based and host:
            # Host-based address - check host logical
            logical = host
            accepted_logicals = self._get_accepted_logicals()
            pool_claim = self._find_host_pool_claim(accepted_logicals, logical)
            result = pool_claim is not None or self._is_accepted_logical_host(logical)
        else:
            # Physical address - no upstream binding for physical addresses
            result = False

        logger.trace("checking_upstream_bind_eligibility", address=address, rebind=result)
        return result

    async def rebind_addresses_upstream(self):
        if not self._has_upstream:
            logger.warning("No upstream defined to rebind addresses")
            return

        logger.debug("binding_addresses_upstream")

        sem = asyncio.Semaphore(32)  # throttle burst to 32 in-flight

        async def _bind(address: FameAddress) -> None:
            async with sem:
                try:
                    logger.debug("rebinding_address_route_upstream", address=address)
                    await self._bind_address_upstream(
                        address,
                        # force=True           # skip the “is it already bound?” check
                    )
                except Exception as e:
                    logger.error("rebind_failed", address=address, error=e, exc_info=True)

        addresses_to_rebind = [a for a in self._bindings if self._should_rebind(a)]

        await asyncio.gather(*(_bind(a) for a in addresses_to_rebind))

        logger.debug("binding_addresses_upstream_completed", count=len(addresses_to_rebind))

    async def readvertise_capabilities_upstream(self) -> None:
        """Replay CapabilityAdvertise frames for the current epoch."""
        if not self._has_upstream:
            return
        logger.debug("readvertising_capabilities_upstream")

        sem = asyncio.Semaphore(32)

        async def _adv(addr: FameAddress, caps: set[str]) -> None:
            async with sem:
                try:
                    await self._advertise_capabilities(addr, list(caps))
                except Exception as e:
                    logger.error(
                        "capability_replay_failed",
                        address=addr,
                        caps=caps,
                        error=e,
                        exc_info=True,
                    )

        await asyncio.gather(*(_adv(a, c) for a, c in self._capabilities_by_address.items()))
        logger.debug("readvertised_capabilities_upstream")

    async def _advertise_capabilities(self, address: FameAddress, caps: list[str]):
        if not caps:
            return
        corr_id = generate_id()

        frame = CapabilityAdvertiseFrame(
            address=address,
            capabilities=caps,
        )
        reply_to = format_address(SYSTEM_INBOX, self._get_physical_path())
        envelope = self._envelope_factory.create_envelope(frame=frame, corr_id=corr_id, reply_to=reply_to)

        try:
            ok = await self._send_and_wait_for_ack(envelope, timeout_ms=self._ack_timeout_ms)
        except asyncio.TimeoutError:
            raise RuntimeError(f"Timeout waiting for advertise ack for {address!r}")

        if ok:
            self._capabilities_by_address[address].update(caps)
        else:
            raise RuntimeError(f"Capability advertise rejected: {caps}")

    async def withdraw_capabilities(self, address: FameAddress, caps: list[str]) -> None:
        """
        Withdraw previously-advertised capabilities from the upstream router.

        Mirrors advertise_capabilities(): sends CapabilityWithdrawFrame and
        waits for ACK.  Raises on timeout or negative ACK.
        """
        if not caps:
            return  # nothing to withdraw

        corr_id = generate_id()

        frame = CapabilityWithdrawFrame(
            address=address,
            capabilities=caps,
        )
        reply_to = format_address(SYSTEM_INBOX, self._get_physical_path())
        env = self._envelope_factory.create_envelope(frame=frame, corr_id=corr_id, reply_to=reply_to)

        try:
            ok = await self._send_and_wait_for_ack(env, timeout_ms=self._ack_timeout_ms)
        except asyncio.TimeoutError:
            raise RuntimeError(f"Timeout waiting for withdraw caps for address {address!r}")

        if ok:
            remaining = self._capabilities_by_address[address] - set(caps)
            if remaining:
                self._capabilities_by_address[address] = remaining
            else:
                self._capabilities_by_address.pop(address, None)
        else:
            raise RuntimeError(f"Capability withdraw rejected: {caps}")

    def _find_host_pool_claim(self, accepted_logicals: set[str], logical: str) -> Optional[str]:
        """
        Find a pool claim pattern that matches the given logical address.

        Args:
            accepted_logicals: Set of accepted logical patterns (host-like notation)
            logical: Logical address to check (host-like notation)

        Returns:
            Pool pattern that matches, or None if no match
        """
        if not logical:
            return None

        # Check for direct pool pattern match
        for pattern in accepted_logicals:
            if is_pool_logical(pattern) and matches_pool_logical(logical, pattern):
                return pattern

        return None

    def _is_accepted_logical_host(self, logical: str) -> bool:
        """
        Check if a host-like logical address is accepted as an exact match.

        Args:
            logical: Host-like logical address

        Returns:
            True if the logical is accepted as an exact match (not pool pattern)
        """
        if not logical:
            return False

        accepted_logicals = self._get_accepted_logicals()

        # Check for exact match (not a pool pattern)
        return logical in accepted_logicals and not is_pool_logical(logical)

    async def _send_and_wait_for_ack(self, envelope: FameEnvelope, timeout_ms: int) -> bool:
        """Send an RPC request envelope."""

        logger.debug(
            "sending_binding_request",
            envp_id=envelope.id,
            corr_id=envelope.corr_id,
            target_address=envelope.to,
            expected_response_type=FameResponseType.ACK,
        )

        await self._delivery_tracker.track(
            envelope, timeout_ms=timeout_ms, expected_response_type=FameResponseType.ACK
        )

        envelope.rtype = FameResponseType.ACK
        await self._forward_upstream(envelope, local_delivery_context(self._get_id()))

        reply_envelope: FameEnvelope = await self._delivery_tracker.await_ack(envelope.id)

        assert isinstance(reply_envelope.frame, DeliveryAckFrame)

        return reply_envelope.frame.ok
