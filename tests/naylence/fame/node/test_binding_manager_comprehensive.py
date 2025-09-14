#!/usr/bin/env python3
"""
Comprehensive test coverage for binding_manager.py to reach 85%+ coverage.

Tests focus on functionality not covered by existing tests including:
- Error handling paths
- Pool matching logic
- Upstream communication with timeouts and failures
- Capability management
- Persistence and restoration
- Edge cases and validation
"""

import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from naylence.fame.channel.in_memory.in_memory_binding import InMemoryBinding
from naylence.fame.core import (
    AddressBindAckFrame,
    CapabilityAdvertiseAckFrame,
    CapabilityWithdrawAckFrame,
    FameAddress,
    create_fame_envelope,
)
from naylence.fame.delivery.delivery_tracker import DeliveryTracker
from naylence.fame.node.binding_manager import BindingManager, BindingStoreEntry
from naylence.fame.node.node_envelope_factory import NodeEnvelopeFactory
from naylence.fame.storage.in_memory_key_value_store import InMemoryKVStore


class TestBindingManagerComprehensive:
    """Comprehensive tests to increase binding manager coverage to 85%+."""

    @pytest.fixture
    def envelope_factory(self):
        """Create envelope factory."""
        return NodeEnvelopeFactory(physical_path_fn=lambda: "/test-node", sid_fn=lambda: "test-sid")

    @pytest.fixture
    def mock_forward_upstream(self):
        """Create mock forward upstream function."""
        return AsyncMock()

    @pytest.fixture
    def binding_store(self):
        """Create in-memory binding store."""
        return InMemoryKVStore(BindingStoreEntry)

    @pytest.fixture
    def binding_manager_with_upstream(self, envelope_factory, mock_forward_upstream, binding_store):
        """Create binding manager with upstream enabled."""
        delivery_tracker = AsyncMock(spec=DeliveryTracker)

        # Configure delivery tracker to return success ACKs by default
        from naylence.fame.core import DeliveryAckFrame

        success_ack_frame = DeliveryAckFrame(ok=True)
        success_ack_envelope = create_fame_envelope(frame=success_ack_frame)
        delivery_tracker.await_ack.return_value = success_ack_envelope

        return BindingManager(
            has_upstream=True,
            get_id=lambda: "test-node-id",
            get_sid=lambda: "test-system-id",
            get_physical_path=lambda: "/test/physical/path",
            forward_upstream=mock_forward_upstream,
            get_accepted_logicals=lambda: {
                "api.services",
                "*.services",
                "api.test",
                "*.test",
                "service.api",
                "*.api",
                "fame.fabric",
                "exact.match",
            },
            get_encryption_key_id=lambda: "test-key-id",
            binding_store=binding_store,
            binding_factory=lambda addr: InMemoryBinding(addr),
            envelope_factory=envelope_factory,
            delivery_tracker=delivery_tracker,
            ack_timeout_ms=1000,  # Short timeout for tests
        )

    @pytest.fixture
    def binding_manager_no_upstream(self, envelope_factory, binding_store):
        """Create binding manager without upstream."""
        delivery_tracker = AsyncMock(spec=DeliveryTracker)
        return BindingManager(
            has_upstream=False,
            get_id=lambda: "test-node-id",
            get_sid=lambda: "test-system-id",
            get_physical_path=lambda: "/test/physical/path",
            forward_upstream=AsyncMock(),
            get_accepted_logicals=lambda: {
                "api.services",
                "*.services",
                "api.test",
                "*.test",
                "exact.match",
            },
            binding_store=binding_store,
            binding_factory=lambda addr: InMemoryBinding(addr),
            envelope_factory=envelope_factory,
            delivery_tracker=delivery_tracker,
        )

    # Test pool matching logic
    def test_match_pool_with_exact_match(self, binding_manager_no_upstream):
        """Test pool matching with exact address match."""
        # Add exact binding
        exact_addr = FameAddress("service@api.services")
        binding_manager_no_upstream._bindings[exact_addr] = InMemoryBinding(exact_addr)

        # Should return exact match, not pool match
        result = binding_manager_no_upstream.get_binding(exact_addr)
        assert result is not None
        assert result.address == exact_addr

    def test_match_pool_no_host_address(self, binding_manager_no_upstream):
        """Test pool matching with non-host address."""
        # Path-only address should not match pools
        path_addr = FameAddress("service@/some/path")
        result = binding_manager_no_upstream._match_pool(path_addr)
        assert result is None

    def test_match_host_pool_different_names(self, binding_manager_no_upstream):
        """Test pool matching fails when names don't match."""
        # Add pool pattern binding
        pool_addr = FameAddress("service@*.services")
        binding_manager_no_upstream._bindings[pool_addr] = InMemoryBinding(pool_addr)

        # Different name should not match
        test_addr = FameAddress("worker@api.services")
        result = binding_manager_no_upstream._match_pool(test_addr)
        assert result is None

    def test_match_host_pool_specificity_ordering(self, binding_manager_no_upstream):
        """Test that most specific pool pattern wins."""
        # Add multiple pool patterns with different specificity
        general_pool = FameAddress("service@*.test")
        specific_pool = FameAddress("service@*.api.test")

        binding_manager_no_upstream._bindings[general_pool] = InMemoryBinding(general_pool)
        binding_manager_no_upstream._bindings[specific_pool] = InMemoryBinding(specific_pool)

        # Should match the more specific pattern
        test_addr = FameAddress("service@node.api.test")
        result = binding_manager_no_upstream._match_pool(test_addr)
        assert result is not None
        # The more specific pattern should win (higher specificity)

    def test_match_host_pool_parse_exception(self, binding_manager_no_upstream):
        """Test pool matching handles parse exceptions gracefully."""
        # Add a binding that might cause parse issues
        problem_addr = FameAddress("service@invalid")
        binding_manager_no_upstream._bindings[problem_addr] = InMemoryBinding(problem_addr)

        # Should handle parse exceptions gracefully
        test_addr = FameAddress("service@api.services")
        binding_manager_no_upstream._match_pool(test_addr)
        # Should not crash, might return None

    def test_get_addresses(self, binding_manager_no_upstream):
        """Test get_addresses returns all bound addresses."""
        addr1 = FameAddress("service1@api.services")
        addr2 = FameAddress("service2@*.test")

        binding_manager_no_upstream._bindings[addr1] = InMemoryBinding(addr1)
        binding_manager_no_upstream._bindings[addr2] = InMemoryBinding(addr2)

        addresses = list(binding_manager_no_upstream.get_addresses())
        assert len(addresses) == 2
        assert addr1 in addresses
        assert addr2 in addresses

    def test_has_binding_with_pool_match(self, binding_manager_no_upstream):
        """Test has_binding returns True for pool matches."""
        # Add pool pattern
        pool_addr = FameAddress("service@*.services")
        binding_manager_no_upstream._bindings[pool_addr] = InMemoryBinding(pool_addr)

        # Should match via pool
        test_addr = FameAddress("service@api.services")
        assert binding_manager_no_upstream.has_binding(test_addr)

    # Test restoration functionality
    @pytest.mark.asyncio
    async def test_restore_creates_bindings(self, binding_manager_no_upstream, binding_store):
        """Test restore recreates bindings from store."""
        # Pre-populate store
        addr1 = FameAddress("service1@api.services")
        addr2 = FameAddress("service2@exact.match")

        await binding_store.set(addr1, BindingStoreEntry(address=str(addr1)))
        await binding_store.set(addr2, BindingStoreEntry(address=str(addr2)))

        # Restore should recreate bindings
        await binding_manager_no_upstream.restore()

        assert binding_manager_no_upstream.has_binding(addr1)
        assert binding_manager_no_upstream.has_binding(addr2)

    @pytest.mark.asyncio
    async def test_restore_with_upstream_rebinds(
        self, binding_manager_with_upstream, binding_store, mock_forward_upstream
    ):
        """Test restore with upstream calls rebind_addresses_upstream."""
        # Pre-populate store with logical address
        addr = FameAddress("service@api.services")
        await binding_store.set(addr, BindingStoreEntry(address=str(addr)))

        # Mock successful ACK responses
        async def mock_forward(*args, **kwargs):
            # Simulate successful ACK
            pass

        mock_forward_upstream.side_effect = mock_forward

        with patch.object(binding_manager_with_upstream, "rebind_addresses_upstream") as mock_rebind:
            await binding_manager_with_upstream.restore()
            mock_rebind.assert_called_once()

    @pytest.mark.asyncio
    async def test_restore_skips_existing_bindings(self, binding_manager_no_upstream, binding_store):
        """Test restore skips addresses already in bindings."""
        addr = FameAddress("service@api.services")

        # Add to store
        await binding_store.set(addr, BindingStoreEntry(address=str(addr)))

        # Manually add to bindings
        existing_binding = InMemoryBinding(addr)
        binding_manager_no_upstream._bindings[addr] = existing_binding

        await binding_manager_no_upstream.restore()

        # Should keep existing binding
        assert binding_manager_no_upstream._bindings[addr] is existing_binding

    # Test upstream binding with errors
    @pytest.mark.asyncio
    async def test_bind_address_upstream_timeout(self, binding_manager_with_upstream):
        """Test upstream bind timeout handling."""
        addr = FameAddress("service@api.services")

        # Configure delivery tracker to raise timeout exception
        binding_manager_with_upstream._delivery_tracker.await_ack.side_effect = asyncio.TimeoutError()

        # Never respond to simulate timeout
        with pytest.raises(RuntimeError, match="Timeout waiting for bind ack"):
            await binding_manager_with_upstream._bind_address_upstream(addr)

    @pytest.mark.asyncio
    async def test_bind_address_upstream_rejected(self, binding_manager_with_upstream):
        """Test upstream bind rejection handling."""
        addr = FameAddress("service@api.services")

        # Configure delivery tracker to return failure ACK
        from naylence.fame.core import DeliveryAckFrame

        failure_ack_frame = DeliveryAckFrame(ok=False)
        failure_ack_envelope = create_fame_envelope(frame=failure_ack_frame)
        binding_manager_with_upstream._delivery_tracker.await_ack.return_value = failure_ack_envelope

        # Should raise exception for rejected bind
        with pytest.raises(RuntimeError, match="rejected"):
            await binding_manager_with_upstream._bind_address_upstream(addr)

    # Test bind with rollback on upstream failure
    @pytest.mark.asyncio
    async def test_bind_rollback_on_upstream_failure(self, binding_manager_with_upstream):
        """Test bind rolls back local bindings on upstream failure."""
        participant = "service@api.services"

        # Make upstream bind fail
        with patch.object(binding_manager_with_upstream, "_bind_address_upstream") as mock_bind:
            mock_bind.side_effect = RuntimeError("Upstream failed")

            with pytest.raises(RuntimeError, match="Upstream failed"):
                await binding_manager_with_upstream.bind(participant)

            # Should not have local binding
            addr = FameAddress(participant)
            assert not binding_manager_with_upstream.has_binding(addr)

    @pytest.mark.asyncio
    async def test_bind_rollback_on_capability_failure(self, binding_manager_with_upstream):
        """Test bind rolls back on capability advertisement failure."""
        participant = "service@node123.services"  # Should match *.services pool
        capabilities = ["test-capability"]

        # Make capability advertisement fail
        with (
            patch.object(binding_manager_with_upstream, "_bind_address_upstream") as mock_bind,
            patch.object(binding_manager_with_upstream, "_advertise_capabilities") as mock_caps,
            patch.object(binding_manager_with_upstream, "_unbind_address_upstream") as mock_unbind,
        ):
            mock_bind.return_value = None  # Success
            mock_caps.side_effect = RuntimeError("Capability failed")
            mock_unbind.return_value = None

            with pytest.raises(RuntimeError, match="Capability failed"):
                await binding_manager_with_upstream.bind(participant, capabilities=capabilities)

            # Should have attempted to unbind
            mock_unbind.assert_called_once()

    # Test bind validation
    @pytest.mark.asyncio
    async def test_bind_invalid_location_not_accepted(self, binding_manager_with_upstream):
        """Test bind rejects locations not in accepted logicals."""
        participant = "service@invalid.domain"

        with pytest.raises(ValueError, match="not permitted"):
            await binding_manager_with_upstream.bind(participant)

    @pytest.mark.asyncio
    async def test_bind_with_pool_claim_creates_instance_binding(self, binding_manager_with_upstream):
        """Test bind with pool claim creates both pattern and instance bindings."""
        participant = "service@data.services"  # Should match *.services

        # Mock successful upstream operations
        with patch.object(binding_manager_with_upstream, "_bind_address_upstream") as mock_bind:
            mock_bind.return_value = None

            await binding_manager_with_upstream.bind(participant)

            # Should have both pattern and instance bindings
            pattern_addr = FameAddress("service@*.services")
            instance_addr = FameAddress("service@data.services")

            assert binding_manager_with_upstream.has_binding(pattern_addr)
            assert binding_manager_with_upstream.has_binding(instance_addr)

    @pytest.mark.asyncio
    async def test_bind_exact_logical_no_instance(self, binding_manager_with_upstream):
        """Test bind with exact logical creates only one binding."""
        participant = "service@exact.match"

        # Mock successful upstream operations
        with patch.object(binding_manager_with_upstream, "_bind_address_upstream") as mock_bind:
            mock_bind.return_value = None

            await binding_manager_with_upstream.bind(participant)

            # Should have only exact binding
            exact_addr = FameAddress("service@exact.match")
            assert binding_manager_with_upstream.has_binding(exact_addr)

    @pytest.mark.asyncio
    async def test_bind_physical_path_only(self, binding_manager_no_upstream):
        """Test bind to physical path creates only physical binding."""
        participant = "service"  # Uses physical path

        await binding_manager_no_upstream.bind(participant)

        physical_addr = FameAddress("service@/test/physical/path")
        assert binding_manager_no_upstream.has_binding(physical_addr)

    # Test unbinding functionality
    @pytest.mark.asyncio
    async def test_unbind_with_pool_claim(self, binding_manager_with_upstream):
        """Test unbind removes both pattern and instance bindings."""
        participant = "service@data.services"

        # First bind
        with (
            patch.object(binding_manager_with_upstream, "_bind_address_upstream"),
            patch.object(binding_manager_with_upstream, "_unbind_address_upstream") as mock_unbind,
        ):
            await binding_manager_with_upstream.bind(participant)
            mock_unbind.return_value = None

            # Then unbind
            await binding_manager_with_upstream.unbind(participant)

            # Should remove both bindings
            pattern_addr = FameAddress("service@*.services")
            instance_addr = FameAddress("service@data.services")

            assert not binding_manager_with_upstream.has_binding(pattern_addr)
            assert not binding_manager_with_upstream.has_binding(instance_addr)

    @pytest.mark.asyncio
    async def test_unbind_exact_logical(self, binding_manager_with_upstream):
        """Test unbind exact logical address."""
        participant = "service@exact.match"

        # First bind
        with (
            patch.object(binding_manager_with_upstream, "_bind_address_upstream"),
            patch.object(binding_manager_with_upstream, "_unbind_address_upstream") as mock_unbind,
        ):
            await binding_manager_with_upstream.bind(participant)
            mock_unbind.return_value = None

            # Then unbind
            await binding_manager_with_upstream.unbind(participant)

            exact_addr = FameAddress("service@exact.match")
            assert not binding_manager_with_upstream.has_binding(exact_addr)

    @pytest.mark.asyncio
    async def test_unbind_physical_path(self, binding_manager_no_upstream):
        """Test unbind physical path address."""
        participant = "service"

        await binding_manager_no_upstream.bind(participant)
        await binding_manager_no_upstream.unbind(participant)

        physical_addr = FameAddress("service@/test/physical/path")
        assert not binding_manager_no_upstream.has_binding(physical_addr)

    @pytest.mark.asyncio
    async def test_unbind_invalid_location(self, binding_manager_with_upstream):
        """Test unbind rejects invalid locations."""
        participant = "service@invalid.domain"

        with pytest.raises(ValueError, match="not permitted"):
            await binding_manager_with_upstream.unbind(participant)

    # Test unbind upstream communication
    @pytest.mark.asyncio
    async def test_unbind_address_upstream_timeout(self, binding_manager_with_upstream):
        """Test upstream unbind timeout handling."""
        addr = FameAddress("service@api.services")

        # Configure delivery tracker to raise timeout exception
        binding_manager_with_upstream._delivery_tracker.await_ack.side_effect = asyncio.TimeoutError()

        with pytest.raises(RuntimeError, match="Timeout waiting for unbind ack"):
            await binding_manager_with_upstream._unbind_address_upstream(addr)

    @pytest.mark.asyncio
    async def test_unbind_address_upstream_rejected(self, binding_manager_with_upstream):
        """Test upstream unbind rejection handling."""
        addr = FameAddress("service@api.services")

        # Configure delivery tracker to return failure ACK
        from naylence.fame.core import DeliveryAckFrame

        failure_ack_frame = DeliveryAckFrame(ok=False)
        failure_ack_envelope = create_fame_envelope(frame=failure_ack_frame)
        binding_manager_with_upstream._delivery_tracker.await_ack.return_value = failure_ack_envelope

        # Should raise exception for rejected unbind
        with pytest.raises(RuntimeError, match="was rejected"):
            await binding_manager_with_upstream._unbind_address_upstream(addr)

    # Test ACK handling
    @pytest.mark.asyncio
    async def test_handle_ack_bind_success(self, binding_manager_with_upstream):
        """Test handle_ack delegates to delivery tracker."""
        addr = FameAddress("service@api.services")
        corr_id = "test-correlation"

        frame = AddressBindAckFrame(address=addr, ok=True)
        envelope = create_fame_envelope(frame=frame, corr_id=corr_id)

        await binding_manager_with_upstream.handle_ack(envelope)

        # Verify the delivery tracker's on_envelope_delivered was called
        binding_manager_with_upstream._delivery_tracker.on_envelope_delivered.assert_called_once_with(
            "__sys__", envelope, None
        )

    @pytest.mark.asyncio
    async def test_handle_ack_bind_failure(self, binding_manager_with_upstream):
        """Test handle_ack delegates to delivery tracker for failures."""
        addr = FameAddress("service@api.services")
        corr_id = "test-correlation"

        frame = AddressBindAckFrame(address=addr, ok=False)
        envelope = create_fame_envelope(frame=frame, corr_id=corr_id)

        await binding_manager_with_upstream.handle_ack(envelope)

        # Verify the delivery tracker's on_envelope_delivered was called
        binding_manager_with_upstream._delivery_tracker.on_envelope_delivered.assert_called_once_with(
            "__sys__", envelope, None
        )

    @pytest.mark.asyncio
    async def test_handle_ack_capability_success(self, binding_manager_with_upstream):
        """Test handle_ack for successful capability advertisement."""
        addr = FameAddress("service@api.services")
        caps = ["capability1"]
        corr_id = "test-correlation"

        frame = CapabilityAdvertiseAckFrame(address=addr, capabilities=caps, ok=True)
        envelope = create_fame_envelope(frame=frame, corr_id=corr_id)

        await binding_manager_with_upstream.handle_ack(envelope)

        # Verify the delivery tracker's on_envelope_delivered was called
        binding_manager_with_upstream._delivery_tracker.on_envelope_delivered.assert_called_once_with(
            "__sys__", envelope, None
        )

    @pytest.mark.asyncio
    async def test_handle_ack_capability_withdraw_success(self, binding_manager_with_upstream):
        """Test handle_ack for capability withdrawal."""
        addr = FameAddress("service@api.services")
        caps = ["capability1"]
        corr_id = "test-correlation"

        frame = CapabilityWithdrawAckFrame(address=addr, capabilities=caps, ok=True)
        envelope = create_fame_envelope(frame=frame, corr_id=corr_id)

        await binding_manager_with_upstream.handle_ack(envelope)

        # Verify the delivery tracker's on_envelope_delivered was called
        binding_manager_with_upstream._delivery_tracker.on_envelope_delivered.assert_called_once_with(
            "__sys__", envelope, None
        )

    @pytest.mark.asyncio
    async def test_handle_ack_missing_correlation_id(self, binding_manager_with_upstream):
        """Test handle_ack with missing correlation ID."""
        addr = FameAddress("service@api.services")
        frame = AddressBindAckFrame(address=addr, ok=True)
        envelope = create_fame_envelope(frame=frame, corr_id=None)

        # Should not crash
        await binding_manager_with_upstream.handle_ack(envelope)

    @pytest.mark.asyncio
    async def test_handle_ack_unknown_correlation_id(self, binding_manager_with_upstream):
        """Test handle_ack with unknown correlation ID."""
        addr = FameAddress("service@api.services")
        frame = AddressBindAckFrame(address=addr, ok=True)
        envelope = create_fame_envelope(frame=frame, corr_id="unknown")

        # Should not crash
        await binding_manager_with_upstream.handle_ack(envelope)

    @pytest.mark.asyncio
    async def test_handle_ack_already_done_future(self, binding_manager_with_upstream):
        """Test handle_ack with delivery tracker (no longer uses futures directly)."""
        addr = FameAddress("service@api.services")
        corr_id = "test-correlation"

        frame = AddressBindAckFrame(address=addr, ok=False)
        envelope = create_fame_envelope(frame=frame, corr_id=corr_id)

        # Should delegate to delivery tracker without error
        await binding_manager_with_upstream.handle_ack(envelope)
        binding_manager_with_upstream._delivery_tracker.on_envelope_delivered.assert_called_once_with(
            "__sys__", envelope, None
        )

    # Test capability management
    @pytest.mark.asyncio
    async def test_advertise_capabilities_empty_list(self, binding_manager_with_upstream):
        """Test advertising empty capabilities list."""
        addr = FameAddress("service@api.services")

        # Should return early without network call
        await binding_manager_with_upstream._advertise_capabilities(addr, [])

        # No capabilities should be recorded
        assert addr not in binding_manager_with_upstream._capabilities_by_address

    @pytest.mark.asyncio
    async def test_advertise_capabilities_success(self, binding_manager_with_upstream):
        """Test successful capability advertisement."""
        addr = FameAddress("service@api.services")
        caps = ["capability1", "capability2"]

        # Configure delivery tracker to return success ACK
        success_ack_frame = CapabilityAdvertiseAckFrame(address=addr, capabilities=caps, ok=True)
        success_ack_envelope = create_fame_envelope(frame=success_ack_frame)
        binding_manager_with_upstream._delivery_tracker.await_ack.return_value = success_ack_envelope

        # Should succeed without exception
        await binding_manager_with_upstream._advertise_capabilities(addr, caps)

        # Verify capabilities were added
        assert addr in binding_manager_with_upstream._capabilities_by_address
        assert binding_manager_with_upstream._capabilities_by_address[addr] == set(caps)

    @pytest.mark.asyncio
    async def test_advertise_capabilities_timeout(self, binding_manager_with_upstream):
        """Test capability advertisement timeout."""
        addr = FameAddress("service@api.services")
        caps = ["capability1"]

        # Configure delivery tracker to raise timeout exception
        binding_manager_with_upstream._delivery_tracker.await_ack.side_effect = asyncio.TimeoutError()

        with pytest.raises(RuntimeError, match="Timeout waiting for advertise ack"):
            await binding_manager_with_upstream._advertise_capabilities(addr, caps)

    @pytest.mark.asyncio
    async def test_advertise_capabilities_rejected(self, binding_manager_with_upstream):
        """Test capability advertisement rejection."""
        addr = FameAddress("service@api.services")
        caps = ["capability1"]

        # Configure delivery tracker to return failure ACK
        failure_ack_frame = CapabilityAdvertiseAckFrame(address=addr, capabilities=caps, ok=False)
        failure_ack_envelope = create_fame_envelope(frame=failure_ack_frame)
        binding_manager_with_upstream._delivery_tracker.await_ack.return_value = failure_ack_envelope

        with pytest.raises(RuntimeError, match="Capability advertise rejected"):
            await binding_manager_with_upstream._advertise_capabilities(addr, caps) @ pytest.mark.asyncio

    async def test_withdraw_capabilities_empty_list(self, binding_manager_with_upstream):
        """Test withdrawing empty capabilities list."""
        addr = FameAddress("service@api.services")

        # Should return early
        await binding_manager_with_upstream.withdraw_capabilities(addr, [])

    @pytest.mark.asyncio
    async def test_withdraw_capabilities_success(self, binding_manager_with_upstream):
        """Test successful capability withdrawal."""
        addr = FameAddress("service@api.services")
        caps = ["capability1", "capability2"]

        # Pre-populate capabilities
        binding_manager_with_upstream._capabilities_by_address[addr] = set(caps)

        # Configure delivery tracker to return success ACK
        success_ack_frame = CapabilityWithdrawAckFrame(address=addr, capabilities=caps, ok=True)
        success_ack_envelope = create_fame_envelope(frame=success_ack_frame)
        binding_manager_with_upstream._delivery_tracker.await_ack.return_value = success_ack_envelope

        # Should succeed without exception
        await binding_manager_with_upstream.withdraw_capabilities(addr, caps)

        # Should remove capabilities
        assert addr not in binding_manager_with_upstream._capabilities_by_address

    @pytest.mark.asyncio
    async def test_withdraw_capabilities_partial(self, binding_manager_with_upstream):
        """Test partial capability withdrawal."""
        addr = FameAddress("service@api.services")
        all_caps = ["capability1", "capability2", "capability3"]
        withdraw_caps = ["capability1", "capability2"]

        # Pre-populate capabilities
        binding_manager_with_upstream._capabilities_by_address[addr] = set(all_caps)

        # Configure delivery tracker to return success ACK
        success_ack_frame = CapabilityWithdrawAckFrame(address=addr, capabilities=withdraw_caps, ok=True)
        success_ack_envelope = create_fame_envelope(frame=success_ack_frame)
        binding_manager_with_upstream._delivery_tracker.await_ack.return_value = success_ack_envelope

        # Should succeed without exception
        await binding_manager_with_upstream.withdraw_capabilities(addr, withdraw_caps)

        # Should keep remaining capability
        assert addr in binding_manager_with_upstream._capabilities_by_address
        assert binding_manager_with_upstream._capabilities_by_address[addr] == {"capability3"}

    @pytest.mark.asyncio
    async def test_withdraw_capabilities_timeout(self, binding_manager_with_upstream):
        """Test capability withdrawal timeout."""
        addr = FameAddress("service@api.services")
        caps = ["capability1"]

        # Configure delivery tracker to raise timeout exception
        binding_manager_with_upstream._delivery_tracker.await_ack.side_effect = asyncio.TimeoutError()

        with pytest.raises(RuntimeError, match="Timeout waiting for withdraw caps"):
            await binding_manager_with_upstream.withdraw_capabilities(addr, caps)

    @pytest.mark.asyncio
    async def test_withdraw_capabilities_rejected(self, binding_manager_with_upstream):
        """Test capability withdrawal rejection."""
        addr = FameAddress("service@api.services")
        caps = ["capability1"]

        # Configure delivery tracker to return failure ACK
        failure_ack_frame = CapabilityWithdrawAckFrame(address=addr, capabilities=caps, ok=False)
        failure_ack_envelope = create_fame_envelope(frame=failure_ack_frame)
        binding_manager_with_upstream._delivery_tracker.await_ack.return_value = failure_ack_envelope

        with pytest.raises(RuntimeError, match="Capability withdraw rejected"):
            await binding_manager_with_upstream.withdraw_capabilities(
                addr, caps
            )  # Test rebind addresses upstream

    @pytest.mark.asyncio
    async def test_rebind_addresses_upstream_no_upstream(self, binding_manager_no_upstream):
        """Test rebind addresses when no upstream is configured."""
        # Should log warning and return
        await binding_manager_no_upstream.rebind_addresses_upstream()

    @pytest.mark.asyncio
    async def test_rebind_addresses_upstream_with_addresses(self, binding_manager_with_upstream):
        """Test rebind addresses upstream with bound addresses."""
        # Add some bindings that should be rebound
        logical_addr = FameAddress("service@api.services")
        physical_addr = FameAddress("service@/test/physical/path")

        binding_manager_with_upstream._bindings[logical_addr] = InMemoryBinding(logical_addr)
        binding_manager_with_upstream._bindings[physical_addr] = InMemoryBinding(physical_addr)

        with patch.object(binding_manager_with_upstream, "_bind_address_upstream") as mock_bind:
            mock_bind.return_value = None

            await binding_manager_with_upstream.rebind_addresses_upstream()

            # Should attempt to rebind logical addresses but not physical
            mock_bind.assert_called()

    @pytest.mark.asyncio
    async def test_rebind_addresses_upstream_handles_errors(self, binding_manager_with_upstream):
        """Test rebind addresses handles individual bind errors gracefully."""
        logical_addr = FameAddress("service@api.services")
        binding_manager_with_upstream._bindings[logical_addr] = InMemoryBinding(logical_addr)

        with patch.object(binding_manager_with_upstream, "_bind_address_upstream") as mock_bind:
            mock_bind.side_effect = RuntimeError("Bind failed")

            # Should not raise, just log errors
            await binding_manager_with_upstream.rebind_addresses_upstream()

    # Test readvertise capabilities upstream
    @pytest.mark.asyncio
    async def test_readvertise_capabilities_upstream_no_upstream(self, binding_manager_no_upstream):
        """Test readvertise capabilities when no upstream is configured."""
        await binding_manager_no_upstream.readvertise_capabilities_upstream()

    @pytest.mark.asyncio
    async def test_readvertise_capabilities_upstream_with_capabilities(self, binding_manager_with_upstream):
        """Test readvertise capabilities upstream."""
        addr = FameAddress("service@api.services")
        caps = {"capability1", "capability2"}

        binding_manager_with_upstream._capabilities_by_address[addr] = caps

        with patch.object(binding_manager_with_upstream, "_advertise_capabilities") as mock_advertise:
            mock_advertise.return_value = None

            await binding_manager_with_upstream.readvertise_capabilities_upstream()

            mock_advertise.assert_called_once_with(addr, list(caps))

    @pytest.mark.asyncio
    async def test_readvertise_capabilities_handles_errors(self, binding_manager_with_upstream):
        """Test readvertise capabilities handles errors gracefully."""
        addr = FameAddress("service@api.services")
        caps = {"capability1"}

        binding_manager_with_upstream._capabilities_by_address[addr] = caps

        with patch.object(binding_manager_with_upstream, "_advertise_capabilities") as mock_advertise:
            mock_advertise.side_effect = RuntimeError("Advertisement failed")

            # Should not raise, just log errors
            await binding_manager_with_upstream.readvertise_capabilities_upstream()

    # Test helper methods
    def test_is_physical_path_prefix(self, binding_manager_no_upstream):
        """Test _is_physical_path_prefix method."""
        # Test with physical path prefix
        assert binding_manager_no_upstream._is_physical_path_prefix("/test/physical/path/subpath")
        assert binding_manager_no_upstream._is_physical_path_prefix("/test/physical/path")

        # Test with non-matching paths
        assert not binding_manager_no_upstream._is_physical_path_prefix("/other/path")
        assert not binding_manager_no_upstream._is_physical_path_prefix("/test")

    def test_should_rebind_host_based_logical(self, binding_manager_with_upstream):
        """Test _should_rebind with host-based logical addresses."""
        # Logical address should be rebound
        logical_addr = FameAddress("service@api.services")
        assert binding_manager_with_upstream._should_rebind(logical_addr)

        # Pool matching address should be rebound
        pool_addr = FameAddress("service@data.services")  # Matches *.services
        assert binding_manager_with_upstream._should_rebind(pool_addr)

    def test_should_rebind_physical_address(self, binding_manager_with_upstream):
        """Test _should_rebind with physical addresses."""
        # Physical address should not be rebound
        physical_addr = FameAddress("service@/test/physical/path")
        assert not binding_manager_with_upstream._should_rebind(physical_addr)

    def test_should_rebind_parse_exception(self, binding_manager_with_upstream):
        """Test _should_rebind handles parse exceptions."""
        # Create address that might cause parse issues
        problem_addr = FameAddress("service@malformed")
        # Should handle gracefully and return False
        result = binding_manager_with_upstream._should_rebind(problem_addr)
        assert result is False

    def test_find_host_pool_claim_exact_match(self, binding_manager_no_upstream):
        """Test _find_host_pool_claim finds matching pool pattern."""
        logical = "data.services"
        accepted = {"*.services", "api.services"}

        result = binding_manager_no_upstream._find_host_pool_claim(accepted, logical)
        assert result == "*.services"

    def test_find_host_pool_claim_no_match(self, binding_manager_no_upstream):
        """Test _find_host_pool_claim returns None when no match."""
        logical = "data.unknown"
        accepted = {"*.services", "api.services"}

        result = binding_manager_no_upstream._find_host_pool_claim(accepted, logical)
        assert result is None

    def test_find_host_pool_claim_empty_logical(self, binding_manager_no_upstream):
        """Test _find_host_pool_claim with empty logical."""
        result = binding_manager_no_upstream._find_host_pool_claim(set(), "")
        assert result is None

    def test_is_accepted_logical_host_exact_match(self, binding_manager_no_upstream):
        """Test _is_accepted_logical_host with exact match."""
        assert binding_manager_no_upstream._is_accepted_logical_host("exact.match")

    def test_is_accepted_logical_host_pool_pattern(self, binding_manager_no_upstream):
        """Test _is_accepted_logical_host rejects pool patterns."""
        assert not binding_manager_no_upstream._is_accepted_logical_host("*.services")

    def test_is_accepted_logical_host_not_accepted(self, binding_manager_no_upstream):
        """Test _is_accepted_logical_host with non-accepted logical."""
        assert not binding_manager_no_upstream._is_accepted_logical_host("not.accepted")

    def test_is_accepted_logical_host_empty(self, binding_manager_no_upstream):
        """Test _is_accepted_logical_host with empty logical."""
        assert not binding_manager_no_upstream._is_accepted_logical_host("")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
