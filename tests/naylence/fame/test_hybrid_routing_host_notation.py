"""
Comprehensive tests for hybrid path routing policy with host-like logical addresses.

These tests ensure the routing policy correctly handles:
1. Host-like logical addresses (e.g., alice@api.services)
2. Pool routing with host-like patterns (e.g., *.services)
3. Mixed routing scenarios combining host-like and path-based addresses
4. Edge cases and backward compatibility
"""

import pytest

from naylence.fame.core import (
    DataFrame,
    create_fame_envelope,
    format_address,
    format_address_from_components,
)
from naylence.fame.sentinel.hybrid_path_routing_policy import HybridPathRoutingPolicy
from naylence.fame.sentinel.router import (
    DeliverLocal,
    Drop,
    ForwardChild,
    ForwardPeer,
    ForwardUp,
    RouterState,
)


class TestHybridPathRoutingPolicyHostNotation:
    """Test hybrid path routing policy with host-like logical addresses."""

    @pytest.fixture
    def policy(self):
        """Create a routing policy instance."""
        return HybridPathRoutingPolicy()

    @pytest.fixture
    def base_state(self):
        """Create a base router state."""
        return RouterState(
            node_id="router1",
            local=set(),
            downstream_address_routes={},
            peer_address_routes={},
            pools={},
            has_parent=True,
            physical_segments=["segment1"],
            child_segments={"child1", "child2"},
            peer_segments={"peer1"},
        )

    @pytest.mark.asyncio
    async def test_deliver_local_host_address(self, policy, base_state):
        """Test local delivery for host-like addresses."""
        addr = format_address_from_components("service", host="api.internal")
        env = create_fame_envelope(frame=DataFrame(payload="test"), to=addr)

        base_state.local.add(addr)
        action = await policy.decide(env, base_state)

        assert isinstance(action, DeliverLocal)
        assert action.recipient_name == addr

    @pytest.mark.asyncio
    async def test_deliver_local_host_with_path_address(self, policy, base_state):
        """Test local delivery for host+path addresses."""
        addr = format_address_from_components("service", host="api.internal", path="/v1")
        env = create_fame_envelope(frame=DataFrame(payload="test"), to=addr)

        base_state.local.add(addr)
        action = await policy.decide(env, base_state)

        assert isinstance(action, DeliverLocal)
        assert action.recipient_name == addr

    @pytest.mark.asyncio
    async def test_forward_child_exact_host_route(self, policy, base_state):
        """Test forwarding to child for exact host route."""
        addr = format_address_from_components("service", host="api.downstream")
        env = create_fame_envelope(frame=DataFrame(payload="test"), to=addr)

        base_state.downstream_address_routes[addr] = "child1"
        action = await policy.decide(env, base_state)

        assert isinstance(action, ForwardChild)
        assert action.segment == "child1"

    @pytest.mark.asyncio
    async def test_forward_peer_exact_host_route(self, policy, base_state):
        """Test forwarding to peer for exact host route."""
        addr = format_address_from_components("service", host="api.peer")
        env = create_fame_envelope(frame=DataFrame(payload="test"), to=addr)

        base_state.peer_address_routes[addr] = "peer1"
        action = await policy.decide(env, base_state)

        assert isinstance(action, ForwardPeer)
        assert action.segment == "peer1"

    @pytest.mark.asyncio
    async def test_host_pool_routing_single_pattern(self, policy, base_state):
        """Test pool routing with a single host-like pattern."""
        # Create an address that should match *.services pool pattern
        target_addr = format_address_from_components("worker", host="api.services")
        env = create_fame_envelope(frame=DataFrame(payload="work"), to=target_addr)

        # Set up pool with host-like pattern
        pool_key = ("worker", "*.services")
        base_state.pools[pool_key] = {"child1", "child2"}

        action = await policy.decide(env, base_state)

        assert isinstance(action, ForwardChild)
        assert action.segment in {"child1", "child2"}

    @pytest.mark.asyncio
    async def test_host_pool_routing_multiple_patterns(self, policy, base_state):
        """Test pool routing with multiple host-like patterns."""
        # Test api.services matches *.services
        api_addr = format_address_from_components("worker", host="api.services")
        api_env = create_fame_envelope(frame=DataFrame(payload="api"), to=api_addr)

        # Test data.services matches *.services
        data_addr = format_address_from_components("worker", host="data.services")
        data_env = create_fame_envelope(frame=DataFrame(payload="data"), to=data_addr)

        # Test auth.internal matches *.internal
        auth_addr = format_address_from_components("worker", host="auth.internal")
        auth_env = create_fame_envelope(frame=DataFrame(payload="auth"), to=auth_addr)

        # Set up pools
        base_state.pools[("worker", "*.services")] = {"services-child"}
        base_state.pools[("worker", "*.internal")] = {"internal-child"}

        # Test *.services pool
        action1 = await policy.decide(api_env, base_state)
        assert isinstance(action1, ForwardChild)
        assert action1.segment == "services-child"

        action2 = await policy.decide(data_env, base_state)
        assert isinstance(action2, ForwardChild)
        assert action2.segment == "services-child"

        # Test *.internal pool
        action3 = await policy.decide(auth_env, base_state)
        assert isinstance(action3, ForwardChild)
        assert action3.segment == "internal-child"

    @pytest.mark.asyncio
    async def test_host_pool_routing_no_match(self, policy, base_state):
        """Test that non-matching hosts don't route to pools."""
        # Address that shouldn't match any pool pattern
        addr = format_address_from_components("worker", host="external.domain")
        env = create_fame_envelope(frame=DataFrame(payload="external"), to=addr)

        # Set up pools that shouldn't match
        base_state.pools[("worker", "*.services")] = {"child1"}
        base_state.pools[("worker", "*.internal")] = {"child2"}

        action = await policy.decide(env, base_state)

        # Should fallback to ForwardUp since has_parent=True
        assert isinstance(action, ForwardUp)

    @pytest.mark.asyncio
    async def test_host_pool_routing_with_paths(self, policy, base_state):
        """Test pool routing with host+path addresses."""
        # Test that host+path addresses can match host-only pool patterns
        addr = format_address_from_components("worker", host="api.services", path="/v1/process")
        env = create_fame_envelope(frame=DataFrame(payload="process"), to=addr)

        base_state.pools[("worker", "*.services")] = {"services-pool"}

        action = await policy.decide(env, base_state)

        assert isinstance(action, ForwardChild)
        assert action.segment == "services-pool"

    @pytest.mark.asyncio
    async def test_legacy_path_pool_routing_backward_compatibility(self, policy, base_state):
        """Test that legacy path-based pool routing still works."""
        # Traditional path-based address
        addr = format_address("worker", "/legacy/path")
        env = create_fame_envelope(frame=DataFrame(payload="legacy"), to=addr)

        # Set up legacy path-based pool with the correct normalized key
        # For /legacy/path, the logical is /legacy/path, normalized to "legacy/path"
        base_state.pools[("worker", "legacy/path")] = {"legacy-child"}

        action = await policy.decide(env, base_state)

        assert isinstance(action, ForwardChild)
        assert action.segment == "legacy-child"

    @pytest.mark.asyncio
    async def test_mixed_routing_host_takes_precedence(self, policy, base_state):
        """Test that host-like routing takes precedence over path-based."""
        # Address that could match both host and path patterns
        addr = format_address_from_components("worker", host="api.services", path="/services")
        env = create_fame_envelope(frame=DataFrame(payload="mixed"), to=addr)

        # Set up both host and path pools
        base_state.pools[("worker", "*.services")] = {"host-pool"}
        base_state.pools[("worker", "/services")] = {"path-pool"}

        action = await policy.decide(env, base_state)

        # Host-like routing should take precedence
        assert isinstance(action, ForwardChild)
        assert action.segment == "host-pool"

    @pytest.mark.asyncio
    async def test_routing_priority_order(self, policy, base_state):
        """Test the priority order: local > exact route > pool > physical > up/drop."""
        addr = format_address_from_components("service", host="api.services")
        env = create_fame_envelope(frame=DataFrame(payload="priority"), to=addr)

        # Set up multiple potential routes
        base_state.local.add(addr)
        base_state.downstream_address_routes[addr] = "exact-child"
        base_state.pools[("service", "*.services")] = {"pool-child"}

        action = await policy.decide(env, base_state)

        # Local delivery should win
        assert isinstance(action, DeliverLocal)

        # Remove local, exact route should win
        base_state.local.remove(addr)
        action = await policy.decide(env, base_state)
        assert isinstance(action, ForwardChild)
        assert action.segment == "exact-child"

        # Remove exact route, pool should win
        del base_state.downstream_address_routes[addr]
        action = await policy.decide(env, base_state)
        assert isinstance(action, ForwardChild)
        assert action.segment == "pool-child"

    @pytest.mark.asyncio
    async def test_pool_routing_different_participants(self, policy, base_state):
        """Test that pool routing respects participant names."""
        # Same host, different participants
        worker_addr = format_address_from_components("worker", host="api.services")
        service_addr = format_address_from_components("service", host="api.services")

        worker_env = create_fame_envelope(frame=DataFrame(payload="worker"), to=worker_addr)
        service_env = create_fame_envelope(frame=DataFrame(payload="service"), to=service_addr)

        # Set up pools for different participants
        base_state.pools[("worker", "*.services")] = {"worker-pool"}
        base_state.pools[("service", "*.services")] = {"service-pool"}

        worker_action = await policy.decide(worker_env, base_state)
        service_action = await policy.decide(service_env, base_state)

        assert isinstance(worker_action, ForwardChild)
        assert worker_action.segment == "worker-pool"

        assert isinstance(service_action, ForwardChild)
        assert service_action.segment == "service-pool"

    @pytest.mark.asyncio
    async def test_host_only_address_routing(self, policy, base_state):
        """Test routing for host-only addresses (no path component)."""
        addr = format_address_from_components("service", host="api.domain")
        env = create_fame_envelope(frame=DataFrame(payload="host-only"), to=addr)

        base_state.pools[("service", "*.domain")] = {"domain-pool"}

        action = await policy.decide(env, base_state)

        assert isinstance(action, ForwardChild)
        assert action.segment == "domain-pool"

    @pytest.mark.asyncio
    async def test_complex_host_patterns(self, policy, base_state):
        """Test routing with complex host patterns."""
        # Test nested domain patterns
        addr1 = format_address_from_components("service", host="sub.api.services")
        addr2 = format_address_from_components("service", host="another.api.services")

        env1 = create_fame_envelope(frame=DataFrame(payload="sub"), to=addr1)
        env2 = create_fame_envelope(frame=DataFrame(payload="another"), to=addr2)

        # Pattern should match both
        base_state.pools[("service", "*.api.services")] = {"api-services-pool"}

        action1 = await policy.decide(env1, base_state)
        action2 = await policy.decide(env2, base_state)

        assert isinstance(action1, ForwardChild)
        assert action1.segment == "api-services-pool"

        assert isinstance(action2, ForwardChild)
        assert action2.segment == "api-services-pool"

    @pytest.mark.asyncio
    async def test_no_route_fallback_behavior(self, policy, base_state):
        """Test fallback behavior when no routes match."""
        addr = format_address_from_components("unknown", host="nowhere.domain")
        env = create_fame_envelope(frame=DataFrame(payload="nowhere"), to=addr)

        # Test with parent - should forward up
        base_state.has_parent = True
        action = await policy.decide(env, base_state)
        assert isinstance(action, ForwardUp)

        # Test without parent - should drop
        base_state.has_parent = False
        action = await policy.decide(env, base_state)
        assert isinstance(action, Drop)
