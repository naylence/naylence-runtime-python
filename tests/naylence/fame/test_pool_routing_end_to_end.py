#!/usr/bin/env python3
"""
End-to-end integration test for pool routing with host-based wildcards.

Tests that pool routing works correctly with the updated pool pattern storage
and host-based wildcard matching logic.
"""

import pytest

from naylence.fame.core.address import parse_address_components
from naylence.fame.sentinel.hybrid_path_routing_policy import HybridPathRoutingPolicy
from naylence.fame.sentinel.load_balancing_strategy import RoundRobinLoadBalancingStrategy
from naylence.fame.sentinel.router import RouterState


class TestPoolRoutingEndToEnd:
    """End-to-end pool routing integration tests."""

    def test_host_based_pool_routing(self):
        """Test that host-based pool routing works end-to-end."""
        # Create routing policy
        policy = HybridPathRoutingPolicy(load_balancing_strategy=RoundRobinLoadBalancingStrategy())

        # Create router state with pool pattern
        state = RouterState(
            node_id="test-node",
            local={},
            downstream_address_routes={},
            child_segments=set(),
            peer_segments=set(),
            has_parent=False,
            physical_segments={},
            pools={},
        )

        # Store pool pattern as address bind handler does: (name, host) tuple
        pool_key = ("math", "*.fame.fabric")
        pool_members = {"node1", "node2", "node3"}
        state.pools[pool_key] = pool_members

        # Test addresses that should match the pool
        matching_addresses = [
            "math@api.fame.fabric",
            "math@compute.fame.fabric",
            "math@data.fame.fabric",
            "math@fame.fabric",  # Base domain should also match
        ]

        for address in matching_addresses:
            participant, host, path = parse_address_components(address)
            chosen = policy._find_host_pool_route(participant, host, state, None)

            # Should find a route in the pool
            assert chosen is not None, f"Expected route for {address}, got None"
            assert chosen in pool_members, f"Route {chosen} not in pool members {pool_members}"

    def test_pool_routing_exclusions(self):
        """Test that non-matching addresses don't route to the pool."""
        policy = HybridPathRoutingPolicy(load_balancing_strategy=RoundRobinLoadBalancingStrategy())

        state = RouterState(
            node_id="test-node",
            local={},
            downstream_address_routes={},
            child_segments=set(),
            peer_segments=set(),
            has_parent=False,
            physical_segments={},
            pools={},
        )

        # Store pool pattern
        pool_key = ("math", "*.fame.fabric")
        state.pools[pool_key] = {"node1", "node2", "node3"}

        # Test addresses that should NOT match the pool
        non_matching_addresses = [
            "physics@api.fame.fabric",  # Different participant
            "math@api.other.domain",  # Different base domain
            "math@other.domain",  # Completely different domain
        ]

        for address in non_matching_addresses:
            participant, host, path = parse_address_components(address)
            chosen = policy._find_host_pool_route(participant, host, state, None)

            # Should not find a route in the pool
            assert chosen is None, f"Expected no route for {address}, got {chosen}"

    def test_multiple_pool_patterns(self):
        """Test routing with multiple pool patterns."""
        policy = HybridPathRoutingPolicy(load_balancing_strategy=RoundRobinLoadBalancingStrategy())

        state = RouterState(
            node_id="test-node",
            local={},
            downstream_address_routes={},
            child_segments=set(),
            peer_segments=set(),
            has_parent=False,
            physical_segments={},
            pools={},
        )

        # Store multiple pool patterns
        state.pools[("math", "*.fame.fabric")] = {"math-node1", "math-node2"}
        state.pools[("api", "*.service.domain")] = {"api-node1", "api-node2"}

        # Test routing to first pool
        participant, host, path = parse_address_components("math@compute.fame.fabric")
        chosen = policy._find_host_pool_route(participant, host, state, None)
        assert chosen in {"math-node1", "math-node2"}

        # Test routing to second pool
        participant, host, path = parse_address_components("api@gateway.service.domain")
        chosen = policy._find_host_pool_route(participant, host, state, None)
        assert chosen in {"api-node1", "api-node2"}

        # Test non-matching address
        participant, host, path = parse_address_components("worker@compute.fame.fabric")
        chosen = policy._find_host_pool_route(participant, host, state, None)
        assert chosen is None

    def test_pool_routing_with_paths(self):
        """Test that pool routing works with path-containing addresses."""
        policy = HybridPathRoutingPolicy(load_balancing_strategy=RoundRobinLoadBalancingStrategy())

        state = RouterState(
            node_id="test-node",
            local={},
            downstream_address_routes={},
            child_segments=set(),
            peer_segments=set(),
            has_parent=False,
            physical_segments={},
            pools={},
        )

        # Store pool pattern with path
        pool_key = ("math", "*.fame.fabric")
        state.pools[pool_key] = {"node1", "node2"}

        # Test that host-based pool routing works regardless of path
        test_cases = [
            "math@api.fame.fabric/compute",
            "math@compute.fame.fabric/jobs/task1",
            "math@fame.fabric/status",
        ]

        for address in test_cases:
            participant, host, path = parse_address_components(address)
            chosen = policy._find_host_pool_route(participant, host, state, None)
            assert chosen in {"node1", "node2"}, f"Expected pool route for {address}"

    def test_load_balancing_distribution(self):
        """Test that load balancing distributes across pool members."""
        policy = HybridPathRoutingPolicy(load_balancing_strategy=RoundRobinLoadBalancingStrategy())

        state = RouterState(
            node_id="test-node",
            local={},
            downstream_address_routes={},
            child_segments=set(),
            peer_segments=set(),
            has_parent=False,
            physical_segments={},
            pools={},
        )

        # Store pool pattern
        pool_key = ("math", "*.fame.fabric")
        pool_members = {"node1", "node2", "node3"}
        state.pools[pool_key] = pool_members

        # Make multiple routing decisions
        chosen_nodes = set()
        for i in range(10):  # Try enough times to likely hit all nodes
            participant, host, path = parse_address_components("math@api.fame.fabric")
            chosen = policy._find_host_pool_route(participant, host, state, None)
            assert chosen in pool_members
            chosen_nodes.add(chosen)

        # Should have distributed across multiple nodes (round-robin)
        assert len(chosen_nodes) > 1, (
            f"Load balancing should distribute across nodes, only got {chosen_nodes}"
        )

    def test_complex_host_patterns(self):
        """Test pool routing with complex host patterns."""
        policy = HybridPathRoutingPolicy(load_balancing_strategy=RoundRobinLoadBalancingStrategy())

        state = RouterState(
            node_id="test-node",
            local={},
            downstream_address_routes={},
            child_segments=set(),
            peer_segments=set(),
            has_parent=False,
            physical_segments={},
            pools={},
        )

        # Store complex pool pattern
        pool_key = ("service", "*.api.fame.fabric")
        state.pools[pool_key] = {"api-node1", "api-node2"}

        # Test matching addresses
        matching_addresses = [
            "service@v1.api.fame.fabric",
            "service@gateway.api.fame.fabric",
            "service@api.fame.fabric",  # Base matches
        ]

        for address in matching_addresses:
            participant, host, path = parse_address_components(address)
            chosen = policy._find_host_pool_route(participant, host, state, None)
            assert chosen in {"api-node1", "api-node2"}, f"Expected pool route for {address}"

        # Test non-matching addresses
        non_matching_addresses = [
            "service@v1.other.fame.fabric",  # Different middle segment
            "other@v1.api.fame.fabric",  # Different participant
        ]

        for address in non_matching_addresses:
            participant, host, path = parse_address_components(address)
            chosen = policy._find_host_pool_route(participant, host, state, None)
            assert chosen is None, f"Should not route {address} to pool"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
