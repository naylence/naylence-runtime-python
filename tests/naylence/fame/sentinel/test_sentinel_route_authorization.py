"""
Integration tests for Sentinel.deliver() with route authorization.

These tests verify that the on_routing_action_selected hook is properly
wired into the Sentinel routing pipeline and works with real authorization
policies to allow or deny routing actions.
"""

from typing import Any, Optional
from unittest.mock import AsyncMock, MagicMock

import pytest

from naylence.fame.core import (
    AuthorizationContext,
    DataFrame,
    DeliveryOriginType,
    FameConnector,
    FameDeliveryContext,
    FameEnvelope,
    SecurityContext,
    create_fame_envelope,
    format_address,
    local_delivery_context,
)
from naylence.fame.node.node_event_listener import NodeEventListener
from naylence.fame.node.upstream_session_manager import UpstreamSessionManager
from naylence.fame.security.auth.default_policy_authorizer import (
    DefaultPolicyAuthorizer,
)
from naylence.fame.security.auth.policy import BasicAuthorizationPolicy
from naylence.fame.security.auth.policy.authorization_policy_definition import (
    AuthorizationPolicyDefinition,
)
from naylence.fame.security.auth.policy.basic_authorization_policy import (
    BasicAuthorizationPolicyOptions,
)
from naylence.fame.security.default_security_manager import DefaultSecurityManager
from naylence.fame.security.policy.default_security_policy import DefaultSecurityPolicy
from naylence.fame.sentinel.router import (
    DeliverLocal,
    Deny,
    Drop,
    ForwardChild,
    ForwardPeer,
    ForwardUp,
    RouterState,
    RoutingAction,
    map_routing_action_to_authorization_action,
)
from naylence.fame.sentinel.routing_policy import RoutingPolicy
from naylence.fame.sentinel.sentinel import Sentinel
from naylence.fame.sentinel.store.route_store import RouteStore


def create_allow_all_policy() -> BasicAuthorizationPolicy:
    """Create a policy that allows all routing actions."""
    policy_def = AuthorizationPolicyDefinition.from_dict({
        "version": "1.0",
        "default_effect": "allow",
        "rules": [],
    })
    return BasicAuthorizationPolicy(
        BasicAuthorizationPolicyOptions(policy_definition=policy_def)
    )


def create_deny_all_policy() -> BasicAuthorizationPolicy:
    """Create a policy that denies all routing actions."""
    policy_def = AuthorizationPolicyDefinition.from_dict({
        "version": "1.0",
        "default_effect": "deny",
        "rules": [],
    })
    return BasicAuthorizationPolicy(
        BasicAuthorizationPolicyOptions(policy_definition=policy_def)
    )


def create_selective_policy(allowed_actions: list[str]) -> BasicAuthorizationPolicy:
    """Create a policy that allows specific actions and denies others."""
    rules = []
    if allowed_actions:
        rules.append({
            "id": "allow-specific",
            "effect": "allow",
            "action": allowed_actions,
        })

    policy_def = AuthorizationPolicyDefinition.from_dict({
        "version": "1.0",
        "default_effect": "deny",
        "rules": rules,
    })
    return BasicAuthorizationPolicy(
        BasicAuthorizationPolicyOptions(policy_definition=policy_def)
    )


def create_address_based_policy(
    allowed_patterns: list[str],
    denied_patterns: Optional[list[str]] = None,
) -> BasicAuthorizationPolicy:
    """Create a policy that allows/denies based on address patterns."""
    rules = []

    # Deny rules come first (evaluated first in first-match-wins)
    if denied_patterns:
        rules.extend([
            {
                "id": f"deny-{pattern}",
                "effect": "deny",
                "address": pattern,
            }
            for pattern in denied_patterns
        ])

    # Then allow rules
    rules.extend([
        {
            "id": f"allow-{pattern}",
            "effect": "allow",
            "address": pattern,
        }
        for pattern in allowed_patterns
    ])

    policy_def = AuthorizationPolicyDefinition.from_dict({
        "version": "1.0",
        "default_effect": "deny",
        "rules": rules,
    })
    return BasicAuthorizationPolicy(
        BasicAuthorizationPolicyOptions(policy_definition=policy_def)
    )


def create_origin_type_policy(
    allowed_origins: list[str],
) -> BasicAuthorizationPolicy:
    """Create a policy that allows specific origin types."""
    policy_def = AuthorizationPolicyDefinition.from_dict({
        "version": "1.0",
        "default_effect": "deny",
        "rules": [{
            "id": "allow-specific-origins",
            "effect": "allow",
            "origin_type": allowed_origins,
        }],
    })
    return BasicAuthorizationPolicy(
        BasicAuthorizationPolicyOptions(policy_definition=policy_def)
    )


def create_scope_required_policy(
    required_scope: str,
) -> BasicAuthorizationPolicy:
    """Create a policy that requires a specific scope."""
    policy_def = AuthorizationPolicyDefinition.from_dict({
        "version": "1.0",
        "default_effect": "deny",
        "rules": [{
            "id": "require-scope",
            "effect": "allow",
            "scope": required_scope,
        }],
    })
    return BasicAuthorizationPolicy(
        BasicAuthorizationPolicyOptions(policy_definition=policy_def)
    )


def create_complex_policy() -> BasicAuthorizationPolicy:
    """
    Create a complex policy combining multiple aspects.

    Policy logic:
    1. Deny all access to admin addresses
    2. Allow ForwardUpstream to services/** from local origin with 'messaging.send' scope
    3. Allow DeliverLocal to inbox/** from any downstream/local origin
    4. Allow ForwardPeer from peer origins only
    5. Deny everything else
    """
    policy_def = AuthorizationPolicyDefinition.from_dict({
        "version": "1.0",
        "default_effect": "deny",
        "rules": [
            # Rule 1: Deny admin addresses (first-match-wins, so deny checked first)
            {
                "id": "deny-admin",
                "effect": "deny",
                "address": "*@/admin/**",
                "description": "Block all access to admin paths",
            },
            # Rule 2: Allow ForwardUpstream to services with proper scope from local
            {
                "id": "allow-service-forward",
                "effect": "allow",
                "action": "ForwardUpstream",
                "address": "*@/services/**",
                "origin_type": "local",
                "scope": "messaging.send",
                "description": "Allow local clients to send to services",
            },
            # Rule 3: Allow local delivery to inbox from downstream or local
            {
                "id": "allow-inbox-delivery",
                "effect": "allow",
                "action": "DeliverLocal",
                "address": "*@/inbox/**",
                "origin_type": ["downstream", "local"],
                "description": "Allow message delivery to local inboxes",
            },
            # Rule 4: Allow peer forwarding from peers
            {
                "id": "allow-peer-forward",
                "effect": "allow",
                "action": "ForwardPeer",
                "origin_type": "peer",
                "description": "Allow peer-to-peer forwarding",
            },
        ],
    })
    return BasicAuthorizationPolicy(
        BasicAuthorizationPolicyOptions(policy_definition=policy_def)
    )


def mock_delivery_tracker() -> MagicMock:
    """Create a mock delivery tracker with required methods."""
    tracker = MagicMock()
    tracker.track_delivery = AsyncMock()
    tracker.complete_delivery = AsyncMock()
    tracker.fail_delivery = AsyncMock()
    tracker.list_inbound = AsyncMock(return_value=[])
    return tracker


def mock_session_manager() -> MagicMock:
    """Create a mock session manager that passes isinstance checks."""
    manager = MagicMock(spec=UpstreamSessionManager)
    manager.get_or_create_session_id = MagicMock(return_value="test-session-id")
    manager.get_existing_session_id = MagicMock(return_value=None)
    manager.send = AsyncMock()
    return manager


def mock_security_manager() -> MagicMock:
    """Create a mock security manager with all async methods returning passthrough."""
    manager = MagicMock()
    manager.authorizer = MagicMock()
    manager.key_manager = MagicMock()
    manager.priority = 1000

    # Lifecycle methods
    manager.on_node_initialized = AsyncMock()
    manager.on_node_started = AsyncMock()
    manager.on_node_preparing_to_stop = AsyncMock()
    manager.on_node_stopped = AsyncMock()
    manager.on_welcome = AsyncMock()

    # Envelope processing passthrough - **kwargs to accept extra args like error=
    async def passthrough_envelope(node, envelope, *, context=None, **kwargs):
        return envelope

    # Routing action passthrough
    async def passthrough_routing_action(node, envelope, selected, state, context=None):
        return selected

    # Apply to all envelope-related hooks
    manager.on_deliver = AsyncMock(side_effect=passthrough_envelope)
    manager.on_envelope_received = AsyncMock(side_effect=passthrough_envelope)
    manager.on_forward_upstream = AsyncMock(side_effect=passthrough_envelope)
    manager.on_forward_upstream_complete = AsyncMock(side_effect=passthrough_envelope)
    manager.on_forward_downstream = AsyncMock(side_effect=passthrough_envelope)
    manager.on_forward_downstream_complete = AsyncMock(side_effect=passthrough_envelope)
    manager.on_forward_peer = AsyncMock(side_effect=passthrough_envelope)
    manager.on_forward_peer_complete = AsyncMock(side_effect=passthrough_envelope)
    manager.on_deliver_local = AsyncMock(side_effect=passthrough_envelope)
    manager.on_deliver_local_complete = AsyncMock(side_effect=passthrough_envelope)

    manager.on_routing_action_selected = AsyncMock(side_effect=passthrough_routing_action)
    return manager


def mock_route_store() -> MagicMock:
    """Create a mock route store."""
    store = MagicMock(spec=RouteStore)
    store.get_all_routes = AsyncMock(return_value=[])
    store.store_route = AsyncMock()
    store.remove_route = AsyncMock()
    store.list = AsyncMock(return_value={})
    return store


def create_test_sentinel(
    *,
    routing_policy: RoutingPolicy,
    security_manager: Optional[Any] = None,
    event_listeners: Optional[list] = None,
) -> Sentinel:
    """Create a properly configured Sentinel for testing."""
    sec_manager = security_manager or mock_security_manager()
    listeners = event_listeners or []

    sentinel = Sentinel(
        id="test-sentinel",
        route_store=mock_route_store(),
        has_parent=True,
        routing_policy=routing_policy,
        security_manager=sec_manager,
        delivery_tracker=mock_delivery_tracker(),
        event_listeners=listeners,
    )
    sentinel._upstream_connector = MagicMock(spec=FameConnector)
    sentinel._upstream_connector.send = AsyncMock()
    sentinel._session_manager = mock_session_manager()
    sentinel._is_started = True
    return sentinel


class MockRoutingPolicy(RoutingPolicy):
    """Mock routing policy that returns a fixed action."""

    def __init__(self, action: RoutingAction):
        self._action = action

    async def decide(
        self,
        envelope: FameEnvelope,
        state: RouterState,
        context: Optional[FameDeliveryContext] = None,
    ) -> RoutingAction:
        return self._action


class ActionTracker(NodeEventListener):
    """Event listener that tracks routing action selections."""

    def __init__(self):
        self.selected_actions: list[RoutingAction] = []

    @property
    def priority(self) -> int:
        return 3000  # Run after security manager

    async def on_routing_action_selected(
        self,
        node: Any,
        envelope: FameEnvelope,
        selected: RoutingAction,
        state: RouterState,
        context: Optional[FameDeliveryContext] = None,
    ) -> Optional[RoutingAction]:
        """Track the selected action and pass through unchanged."""
        self.selected_actions.append(selected)
        return selected


class TestSentinelRouteAuthorizationWiring:
    """Tests that verify on_routing_action_selected is properly wired in Sentinel."""

    @pytest.mark.asyncio
    async def test_routing_action_hook_is_called(self):
        """Verify on_routing_action_selected hook is invoked during routing."""
        tracker = ActionTracker()

        sentinel = create_test_sentinel(
            routing_policy=MockRoutingPolicy(ForwardUp()),
            event_listeners=[tracker],
        )

        envelope = create_fame_envelope(
            frame=DataFrame(payload="test"),
            to=format_address("service", "/upstream/target"),
        )

        await sentinel.deliver(envelope, local_delivery_context())

        # Verify the hook was called with ForwardUp action
        assert len(tracker.selected_actions) == 1
        assert isinstance(tracker.selected_actions[0], ForwardUp)

    @pytest.mark.asyncio
    async def test_hook_can_replace_action(self):
        """Verify that a listener can replace the routing action."""

        class ActionReplacer(NodeEventListener):
            """Replaces ForwardUp with Drop."""

            @property
            def priority(self) -> int:
                return 1000

            async def on_routing_action_selected(
                self,
                node: Any,
                envelope: FameEnvelope,
                selected: RoutingAction,
                state: RouterState,
                context: Optional[FameDeliveryContext] = None,
            ) -> Optional[RoutingAction]:
                if isinstance(selected, ForwardUp):
                    return Drop()
                return selected

        replacer = ActionReplacer()

        sentinel = create_test_sentinel(
            routing_policy=MockRoutingPolicy(ForwardUp()),
            event_listeners=[replacer],
        )

        envelope = create_fame_envelope(
            frame=DataFrame(payload="test"),
            to=format_address("service", "/upstream/target"),
        )

        await sentinel.deliver(envelope, local_delivery_context())

        # ForwardUp was replaced with Drop, so no upstream send
        sentinel._upstream_connector.send.assert_not_called()

    @pytest.mark.asyncio
    async def test_hook_returning_none_triggers_drop(self):
        """Verify that returning None from hook causes envelope to be dropped."""

        class ActionDropper(NodeEventListener):
            """Returns None to drop the envelope."""

            @property
            def priority(self) -> int:
                return 1000

            async def on_routing_action_selected(
                self,
                node: Any,
                envelope: FameEnvelope,
                selected: RoutingAction,
                state: RouterState,
                context: Optional[FameDeliveryContext] = None,
            ) -> Optional[RoutingAction]:
                return None

        dropper = ActionDropper()

        sentinel = create_test_sentinel(
            routing_policy=MockRoutingPolicy(ForwardUp()),
            event_listeners=[dropper],
        )

        envelope = create_fame_envelope(
            frame=DataFrame(payload="test"),
            to=format_address("service", "/upstream/target"),
        )

        await sentinel.deliver(envelope, local_delivery_context())

        # Envelope should be dropped, no upstream send
        sentinel._upstream_connector.send.assert_not_called()


class TestSentinelWithRealSecurityManager:
    """Integration tests with DefaultSecurityManager and real policies."""

    @pytest.mark.asyncio
    async def test_allow_all_policy_permits_routing(self):
        """Test that allow-all policy permits all routing actions."""
        policy = create_allow_all_policy()
        authorizer = DefaultPolicyAuthorizer(policy=policy)

        security_manager = DefaultSecurityManager(
            policy=DefaultSecurityPolicy(),
            authorizer=authorizer,
        )

        sentinel = create_test_sentinel(
            routing_policy=MockRoutingPolicy(ForwardUp()),
            security_manager=security_manager,
        )

        auth_context = AuthorizationContext(authenticated=True, authorized=True)
        context = FameDeliveryContext(
            origin_type=DeliveryOriginType.LOCAL,
            from_system_id="test",
            security=SecurityContext(authorization=auth_context),
        )

        envelope = create_fame_envelope(
            frame=DataFrame(payload="test"),
            to=format_address("service", "/upstream/target"),
        )

        await sentinel.deliver(envelope, context)

        # With allow-all policy and authenticated context, should forward upstream
        sentinel._session_manager.send.assert_called_once()

    @pytest.mark.asyncio
    async def test_deny_all_policy_blocks_routing(self):
        """Test that deny-all policy blocks all routing actions."""
        policy = create_deny_all_policy()
        authorizer = DefaultPolicyAuthorizer(policy=policy)

        security_manager = DefaultSecurityManager(
            policy=DefaultSecurityPolicy(),
            authorizer=authorizer,
        )

        sentinel = create_test_sentinel(
            routing_policy=MockRoutingPolicy(ForwardUp()),
            security_manager=security_manager,
        )

        auth_context = AuthorizationContext(authenticated=True, authorized=True)
        context = FameDeliveryContext(
            origin_type=DeliveryOriginType.LOCAL,
            from_system_id="test",
            security=SecurityContext(authorization=auth_context),
        )

        envelope = create_fame_envelope(
            frame=DataFrame(payload="test"),
            to=format_address("service", "/upstream/target"),
        )

        await sentinel.deliver(envelope, context)

        # With deny-all policy, should NOT forward upstream
        sentinel._upstream_connector.send.assert_not_called()

    @pytest.mark.asyncio
    async def test_selective_policy_allows_specific_actions(self):
        """Test that selective policy allows only ForwardUpstream."""
        # Allow ForwardUpstream
        policy = create_selective_policy(allowed_actions=["ForwardUpstream"])
        authorizer = DefaultPolicyAuthorizer(policy=policy)

        security_manager = DefaultSecurityManager(
            policy=DefaultSecurityPolicy(),
            authorizer=authorizer,
        )

        sentinel = create_test_sentinel(
            routing_policy=MockRoutingPolicy(ForwardUp()),
            security_manager=security_manager,
        )

        auth_context = AuthorizationContext(authenticated=True, authorized=True)
        context = FameDeliveryContext(
            origin_type=DeliveryOriginType.LOCAL,
            from_system_id="test",
            security=SecurityContext(authorization=auth_context),
        )

        envelope = create_fame_envelope(
            frame=DataFrame(payload="test"),
            to=format_address("service", "/upstream/target"),
        )

        await sentinel.deliver(envelope, context)

        # ForwardUpstream is allowed, should forward
        sentinel._session_manager.send.assert_called_once()

    @pytest.mark.asyncio
    async def test_unauthenticated_requests_denied(self):
        """Test that unauthenticated requests are denied."""
        policy = create_allow_all_policy()
        authorizer = DefaultPolicyAuthorizer(policy=policy)

        security_manager = DefaultSecurityManager(
            policy=DefaultSecurityPolicy(),
            authorizer=authorizer,
        )

        sentinel = create_test_sentinel(
            routing_policy=MockRoutingPolicy(ForwardUp()),
            security_manager=security_manager,
        )

        # Unauthenticated context
        auth_context = AuthorizationContext(authenticated=False, authorized=False)
        context = FameDeliveryContext(
            origin_type=DeliveryOriginType.DOWNSTREAM,
            from_system_id="test",
            security=SecurityContext(authorization=auth_context),
        )

        envelope = create_fame_envelope(
            frame=DataFrame(payload="test"),
            to=format_address("service", "/upstream/target"),
        )

        await sentinel.deliver(envelope, context)

        # Unauthenticated, should be denied
        sentinel._upstream_connector.send.assert_not_called()


class TestRoutingActionMapping:
    """Tests verifying correct action-to-token mapping."""

    def test_forward_up_maps_to_forward_upstream(self):
        """Test ForwardUp action maps to ForwardUpstream token."""
        action = ForwardUp()
        token = map_routing_action_to_authorization_action(action)
        assert token == "ForwardUpstream"

    def test_forward_child_maps_to_forward_downstream(self):
        """Test ForwardChild action maps to ForwardDownstream token."""
        action = ForwardChild("child-segment")
        token = map_routing_action_to_authorization_action(action)
        assert token == "ForwardDownstream"

    def test_forward_peer_maps_to_forward_peer(self):
        """Test ForwardPeer action maps to ForwardPeer token."""
        action = ForwardPeer("peer-segment")
        token = map_routing_action_to_authorization_action(action)
        assert token == "ForwardPeer"

    def test_deliver_local_maps_to_deliver_local(self):
        """Test DeliverLocal action maps to DeliverLocal token."""
        action = DeliverLocal(format_address("inbox", "/local"))
        token = map_routing_action_to_authorization_action(action)
        assert token == "DeliverLocal"

    def test_drop_returns_none(self):
        """Test Drop action returns None (no authorization needed)."""
        action = Drop()
        token = map_routing_action_to_authorization_action(action)
        assert token is None

    def test_deny_returns_none(self):
        """Test Deny action returns None (no authorization needed)."""
        action = Deny()
        token = map_routing_action_to_authorization_action(action)
        assert token is None


class TestAddressBasedPolicies:
    """Tests for policies with address pattern matching."""

    @pytest.mark.asyncio
    async def test_address_pattern_allows_matching(self):
        """Test that address patterns correctly allow matching addresses."""
        # Allow only addresses matching *@/services/**
        policy = create_address_based_policy(
            allowed_patterns=["*@/services/**"]
        )
        authorizer = DefaultPolicyAuthorizer(policy=policy)

        security_manager = DefaultSecurityManager(
            policy=DefaultSecurityPolicy(),
            authorizer=authorizer,
        )

        sentinel = create_test_sentinel(
            routing_policy=MockRoutingPolicy(ForwardUp()),
            security_manager=security_manager,
        )

        auth_context = AuthorizationContext(authenticated=True, authorized=True)
        context = FameDeliveryContext(
            origin_type=DeliveryOriginType.LOCAL,
            from_system_id="test",
            security=SecurityContext(authorization=auth_context),
        )

        # Address matching /services/** should be allowed
        envelope = create_fame_envelope(
            frame=DataFrame(payload="test"),
            to=format_address("api", "/services/users"),
        )

        await sentinel.deliver(envelope, context)

        # Should forward because address matches pattern
        sentinel._session_manager.send.assert_called_once()

    @pytest.mark.asyncio
    async def test_address_pattern_denies_non_matching(self):
        """Test that address patterns correctly deny non-matching addresses."""
        # Allow only addresses matching *@/services/**
        policy = create_address_based_policy(
            allowed_patterns=["*@/services/**"]
        )
        authorizer = DefaultPolicyAuthorizer(policy=policy)

        security_manager = DefaultSecurityManager(
            policy=DefaultSecurityPolicy(),
            authorizer=authorizer,
        )

        sentinel = create_test_sentinel(
            routing_policy=MockRoutingPolicy(ForwardUp()),
            security_manager=security_manager,
        )

        auth_context = AuthorizationContext(authenticated=True, authorized=True)
        context = FameDeliveryContext(
            origin_type=DeliveryOriginType.LOCAL,
            from_system_id="test",
            security=SecurityContext(authorization=auth_context),
        )

        # Address NOT matching /services/** should be denied
        envelope = create_fame_envelope(
            frame=DataFrame(payload="test"),
            to=format_address("api", "/admin/users"),
        )

        await sentinel.deliver(envelope, context)

        # Should NOT forward because address doesn't match pattern
        sentinel._upstream_connector.send.assert_not_called()

    @pytest.mark.asyncio
    async def test_deny_pattern_takes_precedence(self):
        """Test that deny patterns are evaluated first (first-match-wins)."""
        # Allow /services/** but deny /services/admin/**
        policy = create_address_based_policy(
            allowed_patterns=["*@/services/**"],
            denied_patterns=["*@/services/admin/**"],
        )
        authorizer = DefaultPolicyAuthorizer(policy=policy)

        security_manager = DefaultSecurityManager(
            policy=DefaultSecurityPolicy(),
            authorizer=authorizer,
        )

        sentinel = create_test_sentinel(
            routing_policy=MockRoutingPolicy(ForwardUp()),
            security_manager=security_manager,
        )

        auth_context = AuthorizationContext(authenticated=True, authorized=True)
        context = FameDeliveryContext(
            origin_type=DeliveryOriginType.LOCAL,
            from_system_id="test",
            security=SecurityContext(authorization=auth_context),
        )

        # Address matching denied pattern should be blocked
        envelope = create_fame_envelope(
            frame=DataFrame(payload="test"),
            to=format_address("api", "/services/admin/config"),
        )

        await sentinel.deliver(envelope, context)

        # Should NOT forward due to deny pattern
        sentinel._upstream_connector.send.assert_not_called()


class TestOriginTypePolicies:
    """Tests for policies with origin_type matching."""

    @pytest.mark.asyncio
    async def test_local_origin_allowed(self):
        """Test that local origin is allowed when specified in policy."""
        policy = create_origin_type_policy(allowed_origins=["local"])
        authorizer = DefaultPolicyAuthorizer(policy=policy)

        security_manager = DefaultSecurityManager(
            policy=DefaultSecurityPolicy(),
            authorizer=authorizer,
        )

        sentinel = create_test_sentinel(
            routing_policy=MockRoutingPolicy(ForwardUp()),
            security_manager=security_manager,
        )

        auth_context = AuthorizationContext(authenticated=True, authorized=True)
        context = FameDeliveryContext(
            origin_type=DeliveryOriginType.LOCAL,
            from_system_id="test",
            security=SecurityContext(authorization=auth_context),
        )

        envelope = create_fame_envelope(
            frame=DataFrame(payload="test"),
            to=format_address("service", "/target"),
        )

        await sentinel.deliver(envelope, context)

        # Local origin is allowed
        sentinel._session_manager.send.assert_called_once()

    @pytest.mark.asyncio
    async def test_downstream_origin_denied_when_only_local_allowed(self):
        """Test that downstream origin is denied when only local is allowed."""
        policy = create_origin_type_policy(allowed_origins=["local"])
        authorizer = DefaultPolicyAuthorizer(policy=policy)

        security_manager = DefaultSecurityManager(
            policy=DefaultSecurityPolicy(),
            authorizer=authorizer,
        )

        sentinel = create_test_sentinel(
            routing_policy=MockRoutingPolicy(ForwardUp()),
            security_manager=security_manager,
        )

        auth_context = AuthorizationContext(authenticated=True, authorized=True)
        context = FameDeliveryContext(
            origin_type=DeliveryOriginType.DOWNSTREAM,
            from_system_id="test",
            security=SecurityContext(authorization=auth_context),
        )

        envelope = create_fame_envelope(
            frame=DataFrame(payload="test"),
            to=format_address("service", "/target"),
        )

        await sentinel.deliver(envelope, context)

        # Downstream origin is NOT allowed
        sentinel._upstream_connector.send.assert_not_called()

    @pytest.mark.asyncio
    async def test_multiple_origins_allowed(self):
        """Test that multiple origin types can be allowed."""
        policy = create_origin_type_policy(
            allowed_origins=["local", "downstream"]
        )
        authorizer = DefaultPolicyAuthorizer(policy=policy)

        security_manager = DefaultSecurityManager(
            policy=DefaultSecurityPolicy(),
            authorizer=authorizer,
        )

        sentinel = create_test_sentinel(
            routing_policy=MockRoutingPolicy(ForwardUp()),
            security_manager=security_manager,
        )

        auth_context = AuthorizationContext(authenticated=True, authorized=True)

        # Test downstream origin
        context = FameDeliveryContext(
            origin_type=DeliveryOriginType.DOWNSTREAM,
            from_system_id="test",
            security=SecurityContext(authorization=auth_context),
        )

        envelope = create_fame_envelope(
            frame=DataFrame(payload="test"),
            to=format_address("service", "/target"),
        )

        await sentinel.deliver(envelope, context)

        # Downstream origin is allowed
        sentinel._session_manager.send.assert_called_once()


class TestScopePolicies:
    """Tests for policies with scope requirements."""

    @pytest.mark.asyncio
    async def test_scope_requirement_allowed_when_present(self):
        """Test that requests with required scope are allowed."""
        policy = create_scope_required_policy(required_scope="messaging.send")
        authorizer = DefaultPolicyAuthorizer(policy=policy)

        security_manager = DefaultSecurityManager(
            policy=DefaultSecurityPolicy(),
            authorizer=authorizer,
        )

        sentinel = create_test_sentinel(
            routing_policy=MockRoutingPolicy(ForwardUp()),
            security_manager=security_manager,
        )

        # Context with required scope
        auth_context = AuthorizationContext(
            authenticated=True,
            authorized=True,
            granted_scopes=["messaging.send", "messaging.receive"],
        )
        context = FameDeliveryContext(
            origin_type=DeliveryOriginType.LOCAL,
            from_system_id="test",
            security=SecurityContext(authorization=auth_context),
        )

        envelope = create_fame_envelope(
            frame=DataFrame(payload="test"),
            to=format_address("service", "/target"),
        )

        await sentinel.deliver(envelope, context)

        # Should be allowed because scope is present
        sentinel._session_manager.send.assert_called_once()

    @pytest.mark.asyncio
    async def test_scope_requirement_denied_when_missing(self):
        """Test that requests missing required scope are denied."""
        policy = create_scope_required_policy(required_scope="messaging.send")
        authorizer = DefaultPolicyAuthorizer(policy=policy)

        security_manager = DefaultSecurityManager(
            policy=DefaultSecurityPolicy(),
            authorizer=authorizer,
        )

        sentinel = create_test_sentinel(
            routing_policy=MockRoutingPolicy(ForwardUp()),
            security_manager=security_manager,
        )

        # Context without required scope
        auth_context = AuthorizationContext(
            authenticated=True,
            authorized=True,
            granted_scopes=["messaging.receive"],  # Missing messaging.send
        )
        context = FameDeliveryContext(
            origin_type=DeliveryOriginType.LOCAL,
            from_system_id="test",
            security=SecurityContext(authorization=auth_context),
        )

        envelope = create_fame_envelope(
            frame=DataFrame(payload="test"),
            to=format_address("service", "/target"),
        )

        await sentinel.deliver(envelope, context)

        # Should be denied because required scope is missing
        sentinel._upstream_connector.send.assert_not_called()


class TestComplexPolicies:
    """Tests for complex policies combining multiple aspects."""

    @pytest.mark.asyncio
    async def test_complex_policy_allows_valid_service_forward(self):
        """Test complex policy allows ForwardUpstream to services with scope."""
        policy = create_complex_policy()
        authorizer = DefaultPolicyAuthorizer(policy=policy)

        security_manager = DefaultSecurityManager(
            policy=DefaultSecurityPolicy(),
            authorizer=authorizer,
        )

        sentinel = create_test_sentinel(
            routing_policy=MockRoutingPolicy(ForwardUp()),
            security_manager=security_manager,
        )

        # Context: local origin with messaging.send scope
        auth_context = AuthorizationContext(
            authenticated=True,
            authorized=True,
            granted_scopes=["messaging.send"],
        )
        context = FameDeliveryContext(
            origin_type=DeliveryOriginType.LOCAL,
            from_system_id="test",
            security=SecurityContext(authorization=auth_context),
        )

        # Address: /services/users
        envelope = create_fame_envelope(
            frame=DataFrame(payload="test"),
            to=format_address("api", "/services/users"),
        )

        await sentinel.deliver(envelope, context)

        # Should be allowed: ForwardUpstream + /services/** + local + scope
        sentinel._session_manager.send.assert_called_once()

    @pytest.mark.asyncio
    async def test_complex_policy_denies_admin_path(self):
        """Test complex policy denies access to admin paths."""
        policy = create_complex_policy()
        authorizer = DefaultPolicyAuthorizer(policy=policy)

        security_manager = DefaultSecurityManager(
            policy=DefaultSecurityPolicy(),
            authorizer=authorizer,
        )

        sentinel = create_test_sentinel(
            routing_policy=MockRoutingPolicy(ForwardUp()),
            security_manager=security_manager,
        )

        # Even with all the right attributes, admin path should be denied
        auth_context = AuthorizationContext(
            authenticated=True,
            authorized=True,
            granted_scopes=["messaging.send", "admin"],
        )
        context = FameDeliveryContext(
            origin_type=DeliveryOriginType.LOCAL,
            from_system_id="test",
            security=SecurityContext(authorization=auth_context),
        )

        # Address: /admin/config (denied by rule 1)
        envelope = create_fame_envelope(
            frame=DataFrame(payload="test"),
            to=format_address("api", "/admin/config"),
        )

        await sentinel.deliver(envelope, context)

        # Should be denied: admin path is blocked
        sentinel._upstream_connector.send.assert_not_called()

    @pytest.mark.asyncio
    async def test_complex_policy_denies_wrong_origin_for_service(self):
        """Test complex policy denies non-local origin for service forward."""
        policy = create_complex_policy()
        authorizer = DefaultPolicyAuthorizer(policy=policy)

        security_manager = DefaultSecurityManager(
            policy=DefaultSecurityPolicy(),
            authorizer=authorizer,
        )

        sentinel = create_test_sentinel(
            routing_policy=MockRoutingPolicy(ForwardUp()),
            security_manager=security_manager,
        )

        # Context: downstream origin (not local)
        auth_context = AuthorizationContext(
            authenticated=True,
            authorized=True,
            granted_scopes=["messaging.send"],
        )
        context = FameDeliveryContext(
            origin_type=DeliveryOriginType.DOWNSTREAM,
            from_system_id="test",
            security=SecurityContext(authorization=auth_context),
        )

        # Address: /services/users - would be allowed for local but not downstream
        envelope = create_fame_envelope(
            frame=DataFrame(payload="test"),
            to=format_address("api", "/services/users"),
        )

        await sentinel.deliver(envelope, context)

        # Should be denied: downstream origin not allowed for service forward
        sentinel._upstream_connector.send.assert_not_called()

    @pytest.mark.asyncio
    async def test_complex_policy_denies_missing_scope_for_service(self):
        """Test complex policy denies missing scope for service forward."""
        policy = create_complex_policy()
        authorizer = DefaultPolicyAuthorizer(policy=policy)

        security_manager = DefaultSecurityManager(
            policy=DefaultSecurityPolicy(),
            authorizer=authorizer,
        )

        sentinel = create_test_sentinel(
            routing_policy=MockRoutingPolicy(ForwardUp()),
            security_manager=security_manager,
        )

        # Context: local origin but NO messaging.send scope
        auth_context = AuthorizationContext(
            authenticated=True,
            authorized=True,
            granted_scopes=["messaging.receive"],  # Wrong scope
        )
        context = FameDeliveryContext(
            origin_type=DeliveryOriginType.LOCAL,
            from_system_id="test",
            security=SecurityContext(authorization=auth_context),
        )

        envelope = create_fame_envelope(
            frame=DataFrame(payload="test"),
            to=format_address("api", "/services/users"),
        )

        await sentinel.deliver(envelope, context)

        # Should be denied: missing required scope
        sentinel._upstream_connector.send.assert_not_called()

    @pytest.mark.asyncio
    async def test_complex_policy_allows_inbox_delivery_from_downstream(self):
        """Test complex policy allows inbox delivery from downstream."""
        policy = create_complex_policy()
        authorizer = DefaultPolicyAuthorizer(policy=policy)

        security_manager = DefaultSecurityManager(
            policy=DefaultSecurityPolicy(),
            authorizer=authorizer,
        )

        # Need to mock a local address registration for DeliverLocal to work
        local_address = format_address("inbox", "/inbox/user1")

        sentinel = create_test_sentinel(
            routing_policy=MockRoutingPolicy(DeliverLocal(local_address)),
            security_manager=security_manager,
        )

        # Mock binding manager for local delivery
        mock_binding = MagicMock()
        mock_channel = MagicMock()
        mock_channel.send = AsyncMock()
        mock_binding.channel = mock_channel
        sentinel._binding_manager = MagicMock()
        sentinel._binding_manager.get_binding.return_value = mock_binding

        auth_context = AuthorizationContext(
            authenticated=True,
            authorized=True,
        )
        context = FameDeliveryContext(
            origin_type=DeliveryOriginType.DOWNSTREAM,
            from_system_id="test",
            security=SecurityContext(authorization=auth_context),
        )

        envelope = create_fame_envelope(
            frame=DataFrame(payload="test"),
            to=local_address,
        )

        await sentinel.deliver(envelope, context)

        # Should be allowed: DeliverLocal to inbox from downstream
        mock_channel.send.assert_called_once()

    @pytest.mark.asyncio
    async def test_complex_policy_allows_peer_forward_from_peer(self):
        """Test complex policy allows peer forwarding from peer origin."""
        policy = create_complex_policy()
        authorizer = DefaultPolicyAuthorizer(policy=policy)

        security_manager = DefaultSecurityManager(
            policy=DefaultSecurityPolicy(),
            authorizer=authorizer,
        )

        sentinel = create_test_sentinel(
            routing_policy=MockRoutingPolicy(ForwardPeer("peer-node")),
            security_manager=security_manager,
        )

        # Mock peer connector in the correct location
        mock_peer = MagicMock()
        mock_peer.send = AsyncMock()
        sentinel._route_manager._peer_routes = {"peer-node": mock_peer}

        auth_context = AuthorizationContext(
            authenticated=True,
            authorized=True,
        )
        context = FameDeliveryContext(
            origin_type=DeliveryOriginType.PEER,
            from_system_id="test",
            security=SecurityContext(authorization=auth_context),
        )

        envelope = create_fame_envelope(
            frame=DataFrame(payload="test"),
            to=format_address("service", "/peer/target"),
        )

        await sentinel.deliver(envelope, context)

        # Should be allowed: ForwardPeer from peer origin
        mock_peer.send.assert_called_once()
