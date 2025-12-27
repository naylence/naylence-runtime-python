"""Tests for router authorization integration."""

from __future__ import annotations

from naylence.fame.sentinel.router import (
    DeliverLocal,
    Deny,
    DenyOptions,
    Drop,
    ForwardChild,
    ForwardPeer,
    ForwardUp,
    RoutingAction,
    map_routing_action_to_authorization_action,
)


class TestMapRoutingActionToAuthorizationAction:
    """Tests for map_routing_action_to_authorization_action function."""

    def test_maps_forward_up_to_forward_upstream(self):
        """Should map ForwardUp to ForwardUpstream."""
        action = ForwardUp()
        result = map_routing_action_to_authorization_action(action)
        assert result == "ForwardUpstream"

    def test_maps_forward_child_to_forward_downstream(self):
        """Should map ForwardChild to ForwardDownstream."""
        action = ForwardChild("child-segment")
        result = map_routing_action_to_authorization_action(action)
        assert result == "ForwardDownstream"

    def test_maps_forward_peer_to_forward_peer(self):
        """Should map ForwardPeer to ForwardPeer."""
        action = ForwardPeer("peer-segment")
        result = map_routing_action_to_authorization_action(action)
        assert result == "ForwardPeer"

    def test_maps_deliver_local_to_deliver_local(self):
        """Should map DeliverLocal to DeliverLocal."""
        action = DeliverLocal("test://node/address")
        result = map_routing_action_to_authorization_action(action)
        assert result == "DeliverLocal"

    def test_returns_none_for_drop(self):
        """Should return None for Drop action."""
        action = Drop()
        result = map_routing_action_to_authorization_action(action)
        assert result is None

    def test_returns_none_for_deny(self):
        """Should return None for Deny action."""
        action = Deny(internal_reason="test")
        result = map_routing_action_to_authorization_action(action)
        assert result is None

    def test_returns_none_for_unknown_action(self):
        """Should return None for unknown action type."""

        class CustomAction(RoutingAction):
            async def execute(self, envelope, router, state, context=None):
                pass

        action = CustomAction()
        result = map_routing_action_to_authorization_action(action)
        assert result is None


class TestDenyRoutingAction:
    """Tests for Deny routing action."""

    def test_default_values(self):
        """Should have correct default values."""
        action = Deny()
        assert action.internal_reason == "unauthorized"
        assert action.denied_action is None
        assert action.matched_rule is None
        assert action.disclosure == "opaque"
        assert action.context == {}

    def test_accepts_keyword_args(self):
        """Should accept keyword arguments."""
        action = Deny(
            internal_reason="access_denied",
            denied_action="ForwardUpstream",
            matched_rule="deny-rule",
            disclosure="minimal",
            context={"key": "value"},
        )
        assert action.internal_reason == "access_denied"
        assert action.denied_action == "ForwardUpstream"
        assert action.matched_rule == "deny-rule"
        assert action.disclosure == "minimal"
        assert action.context == {"key": "value"}

    def test_accepts_deny_options(self):
        """Should accept DenyOptions object."""
        options = DenyOptions(
            internal_reason="policy_denied",
            denied_action="ForwardDownstream",
            matched_rule="test-rule",
            disclosure="verbose",
            context={"frame_type": "DataFrame"},
        )
        action = Deny(options)
        assert action.internal_reason == "policy_denied"
        assert action.denied_action == "ForwardDownstream"
        assert action.matched_rule == "test-rule"
        assert action.disclosure == "verbose"
        assert action.context == {"frame_type": "DataFrame"}

    def test_accepts_dict_options(self):
        """Should accept dict as options."""
        options = {
            "internal_reason": "unauthorized_route",
            "denied_action": "DeliverLocal",
            "disclosure": "opaque",
        }
        action = Deny(options)
        assert action.internal_reason == "unauthorized_route"
        assert action.denied_action == "DeliverLocal"
        assert action.disclosure == "opaque"


class TestDenyOptionsDataclass:
    """Tests for DenyOptions dataclass."""

    def test_default_values(self):
        """Should have correct default values."""
        options = DenyOptions()
        assert options.internal_reason == "unauthorized"
        assert options.denied_action is None
        assert options.matched_rule is None
        assert options.disclosure == "opaque"

    def test_accepts_all_fields(self):
        """Should accept all fields."""
        options = DenyOptions(
            internal_reason="test_reason",
            denied_action="ForwardUpstream",
            matched_rule="test-rule",
            disclosure="verbose",
            context={"key": "value"},
        )
        assert options.internal_reason == "test_reason"
        assert options.denied_action == "ForwardUpstream"
        assert options.matched_rule == "test-rule"
        assert options.disclosure == "verbose"
        assert options.context == {"key": "value"}
