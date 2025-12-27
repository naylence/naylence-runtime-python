"""
Authorization policy interface.

Defines the protocol for authorization policies that evaluate
whether a request should be allowed or denied.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Literal, Optional, Protocol, runtime_checkable

if TYPE_CHECKING:
    from naylence.fame.core import FameDeliveryContext, FameEnvelope
    from naylence.fame.node.node_like import NodeLike

from .authorization_policy_definition import RuleAction

# The effect of an authorization decision
AuthorizationEffect = Literal["allow", "deny"]


@dataclass
class AuthorizationEvaluationStep:
    """
    Represents a single step in the policy evaluation process.

    Useful for debugging and auditing authorization decisions.
    """

    # Rule identifier that was evaluated
    rule_id: str

    # Result of the evaluation
    result: bool

    # Expression or condition that was evaluated
    expression: Optional[str] = None

    # Context values used in evaluation (for debugging)
    bound_values: Optional[dict[str, Any]] = None


@dataclass
class AuthorizationDecision:
    """The result of an authorization policy evaluation."""

    # The authorization effect: allow or deny
    effect: AuthorizationEffect

    # Human-readable reason for the decision
    reason: Optional[str] = None

    # Identifier of the rule that matched (for debugging/audit)
    matched_rule: Optional[str] = None

    # Evaluation trace for detailed debugging
    evaluation_trace: list[AuthorizationEvaluationStep] = field(default_factory=list)


@runtime_checkable
class AuthorizationPolicy(Protocol):
    """
    Interface for authorization policies that evaluate whether a request
    should be allowed or denied.

    The policy receives the same parameters as `Authorizer.authorize`,
    giving it full access to the node, envelope, and delivery context
    for making authorization decisions.
    """

    async def evaluate_request(
        self,
        node: NodeLike,
        envelope: FameEnvelope,
        context: Optional[FameDeliveryContext] = None,
        action: Optional[RuleAction] = None,
    ) -> AuthorizationDecision:
        """
        Evaluates an authorization request and returns a decision.

        Args:
            node: The node handling the request
            envelope: The FAME envelope being authorized
            context: Optional delivery context with authorization info, origin, etc.
            action: Optional authorization action token (route-oriented: Connect,
                    ForwardUpstream, ForwardDownstream, ForwardPeer, DeliverLocal, '*')

        Returns:
            A decision indicating whether to allow or deny the request
        """
        ...
