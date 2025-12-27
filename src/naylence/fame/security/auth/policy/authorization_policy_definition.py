"""
Authorization policy definition types.

This module defines the schema for authorization policies that can be
loaded from YAML/JSON files and evaluated at runtime.
"""

from __future__ import annotations

from typing import Any, Literal, Union

from pydantic import BaseModel, ConfigDict, Field

# The effect of an authorization rule
RuleEffect = Literal["allow", "deny"]

# The action type a rule applies to (route-oriented, DX-friendly tokens)
#
# These tokens represent "what will happen next" in routing, not inferred send/receive:
# - Connect: NodeAttach connection handshake (pre-routing)
# - ForwardUpstream: Envelope will be forwarded to parent node
# - ForwardDownstream: Envelope will be forwarded to a child route
# - ForwardPeer: Envelope will be forwarded to a peer node
# - DeliverLocal: Envelope will be delivered to a local address handler
# - '*': Matches all actions (wildcard)
RuleAction = Literal[
    "Connect",
    "ForwardUpstream",
    "ForwardDownstream",
    "ForwardPeer",
    "DeliverLocal",
    "*",
]

# Action input tokens accepted in policy definitions.
# Values are normalized case-insensitively and support snake_case.
RuleActionInput = str

# Forward reference for recursive type
ScopeRequirement = Union[
    str,
    "ScopeRequirementAnyOf",
    "ScopeRequirementAllOf",
    "ScopeRequirementNoneOf",
]


class ScopeRequirementAnyOf(BaseModel):
    """Scope requirement with any_of logical operator."""

    model_config = ConfigDict(extra="forbid")

    any_of: list[ScopeRequirement]


class ScopeRequirementAllOf(BaseModel):
    """Scope requirement with all_of logical operator."""

    model_config = ConfigDict(extra="forbid")

    all_of: list[ScopeRequirement]


class ScopeRequirementNoneOf(BaseModel):
    """Scope requirement with none_of logical operator."""

    model_config = ConfigDict(extra="forbid")

    none_of: list[ScopeRequirement]


# Normalized scope requirement with explicit type discriminator
class NormalizedScopePattern(BaseModel):
    """Normalized scope pattern requirement."""

    model_config = ConfigDict(extra="forbid")

    type: Literal["pattern"] = "pattern"
    pattern: str


class NormalizedScopeAnyOf(BaseModel):
    """Normalized any_of scope requirement."""

    model_config = ConfigDict(extra="forbid")

    type: Literal["any_of"] = "any_of"
    requirements: list[NormalizedScopeRequirement]


class NormalizedScopeAllOf(BaseModel):
    """Normalized all_of scope requirement."""

    model_config = ConfigDict(extra="forbid")

    type: Literal["all_of"] = "all_of"
    requirements: list[NormalizedScopeRequirement]


class NormalizedScopeNoneOf(BaseModel):
    """Normalized none_of scope requirement."""

    model_config = ConfigDict(extra="forbid")

    type: Literal["none_of"] = "none_of"
    requirements: list[NormalizedScopeRequirement]


NormalizedScopeRequirement = Union[
    NormalizedScopePattern,
    NormalizedScopeAnyOf,
    NormalizedScopeAllOf,
    NormalizedScopeNoneOf,
]


class AuthorizationRuleDefinition(BaseModel):
    """
    An authorization rule definition.

    Supports forward compatibility via extra fields (ignored with warning).
    Note: Validation of effect values happens at policy construction time
    in BasicAuthorizationPolicy, not at definition parse time, matching
    TypeScript behavior.
    """

    model_config = ConfigDict(extra="allow")

    # Optional unique identifier for the rule.
    # Used in decision traces for debugging.
    id: str | None = None

    # Optional human-readable description of the rule.
    description: str | None = None

    # The effect when this rule matches: allow or deny.
    # Accepts any string to match TS interface behavior; validation happens
    # at policy construction time.
    effect: str

    # The action type this rule applies to.
    # Can be a single action or an array of actions (implicit any-of).
    # Values are matched case-insensitively and support snake_case equivalents.
    # @default '*' (all actions)
    action: RuleActionInput | list[RuleActionInput] | None = None

    # Address pattern(s) to match using glob syntax.
    # Can be a single pattern or an array (implicit any-of).
    # If omitted, matches all addresses.
    #
    # Glob syntax:
    # - `*` matches any characters except dots (single segment)
    # - `**` matches any characters including dots (any depth)
    # - `?` matches a single character (not a dot)
    # - Other characters are matched literally
    #
    # Note: In OSS/basic policy, patterns are always treated as globs.
    # Patterns starting with `^` are NOT interpreted as regex.
    address: str | list[str] | None = None

    # Optional frame type gating (reserved for advanced-security package).
    # Can be a single frame type string or an array (implicit any-of).
    # Matching is case-insensitive.
    #
    # WARNING: Basic policy parser will skip rules containing this field
    # and log a warning during policy construction. This field is only
    # supported in the advanced-security package.
    frame_type: str | list[str] | None = None

    # Optional delivery origin type gating.
    # Can be a single origin type or an array (implicit any-of).
    # Valid values: 'downstream', 'upstream', 'peer', 'local'.
    # Matching is case-insensitive with whitespace trimmed.
    # If omitted, matches any origin type.
    # If specified but context.originType is undefined, rule does not match.
    origin_type: str | list[str] | None = None

    # Scope requirement for the rule to match.
    # If omitted, no scope check is performed.
    scope: ScopeRequirement | None = None

    # Expression condition (reserved for advanced-security package).
    # Basic policy parser ignores this field.
    when: str | None = None


class AuthorizationPolicyDefinition(BaseModel):
    """
    Authorization policy definition loaded from a file.

    Supports forward compatibility via extra fields (ignored).
    Note: Validation of default_effect values happens at policy construction
    time in BasicAuthorizationPolicy, not at definition parse time, matching
    TypeScript behavior.
    """

    model_config = ConfigDict(extra="allow")

    # Schema version for the policy format.
    version: str = "1"

    # Default effect when no rule matches.
    # Accepts any string to match TS interface behavior; validation happens
    # at policy construction time.
    default_effect: str | None = None

    # List of authorization rules, evaluated in order.
    # First matching rule determines the outcome.
    rules: list[AuthorizationRuleDefinition] = Field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuthorizationPolicyDefinition:
        """
        Create a policy definition from a dictionary.

        This method handles conversion of nested rule dictionaries to
        AuthorizationRuleDefinition objects.

        Args:
            data: Dictionary containing policy definition data.

        Returns:
            An AuthorizationPolicyDefinition instance.
        """
        return cls.model_validate(data)


# Maximum nesting depth for scope requirements
MAX_SCOPE_NESTING_DEPTH = 5

# Known fields in AuthorizationPolicyDefinition
KNOWN_POLICY_FIELDS = frozenset(["version", "default_effect", "rules"])

# Known fields in AuthorizationRuleDefinition
# Fields not in this set trigger a warning.
KNOWN_RULE_FIELDS = frozenset([
    "id",
    "description",
    "effect",
    "action",
    "address",
    "frame_type",  # Reserved for advanced-security
    "origin_type",
    "scope",
    "when",  # Reserved for advanced-security
])

# Valid action values
VALID_ACTIONS: tuple[str, ...] = (
    "Connect",
    "ForwardUpstream",
    "ForwardDownstream",
    "ForwardPeer",
    "DeliverLocal",
    "*",
)

# Valid origin type values (lowercase, matching DeliveryOriginType string values)
VALID_ORIGIN_TYPES: tuple[str, ...] = (
    "downstream",
    "upstream",
    "peer",
    "local",
)

# Valid effect values
VALID_EFFECTS: tuple[RuleEffect, ...] = ("allow", "deny")


# Rebuild models to resolve forward references
ScopeRequirementAnyOf.model_rebuild()
ScopeRequirementAllOf.model_rebuild()
ScopeRequirementNoneOf.model_rebuild()
NormalizedScopeAnyOf.model_rebuild()
NormalizedScopeAllOf.model_rebuild()
NormalizedScopeNoneOf.model_rebuild()
AuthorizationRuleDefinition.model_rebuild()
AuthorizationPolicyDefinition.model_rebuild()
