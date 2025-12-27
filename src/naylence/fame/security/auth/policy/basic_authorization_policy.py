"""
Basic authorization policy implementation.

Evaluates authorization rules defined in YAML/JSON policy files.
Uses first-match-wins semantics with glob/regex pattern matching.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Callable, Optional, Sequence

if TYPE_CHECKING:
    from naylence.fame.core import FameDeliveryContext, FameEnvelope
    from naylence.fame.node.node_like import NodeLike

from .authorization_policy import (
    AuthorizationDecision,
    AuthorizationEvaluationStep,
    AuthorizationPolicy,
)
from .authorization_policy_definition import (
    VALID_ACTIONS,
    VALID_EFFECTS,
    VALID_ORIGIN_TYPES,
    AuthorizationPolicyDefinition,
    AuthorizationRuleDefinition,
    RuleAction,
    RuleActionInput,
)
from .pattern_matcher import CompiledPattern, compile_glob_pattern
from .scope_matcher import compile_glob_only_scope_requirement

logger = logging.getLogger(
    "naylence.fame.security.auth.policy.basic_authorization_policy"
)


@dataclass
class CompiledRule:
    """Compiled rule for efficient repeated evaluation."""

    id: str
    description: Optional[str]
    effect: str  # 'allow' or 'deny'
    # Set of allowed actions. Contains '*' if wildcard.
    actions: set[RuleAction]
    frame_types: Optional[set[str]] = None
    # Set of allowed origin types (lowercase). If None, matches any origin.
    origin_types: Optional[set[str]] = None
    # Address matchers (any-of). If None, matches any address.
    address_patterns: Optional[list[CompiledPattern]] = None
    scope_matcher: Optional[Callable[[Sequence[str]], bool]] = None
    has_when_clause: bool = False
    has_frame_type_clause: bool = False


def _extract_address(envelope: FameEnvelope) -> Optional[str]:
    """Extract the target address string from the envelope."""
    to = envelope.to
    if to is None:
        return None

    # FameAddress can be a string or object with __str__
    if isinstance(to, str):
        return to

    if hasattr(to, "__str__"):
        return str(to)

    return None


def _extract_granted_scopes(
    context: Optional[FameDeliveryContext],
) -> Sequence[str]:
    """Extract granted scopes from the authorization context."""
    if context is None:
        return []

    # Access security.authorization from context
    security = getattr(context, "security", None)
    if security is None:
        return []

    auth_context = getattr(security, "authorization", None)
    if auth_context is None:
        return []

    # Check grantedScopes first (snake_case for Python)
    granted = getattr(auth_context, "granted_scopes", None)
    if granted is None:
        granted = getattr(auth_context, "grantedScopes", None)
    if isinstance(granted, list | tuple):
        return list(granted)

    # Fall back to claims.scope if available
    claims = getattr(auth_context, "claims", None)
    if isinstance(claims, dict):
        # Try various scope claim names
        scope_claim = claims.get("scope") or claims.get("scopes") or claims.get("scp")

        if isinstance(scope_claim, str):
            # Space-separated scopes (OAuth2 convention)
            return [s for s in scope_claim.split() if s]

        if isinstance(scope_claim, list | tuple):
            return [s for s in scope_claim if isinstance(s, str)]

    return []


@dataclass
class BasicAuthorizationPolicyOptions:
    """Options for creating a BasicAuthorizationPolicy."""

    # The policy definition to evaluate
    policy_definition: AuthorizationPolicyDefinition
    # Whether to log warnings for unknown fields
    warn_on_unknown_fields: bool = True


class BasicAuthorizationPolicy(AuthorizationPolicy):
    """
    Basic authorization policy that evaluates rules from a policy definition.

    Features:
    - First-match-wins rule evaluation
    - Glob and regex pattern matching for addresses
    - Scope matching with any_of/all_of/none_of operators
    - Action-based filtering (connect, send, receive)
    """

    def __init__(self, options: BasicAuthorizationPolicyOptions):
        policy_definition = options.policy_definition
        warn_on_unknown_fields = options.warn_on_unknown_fields

        # Validate and extract default effect
        self._default_effect = self._validate_default_effect(
            policy_definition.default_effect
        )

        # Warn about unknown policy fields
        if warn_on_unknown_fields:
            self._warn_unknown_policy_fields(policy_definition)

        # Compile rules for efficient evaluation
        self._compiled_rules = self._compile_rules(
            policy_definition.rules,
            warn_on_unknown_fields,
        )

        logger.debug(
            "policy_compiled",
            extra={
                "default_effect": self._default_effect,
                "rule_count": len(self._compiled_rules),
            },
        )

    async def evaluate_request(
        self,
        node: NodeLike,
        envelope: FameEnvelope,
        context: Optional[FameDeliveryContext] = None,
        action: Optional[RuleAction] = None,
    ) -> AuthorizationDecision:
        """
        Evaluate the policy against a request with an explicitly provided action.

        Args:
            node: The node handling the request (unused in basic policy)
            envelope: The FAME envelope being authorized
            context: Optional delivery context with authorization info
            action: The authorization action token (required, no inference)

        Returns:
            Authorization decision indicating allow/deny
        """
        # Action must be explicitly provided; default to wildcard if omitted
        # for backward compatibility during transition
        resolved_action: RuleAction = action or "*"
        resolved_action_normalized = (
            self._normalize_action_token(resolved_action) or resolved_action
        )
        address = _extract_address(envelope)
        granted_scopes = _extract_granted_scopes(context)

        # Extract and normalize origin type for rule matching
        raw_origin_type = getattr(context, "origin_type", None)
        if raw_origin_type is None and context is not None:
            # Try camelCase variant
            raw_origin_type = getattr(context, "originType", None)

        origin_type_normalized: Optional[str] = None
        if isinstance(raw_origin_type, str):
            origin_type_normalized = self._normalize_origin_type_token(raw_origin_type)
        elif raw_origin_type is not None:
            # Handle enum types
            raw_str = str(raw_origin_type).lower()
            # Extract just the value if it's an enum like 'DeliveryOriginType.LOCAL'
            if "." in raw_str:
                raw_str = raw_str.split(".")[-1]
            origin_type_normalized = self._normalize_origin_type_token(raw_str)

        evaluation_trace: list[AuthorizationEvaluationStep] = []

        # Evaluate rules in order (first match wins)
        for rule in self._compiled_rules:
            step = AuthorizationEvaluationStep(
                rule_id=rule.id,
                result=False,
            )

            # Skip rules with 'when' clause (handled by advanced policy)
            if rule.has_when_clause:
                step.expression = "when clause (skipped by basic policy)"
                step.result = False
                evaluation_trace.append(step)
                logger.debug(
                    "rule_skipped_when_clause",
                    extra={"rule_id": rule.id},
                )
                continue

            # Skip rules with 'frame_type' clause (reserved for advanced-security)
            if rule.has_frame_type_clause:
                step.expression = "frame_type clause (skipped by basic policy)"
                step.result = False
                evaluation_trace.append(step)
                logger.debug(
                    "rule_skipped_frame_type_clause",
                    extra={"rule_id": rule.id},
                )
                continue

            # Check origin type match (early gate for efficiency)
            if rule.origin_types is not None:
                if origin_type_normalized is None:
                    step.expression = "origin_type: missing (rule requires origin)"
                    step.result = False
                    evaluation_trace.append(step)
                    continue

                if origin_type_normalized not in rule.origin_types:
                    origin_list = ", ".join(sorted(rule.origin_types))
                    raw_display = (
                        str(raw_origin_type) if raw_origin_type else "unknown"
                    )
                    step.expression = (
                        f"origin_type: {raw_display} not in [{origin_list}]"
                    )
                    step.result = False
                    evaluation_trace.append(step)
                    continue

            # Check action match
            if "*" not in rule.actions and resolved_action_normalized not in rule.actions:
                action_list = ", ".join(sorted(rule.actions))
                step.expression = (
                    f"action: {resolved_action_normalized} not in [{action_list}]"
                )
                step.result = False
                evaluation_trace.append(step)
                continue

            # Check address match (any pattern in the list matches)
            if rule.address_patterns is not None:
                if not address:
                    step.expression = (
                        "address: pattern requires address, but none provided"
                    )
                    step.result = False
                    evaluation_trace.append(step)
                    continue

                matched = any(p.match(address) for p in rule.address_patterns)
                if not matched:
                    patterns = ", ".join(p.source for p in rule.address_patterns)
                    step.expression = (
                        f"address: none of [{patterns}] matched {address}"
                    )
                    step.result = False
                    evaluation_trace.append(step)
                    continue

            # Check scope match
            if rule.scope_matcher is not None:
                if not rule.scope_matcher(granted_scopes):
                    step.expression = "scope: requirement not satisfied"
                    step.bound_values = {"grantedScopes": list(granted_scopes)}
                    step.result = False
                    evaluation_trace.append(step)
                    continue

            # Rule matched
            step.result = True
            step.expression = "all conditions matched"
            step.bound_values = {
                "action": resolved_action,
                "address": address,
                "grantedScopes": list(granted_scopes),
            }
            evaluation_trace.append(step)

            logger.debug(
                "rule_matched",
                extra={
                    "rule_id": rule.id,
                    "effect": rule.effect,
                    "action": resolved_action,
                    "address": address,
                },
            )

            return AuthorizationDecision(
                effect=rule.effect,  # type: ignore
                reason=rule.description or f"Matched rule: {rule.id}",
                matched_rule=rule.id,
                evaluation_trace=evaluation_trace,
            )

        # No rule matched, apply default effect
        logger.debug(
            "no_rule_matched",
            extra={
                "default_effect": self._default_effect,
                "action": resolved_action,
                "address": address,
            },
        )

        return AuthorizationDecision(
            effect=self._default_effect,  # type: ignore
            reason=f"No rule matched, applying default effect: {self._default_effect}",
            evaluation_trace=evaluation_trace,
        )

    def _validate_default_effect(self, effect: Any) -> str:
        """Validate and return the default effect."""
        if effect is None:
            return "deny"
        if effect not in ("allow", "deny"):
            raise ValueError(
                f'Invalid default_effect: "{effect}". Must be "allow" or "deny"'
            )
        return effect

    def _warn_unknown_policy_fields(
        self,
        definition: AuthorizationPolicyDefinition,
    ) -> None:
        """Log warnings for unknown policy fields."""
        # Get extra fields from the Pydantic model
        # model_extra contains fields not defined in the schema
        extra_fields = definition.model_extra or {}
        for key in extra_fields.keys():
            logger.warning(
                "unknown_policy_field",
                extra={"field": key},
            )

    def _compile_rules(
        self,
        rules: list[AuthorizationRuleDefinition],
        warn_on_unknown: bool,
    ) -> list[CompiledRule]:
        """Compile all rules for efficient evaluation."""
        return [
            self._compile_rule(rule, index, warn_on_unknown)
            for index, rule in enumerate(rules)
        ]

    def _compile_rule(
        self,
        rule: AuthorizationRuleDefinition,
        index: int,
        warn_on_unknown: bool,
    ) -> CompiledRule:
        """Compile a single rule for efficient evaluation."""
        # Generate ID if not provided
        rule_id = rule.id or f"rule_{index}"

        # Validate effect
        if rule.effect not in VALID_EFFECTS:
            raise ValueError(
                f'Invalid effect in rule "{rule_id}": "{rule.effect}". '
                f'Must be "allow" or "deny"'
            )

        # Validate and compile action(s)
        actions = self._compile_actions(rule.action, rule_id)

        # Compile address patterns (glob-only, no regex)
        address_patterns = self._compile_address(rule.address, rule_id)

        # Check for frame_type clause (reserved for advanced-security)
        has_frame_type_clause = rule.frame_type is not None
        if has_frame_type_clause and warn_on_unknown:
            logger.warning(
                "reserved_field_frame_type_will_be_skipped",
                extra={
                    "rule_id": rule_id,
                    "message": (
                        f'Rule "{rule_id}" uses reserved field "frame_type" which '
                        f"is only supported in advanced-security package. "
                        f"This rule will be skipped during evaluation."
                    ),
                },
            )

        # Compile origin type gating
        origin_types = self._compile_origin_types(rule.origin_type, rule_id)

        # Compile scope matcher (glob-only, no regex)
        scope_matcher: Optional[Callable[[Sequence[str]], bool]] = None
        if rule.scope is not None:
            try:
                compiled = compile_glob_only_scope_requirement(
                    rule.scope,
                    rule_id,
                )
                scope_matcher = compiled.evaluate
            except Exception as e:
                raise ValueError(
                    f'Invalid scope requirement in rule "{rule_id}": {e}'
                )

        # Warn about unknown fields
        if warn_on_unknown:
            extra_fields = rule.model_extra or {}
            for key in extra_fields.keys():
                logger.warning(
                    "unknown_rule_field",
                    extra={"rule_id": rule_id, "field": key},
                )

        return CompiledRule(
            id=rule_id,
            description=rule.description,
            effect=rule.effect,
            actions=actions,
            frame_types=None,  # No longer used; reserved for advanced-security
            origin_types=origin_types,
            address_patterns=address_patterns,
            scope_matcher=scope_matcher,
            has_when_clause=isinstance(rule.when, str) and len(rule.when) > 0,
            has_frame_type_clause=has_frame_type_clause,
        )

    def _compile_actions(
        self,
        action: Optional[RuleActionInput | list[RuleActionInput]],
        rule_id: str,
    ) -> set[RuleAction]:
        """
        Compile action field into a set of valid actions.

        Supports single RuleAction or array of RuleAction (implicit any-of).
        """
        # Default to wildcard if not specified
        if action is None:
            return {"*"}

        # Handle single action
        if isinstance(action, str):
            normalized = self._normalize_action_token(action)
            if normalized is None:
                valid = ", ".join(VALID_ACTIONS)
                raise ValueError(
                    f'Invalid action in rule "{rule_id}": "{action}". '
                    f"Must be one of: {valid}"
                )
            return {normalized}

        # Handle array of actions
        if not isinstance(action, list):
            raise ValueError(
                f'Invalid action in rule "{rule_id}": '
                f"must be a string or array of strings"
            )

        if len(action) == 0:
            raise ValueError(
                f'Invalid action in rule "{rule_id}": array must not be empty'
            )

        actions: set[RuleAction] = set()
        for a in action:
            if not isinstance(a, str):
                raise ValueError(
                    f'Invalid action in rule "{rule_id}": all values must be strings'
                )
            normalized = self._normalize_action_token(a)
            if normalized is None:
                valid = ", ".join(VALID_ACTIONS)
                raise ValueError(
                    f'Invalid action in rule "{rule_id}": "{a}". '
                    f"Must be one of: {valid}"
                )
            actions.add(normalized)

        return actions

    def _compile_address(
        self,
        address: Optional[str | list[str]],
        rule_id: str,
    ) -> Optional[list[CompiledPattern]]:
        """
        Compile address field into a list of glob matchers.

        Supports single string or array of strings (implicit any-of).
        Returns None if not specified (no address gating).

        All patterns are treated as globs - `^` prefix is rejected as an error.
        """
        if address is None:
            return None

        context = f'address in rule "{rule_id}"'

        # Handle single address pattern
        if isinstance(address, str):
            trimmed = address.strip()
            if not trimmed:
                raise ValueError(
                    f'Invalid address in rule "{rule_id}": value must not be empty'
                )
            try:
                return [compile_glob_pattern(trimmed, context)]
            except Exception as e:
                raise ValueError(
                    f'Invalid address in rule "{rule_id}": {e}'
                )

        # Handle array of address patterns
        if not isinstance(address, list):
            raise ValueError(
                f'Invalid address in rule "{rule_id}": '
                f"must be a string or array of strings"
            )

        if len(address) == 0:
            raise ValueError(
                f'Invalid address in rule "{rule_id}": array must not be empty'
            )

        patterns: list[CompiledPattern] = []
        for addr in address:
            if not isinstance(addr, str):
                raise ValueError(
                    f'Invalid address in rule "{rule_id}": all values must be strings'
                )
            trimmed = addr.strip()
            if not trimmed:
                raise ValueError(
                    f'Invalid address in rule "{rule_id}": values must not be empty'
                )
            try:
                patterns.append(compile_glob_pattern(trimmed, context))
            except Exception as e:
                raise ValueError(
                    f'Invalid address in rule "{rule_id}": {e}'
                )

        return patterns

    def _compile_origin_types(
        self,
        origin_type: Optional[str | list[str]],
        rule_id: str,
    ) -> Optional[set[str]]:
        """
        Compile origin_type field into a set of normalized origin types.

        Supports single string or array of strings (implicit any-of).
        Returns None if not specified (no origin type gating).
        Valid values: 'downstream', 'upstream', 'peer', 'local' (case-insensitive).
        """
        if origin_type is None:
            return None

        # Handle single origin type
        if isinstance(origin_type, str):
            trimmed = origin_type.strip()
            if not trimmed:
                raise ValueError(
                    f'Invalid origin_type in rule "{rule_id}": value must not be empty'
                )
            normalized = self._normalize_origin_type_token(trimmed)
            if normalized is None:
                valid = ", ".join(VALID_ORIGIN_TYPES)
                raise ValueError(
                    f'Invalid origin_type in rule "{rule_id}": "{origin_type}". '
                    f"Must be one of: {valid}"
                )
            return {normalized}

        # Handle array of origin types
        if not isinstance(origin_type, list):
            raise ValueError(
                f'Invalid origin_type in rule "{rule_id}": '
                f"must be a string or array of strings"
            )

        if len(origin_type) == 0:
            raise ValueError(
                f'Invalid origin_type in rule "{rule_id}": array must not be empty'
            )

        origin_types: set[str] = set()
        for ot in origin_type:
            if not isinstance(ot, str):
                raise ValueError(
                    f'Invalid origin_type in rule "{rule_id}": '
                    f"all values must be strings"
                )
            trimmed = ot.strip()
            if not trimmed:
                raise ValueError(
                    f'Invalid origin_type in rule "{rule_id}": '
                    f"values must not be empty"
                )
            normalized = self._normalize_origin_type_token(trimmed)
            if normalized is None:
                valid = ", ".join(VALID_ORIGIN_TYPES)
                raise ValueError(
                    f'Invalid origin_type in rule "{rule_id}": "{ot}". '
                    f"Must be one of: {valid}"
                )
            origin_types.add(normalized)

        return origin_types

    def _normalize_action_token(self, value: str) -> Optional[RuleAction]:
        """Normalize an action token to its canonical form."""
        trimmed = value.strip()
        if not trimmed:
            return None
        if trimmed == "*":
            return "*"
        # Remove spaces, underscores, hyphens and lowercase for comparison
        normalized = trimmed.replace(" ", "").replace("_", "").replace("-", "").lower()
        action_map: dict[str, RuleAction] = {
            "connect": "Connect",
            "forwardupstream": "ForwardUpstream",
            "forwarddownstream": "ForwardDownstream",
            "forwardpeer": "ForwardPeer",
            "deliverlocal": "DeliverLocal",
        }
        return action_map.get(normalized)

    def _normalize_origin_type_token(self, value: str) -> Optional[str]:
        """Normalize an origin type token to its canonical form."""
        trimmed = value.strip()
        if not trimmed:
            return None
        # Remove spaces, underscores, hyphens and lowercase for comparison
        normalized = trimmed.replace(" ", "").replace("_", "").replace("-", "").lower()
        origin_map: dict[str, str] = {
            "downstream": "downstream",
            "upstream": "upstream",
            "peer": "peer",
            "local": "local",
        }
        return origin_map.get(normalized)
