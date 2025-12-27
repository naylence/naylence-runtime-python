"""
Scope matching utilities for authorization policies.

Supports:
- Simple string patterns (glob only in OSS/basic policy)
- Logical operators: any_of, all_of, none_of
- Recursive nesting with depth limits
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Literal, Sequence, Union

from .authorization_policy_definition import (
    MAX_SCOPE_NESTING_DEPTH,
    NormalizedScopeAllOf,
    NormalizedScopeAnyOf,
    NormalizedScopeNoneOf,
    NormalizedScopePattern,
    NormalizedScopeRequirement,
    ScopeRequirement,
    ScopeRequirementAllOf,
    ScopeRequirementAnyOf,
    ScopeRequirementNoneOf,
)
from .pattern_matcher import CompiledPattern, compile_glob_pattern, match_pattern


def _any_scope_matches_pattern(
    granted_scopes: Sequence[str],
    pattern: str,
) -> bool:
    """Check if any of the granted scopes match the given pattern."""
    return any(match_pattern(pattern, scope) for scope in granted_scopes)


def normalize_scope_requirement(
    requirement: ScopeRequirement,
    depth: int = 0,
) -> NormalizedScopeRequirement:
    """
    Normalize a scope requirement into a typed structure.

    Args:
        requirement: The scope requirement to normalize
            Can be a string, dict, or a Pydantic ScopeRequirement* model
        depth: Current nesting depth (for recursion limit)

    Returns:
        Normalized scope requirement

    Raises:
        ValueError: If nesting exceeds maximum depth
        ValueError: If requirement is invalid
    """
    if depth > MAX_SCOPE_NESTING_DEPTH:
        raise ValueError(
            f"Scope requirement nesting exceeds maximum depth of "
            f"{MAX_SCOPE_NESTING_DEPTH}"
        )

    # Simple string pattern
    if isinstance(requirement, str):
        return NormalizedScopePattern(pattern=requirement)

    # Handle Pydantic models (from parsed AuthorizationPolicyDefinition)
    if isinstance(requirement, ScopeRequirementAnyOf):
        nested = [
            normalize_scope_requirement(item, depth + 1)
            for item in requirement.any_of
        ]
        return NormalizedScopeAnyOf(requirements=nested)

    if isinstance(requirement, ScopeRequirementAllOf):
        nested = [
            normalize_scope_requirement(item, depth + 1)
            for item in requirement.all_of
        ]
        return NormalizedScopeAllOf(requirements=nested)

    if isinstance(requirement, ScopeRequirementNoneOf):
        nested = [
            normalize_scope_requirement(item, depth + 1)
            for item in requirement.none_of
        ]
        return NormalizedScopeNoneOf(requirements=nested)

    # Object with logical operator (raw dict input)
    if not isinstance(requirement, dict):
        raise ValueError(f"Invalid scope requirement: {requirement}")

    keys = list(requirement.keys())
    if len(keys) != 1:
        raise ValueError(
            f"Scope requirement object must have exactly one key "
            f"(any_of, all_of, or none_of), got: {', '.join(keys)}"
        )

    key = keys[0]
    value = requirement[key]

    if not isinstance(value, list):
        raise ValueError(
            f'Scope requirement "{key}" must have a list value, '
            f"got: {type(value).__name__}"
        )

    nested = [
        normalize_scope_requirement(item, depth + 1)
        for item in value
    ]

    if key == "any_of":
        return NormalizedScopeAnyOf(requirements=nested)
    elif key == "all_of":
        return NormalizedScopeAllOf(requirements=nested)
    elif key == "none_of":
        return NormalizedScopeNoneOf(requirements=nested)
    else:
        raise ValueError(
            f'Unknown scope requirement operator: "{key}". '
            f"Expected any_of, all_of, or none_of"
        )


def evaluate_normalized_scope_requirement(
    requirement: NormalizedScopeRequirement,
    granted_scopes: Sequence[str],
) -> bool:
    """
    Evaluate a normalized scope requirement against granted scopes.

    Args:
        requirement: The normalized scope requirement
        granted_scopes: The scopes granted to the principal

    Returns:
        True if the requirement is satisfied
    """
    if isinstance(requirement, NormalizedScopePattern):
        return _any_scope_matches_pattern(granted_scopes, requirement.pattern)

    if isinstance(requirement, NormalizedScopeAnyOf):
        return any(
            evaluate_normalized_scope_requirement(req, granted_scopes)
            for req in requirement.requirements
        )

    if isinstance(requirement, NormalizedScopeAllOf):
        return all(
            evaluate_normalized_scope_requirement(req, granted_scopes)
            for req in requirement.requirements
        )

    if isinstance(requirement, NormalizedScopeNoneOf):
        return not any(
            evaluate_normalized_scope_requirement(req, granted_scopes)
            for req in requirement.requirements
        )

    # Exhaustive check
    raise ValueError(f"Unknown scope requirement type: {type(requirement)}")


def evaluate_scope_requirement(
    requirement: ScopeRequirement,
    granted_scopes: Sequence[str],
) -> bool:
    """
    Evaluate a scope requirement against granted scopes.

    This is the main entry point for scope matching.

    Args:
        requirement: The scope requirement (string or object)
        granted_scopes: The scopes granted to the principal

    Returns:
        True if the requirement is satisfied
    """
    normalized = normalize_scope_requirement(requirement)
    return evaluate_normalized_scope_requirement(normalized, granted_scopes)


def compile_scope_requirement(
    requirement: ScopeRequirement,
) -> Callable[[Sequence[str]], bool]:
    """
    Pre-compile a scope requirement for efficient repeated evaluation.

    Args:
        requirement: The scope requirement to compile

    Returns:
        A function that evaluates the requirement against granted scopes
    """
    normalized = normalize_scope_requirement(requirement)
    return lambda granted_scopes: evaluate_normalized_scope_requirement(
        normalized, granted_scopes
    )


# Compiled scope requirement for efficient repeated evaluation with glob-only patterns
@dataclass
class CompiledScopeRequirement:
    """Compiled scope requirement for efficient repeated evaluation."""

    evaluate: Callable[[Sequence[str]], bool]


# Compiled scope node types
@dataclass
class CompiledScopePatternNode:
    """Compiled scope pattern node."""

    type: Literal["pattern"] = "pattern"
    matcher: CompiledPattern = None  # type: ignore


@dataclass
class CompiledScopeAnyOfNode:
    """Compiled scope any_of node."""

    type: Literal["any_of"] = "any_of"
    requirements: list[CompiledScopeNode] = None  # type: ignore


@dataclass
class CompiledScopeAllOfNode:
    """Compiled scope all_of node."""

    type: Literal["all_of"] = "all_of"
    requirements: list[CompiledScopeNode] = None  # type: ignore


@dataclass
class CompiledScopeNoneOfNode:
    """Compiled scope none_of node."""

    type: Literal["none_of"] = "none_of"
    requirements: list[CompiledScopeNode] = None  # type: ignore


CompiledScopeNode = Union[
    CompiledScopePatternNode,
    CompiledScopeAnyOfNode,
    CompiledScopeAllOfNode,
    CompiledScopeNoneOfNode,
]


def _compile_glob_only_normalized(
    requirement: NormalizedScopeRequirement,
    context: str,
) -> CompiledScopeNode:
    """Compile a normalized scope requirement into efficient matchers (glob-only)."""
    if isinstance(requirement, NormalizedScopePattern):
        node = CompiledScopePatternNode()
        node.matcher = compile_glob_pattern(requirement.pattern, context)
        return node

    if isinstance(requirement, NormalizedScopeAnyOf):
        node = CompiledScopeAnyOfNode()
        node.requirements = [
            _compile_glob_only_normalized(r, context)
            for r in requirement.requirements
        ]
        return node

    if isinstance(requirement, NormalizedScopeAllOf):
        node = CompiledScopeAllOfNode()
        node.requirements = [
            _compile_glob_only_normalized(r, context)
            for r in requirement.requirements
        ]
        return node

    if isinstance(requirement, NormalizedScopeNoneOf):
        node = CompiledScopeNoneOfNode()
        node.requirements = [
            _compile_glob_only_normalized(r, context)
            for r in requirement.requirements
        ]
        return node

    raise ValueError(f"Unknown scope requirement type: {type(requirement)}")


def _evaluate_compiled_scope(
    node: CompiledScopeNode,
    granted_scopes: Sequence[str],
) -> bool:
    """Evaluate a compiled scope node against granted scopes."""
    if isinstance(node, CompiledScopePatternNode):
        return any(node.matcher.match(scope) for scope in granted_scopes)

    if isinstance(node, CompiledScopeAnyOfNode):
        return any(
            _evaluate_compiled_scope(r, granted_scopes)
            for r in node.requirements
        )

    if isinstance(node, CompiledScopeAllOfNode):
        return all(
            _evaluate_compiled_scope(r, granted_scopes)
            for r in node.requirements
        )

    if isinstance(node, CompiledScopeNoneOfNode):
        return not any(
            _evaluate_compiled_scope(r, granted_scopes)
            for r in node.requirements
        )

    raise ValueError(f"Unknown compiled scope node type: {type(node)}")


def compile_glob_only_scope_requirement(
    requirement: ScopeRequirement,
    rule_id: str,
) -> CompiledScopeRequirement:
    """
    Pre-compile a scope requirement for OSS/basic policy (glob-only, no regex).

    This version rejects patterns starting with `^` at compile time.

    Args:
        requirement: The scope requirement to compile
        rule_id: Rule ID for error messages

    Returns:
        A compiled scope requirement

    Raises:
        ValueError: If any pattern starts with `^` (regex attempt)
    """
    context = f'scope in rule "{rule_id}"'

    # Compile the requirement, pre-compiling all patterns as globs
    compiled = _compile_glob_only_normalized(
        normalize_scope_requirement(requirement),
        context,
    )

    return CompiledScopeRequirement(
        evaluate=lambda granted_scopes: _evaluate_compiled_scope(
            compiled, granted_scopes
        )
    )
