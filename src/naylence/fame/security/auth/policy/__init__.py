"""
Authorization policy module exports.

This module provides interfaces and factories for pluggable authorization policies.
"""

# Core interfaces and types
from .authorization_policy import (
    AuthorizationDecision,
    AuthorizationEffect,
    AuthorizationEvaluationStep,
    AuthorizationPolicy,
)
from .authorization_policy_definition import (
    KNOWN_POLICY_FIELDS,
    KNOWN_RULE_FIELDS,
    MAX_SCOPE_NESTING_DEPTH,
    VALID_ACTIONS,
    VALID_EFFECTS,
    VALID_ORIGIN_TYPES,
    AuthorizationPolicyDefinition,
    AuthorizationRuleDefinition,
    NormalizedScopeAllOf,
    NormalizedScopeAnyOf,
    NormalizedScopeNoneOf,
    NormalizedScopePattern,
    NormalizedScopeRequirement,
    RuleAction,
    RuleActionInput,
    RuleEffect,
    ScopeRequirement,
)

# Factory base classes
from .authorization_policy_factory import (
    AUTHORIZATION_POLICY_FACTORY_BASE_TYPE,
    AuthorizationPolicyConfig,
    AuthorizationPolicyFactory,
)

# Authorization policy source (interface)
from .authorization_policy_source import (
    AuthorizationPolicySource,
)

# Authorization policy source factory
from .authorization_policy_source_factory import (
    AUTHORIZATION_POLICY_SOURCE_FACTORY_BASE_TYPE,
    AuthorizationPolicySourceConfig,
    AuthorizationPolicySourceFactory,
)

# Basic authorization policy (browser and node)
from .basic_authorization_policy import (
    BasicAuthorizationPolicy,
    BasicAuthorizationPolicyOptions,
)

# Basic authorization policy factory
from .basic_authorization_policy_factory import (
    BasicAuthorizationPolicyConfig,
    BasicAuthorizationPolicyFactory,
)

# Local file authorization policy source
from .local_file_authorization_policy_source import (
    LocalFileAuthorizationPolicySource,
    LocalFileAuthorizationPolicySourceOptions,
    PolicyFileFormat,
)

# Local file authorization policy source factory
from .local_file_authorization_policy_source_factory import (
    LocalFileAuthorizationPolicySourceConfig,
    LocalFileAuthorizationPolicySourceFactory,
)

# Pattern and scope matchers
from .pattern_matcher import (
    CompiledPattern,
    assert_not_regex_pattern,
    clear_pattern_cache,
    compile_glob_pattern,
    compile_pattern,
    get_compiled_glob_pattern,
    get_compiled_pattern,
    is_regex_pattern,
    match_pattern,
)
from .scope_matcher import (
    CompiledScopeRequirement,
    compile_glob_only_scope_requirement,
    compile_scope_requirement,
    evaluate_scope_requirement,
    normalize_scope_requirement,
)

__all__ = [
    # Core interfaces
    "AuthorizationPolicy",
    "AuthorizationDecision",
    "AuthorizationEffect",
    "AuthorizationEvaluationStep",
    # Definition types
    "AuthorizationPolicyDefinition",
    "AuthorizationRuleDefinition",
    "RuleAction",
    "RuleActionInput",
    "RuleEffect",
    "ScopeRequirement",
    "NormalizedScopeRequirement",
    "NormalizedScopePattern",
    "NormalizedScopeAnyOf",
    "NormalizedScopeAllOf",
    "NormalizedScopeNoneOf",
    # Constants
    "MAX_SCOPE_NESTING_DEPTH",
    "KNOWN_POLICY_FIELDS",
    "KNOWN_RULE_FIELDS",
    "VALID_ACTIONS",
    "VALID_EFFECTS",
    "VALID_ORIGIN_TYPES",
    # Pattern matching
    "CompiledPattern",
    "compile_pattern",
    "compile_glob_pattern",
    "get_compiled_pattern",
    "get_compiled_glob_pattern",
    "match_pattern",
    "is_regex_pattern",
    "assert_not_regex_pattern",
    "clear_pattern_cache",
    # Scope matching
    "CompiledScopeRequirement",
    "normalize_scope_requirement",
    "evaluate_scope_requirement",
    "compile_scope_requirement",
    "compile_glob_only_scope_requirement",
    # Basic policy
    "BasicAuthorizationPolicy",
    "BasicAuthorizationPolicyOptions",
    # Factory base classes
    "AUTHORIZATION_POLICY_FACTORY_BASE_TYPE",
    "AuthorizationPolicyFactory",
    "AuthorizationPolicyConfig",
    # Basic policy factory
    "BasicAuthorizationPolicyFactory",
    "BasicAuthorizationPolicyConfig",
    # Authorization policy source
    "AuthorizationPolicySource",
    # Authorization policy source factory
    "AUTHORIZATION_POLICY_SOURCE_FACTORY_BASE_TYPE",
    "AuthorizationPolicySourceConfig",
    "AuthorizationPolicySourceFactory",
    # Local file authorization policy source
    "LocalFileAuthorizationPolicySource",
    "LocalFileAuthorizationPolicySourceOptions",
    "PolicyFileFormat",
    # Local file authorization policy source factory
    "LocalFileAuthorizationPolicySourceConfig",
    "LocalFileAuthorizationPolicySourceFactory",
]
