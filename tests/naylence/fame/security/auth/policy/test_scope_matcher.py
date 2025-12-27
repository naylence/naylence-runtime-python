"""Tests for scope matcher functionality."""

import pytest

from naylence.fame.security.auth.policy.authorization_policy_definition import (
    MAX_SCOPE_NESTING_DEPTH,
    NormalizedScopeAllOf,
    NormalizedScopeAnyOf,
    NormalizedScopeNoneOf,
    NormalizedScopePattern,
)
from naylence.fame.security.auth.policy.scope_matcher import (
    compile_glob_only_scope_requirement,
    evaluate_scope_requirement,
    normalize_scope_requirement,
)


class TestNormalizeScopeRequirement:
    """Tests for normalize_scope_requirement function."""

    def test_normalizes_simple_string(self):
        """Should normalize simple string to NormalizedScopePattern."""
        result = normalize_scope_requirement("read")
        assert isinstance(result, NormalizedScopePattern)
        assert result.pattern == "read"

    def test_normalizes_any_of_operator(self):
        """Should normalize any_of operator."""
        result = normalize_scope_requirement({"any_of": ["admin", "superuser"]})
        assert isinstance(result, NormalizedScopeAnyOf)
        assert len(result.requirements) == 2
        assert all(isinstance(p, NormalizedScopePattern) for p in result.requirements)
        assert result.requirements[0].pattern == "admin"
        assert result.requirements[1].pattern == "superuser"

    def test_normalizes_all_of_operator(self):
        """Should normalize all_of operator."""
        result = normalize_scope_requirement({"all_of": ["read", "write"]})
        assert isinstance(result, NormalizedScopeAllOf)
        assert len(result.requirements) == 2

    def test_normalizes_none_of_operator(self):
        """Should normalize none_of operator."""
        result = normalize_scope_requirement({"none_of": ["restricted", "blocked"]})
        assert isinstance(result, NormalizedScopeNoneOf)
        assert len(result.requirements) == 2

    def test_normalizes_nested_requirements(self):
        """Should normalize nested scope requirements."""
        result = normalize_scope_requirement({
            "all_of": [
                "base",
                {"any_of": ["feature-a", "feature-b"]},
            ]
        })
        assert isinstance(result, NormalizedScopeAllOf)
        assert len(result.requirements) == 2
        assert isinstance(result.requirements[0], NormalizedScopePattern)
        assert isinstance(result.requirements[1], NormalizedScopeAnyOf)

    def test_rejects_non_dict_non_string(self):
        """Should reject non-dict, non-string input like lists."""
        with pytest.raises(ValueError):
            normalize_scope_requirement(["read", "write"])  # type: ignore

    def test_rejects_invalid_operator(self):
        """Should reject invalid operator."""
        with pytest.raises(ValueError) as exc_info:
            normalize_scope_requirement({"invalid_op": ["a", "b"]})
        assert "Unknown scope" in str(exc_info.value)

    def test_rejects_multiple_operators(self):
        """Should reject multiple operators in same object."""
        with pytest.raises(ValueError) as exc_info:
            normalize_scope_requirement({"any_of": ["a"], "all_of": ["b"]})
        assert "exactly one" in str(exc_info.value).lower()

    def test_rejects_excessive_nesting(self):
        """Should reject scope requirements nested too deeply."""
        # Build deeply nested structure
        nested: dict = "deep_scope"  # type: ignore
        for _ in range(MAX_SCOPE_NESTING_DEPTH + 1):
            nested = {"any_of": [nested]}

        with pytest.raises(ValueError) as exc_info:
            normalize_scope_requirement(nested)
        assert "maximum depth" in str(exc_info.value).lower()


class TestEvaluateScopeRequirement:
    """Tests for evaluate_scope_requirement function."""

    def test_matches_simple_pattern(self):
        """Should match simple pattern."""
        assert evaluate_scope_requirement("read", ["read", "write"]) is True
        assert evaluate_scope_requirement("read", ["write"]) is False

    def test_matches_glob_pattern(self):
        """Should match glob pattern."""
        assert evaluate_scope_requirement("api.*", ["api.read"]) is True
        assert evaluate_scope_requirement("api.*", ["api.write"]) is True
        assert evaluate_scope_requirement("api.*", ["other"]) is False

    def test_matches_any_of(self):
        """Should match any_of (any scope matches)."""
        req = {"any_of": ["admin", "super"]}
        assert evaluate_scope_requirement(req, ["user", "admin"]) is True
        assert evaluate_scope_requirement(req, ["super"]) is True
        assert evaluate_scope_requirement(req, ["user"]) is False

    def test_matches_all_of(self):
        """Should match all_of (all scopes must match)."""
        req = {"all_of": ["read", "write"]}
        assert evaluate_scope_requirement(req, ["read", "write", "delete"]) is True
        assert evaluate_scope_requirement(req, ["read"]) is False
        assert evaluate_scope_requirement(req, ["write"]) is False

    def test_matches_none_of(self):
        """Should match none_of (no scope matches)."""
        req = {"none_of": ["restricted", "blocked"]}
        assert evaluate_scope_requirement(req, ["read", "write"]) is True
        assert evaluate_scope_requirement(req, ["read", "restricted"]) is False
        assert evaluate_scope_requirement(req, ["blocked"]) is False

    def test_matches_nested_all_of_any_of(self):
        """Should match nested all_of containing any_of."""
        req = {
            "all_of": [
                "base",
                {"any_of": ["feature-a", "feature-b"]},
            ]
        }
        # Needs "base" AND (feature-a OR feature-b)
        assert evaluate_scope_requirement(req, ["base", "feature-a"]) is True
        assert evaluate_scope_requirement(req, ["base", "feature-b"]) is True
        assert evaluate_scope_requirement(req, ["base"]) is False
        assert evaluate_scope_requirement(req, ["feature-a"]) is False

    def test_matches_nested_any_of_all_of(self):
        """Should match nested any_of containing all_of."""
        req = {
            "any_of": [
                "admin",
                {"all_of": ["user", "premium"]},
            ]
        }
        # Needs "admin" OR (user AND premium)
        assert evaluate_scope_requirement(req, ["admin"]) is True
        assert evaluate_scope_requirement(req, ["user", "premium"]) is True
        assert evaluate_scope_requirement(req, ["user"]) is False

    def test_matches_complex_nested(self):
        """Should match complex nested requirements."""
        req = {
            "all_of": [
                {"none_of": ["blocked"]},
                {"any_of": ["read", "write"]},
            ]
        }
        # Not "blocked" AND (read OR write)
        assert evaluate_scope_requirement(req, ["read"]) is True
        assert evaluate_scope_requirement(req, ["write"]) is True
        assert evaluate_scope_requirement(req, ["read", "blocked"]) is False
        assert evaluate_scope_requirement(req, ["other"]) is False

    def test_handles_empty_granted_scopes(self):
        """Should handle empty granted scopes."""
        assert evaluate_scope_requirement("read", []) is False

    def test_handles_none_of_with_empty_scopes(self):
        """Should handle none_of with empty granted scopes (vacuously true)."""
        # No scopes granted means none of them are "restricted"
        assert evaluate_scope_requirement({"none_of": ["restricted"]}, []) is True

    def test_handles_glob_in_any_of(self):
        """Should handle glob patterns in any_of."""
        req = {"any_of": ["api.*", "web.*"]}
        assert evaluate_scope_requirement(req, ["api.read"]) is True
        assert evaluate_scope_requirement(req, ["web.home"]) is True
        assert evaluate_scope_requirement(req, ["other.thing"]) is False

    def test_handles_glob_in_none_of(self):
        """Should handle glob patterns in none_of."""
        req = {"none_of": ["admin.*"]}
        assert evaluate_scope_requirement(req, ["user.read"]) is True
        assert evaluate_scope_requirement(req, ["admin.super"]) is False


class TestCompileGlobOnlyScopeRequirement:
    """Tests for compile_glob_only_scope_requirement function."""

    def test_compiles_simple_pattern(self):
        """Should compile simple pattern."""
        compiled = compile_glob_only_scope_requirement("read", "test-rule")
        assert compiled is not None
        assert compiled.evaluate(["read", "write"]) is True
        assert compiled.evaluate(["write"]) is False

    def test_compiles_glob_pattern(self):
        """Should compile glob pattern."""
        compiled = compile_glob_only_scope_requirement("api.*", "test-rule")
        assert compiled.evaluate(["api.read"]) is True
        assert compiled.evaluate(["other"]) is False

    def test_compiles_nested_requirement(self):
        """Should compile nested requirement."""
        compiled = compile_glob_only_scope_requirement({
            "all_of": ["base", {"any_of": ["a", "b"]}]
        }, "test-rule")
        assert compiled.evaluate(["base", "a"]) is True
        assert compiled.evaluate(["base"]) is False

    def test_rejects_regex_pattern(self):
        """Should reject regex patterns in scope."""
        with pytest.raises(ValueError) as exc_info:
            compile_glob_only_scope_requirement("^api\\..*$", "test-rule")
        assert "Regex patterns are not supported" in str(exc_info.value)

    def test_rejects_regex_in_nested(self):
        """Should reject regex patterns nested in scope requirements."""
        with pytest.raises(ValueError) as exc_info:
            compile_glob_only_scope_requirement({
                "any_of": ["read", "^admin\\..*$"]
            }, "test-rule")
        assert "Regex patterns are not supported" in str(exc_info.value)

    def test_includes_rule_id_in_error(self):
        """Should include rule ID in error message."""
        with pytest.raises(ValueError) as exc_info:
            compile_glob_only_scope_requirement("^regex$", "my-custom-rule")
        assert "my-custom-rule" in str(exc_info.value)


class TestScopeRequirementEdgeCases:
    """Tests for edge cases in scope requirement handling."""

    def test_single_item_any_of(self):
        """Single-item any_of should work correctly."""
        compiled = compile_glob_only_scope_requirement(
            {"any_of": ["read"]}, "test-rule"
        )
        assert compiled.evaluate(["read"]) is True
        assert compiled.evaluate(["write"]) is False

    def test_single_item_all_of(self):
        """Single-item all_of should work correctly."""
        compiled = compile_glob_only_scope_requirement(
            {"all_of": ["read"]}, "test-rule"
        )
        assert compiled.evaluate(["read"]) is True
        assert compiled.evaluate(["write"]) is False

    def test_single_item_none_of(self):
        """Single-item none_of should work correctly."""
        compiled = compile_glob_only_scope_requirement(
            {"none_of": ["blocked"]}, "test-rule"
        )
        assert compiled.evaluate(["read"]) is True
        assert compiled.evaluate(["blocked"]) is False

    def test_deeply_nested_but_valid(self):
        """Should accept deeply nested requirements within limit."""
        # Build nested structure at exactly MAX_SCOPE_NESTING_DEPTH levels
        nested: dict = "scope"  # type: ignore
        for _ in range(MAX_SCOPE_NESTING_DEPTH):
            nested = {"any_of": [nested]}

        # Should not raise
        compiled = compile_glob_only_scope_requirement(nested, "test-rule")
        assert compiled.evaluate(["scope"]) is True

    def test_any_of_with_all_matching(self):
        """any_of should return True if any scope matches."""
        compiled = compile_glob_only_scope_requirement(
            {"any_of": ["a", "b", "c"]}, "test-rule"
        )
        assert compiled.evaluate(["a"]) is True
        assert compiled.evaluate(["b"]) is True
        assert compiled.evaluate(["a", "b", "c"]) is True
        assert compiled.evaluate(["d"]) is False

    def test_all_of_with_partial_match(self):
        """all_of should return False if only partial match."""
        compiled = compile_glob_only_scope_requirement(
            {"all_of": ["a", "b", "c"]}, "test-rule"
        )
        assert compiled.evaluate(["a", "b"]) is False
        assert compiled.evaluate(["a", "b", "c"]) is True
        assert compiled.evaluate(["a", "b", "c", "d"]) is True

    def test_none_of_with_partial_forbidden(self):
        """none_of should return False if any forbidden scope present."""
        compiled = compile_glob_only_scope_requirement(
            {"none_of": ["x", "y", "z"]}, "test-rule"
        )
        assert compiled.evaluate(["a", "b"]) is True
        assert compiled.evaluate(["a", "x"]) is False
        assert compiled.evaluate(["x", "y", "z"]) is False
