"""Tests for pattern matcher functionality."""

import pytest

from naylence.fame.security.auth.policy.pattern_matcher import (
    assert_not_regex_pattern,
    clear_pattern_cache,
    compile_glob_pattern,
    compile_pattern,
    get_compiled_glob_pattern,
    get_compiled_pattern,
    match_pattern,
)


@pytest.fixture(autouse=True)
def clear_cache():
    """Clear pattern cache before each test."""
    clear_pattern_cache()
    yield
    clear_pattern_cache()


class TestAssertNotRegexPattern:
    """Tests for assert_not_regex_pattern function."""

    def test_allows_plain_string(self):
        """Should allow plain strings without ^ prefix."""
        # Should not raise
        assert_not_regex_pattern("simple.pattern")

    def test_allows_glob_patterns(self):
        """Should allow glob patterns."""
        assert_not_regex_pattern("api.*")
        assert_not_regex_pattern("api.**")
        assert_not_regex_pattern("api.?")

    def test_rejects_caret_prefix(self):
        """Should reject patterns starting with ^."""
        with pytest.raises(ValueError) as exc_info:
            assert_not_regex_pattern("^api\\..*$", "address")
        assert "Regex patterns are not supported" in str(exc_info.value)
        assert "address" in str(exc_info.value)
        assert "OSS/basic policy" in str(exc_info.value)

    def test_includes_context_in_error(self):
        """Should include context in error message when provided."""
        with pytest.raises(ValueError) as exc_info:
            assert_not_regex_pattern("^pattern$", "scope")
        assert "scope" in str(exc_info.value)


class TestCompileGlobPattern:
    """Tests for compile_glob_pattern function."""

    def test_compiles_exact_pattern(self):
        """Should compile exact patterns."""
        regex = compile_glob_pattern("api.v1.endpoint")
        assert regex.match("api.v1.endpoint") is True
        assert regex.match("api.v2.endpoint") is False

    def test_compiles_single_wildcard(self):
        """Should compile * to match single segment (non-dots)."""
        regex = compile_glob_pattern("api.*.endpoint")
        assert regex.match("api.v1.endpoint") is True
        assert regex.match("api.v2.endpoint") is True
        assert regex.match("api.v1.v2.endpoint") is False  # * shouldn't cross dots

    def test_compiles_double_wildcard(self):
        """Should compile ** to match any depth."""
        regex = compile_glob_pattern("api.**")
        assert regex.match("api.v1") is True
        assert regex.match("api.v1.v2") is True
        assert regex.match("api.v1.v2.endpoint") is True

    def test_compiles_question_mark(self):
        """Should compile ? to match single non-dot character."""
        regex = compile_glob_pattern("api.v?")
        assert regex.match("api.v1") is True
        assert regex.match("api.v2") is True
        assert regex.match("api.v12") is False  # ? is single char

    def test_escapes_regex_metacharacters(self):
        """Should escape regex metacharacters."""
        regex = compile_glob_pattern("api.endpoint(v1)")
        assert regex.match("api.endpoint(v1)") is True
        assert regex.match("api.endpointv1") is False

    def test_rejects_regex_pattern(self):
        """Should reject patterns starting with ^."""
        with pytest.raises(ValueError):
            compile_glob_pattern("^api\\..*$")

    def test_handles_leading_double_wildcard(self):
        """Should handle ** at the start."""
        regex = compile_glob_pattern("**.endpoint")
        assert regex.match("api.endpoint") is True
        assert regex.match("api.v1.endpoint") is True

    def test_handles_multiple_wildcards(self):
        """Should handle multiple wildcards."""
        regex = compile_glob_pattern("api.*.service.*")
        assert regex.match("api.v1.service.user") is True
        assert regex.match("api.v2.service.order") is True
        assert regex.match("api.v1.notservice.user") is False


class TestCompilePattern:
    """Tests for compile_pattern function."""

    def test_treats_non_caret_as_glob(self):
        """Should treat patterns not starting with ^ as glob."""
        regex = compile_pattern("api.*")
        assert regex.match("api.v1") is True
        assert regex.match("api.v2") is True

    def test_accepts_caret_prefix_as_regex(self):
        """Should accept regex patterns (caret prefix)."""
        # compile_pattern allows regex, unlike compile_glob_pattern
        regex = compile_pattern("^api\\..*$")
        assert regex.match("api.v1") is True
        assert regex.match("api.v2.v3") is True

    def test_rejects_invalid_regex(self):
        """Should reject invalid regex patterns."""
        with pytest.raises(ValueError):
            compile_pattern("^(unclosed")


class TestGetCompiledPattern:
    """Tests for get_compiled_pattern caching function."""

    def test_caches_compiled_patterns(self):
        """Should cache compiled patterns."""
        regex1 = get_compiled_pattern("service.*")
        regex2 = get_compiled_pattern("service.*")
        assert regex1 is regex2

    def test_different_patterns_not_same(self):
        """Different patterns should return different regexes."""
        regex1 = get_compiled_pattern("pattern.a.*")
        regex2 = get_compiled_pattern("pattern.b.*")
        assert regex1 is not regex2


class TestGetCompiledGlobPattern:
    """Tests for get_compiled_glob_pattern caching function."""

    def test_caches_glob_patterns(self):
        """Should cache glob patterns."""
        regex1 = get_compiled_glob_pattern("unique.pattern.1.*")
        regex2 = get_compiled_glob_pattern("unique.pattern.1.*")
        assert regex1 is regex2

    def test_rejects_regex_patterns(self):
        """Should reject regex patterns."""
        with pytest.raises(ValueError):
            get_compiled_glob_pattern("^regex.*$")


class TestMatchPattern:
    """Tests for match_pattern function."""

    def test_matches_exact_address(self):
        """Should match exact address."""
        assert match_pattern("api@services.v1", "api@services.v1") is True
        assert match_pattern("api@services.v1", "api@services.v2") is False

    def test_matches_single_wildcard(self):
        """Should match with single wildcard."""
        assert match_pattern("api.*", "api.v1") is True
        assert match_pattern("api.*", "api.v2") is True
        assert match_pattern("api.*", "api.v1.v2") is False

    def test_matches_double_wildcard(self):
        """Should match with double wildcard."""
        assert match_pattern("api.**", "api.v1") is True
        assert match_pattern("api.**", "api.v1.v2") is True
        assert match_pattern("api.**", "api.v1.v2.v3") is True

    def test_matches_question_mark(self):
        """Should match with question mark."""
        assert match_pattern("api.v?", "api.v1") is True
        assert match_pattern("api.v?", "api.v2") is True
        assert match_pattern("api.v?", "api.v12") is False

    def test_matches_with_at_sign(self):
        """Should handle @ in addresses."""
        assert match_pattern("*@services.*", "api@services.v1") is True
        assert match_pattern("*@services.*", "web@services.home") is True

    def test_returns_false_for_empty_value(self):
        """Should return False when value is empty string."""
        assert match_pattern("api.*", "") is False

    def test_handles_complex_patterns(self):
        """Should handle complex glob patterns."""
        pattern = "*@**.services.**"
        assert match_pattern(pattern, "api@public.services.v1") is True
        assert (
            match_pattern(pattern, "web@internal.deep.services.api.endpoint") is True
        )


class TestPatternCaching:
    """Tests for pattern caching behavior."""

    def test_glob_pattern_caching(self):
        """Should cache glob patterns and return same compiled regex."""
        pattern = "unique.pattern.3.*"
        regex1 = get_compiled_glob_pattern(pattern)
        regex2 = get_compiled_glob_pattern(pattern)
        assert regex1 is regex2

    def test_compile_pattern_caching(self):
        """Should cache patterns via get_compiled_pattern."""
        pattern = "unique.pattern.4.*"
        regex1 = get_compiled_pattern(pattern)
        regex2 = get_compiled_pattern(pattern)
        assert regex1 is regex2

    def test_different_patterns_not_same(self):
        """Different patterns should return different regexes."""
        regex1 = get_compiled_glob_pattern("pattern.c.*")
        regex2 = get_compiled_glob_pattern("pattern.d.*")
        assert regex1 is not regex2

    def test_clear_cache_works(self):
        """Clear cache should reset caching."""
        pattern = "cache.test.pattern.*"
        regex1 = get_compiled_pattern(pattern)
        clear_pattern_cache()
        regex2 = get_compiled_pattern(pattern)
        # After cache clear, different instance is created
        assert regex1 is not regex2
