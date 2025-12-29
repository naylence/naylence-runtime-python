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


class TestMultiSeparatorSemantics:
    """Tests for multi-separator glob semantics (., /, @)."""

    def test_star_stops_at_dot(self):
        """Single * should not cross dot separators."""
        regex = compile_glob_pattern("*")
        assert regex.match("hello") is True
        assert regex.match("hello.world") is False

    def test_star_stops_at_slash(self):
        """Single * should not cross slash separators."""
        regex = compile_glob_pattern("*")
        assert regex.match("hello/world") is False
        regex2 = compile_glob_pattern("*/bar")
        assert regex2.match("foo/bar") is True
        assert regex2.match("baz/bar") is True
        assert regex2.match("foo/baz/bar") is False

    def test_star_stops_at_at(self):
        """Single * should not cross @ separators."""
        regex = compile_glob_pattern("*")
        assert regex.match("user@domain") is False
        regex2 = compile_glob_pattern("*@domain")
        assert regex2.match("user@domain") is True
        assert regex2.match("admin@domain") is True
        assert regex2.match("user.name@domain") is False

    def test_question_mark_does_not_match_separators(self):
        """? should not match any separator (., /, @)."""
        regex = compile_glob_pattern("te?t")
        assert regex.match("test") is True
        assert regex.match("text") is True
        assert regex.match("te.t") is False
        assert regex.match("te/t") is False
        assert regex.match("te@t") is False


class TestLogicalAddressMatching:
    """Tests for logical address patterns (name@domain.fabric)."""

    def test_star_in_each_segment(self):
        """Should match * wildcards in each segment."""
        regex = compile_glob_pattern("*@*.fabric")
        assert regex.match("user@example.fabric") is True
        assert regex.match("admin@prod.fabric") is True
        assert regex.match("user@sub.example.fabric") is False

    def test_double_star_for_multi_segment_domains(self):
        """Should match ** across multiple domain segments."""
        regex = compile_glob_pattern("*@**.fabric")
        assert regex.match("user@example.fabric") is True
        assert regex.match("user@sub.example.fabric") is True
        assert regex.match("user@a.b.c.fabric") is True

    def test_exact_address_match(self):
        """Should match specific addresses exactly."""
        regex = compile_glob_pattern("myservice@prod.example.com")
        assert regex.match("myservice@prod.example.com") is True
        assert regex.match("myservice@staging.example.com") is False


class TestPhysicalAddressMatching:
    """Tests for physical address patterns (name@/path/to/node)."""

    def test_star_in_path_segments(self):
        """Should match * wildcards in path segments."""
        regex = compile_glob_pattern("service@/region/*/instance")
        assert regex.match("service@/region/us-east/instance") is True
        assert regex.match("service@/region/eu-west/instance") is True
        assert regex.match("service@/region/us-east/zone-a/instance") is False

    def test_double_star_for_deep_paths(self):
        """Should match ** for deep path matching."""
        regex = compile_glob_pattern("service@/**")
        assert regex.match("service@/a") is True
        assert regex.match("service@/a/b") is True
        assert regex.match("service@/a/b/c/d") is True

    def test_mixed_separators(self):
        """Should match patterns with mixed separators."""
        regex = compile_glob_pattern("*@/*/zone.*")
        assert regex.match("app@/region/zone.primary") is True
        assert regex.match("svc@/datacenter/zone.backup") is True


class TestComplexPatterns:
    """Tests for complex patterns with mixed separators."""

    def test_consecutive_separators(self):
        """Should handle consecutive separators correctly."""
        regex = compile_glob_pattern("a.@/b")
        assert regex.match("a.@/b") is True

    def test_wildcards_between_separators(self):
        """Should handle wildcards between different separators."""
        regex = compile_glob_pattern("*.*@*/*")
        assert regex.match("a.b@c/d") is True
        assert regex.match("x.y@z/w") is True

    def test_double_star_spanning_separator_types(self):
        """Should match ** spanning multiple separator types."""
        regex = compile_glob_pattern("start.**end")
        assert regex.match("start.a.b@c/d.end") is True
        assert regex.match("start.end") is True


class TestGlobEdgeCases:
    """Tests for edge cases in glob patterns."""

    def test_empty_pattern_matches_empty_string(self):
        """Empty pattern should match only empty string."""
        regex = compile_glob_pattern("")
        assert regex.match("") is True
        assert regex.match("a") is False

    def test_star_only_pattern(self):
        """* alone matches single segment."""
        regex = compile_glob_pattern("*")
        assert regex.match("") is True
        assert regex.match("anything") is True
        assert regex.match("no.dots") is False

    def test_double_star_only_pattern(self):
        """** alone matches anything."""
        regex = compile_glob_pattern("**")
        assert regex.match("") is True
        assert regex.match("anything") is True
        assert regex.match("a.b.c@d/e/f") is True

    def test_parentheses_in_pattern(self):
        """Should escape parentheses correctly."""
        regex = compile_glob_pattern("func(*)")
        assert regex.match("func(arg)") is True
        assert regex.match("func()") is True

    def test_brackets_in_pattern(self):
        """Should escape brackets correctly."""
        regex = compile_glob_pattern("arr[*]")
        assert regex.match("arr[0]") is True
        assert regex.match("arr[123]") is True

    def test_plus_in_pattern(self):
        """Should escape + correctly."""
        regex = compile_glob_pattern("a+b")
        assert regex.match("a+b") is True
        assert regex.match("ab") is False
        assert regex.match("aab") is False
