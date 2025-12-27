"""
Pattern matching utilities for authorization policies.

Supports:
- Glob patterns: `*` (single segment), `**` (any depth), `?` (single char)
- Regex patterns: patterns starting with `^` (for advanced/BSL use only)

The OSS/basic policy uses glob-only matching via `compile_glob_pattern()`.
The advanced/BSL policy may use `compile_pattern()` which interprets `^` as regex.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


@dataclass
class CompiledPattern:
    """Compiled pattern for efficient repeated matching."""

    source: str
    is_regex: bool
    _regex: re.Pattern[str]

    def match(self, value: str) -> bool:
        """Check if the value matches this pattern."""
        return bool(self._regex.search(value))


def is_regex_pattern(pattern: str) -> bool:
    """
    Check if a pattern string is a regex pattern.

    Regex patterns start with `^`.
    """
    return pattern.startswith("^")


def assert_not_regex_pattern(pattern: str, context: Optional[str] = None) -> None:
    """
    Assert that a pattern is not a regex pattern.

    Raises an error if the pattern starts with `^`.
    Use this in OSS/basic policy to reject regex patterns.

    Args:
        pattern: The pattern to check
        context: Optional context for the error message (e.g., "address", "scope")

    Raises:
        ValueError: If the pattern is a regex pattern
    """
    if pattern.startswith("^"):
        context_str = f" in {context}" if context else ""
        raise ValueError(
            f"Regex patterns are not supported{context_str} in OSS/basic policy. "
            f'Pattern "{pattern}" starts with \'^\'.. Use glob patterns instead.'
        )


def _escape_regex(s: str) -> str:
    """Escape special regex characters in a string."""
    return re.escape(s)


def _glob_to_regex(glob: str) -> str:
    """
    Convert a glob pattern to a regex pattern.

    Glob syntax:
    - `*` matches a single segment (no dots)
    - `**` matches any number of segments (including zero)
    - `?` matches a single character (not a dot)
    - Other characters are matched literally

    Args:
        glob: The glob pattern to convert

    Returns:
        A regex pattern string (without anchors)
    """
    parts: list[str] = []
    i = 0

    while i < len(glob):
        if glob[i] == "*":
            if i + 1 < len(glob) and glob[i + 1] == "*":
                # `**` matches any characters (including dots)
                parts.append(".*")
                i += 2
            else:
                # `*` matches any characters except dots (single segment)
                parts.append("[^.]*")
                i += 1
        elif glob[i] == "?":
            # `?` matches a single character (not a dot)
            parts.append("[^.]")
            i += 1
        else:
            # Escape and add literal character
            parts.append(_escape_regex(glob[i]))
            i += 1

    return "".join(parts)


def compile_pattern(pattern: str) -> CompiledPattern:
    """
    Compile a pattern string into an efficient matcher.

    Args:
        pattern: Glob pattern or regex (starting with `^`)

    Returns:
        A compiled pattern object

    Raises:
        ValueError: If the regex pattern is invalid
    """
    if is_regex_pattern(pattern):
        # Regex pattern - compile directly
        try:
            regex = re.compile(pattern)
        except re.error as e:
            raise ValueError(f"Invalid regex pattern '{pattern}': {e}")
        return CompiledPattern(source=pattern, is_regex=True, _regex=regex)

    # Glob pattern - convert to regex with anchors
    regex_str = f"^{_glob_to_regex(pattern)}$"
    regex = re.compile(regex_str)

    return CompiledPattern(source=pattern, is_regex=False, _regex=regex)


def compile_glob_pattern(pattern: str, context: Optional[str] = None) -> CompiledPattern:
    """
    Compile a pattern string as a glob pattern only (no regex interpretation).

    This is the preferred method for OSS/basic policy evaluation.
    Patterns starting with `^` are rejected with an error.

    Args:
        pattern: Glob pattern (regex patterns rejected)
        context: Optional context for error messages

    Returns:
        A compiled pattern object

    Raises:
        ValueError: If pattern starts with `^` (regex attempt)
    """
    # Reject regex patterns in OSS/basic policy
    assert_not_regex_pattern(pattern, context)

    # Convert glob to regex with anchors
    regex_str = f"^{_glob_to_regex(pattern)}$"
    regex = re.compile(regex_str)

    return CompiledPattern(source=pattern, is_regex=False, _regex=regex)


# Cache for compiled patterns to avoid recompilation
_pattern_cache: dict[str, CompiledPattern] = {}

# Cache for glob-only compiled patterns
_glob_pattern_cache: dict[str, CompiledPattern] = {}


def get_compiled_pattern(pattern: str) -> CompiledPattern:
    """
    Get or compile a pattern, with caching.

    Args:
        pattern: Glob pattern or regex

    Returns:
        A compiled pattern object
    """
    compiled = _pattern_cache.get(pattern)
    if compiled is None:
        compiled = compile_pattern(pattern)
        _pattern_cache[pattern] = compiled
    return compiled


def get_compiled_glob_pattern(pattern: str) -> CompiledPattern:
    """
    Get or compile a glob-only pattern, with caching.

    This is the preferred method for OSS/basic policy evaluation.
    Patterns are always treated as globs, never regex.

    Args:
        pattern: Glob pattern (never interpreted as regex)

    Returns:
        A compiled pattern object
    """
    compiled = _glob_pattern_cache.get(pattern)
    if compiled is None:
        compiled = compile_glob_pattern(pattern)
        _glob_pattern_cache[pattern] = compiled
    return compiled


def match_pattern(pattern: str, value: str) -> bool:
    """
    Match a value against a pattern string.

    Args:
        pattern: Glob pattern or regex (starting with `^`)
        value: The value to match

    Returns:
        True if the value matches the pattern
    """
    return get_compiled_pattern(pattern).match(value)


def clear_pattern_cache() -> None:
    """
    Clear the pattern cache.

    Useful for testing or when memory is a concern.
    """
    _pattern_cache.clear()
    _glob_pattern_cache.clear()
