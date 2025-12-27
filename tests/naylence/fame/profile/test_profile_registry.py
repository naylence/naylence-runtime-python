"""Tests for profile registry functionality."""

import pytest

from naylence.fame.profile import (
    ProfileConfig,
    RegisterProfileOptions,
    clear_profiles,
    get_profile,
    list_profiles,
    register_profile,
)


@pytest.fixture(autouse=True)
def clear_registry():
    """Clear the profile registry before each test."""
    clear_profiles()
    yield
    clear_profiles()


class TestRegisterProfile:
    """Tests for register_profile function."""

    def test_registers_profile_successfully(self):
        """Should register a profile with valid inputs."""
        config: ProfileConfig = {"type": "TestAuthorizer", "key": "value"}
        register_profile("TestFactory", "test-profile", config)

        result = get_profile("TestFactory", "test-profile")
        assert result == {"type": "TestAuthorizer", "key": "value"}

    def test_rejects_empty_base_type(self):
        """Should reject empty base type."""
        with pytest.raises(ValueError) as exc_info:
            register_profile("", "profile", {"key": "value"})
        assert "must be a non-empty string" in str(exc_info.value)

    def test_rejects_whitespace_base_type(self):
        """Should reject whitespace-only base type."""
        with pytest.raises(ValueError) as exc_info:
            register_profile("   ", "profile", {"key": "value"})
        assert "must be a non-empty string" in str(exc_info.value)

    def test_rejects_empty_profile_name(self):
        """Should reject empty profile name."""
        with pytest.raises(ValueError) as exc_info:
            register_profile("TestFactory", "", {"key": "value"})
        assert "must be a non-empty string" in str(exc_info.value)

    def test_rejects_whitespace_profile_name(self):
        """Should reject whitespace-only profile name."""
        with pytest.raises(ValueError) as exc_info:
            register_profile("TestFactory", "  ", {"key": "value"})
        assert "must be a non-empty string" in str(exc_info.value)

    def test_rejects_none_config(self):
        """Should reject None config."""
        with pytest.raises(ValueError) as exc_info:
            register_profile("TestFactory", "profile", None)  # type: ignore
        assert "config must be an object" in str(exc_info.value)

    def test_rejects_non_dict_config(self):
        """Should reject non-dict config."""
        with pytest.raises(ValueError) as exc_info:
            register_profile("TestFactory", "profile", ["not", "a", "dict"])  # type: ignore
        assert "config must be an object" in str(exc_info.value)

    def test_prevents_duplicate_registration(self):
        """Should prevent duplicate registration without allow_override."""
        register_profile("TestFactory", "profile", {"key": "value1"})

        with pytest.raises(ValueError) as exc_info:
            register_profile("TestFactory", "profile", {"key": "value2"})
        assert "already registered" in str(exc_info.value)

    def test_allows_override_with_option(self):
        """Should allow override when allow_override is True."""
        register_profile("TestFactory", "profile", {"key": "value1"})
        register_profile(
            "TestFactory",
            "profile",
            {"key": "value2"},
            RegisterProfileOptions(allow_override=True),
        )

        result = get_profile("TestFactory", "profile")
        assert result == {"key": "value2"}

    def test_includes_source_in_error_message(self):
        """Should include source in duplicate error message."""
        register_profile("TestFactory", "profile", {"key": "value"})

        with pytest.raises(ValueError) as exc_info:
            register_profile(
                "TestFactory",
                "profile",
                {"key": "value2"},
                RegisterProfileOptions(source="my-module"),
            )
        assert "my-module" in str(exc_info.value)

    def test_normalizes_base_type_whitespace(self):
        """Should normalize leading/trailing whitespace in base type."""
        register_profile("  TestFactory  ", "profile", {"key": "value"})
        result = get_profile("TestFactory", "profile")
        assert result is not None

    def test_normalizes_profile_name_whitespace(self):
        """Should normalize leading/trailing whitespace in profile name."""
        register_profile("TestFactory", "  my-profile  ", {"key": "value"})
        result = get_profile("TestFactory", "my-profile")
        assert result is not None


class TestGetProfile:
    """Tests for get_profile function."""

    def test_returns_profile_when_exists(self):
        """Should return profile when it exists."""
        register_profile("TestFactory", "profile", {"type": "Test", "value": 42})
        result = get_profile("TestFactory", "profile")
        assert result == {"type": "Test", "value": 42}

    def test_returns_none_for_unknown_base_type(self):
        """Should return None for unknown base type."""
        result = get_profile("UnknownFactory", "profile")
        assert result is None

    def test_returns_none_for_unknown_profile_name(self):
        """Should return None for unknown profile name."""
        register_profile("TestFactory", "profile1", {"key": "value"})
        result = get_profile("TestFactory", "profile2")
        assert result is None

    def test_returns_deep_copy(self):
        """Should return a deep copy of the profile config."""
        original = {"nested": {"key": "value"}}
        register_profile("TestFactory", "profile", original)

        result1 = get_profile("TestFactory", "profile")
        result1["nested"]["key"] = "modified"  # type: ignore

        result2 = get_profile("TestFactory", "profile")
        assert result2["nested"]["key"] == "value"  # type: ignore

    def test_normalizes_input_whitespace(self):
        """Should normalize whitespace in inputs."""
        register_profile("TestFactory", "profile", {"key": "value"})
        result = get_profile("  TestFactory  ", "  profile  ")
        assert result is not None


class TestListProfiles:
    """Tests for list_profiles function."""

    def test_returns_empty_list_for_unknown_base_type(self):
        """Should return empty list for unknown base type."""
        result = list_profiles("UnknownFactory")
        assert result == []

    def test_returns_profile_names(self):
        """Should return list of profile names."""
        register_profile("TestFactory", "profile1", {"key": "value1"})
        register_profile("TestFactory", "profile2", {"key": "value2"})
        register_profile("TestFactory", "profile3", {"key": "value3"})

        result = list_profiles("TestFactory")
        assert sorted(result) == ["profile1", "profile2", "profile3"]

    def test_returns_only_profiles_for_base_type(self):
        """Should return only profiles for the specified base type."""
        register_profile("Factory1", "profile1", {"key": "value"})
        register_profile("Factory2", "profile2", {"key": "value"})

        result = list_profiles("Factory1")
        assert result == ["profile1"]


class TestClearProfiles:
    """Tests for clear_profiles function."""

    def test_clears_all_profiles_when_no_base_type(self):
        """Should clear all profiles when no base type specified."""
        register_profile("Factory1", "profile1", {"key": "value"})
        register_profile("Factory2", "profile2", {"key": "value"})

        clear_profiles()

        assert get_profile("Factory1", "profile1") is None
        assert get_profile("Factory2", "profile2") is None

    def test_clears_only_specified_base_type(self):
        """Should clear only profiles for specified base type."""
        register_profile("Factory1", "profile1", {"key": "value1"})
        register_profile("Factory2", "profile2", {"key": "value2"})

        clear_profiles("Factory1")

        assert get_profile("Factory1", "profile1") is None
        assert get_profile("Factory2", "profile2") is not None

    def test_handles_clearing_non_existent_base_type(self):
        """Should handle clearing non-existent base type gracefully."""
        # Should not raise
        clear_profiles("NonExistent")
