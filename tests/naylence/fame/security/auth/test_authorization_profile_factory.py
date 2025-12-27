"""
Tests for the AuthorizationProfileFactory class.

This module tests the factory that creates authorizers from named profiles.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from naylence.fame.security.auth.authorization_profile_factory import (
    AUTHORIZER_FACTORY_BASE_TYPE,
    DEFAULT_PROFILE,
    NOOP_PROFILE,
    OAUTH2_CALLBACK_PROFILE,
    OAUTH2_GATED_PROFILE,
    OAUTH2_PROFILE,
    POLICY_LOCALFILE_PROFILE,
    PROFILE_ALIASES,
    PROFILE_NAME_DEFAULT,
    PROFILE_NAME_NOOP,
    PROFILE_NAME_OAUTH2,
    PROFILE_NAME_OAUTH2_CALLBACK,
    PROFILE_NAME_OAUTH2_GATED,
    PROFILE_NAME_POLICY_LOCALFILE,
    AuthorizationProfileConfig,
    AuthorizationProfileFactory,
    _canonicalize_profile_name,
    _coerce_profile_string,
    _ensure_profiles_registered,
    _normalize_config,
    _resolve_profile_config,
    _resolve_profile_name,
)


class TestProfileNameConstants:
    """Tests for profile name constants."""

    def test_profile_name_default_is_jwt(self):
        """Should have default profile as jwt."""
        assert PROFILE_NAME_DEFAULT == "jwt"

    def test_profile_name_oauth2(self):
        """Should have oauth2 profile."""
        assert PROFILE_NAME_OAUTH2 == "oauth2"

    def test_profile_name_oauth2_gated(self):
        """Should have oauth2-gated profile."""
        assert PROFILE_NAME_OAUTH2_GATED == "oauth2-gated"

    def test_profile_name_oauth2_callback(self):
        """Should have oauth2-callback profile."""
        assert PROFILE_NAME_OAUTH2_CALLBACK == "oauth2-callback"

    def test_profile_name_policy_localfile(self):
        """Should have policy-localfile profile."""
        assert PROFILE_NAME_POLICY_LOCALFILE == "policy-localfile"

    def test_profile_name_noop(self):
        """Should have noop profile."""
        assert PROFILE_NAME_NOOP == "noop"


class TestProfileConfigurations:
    """Tests for profile configuration dictionaries."""

    def test_default_profile_has_type(self):
        """Default profile should have type DefaultAuthorizer."""
        assert DEFAULT_PROFILE["type"] == "DefaultAuthorizer"

    def test_oauth2_profile_has_type(self):
        """OAuth2 profile should have type OAuth2Authorizer."""
        assert OAUTH2_PROFILE["type"] == "OAuth2Authorizer"

    def test_oauth2_gated_profile_extends_oauth2(self):
        """OAuth2 gated profile should extend OAuth2 profile."""
        assert OAUTH2_GATED_PROFILE["type"] == "OAuth2Authorizer"
        assert "enforce_token_subject_node_identity" in OAUTH2_GATED_PROFILE

    def test_oauth2_callback_profile_has_type(self):
        """OAuth2 callback profile should have type OAuth2Authorizer."""
        assert OAUTH2_CALLBACK_PROFILE["type"] == "OAuth2Authorizer"
        assert "token_verifier_config" in OAUTH2_CALLBACK_PROFILE
        assert "token_issuer_config" in OAUTH2_CALLBACK_PROFILE

    def test_noop_profile_has_type(self):
        """Noop profile should have type NoopAuthorizer."""
        assert NOOP_PROFILE["type"] == "NoopAuthorizer"

    def test_policy_localfile_profile_has_type(self):
        """Policy localfile profile should have type PolicyAuthorizer."""
        assert POLICY_LOCALFILE_PROFILE["type"] == "PolicyAuthorizer"
        assert "policy_source" in POLICY_LOCALFILE_PROFILE


class TestProfileAliases:
    """Tests for profile alias mappings."""

    def test_jwt_alias_maps_to_default(self):
        """jwt alias should map to default profile."""
        assert PROFILE_ALIASES["jwt"] == PROFILE_NAME_DEFAULT

    def test_jwks_alias_maps_to_default(self):
        """jwks alias should map to default profile."""
        assert PROFILE_ALIASES["jwks"] == PROFILE_NAME_DEFAULT

    def test_oidc_alias_maps_to_oauth2(self):
        """oidc alias should map to oauth2 profile."""
        assert PROFILE_ALIASES["oidc"] == PROFILE_NAME_OAUTH2

    def test_reverse_auth_alias_maps_to_oauth2_callback(self):
        """reverse-auth alias should map to oauth2-callback profile."""
        assert PROFILE_ALIASES["reverse-auth"] == PROFILE_NAME_OAUTH2_CALLBACK

    def test_noop_variants_map_to_noop(self):
        """noop variants should all map to noop profile."""
        assert PROFILE_ALIASES["noop"] == PROFILE_NAME_NOOP
        assert PROFILE_ALIASES["no-op"] == PROFILE_NAME_NOOP
        assert PROFILE_ALIASES["no_op"] == PROFILE_NAME_NOOP

    def test_policy_aliases_map_to_policy_localfile(self):
        """Policy aliases should map to policy-localfile."""
        assert PROFILE_ALIASES["policy"] == PROFILE_NAME_POLICY_LOCALFILE
        assert PROFILE_ALIASES["policy-localfile"] == PROFILE_NAME_POLICY_LOCALFILE
        assert PROFILE_ALIASES["policy_localfile"] == PROFILE_NAME_POLICY_LOCALFILE


class TestCoerceProfileString:
    """Tests for _coerce_profile_string function."""

    def test_returns_none_for_non_string(self):
        """Should return None for non-string values."""
        assert _coerce_profile_string(123) is None
        assert _coerce_profile_string(None) is None
        assert _coerce_profile_string({}) is None
        assert _coerce_profile_string([]) is None

    def test_returns_trimmed_string(self):
        """Should return trimmed string."""
        assert _coerce_profile_string("  oauth2  ") == "oauth2"
        assert _coerce_profile_string("noop") == "noop"

    def test_returns_none_for_empty_string(self):
        """Should return None for empty or whitespace-only strings."""
        assert _coerce_profile_string("") is None
        assert _coerce_profile_string("   ") is None


class TestCanonicalizeProfileName:
    """Tests for _canonicalize_profile_name function."""

    def test_normalizes_underscores_to_hyphens(self):
        """Should normalize underscores to hyphens."""
        assert _canonicalize_profile_name("oauth2_gated") == "oauth2-gated"
        assert _canonicalize_profile_name("no_op") == "noop"

    def test_normalizes_spaces_to_hyphens(self):
        """Should normalize spaces to hyphens."""
        assert _canonicalize_profile_name("oauth2 gated") == "oauth2-gated"

    def test_lowercases_profile_name(self):
        """Should lowercase profile names."""
        assert _canonicalize_profile_name("OAUTH2") == "oauth2"
        assert _canonicalize_profile_name("NoOp") == "noop"

    def test_uses_alias_when_available(self):
        """Should use alias mapping when available."""
        assert _canonicalize_profile_name("oidc") == PROFILE_NAME_OAUTH2
        assert _canonicalize_profile_name("jwt") == PROFILE_NAME_DEFAULT

    def test_returns_original_when_no_alias(self):
        """Should return original when no alias found."""
        assert _canonicalize_profile_name("custom-profile") == "custom-profile"


class TestResolveProfileName:
    """Tests for _resolve_profile_name function."""

    def test_extracts_profile_from_profile_field(self):
        """Should extract profile from 'profile' field."""
        assert _resolve_profile_name({"profile": "noop"}) == "noop"

    def test_extracts_profile_from_profile_name_field(self):
        """Should extract profile from 'profile_name' legacy field."""
        assert _resolve_profile_name({"profile_name": "oauth2"}) == "oauth2"

    def test_extracts_profile_from_profileName_field(self):
        """Should extract profile from 'profileName' legacy field."""
        assert _resolve_profile_name({"profileName": "jwt"}) == "jwt"

    def test_defaults_to_oauth2_when_missing(self):
        """Should default to oauth2 when no profile specified."""
        assert _resolve_profile_name({}) == PROFILE_NAME_OAUTH2

    def test_prefers_profile_over_legacy_keys(self):
        """Should prefer 'profile' over legacy keys."""
        result = _resolve_profile_name({
            "profile": "noop",
            "profile_name": "oauth2",
            "profileName": "jwt",
        })
        assert result == "noop"


class TestNormalizeConfig:
    """Tests for _normalize_config function."""

    def test_returns_oauth2_for_none_config(self):
        """Should return oauth2 for None config."""
        result = _normalize_config(None)
        assert result["profile"] == PROFILE_NAME_OAUTH2

    def test_handles_dict_config(self):
        """Should handle dict config."""
        result = _normalize_config({"profile": "noop"})
        assert result["profile"] == "noop"

    def test_handles_authorization_profile_config(self):
        """Should handle AuthorizationProfileConfig object."""
        config = AuthorizationProfileConfig(profile="jwt")
        result = _normalize_config(config)
        assert result["profile"] == PROFILE_NAME_DEFAULT

    def test_canonicalizes_profile_name(self):
        """Should canonicalize profile name."""
        result = _normalize_config({"profile": "OAUTH2_GATED"})
        assert result["profile"] == "oauth2-gated"


class TestResolveProfileConfig:
    """Tests for _resolve_profile_config function."""

    def test_resolves_oauth2_profile(self):
        """Should resolve oauth2 profile."""
        config = _resolve_profile_config(PROFILE_NAME_OAUTH2)
        assert config["type"] == "OAuth2Authorizer"

    def test_resolves_noop_profile(self):
        """Should resolve noop profile."""
        config = _resolve_profile_config(PROFILE_NAME_NOOP)
        assert config["type"] == "NoopAuthorizer"

    def test_resolves_policy_localfile_profile(self):
        """Should resolve policy-localfile profile."""
        config = _resolve_profile_config(PROFILE_NAME_POLICY_LOCALFILE)
        assert config["type"] == "PolicyAuthorizer"

    def test_resolves_jwt_profile(self):
        """Should resolve jwt (default) profile."""
        config = _resolve_profile_config(PROFILE_NAME_DEFAULT)
        assert config["type"] == "DefaultAuthorizer"

    def test_raises_for_unknown_profile(self):
        """Should raise ValueError for unknown profile."""
        with pytest.raises(ValueError, match="Unknown authorization profile"):
            _resolve_profile_config("unknown-profile")


class TestEnsureProfilesRegistered:
    """Tests for _ensure_profiles_registered function."""

    def test_profiles_are_registered_after_call(self):
        """Should have profiles registered after call."""
        import naylence.fame.security.auth.authorization_profile_factory as mod

        # Ensure profiles are registered (already registered by module import)
        _ensure_profiles_registered()
        assert mod._profiles_registered is True

    def test_ensure_profiles_is_idempotent(self):
        """Should be idempotent - calling multiple times has no effect."""
        import naylence.fame.security.auth.authorization_profile_factory as mod

        # Call multiple times - should not raise
        _ensure_profiles_registered()
        _ensure_profiles_registered()
        _ensure_profiles_registered()
        assert mod._profiles_registered is True


class TestAuthorizationProfileConfig:
    """Tests for AuthorizationProfileConfig dataclass."""

    def test_default_type_is_authorization_profile(self):
        """Should have default type as AuthorizationProfile."""
        config = AuthorizationProfileConfig()
        assert config.type == "AuthorizationProfile"

    def test_profile_defaults_to_none(self):
        """Should have profile default to None."""
        config = AuthorizationProfileConfig()
        assert config.profile is None

    def test_accepts_profile_parameter(self):
        """Should accept profile parameter."""
        config = AuthorizationProfileConfig(profile="noop")
        assert config.profile == "noop"


class TestAuthorizationProfileFactory:
    """Tests for AuthorizationProfileFactory class."""

    @pytest.fixture
    def factory(self):
        """Create a factory instance."""
        return AuthorizationProfileFactory()

    @pytest.fixture
    def mock_authorizer_factory(self):
        """Mock the AuthorizerFactory.create_authorizer method."""
        with patch(
            "naylence.fame.security.auth.authorization_profile_factory."
            "AuthorizerFactory.create_authorizer"
        ) as mock:
            mock.return_value = MagicMock()
            yield mock

    @pytest.mark.asyncio
    async def test_defaults_to_oauth2_profile_when_config_missing(
        self, factory, mock_authorizer_factory
    ):
        """Should default to oauth2 profile when config is missing."""
        await factory.create(None)

        mock_authorizer_factory.assert_called_once()
        profile_config = mock_authorizer_factory.call_args[0][0]
        assert profile_config["type"] == "OAuth2Authorizer"

    @pytest.mark.asyncio
    async def test_accepts_snake_case_profile_alias(
        self, factory, mock_authorizer_factory
    ):
        """Should accept snake_case profile alias."""
        await factory.create({
            "type": "AuthorizationProfile",
            "profile_name": "no_op",
        })

        mock_authorizer_factory.assert_called_once()
        profile_config = mock_authorizer_factory.call_args[0][0]
        assert profile_config["type"] == "NoopAuthorizer"

    @pytest.mark.asyncio
    async def test_accepts_camelcase_profile_alias_and_normalizes_casing(
        self, factory, mock_authorizer_factory
    ):
        """Should accept camelCase profile alias and normalize casing."""
        await factory.create({
            "type": "AuthorizationProfile",
            "profileName": "OAUTH2",
        })

        mock_authorizer_factory.assert_called_once()
        profile_config = mock_authorizer_factory.call_args[0][0]
        assert profile_config["type"] == "OAuth2Authorizer"

    @pytest.mark.asyncio
    async def test_passes_through_factory_kwargs_when_resolving_authorizer(
        self, factory, mock_authorizer_factory
    ):
        """Should pass through factory kwargs when resolving authorizer."""
        token_verifier = MagicMock()
        await factory.create(
            {
                "type": "AuthorizationProfile",
                "profile": PROFILE_NAME_NOOP,
            },
            token_verifier=token_verifier,
        )

        mock_authorizer_factory.assert_called_once()
        call_kwargs = mock_authorizer_factory.call_args[1]
        assert call_kwargs.get("token_verifier") == token_verifier

    @pytest.mark.asyncio
    async def test_maps_compact_aliases_onto_canonical_profile_names(
        self, factory, mock_authorizer_factory
    ):
        """Should map compact aliases onto canonical profile names."""
        await factory.create({
            "type": "AuthorizationProfile",
            "profile": "oidc",
        })

        mock_authorizer_factory.assert_called_once()
        profile_config = mock_authorizer_factory.call_args[0][0]
        assert profile_config["type"] == "OAuth2Authorizer"

    @pytest.mark.asyncio
    async def test_throws_for_unknown_profiles_after_normalization(self, factory):
        """Should throw for unknown profiles after normalization."""
        with pytest.raises(ValueError, match="Unknown authorization profile"):
            await factory.create({
                "type": "AuthorizationProfile",
                "profile": "custom-profile",
            })

    @pytest.mark.asyncio
    async def test_resolves_explicit_oauth2_profile_name(
        self, factory, mock_authorizer_factory
    ):
        """Should resolve explicit oauth2 profile name."""
        await factory.create({
            "type": "AuthorizationProfile",
            "profile": PROFILE_NAME_OAUTH2,
        })

        mock_authorizer_factory.assert_called_once()
        profile_config = mock_authorizer_factory.call_args[0][0]
        assert profile_config["type"] == "OAuth2Authorizer"

    @pytest.mark.asyncio
    async def test_resolves_policy_localfile_profile_name(
        self, factory, mock_authorizer_factory
    ):
        """Should resolve policy-localfile to PolicyAuthorizer with policy_source."""
        await factory.create({
            "type": "AuthorizationProfile",
            "profile": PROFILE_NAME_POLICY_LOCALFILE,
        })

        mock_authorizer_factory.assert_called_once()
        profile_config = mock_authorizer_factory.call_args[0][0]
        assert profile_config["type"] == "PolicyAuthorizer"
        assert "policy_source" in profile_config
        assert (
            profile_config["policy_source"]["type"]
            == "LocalFileAuthorizationPolicySource"
        )

    @pytest.mark.asyncio
    async def test_throws_when_authorizer_creation_fails(
        self, factory, mock_authorizer_factory
    ):
        """Should throw when authorizer creation returns None."""
        mock_authorizer_factory.return_value = None

        with pytest.raises(ValueError, match="Failed to create authorizer"):
            await factory.create({
                "type": "AuthorizationProfile",
                "profile": PROFILE_NAME_NOOP,
            })

    @pytest.mark.asyncio
    async def test_handles_authorization_profile_config_object(
        self, factory, mock_authorizer_factory
    ):
        """Should handle AuthorizationProfileConfig object."""
        config = AuthorizationProfileConfig(profile="noop")
        await factory.create(config)

        mock_authorizer_factory.assert_called_once()
        profile_config = mock_authorizer_factory.call_args[0][0]
        assert profile_config["type"] == "NoopAuthorizer"

    def test_factory_type_is_authorization_profile(self, factory):
        """Should have type as AuthorizationProfile."""
        assert factory.type == "AuthorizationProfile"


class TestAuthorizerFactoryBaseType:
    """Tests for AUTHORIZER_FACTORY_BASE_TYPE constant."""

    def test_base_type_is_authorizer(self):
        """Should have base type as Authorizer."""
        assert AUTHORIZER_FACTORY_BASE_TYPE == "Authorizer"
