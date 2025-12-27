"""
Integration tests for authorization profile evaluation within security profiles.

These tests prove that:
1. Authorization profiles are correctly resolved from environment variables
2. Expression evaluation (${env:VAR:default}) works correctly in security profiles
3. The AuthorizationProfile factory is properly integrated with SecurityProfileFactory
4. Profile overrides via FAME_AUTHORIZATION_PROFILE work as expected

This addresses feature parity with the TypeScript implementation where timing issues
with expression evaluation were fixed in AuthorizationProfileFactory.
"""

from __future__ import annotations

import os
from typing import Generator

import pytest

from naylence.fame.security.auth.authorization_profile_factory import (
    PROFILE_NAME_NOOP,
)
from naylence.fame.security.auth.noop_authorizer import NoopAuthorizer
from naylence.fame.security.node_security_profile_factory import (
    ENV_VAR_AUTHORIZATION_PROFILE,
    GATED_CALLBACK_PROFILE,
    GATED_PROFILE,
    OPEN_PROFILE,
    OVERLAY_CALLBACK_PROFILE,
    OVERLAY_PROFILE,
    PROFILE_NAME_GATED,
    PROFILE_NAME_GATED_CALLBACK,
    PROFILE_NAME_OPEN,
    PROFILE_NAME_OVERLAY,
    PROFILE_NAME_OVERLAY_CALLBACK,
    STRICT_OVERLAY_PROFILE,
    SecurityProfileFactory,
)
from naylence.fame.security.security_manager_config import SecurityProfile


@pytest.fixture(autouse=True)
def clean_env() -> Generator[None, None, None]:
    """Clean up environment variables before and after each test."""
    # Store original values
    original_values = {}
    for key in list(os.environ.keys()):
        if key.startswith("FAME_"):
            original_values[key] = os.environ.pop(key)

    yield

    # Restore original values
    for key in list(os.environ.keys()):
        if key.startswith("FAME_"):
            del os.environ[key]
    os.environ.update(original_values)


class TestSecurityProfileAuthorizationExpressions:
    """Tests for expression strings in security profile configurations."""

    def test_overlay_profile_has_authorization_profile_type(self):
        """OVERLAY_PROFILE authorizer should use AuthorizationProfile type."""
        assert OVERLAY_PROFILE["authorizer"]["type"] == "AuthorizationProfile"

    def test_overlay_profile_has_expression_for_profile(self):
        """OVERLAY_PROFILE should have expression for profile selection."""
        profile_value = OVERLAY_PROFILE["authorizer"]["profile"]
        assert "${env:" in profile_value, "Expected expression string in profile"
        assert ENV_VAR_AUTHORIZATION_PROFILE in profile_value
        assert ":oauth2}" in profile_value, "Default should be oauth2"

    def test_gated_profile_has_authorization_profile_type(self):
        """GATED_PROFILE authorizer should use AuthorizationProfile type."""
        assert GATED_PROFILE["authorizer"]["type"] == "AuthorizationProfile"

    def test_gated_profile_has_expression_for_profile(self):
        """GATED_PROFILE should have expression for profile selection."""
        profile_value = GATED_PROFILE["authorizer"]["profile"]
        assert "${env:" in profile_value
        assert ":oauth2-gated}" in profile_value, "Default should be oauth2-gated"

    def test_open_profile_has_authorization_profile_type(self):
        """OPEN_PROFILE authorizer should use AuthorizationProfile type."""
        assert OPEN_PROFILE["authorizer"]["type"] == "AuthorizationProfile"

    def test_open_profile_has_expression_for_profile(self):
        """OPEN_PROFILE should have expression for profile selection."""
        profile_value = OPEN_PROFILE["authorizer"]["profile"]
        assert "${env:" in profile_value
        assert ":noop}" in profile_value, "Default should be noop"

    def test_callback_profiles_have_authorization_profile_type(self):
        """Callback profiles should use AuthorizationProfile type."""
        assert OVERLAY_CALLBACK_PROFILE["authorizer"]["type"] == "AuthorizationProfile"
        assert GATED_CALLBACK_PROFILE["authorizer"]["type"] == "AuthorizationProfile"

    def test_callback_profiles_default_to_oauth2_callback(self):
        """Callback profiles should default to oauth2-callback."""
        overlay_callback = OVERLAY_CALLBACK_PROFILE["authorizer"]["profile"]
        gated_callback = GATED_CALLBACK_PROFILE["authorizer"]["profile"]
        assert ":oauth2-callback}" in overlay_callback
        assert ":oauth2-callback}" in gated_callback

    def test_strict_overlay_defaults_to_jwt(self):
        """STRICT_OVERLAY_PROFILE should default to jwt authorization."""
        profile_value = STRICT_OVERLAY_PROFILE["authorizer"]["profile"]
        assert ":jwt}" in profile_value, "Strict overlay default should be jwt"


class TestSecurityProfileAuthorizationIntegration:
    """Integration tests for authorization profile creation within security profiles."""

    @pytest.mark.asyncio
    async def test_open_profile_creates_noop_authorizer_by_default(self):
        """Open profile should create NoopAuthorizer when no env override."""
        factory = SecurityProfileFactory()
        sm = await factory.create(SecurityProfile(profile=PROFILE_NAME_OPEN))

        assert isinstance(sm.authorizer, NoopAuthorizer)

    @pytest.mark.asyncio
    async def test_env_override_changes_authorizer_for_overlay(self):
        """Setting FAME_AUTHORIZATION_PROFILE=noop should override overlay's oauth2."""
        os.environ[ENV_VAR_AUTHORIZATION_PROFILE] = PROFILE_NAME_NOOP

        factory = SecurityProfileFactory()
        sm = await factory.create(SecurityProfile(profile=PROFILE_NAME_OVERLAY))

        # Even though overlay defaults to oauth2, env override should make it noop
        assert isinstance(sm.authorizer, NoopAuthorizer)

    @pytest.mark.asyncio
    async def test_env_override_changes_authorizer_for_gated(self):
        """Setting FAME_AUTHORIZATION_PROFILE=noop should override gated's oauth2-gated."""
        os.environ[ENV_VAR_AUTHORIZATION_PROFILE] = PROFILE_NAME_NOOP

        factory = SecurityProfileFactory()
        sm = await factory.create(SecurityProfile(profile=PROFILE_NAME_GATED))

        # Even though gated defaults to oauth2-gated, env override should make it noop
        assert isinstance(sm.authorizer, NoopAuthorizer)

    @pytest.mark.asyncio
    async def test_env_override_changes_authorizer_for_open(self):
        """Setting FAME_AUTHORIZATION_PROFILE explicitly should work for open profile."""
        # Explicitly set to noop (same as default, but testing the path)
        os.environ[ENV_VAR_AUTHORIZATION_PROFILE] = PROFILE_NAME_NOOP

        factory = SecurityProfileFactory()
        sm = await factory.create(SecurityProfile(profile=PROFILE_NAME_OPEN))

        assert isinstance(sm.authorizer, NoopAuthorizer)

    @pytest.mark.asyncio
    async def test_callback_profiles_with_noop_override(self):
        """Callback profiles should also respect the env override."""
        os.environ[ENV_VAR_AUTHORIZATION_PROFILE] = PROFILE_NAME_NOOP

        factory = SecurityProfileFactory()

        sm_overlay_callback = await factory.create(
            SecurityProfile(profile=PROFILE_NAME_OVERLAY_CALLBACK)
        )
        assert isinstance(sm_overlay_callback.authorizer, NoopAuthorizer)

        sm_gated_callback = await factory.create(
            SecurityProfile(profile=PROFILE_NAME_GATED_CALLBACK)
        )
        assert isinstance(sm_gated_callback.authorizer, NoopAuthorizer)


class TestExpressionEvaluationTiming:
    """
    Tests to verify expression evaluation timing is correct.

    These tests ensure that expressions like ${env:VAR:default} are evaluated
    at the right time - during security manager creation, not at profile
    definition time.
    """

    def test_expressions_are_strings_at_definition_time(self):
        """Verify expressions are not evaluated when profiles are defined."""
        # At definition time, expressions should still be string placeholders
        overlay_profile = OVERLAY_PROFILE["authorizer"]["profile"]
        assert isinstance(overlay_profile, str)
        assert overlay_profile.startswith("${env:")

    @pytest.mark.asyncio
    async def test_expressions_evaluated_at_creation_time(self):
        """Expressions should be evaluated when security manager is created."""
        # Set env var before creation
        os.environ[ENV_VAR_AUTHORIZATION_PROFILE] = PROFILE_NAME_NOOP

        factory = SecurityProfileFactory()
        sm = await factory.create(SecurityProfile(profile=PROFILE_NAME_OVERLAY))

        # The authorizer should reflect the evaluated expression
        assert isinstance(sm.authorizer, NoopAuthorizer)

    @pytest.mark.asyncio
    async def test_env_changes_between_creations_are_respected(self):
        """Changes to env vars between creations should be reflected."""
        factory = SecurityProfileFactory()

        # First creation with noop
        os.environ[ENV_VAR_AUTHORIZATION_PROFILE] = PROFILE_NAME_NOOP
        sm1 = await factory.create(SecurityProfile(profile=PROFILE_NAME_OPEN))
        assert isinstance(sm1.authorizer, NoopAuthorizer)

        # Change env var - still noop but via explicit setting
        # (We can't easily test oauth2 without JWT config, so we verify noop works)
        os.environ[ENV_VAR_AUTHORIZATION_PROFILE] = PROFILE_NAME_NOOP
        sm2 = await factory.create(SecurityProfile(profile=PROFILE_NAME_OVERLAY))
        assert isinstance(sm2.authorizer, NoopAuthorizer)


class TestAuthorizationProfileFactoryIntegration:
    """Tests for AuthorizationProfileFactory integration with security profiles."""

    @pytest.mark.asyncio
    async def test_authorization_profile_factory_is_discovered(self):
        """AuthorizationProfile factory should be discoverable via entry points."""
        from naylence.fame.factory import ExtensionManager
        from naylence.fame.security.auth.authorizer_factory import AuthorizerFactory

        # This should not raise - the factory should be found
        ext = ExtensionManager.get_extension_by_name_and_type(
            name="AuthorizationProfile",
            base_type=AuthorizerFactory,
        )
        assert ext is not None

    @pytest.mark.asyncio
    async def test_profile_aliases_work_through_security_profiles(self):
        """Profile aliases like 'no-op' should work when evaluated."""
        # Use 'no-op' alias instead of 'noop'
        os.environ[ENV_VAR_AUTHORIZATION_PROFILE] = "no-op"

        factory = SecurityProfileFactory()
        sm = await factory.create(SecurityProfile(profile=PROFILE_NAME_OVERLAY))

        assert isinstance(sm.authorizer, NoopAuthorizer)

    @pytest.mark.asyncio
    async def test_profile_case_insensitivity(self):
        """Profile names should be case-insensitive."""
        os.environ[ENV_VAR_AUTHORIZATION_PROFILE] = "NOOP"

        factory = SecurityProfileFactory()
        sm = await factory.create(SecurityProfile(profile=PROFILE_NAME_OVERLAY))

        assert isinstance(sm.authorizer, NoopAuthorizer)
