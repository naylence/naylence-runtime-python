"""
Tests for BasicAuthorizationPolicyFactory.
"""

from __future__ import annotations

import pytest

from naylence.fame.security.auth.policy.authorization_policy import (
    AuthorizationPolicy,
)
from naylence.fame.security.auth.policy.basic_authorization_policy_factory import (
    FACTORY_META,
    BasicAuthorizationPolicyConfig,
    BasicAuthorizationPolicyFactory,
    _normalize_config,
)


class TestFactoryMeta:
    """Tests for FACTORY_META constant."""

    def test_has_correct_base(self):
        """Should have correct base type."""
        assert FACTORY_META["base"] == "AuthorizationPolicyFactory"

    def test_has_correct_key(self):
        """Should have correct key."""
        assert FACTORY_META["key"] == "BasicAuthorizationPolicy"


class TestBasicAuthorizationPolicyConfig:
    """Tests for BasicAuthorizationPolicyConfig."""

    def test_default_type_is_basic_authorization_policy(self):
        """Should have default type."""
        config = BasicAuthorizationPolicyConfig()
        assert config.type == "BasicAuthorizationPolicy"

    def test_policy_definition_defaults_to_none(self):
        """Should have policy_definition default to None."""
        config = BasicAuthorizationPolicyConfig()
        assert config.policy_definition is None

    def test_warn_on_unknown_fields_defaults_to_true(self):
        """Should have warn_on_unknown_fields default to True."""
        config = BasicAuthorizationPolicyConfig()
        assert config.warn_on_unknown_fields is True


class TestNormalizeConfig:
    """Tests for _normalize_config function."""

    def test_raises_when_config_is_none(self):
        """Should raise ValueError when config is None."""
        with pytest.raises(
            ValueError,
            match="BasicAuthorizationPolicyFactory requires a configuration",
        ):
            _normalize_config(None)

    def test_raises_when_policy_definition_missing(self):
        """Should raise ValueError when policyDefinition is missing."""
        with pytest.raises(ValueError, match="requires a policyDefinition object"):
            _normalize_config({})

    def test_raises_when_policy_definition_not_object(self):
        """Should raise ValueError when policyDefinition is not an object."""
        with pytest.raises(ValueError, match="requires a policyDefinition object"):
            _normalize_config({"policy_definition": "not-an-object"})

    def test_accepts_snake_case_policy_definition(self):
        """Should accept snake_case policy_definition."""
        result = _normalize_config({
            "policy_definition": {"version": "1.0", "rules": []},
        })
        assert result["policy_definition"]["version"] == "1.0"

    def test_accepts_camel_case_policy_definition(self):
        """Should accept camelCase policyDefinition."""
        result = _normalize_config({
            "policyDefinition": {"version": "1.0", "rules": []},
        })
        assert result["policy_definition"]["version"] == "1.0"

    def test_accepts_snake_case_warn_on_unknown_fields(self):
        """Should accept snake_case warn_on_unknown_fields."""
        result = _normalize_config({
            "policy_definition": {"version": "1.0", "rules": []},
            "warn_on_unknown_fields": False,
        })
        assert result["warn_on_unknown_fields"] is False

    def test_accepts_camel_case_warn_on_unknown_fields(self):
        """Should accept camelCase warnOnUnknownFields."""
        result = _normalize_config({
            "policyDefinition": {"version": "1.0", "rules": []},
            "warnOnUnknownFields": False,
        })
        assert result["warn_on_unknown_fields"] is False

    def test_defaults_warn_on_unknown_fields_to_true(self):
        """Should default warn_on_unknown_fields to True."""
        result = _normalize_config({
            "policy_definition": {"version": "1.0", "rules": []},
        })
        assert result["warn_on_unknown_fields"] is True

    def test_raises_when_warn_on_unknown_fields_not_boolean(self):
        """Should raise ValueError when warnOnUnknownFields is not boolean."""
        with pytest.raises(ValueError, match="must be a boolean"):
            _normalize_config({
                "policy_definition": {"version": "1.0", "rules": []},
                "warn_on_unknown_fields": "not-a-bool",
            })

    def test_handles_basic_authorization_policy_config_object(self):
        """Should handle BasicAuthorizationPolicyConfig object."""
        from naylence.fame.security.auth.policy.authorization_policy_definition import (
            AuthorizationPolicyDefinition,
        )

        policy_def = AuthorizationPolicyDefinition.from_dict({
            "version": "1.0",
            "rules": [],
        })
        config = BasicAuthorizationPolicyConfig(
            policy_definition=policy_def,
            warn_on_unknown_fields=False,
        )

        result = _normalize_config(config)
        assert result["warn_on_unknown_fields"] is False


class TestBasicAuthorizationPolicyFactory:
    """Tests for BasicAuthorizationPolicyFactory."""

    @pytest.fixture
    def factory(self):
        """Create a factory instance."""
        return BasicAuthorizationPolicyFactory()

    def test_factory_type_is_basic_authorization_policy(self, factory):
        """Should have type as BasicAuthorizationPolicy."""
        assert factory.type == "BasicAuthorizationPolicy"

    @pytest.mark.asyncio
    async def test_raises_when_config_is_none(self, factory):
        """Should raise ValueError when config is None."""
        with pytest.raises(
            ValueError,
            match="BasicAuthorizationPolicyFactory requires a configuration",
        ):
            await factory.create(None)

    @pytest.mark.asyncio
    async def test_raises_when_policy_definition_missing(self, factory):
        """Should raise ValueError when policyDefinition is missing."""
        with pytest.raises(ValueError, match="requires a policyDefinition object"):
            await factory.create({})

    @pytest.mark.asyncio
    async def test_creates_policy_with_valid_config(self, factory):
        """Should create policy with valid config."""
        config = {
            "type": "BasicAuthorizationPolicy",
            "policy_definition": {
                "version": "1.0",
                "default_effect": "deny",
                "rules": [
                    {
                        "id": "test-rule",
                        "effect": "allow",
                        "action": "Connect",
                    }
                ],
            },
        }

        policy = await factory.create(config)
        assert isinstance(policy, AuthorizationPolicy)

    @pytest.mark.asyncio
    async def test_creates_policy_with_camel_case_config(self, factory):
        """Should create policy with camelCase config."""
        config = {
            "type": "BasicAuthorizationPolicy",
            "policyDefinition": {
                "version": "1.0",
                "default_effect": "deny",
                "rules": [],
            },
            "warnOnUnknownFields": False,
        }

        policy = await factory.create(config)
        assert isinstance(policy, AuthorizationPolicy)

    @pytest.mark.asyncio
    async def test_creates_policy_with_basic_authorization_policy_config(self, factory):
        """Should create policy with BasicAuthorizationPolicyConfig object."""
        from naylence.fame.security.auth.policy.authorization_policy_definition import (
            AuthorizationPolicyDefinition,
        )

        policy_def = AuthorizationPolicyDefinition.from_dict({
            "version": "1.0",
            "rules": [],
        })

        config = BasicAuthorizationPolicyConfig(
            policy_definition=policy_def,
            warn_on_unknown_fields=True,
        )

        policy = await factory.create(config)
        assert isinstance(policy, AuthorizationPolicy)
