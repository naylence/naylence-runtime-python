"""
Tests for AuthorizationPolicyFactory base class.
"""

from __future__ import annotations

from typing import Any, Optional
from unittest.mock import patch

import pytest

from naylence.fame.security.auth.policy.authorization_policy import (
    AuthorizationDecision,
    AuthorizationPolicy,
)
from naylence.fame.security.auth.policy.authorization_policy_factory import (
    AUTHORIZATION_POLICY_FACTORY_BASE_TYPE,
    AuthorizationPolicyConfig,
    AuthorizationPolicyFactory,
)


class MockAuthorizationPolicy(AuthorizationPolicy):
    """Mock implementation for testing."""

    async def evaluate_request(
        self, node: Any, envelope: Any, context: Any, action: str = "*"
    ) -> AuthorizationDecision:
        """Mock implementation."""
        return AuthorizationDecision(
            effect="allow",
            matched_rule=None,
            reason="mock decision",
            evaluation_steps=[],
        )


class MockPolicyFactory(AuthorizationPolicyFactory):
    """Mock factory for testing."""

    type: str = "MockPolicy"

    async def create(
        self,
        config: Optional[AuthorizationPolicyConfig | dict[str, Any]] = None,
        **factory_args: Any,
    ) -> AuthorizationPolicy:
        """Mock create method."""
        return MockAuthorizationPolicy()


class TestAuthorizationPolicyFactoryBaseType:
    """Tests for AUTHORIZATION_POLICY_FACTORY_BASE_TYPE constant."""

    def test_base_type_is_authorization_policy_factory(self):
        """Should have base type as AuthorizationPolicyFactory."""
        assert AUTHORIZATION_POLICY_FACTORY_BASE_TYPE == "AuthorizationPolicyFactory"


class TestAuthorizationPolicyConfig:
    """Tests for AuthorizationPolicyConfig."""

    def test_has_type_field(self):
        """Should have type field."""
        config = AuthorizationPolicyConfig(type="SomePolicy")
        assert config.type == "SomePolicy"


class TestAuthorizationPolicyFactory:
    """Tests for AuthorizationPolicyFactory base class."""

    def test_can_instantiate_concrete_implementation(self):
        """Should be able to instantiate concrete implementation."""
        factory = MockPolicyFactory()
        assert factory.type == "MockPolicy"

    @pytest.mark.asyncio
    async def test_concrete_implementation_can_create_policy(self):
        """Should be able to create policy through concrete implementation."""
        factory = MockPolicyFactory()
        policy = await factory.create()
        assert isinstance(policy, AuthorizationPolicy)

    @pytest.mark.asyncio
    async def test_create_authorization_policy_with_config(self):
        """Should create policy from config using static method."""
        config = {"type": "MockPolicy"}

        mock_policy = MockAuthorizationPolicy()
        with patch(
            "naylence.fame.security.auth.policy.authorization_policy_factory.create_resource"
        ) as mock_create:
            mock_create.return_value = mock_policy

            result = await AuthorizationPolicyFactory.create_authorization_policy(config)

            assert result == mock_policy
            mock_create.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_authorization_policy_without_config(self):
        """Should use default resource when config is None."""
        mock_policy = MockAuthorizationPolicy()
        with patch(
            "naylence.fame.security.auth.policy.authorization_policy_factory.create_default_resource"
        ) as mock_create:
            mock_create.return_value = mock_policy

            result = await AuthorizationPolicyFactory.create_authorization_policy(None)

            assert result == mock_policy
            mock_create.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_authorization_policy_raises_when_creation_fails(self):
        """Should raise ValueError when policy creation fails with config."""
        config = {"type": "UnknownPolicy"}

        with patch(
            "naylence.fame.security.auth.policy.authorization_policy_factory.create_resource"
        ) as mock_create:
            mock_create.return_value = None

            with pytest.raises(
                ValueError,
                match="Failed to create authorization policy from configuration",
            ):
                await AuthorizationPolicyFactory.create_authorization_policy(config)

    @pytest.mark.asyncio
    async def test_create_authorization_policy_returns_none_when_no_default(self):
        """Should return None when no default resource available."""
        with patch(
            "naylence.fame.security.auth.policy.authorization_policy_factory.create_default_resource"
        ) as mock_create:
            mock_create.return_value = None

            result = await AuthorizationPolicyFactory.create_authorization_policy(None)

            assert result is None
