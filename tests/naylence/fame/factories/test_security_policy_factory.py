"""Test SecurityPolicyFactory to ensure configs resolve to correct subtypes."""

import pytest

from naylence.fame.core import create_resource
from naylence.fame.security.policy.default_security_policy import DefaultSecurityPolicy
from naylence.fame.security.policy.default_security_policy_factory import DefaultSecurityPolicyConfig
from naylence.fame.security.policy.no_security_policy import NoSecurityPolicy
from naylence.fame.security.policy.no_security_policy_factory import NoSecurityPolicyConfig
from naylence.fame.security.policy.security_policy_factory import SecurityPolicyFactory


class TestSecurityPolicyFactory:
    """Test SecurityPolicyFactory and its implementations."""

    @pytest.mark.asyncio
    async def test_default_security_policy_factory(self):
        """Test DefaultSecurityPolicy factory creates correct instance."""
        config = DefaultSecurityPolicyConfig()
        policy = await create_resource(SecurityPolicyFactory, config)

        assert isinstance(policy, DefaultSecurityPolicy)
        assert policy.__class__.__name__ == "DefaultSecurityPolicy"

    @pytest.mark.asyncio
    async def test_no_security_policy_factory(self):
        """Test NoSecurityPolicy factory creates correct instance."""
        config = NoSecurityPolicyConfig()
        policy = await create_resource(SecurityPolicyFactory, config)

        assert isinstance(policy, NoSecurityPolicy)
        assert policy.__class__.__name__ == "NoSecurityPolicy"

    @pytest.mark.asyncio
    async def test_security_policy_factory_from_dict(self):
        """Test factory with dictionary configuration."""
        config = {"type": "DefaultSecurityPolicy"}
        policy = await create_resource(SecurityPolicyFactory, config)

        assert isinstance(policy, DefaultSecurityPolicy)

    @pytest.mark.asyncio
    async def test_security_policy_factory_invalid_type(self):
        """Test factory with invalid type raises error."""
        config = {"type": "InvalidSecurityPolicy"}

        with pytest.raises(Exception):
            await create_resource(SecurityPolicyFactory, config)
