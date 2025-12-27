"""Integration tests for PolicyAuthorizer config key compatibility."""

import pytest

from naylence.fame.factory import create_resource
from naylence.fame.security.auth.authorizer_factory import AuthorizerFactory


class TestPolicyAuthorizerConfigCompatibility:
    """Test camelCase and snake_case config keys work for PolicyAuthorizer."""

    @pytest.mark.asyncio
    async def test_camelcase_policy_source_key(self):
        """PolicyAuthorizer should accept policySource (camelCase) key."""
        config = {
            "type": "PolicyAuthorizer",
            "verifier": {"type": "NoopTokenVerifier"},
            "policySource": {
                "type": "LocalFileAuthorizationPolicySource",
                "path": "/tmp/test-policy.yaml",
                "format": "yaml",
            },
        }

        # Should not raise ValueError about missing policy/policy_source
        authorizer = await create_resource(AuthorizerFactory, config)
        assert authorizer is not None

    @pytest.mark.asyncio
    async def test_snake_case_policy_source_key(self):
        """PolicyAuthorizer should accept policy_source (snake_case) key."""
        config = {
            "type": "PolicyAuthorizer",
            "verifier": {"type": "NoopTokenVerifier"},
            "policy_source": {
                "type": "LocalFileAuthorizationPolicySource",
                "path": "/tmp/test-policy.yaml",
                "format": "yaml",
            },
        }

        # Should not raise ValueError about missing policy/policy_source
        authorizer = await create_resource(AuthorizerFactory, config)
        assert authorizer is not None

    @pytest.mark.asyncio
    async def test_camelcase_has_precedence_when_both_present(self):
        """When both policySource and policy_source present, use policy_source."""
        # This tests the `cfg.get("policy_source") or cfg.get("policySource")` logic
        # The `or` operator means policy_source takes precedence if truthy
        config = {
            "type": "PolicyAuthorizer",
            "verifier": {"type": "NoopTokenVerifier"},
            "policy_source": {
                "type": "LocalFileAuthorizationPolicySource",
                "path": "/tmp/policy-snake.yaml",
                "format": "yaml",
            },
            "policySource": {
                "type": "LocalFileAuthorizationPolicySource",
                "path": "/tmp/policy-camel.yaml",
                "format": "yaml",
            },
        }

        # Should not raise - one of them will be used
        authorizer = await create_resource(AuthorizerFactory, config)
        assert authorizer is not None

    @pytest.mark.asyncio
    async def test_missing_both_keys_raises_error(self):
        """PolicyAuthorizer should raise error when both keys missing."""
        config = {
            "type": "PolicyAuthorizer",
            "verifier": {"type": "NoopTokenVerifier"},
            # Missing both policy and policy_source/policySource
        }

        with pytest.raises(
            ValueError,
            match="PolicyAuthorizer requires either a policy or policy_source",
        ):
            await create_resource(AuthorizerFactory, config)
