"""
Factory for creating BasicAuthorizationPolicy instances.
"""

from __future__ import annotations

from typing import Any

from pydantic import ConfigDict

from naylence.fame.security.auth.policy.authorization_policy import (
    AuthorizationPolicy,
)
from naylence.fame.security.auth.policy.authorization_policy_definition import (
    AuthorizationPolicyDefinition,
)
from naylence.fame.security.auth.policy.authorization_policy_factory import (
    AUTHORIZATION_POLICY_FACTORY_BASE_TYPE,
    AuthorizationPolicyConfig,
    AuthorizationPolicyFactory,
)


class BasicAuthorizationPolicyConfig(AuthorizationPolicyConfig):
    """Configuration for creating a BasicAuthorizationPolicy via factory."""

    model_config = ConfigDict(extra="allow")

    type: str = "BasicAuthorizationPolicy"

    # The policy definition to evaluate - can be dict or Pydantic model
    policy_definition: AuthorizationPolicyDefinition | dict[str, Any] | None = None

    # Whether to log warnings for unknown fields (default: True)
    warn_on_unknown_fields: bool = True


def _normalize_config(
    config: BasicAuthorizationPolicyConfig | dict[str, Any] | None,
) -> dict[str, Any]:
    """Normalize configuration for BasicAuthorizationPolicy."""
    if config is None:
        raise ValueError(
            "BasicAuthorizationPolicyFactory requires a configuration "
            "with a policyDefinition"
        )

    if isinstance(config, BasicAuthorizationPolicyConfig):
        candidate = config.model_dump()
    else:
        candidate = config

    # Support both snake_case and camelCase for policy_definition
    policy_definition = candidate.get("policy_definition") or candidate.get(
        "policyDefinition"
    )

    if not policy_definition:
        raise ValueError(
            "BasicAuthorizationPolicyConfig requires a policyDefinition object"
        )

    # policy_definition can be a dict or already an AuthorizationPolicyDefinition
    if not isinstance(policy_definition, dict | AuthorizationPolicyDefinition):
        raise ValueError(
            "BasicAuthorizationPolicyConfig requires a policyDefinition object"
        )

    # Support both snake_case and camelCase for warn_on_unknown_fields
    warn_on_unknown_fields = candidate.get(
        "warn_on_unknown_fields", candidate.get("warnOnUnknownFields")
    )

    if warn_on_unknown_fields is not None and not isinstance(
        warn_on_unknown_fields, bool
    ):
        raise ValueError("warnOnUnknownFields must be a boolean")

    return {
        "policy_definition": policy_definition,
        "warn_on_unknown_fields": (
            warn_on_unknown_fields if warn_on_unknown_fields is not None else True
        ),
    }


class BasicAuthorizationPolicyFactory(
    AuthorizationPolicyFactory[BasicAuthorizationPolicyConfig]
):
    """Factory for creating BasicAuthorizationPolicy instances."""

    type: str = "BasicAuthorizationPolicy"

    async def create(
        self,
        config: BasicAuthorizationPolicyConfig | dict[str, Any] | None = None,
        **factory_args: Any,
    ) -> AuthorizationPolicy:
        """
        Create a BasicAuthorizationPolicy from the given configuration.

        Args:
            config: Configuration with policyDefinition
            **factory_args: Additional factory arguments (unused)

        Returns:
            The created authorization policy

        Raises:
            ValueError: If configuration is invalid
        """
        normalized = _normalize_config(config)

        # Lazy import to avoid circular dependencies
        from naylence.fame.security.auth.policy.basic_authorization_policy import (
            BasicAuthorizationPolicy,
            BasicAuthorizationPolicyOptions,
        )

        policy_def_raw = normalized["policy_definition"]

        # Convert to AuthorizationPolicyDefinition if needed
        if isinstance(policy_def_raw, dict):
            policy_def = AuthorizationPolicyDefinition.from_dict(policy_def_raw)
        else:
            policy_def = policy_def_raw

        return BasicAuthorizationPolicy(
            BasicAuthorizationPolicyOptions(
                policy_definition=policy_def,
                warn_on_unknown_fields=normalized["warn_on_unknown_fields"],
            )
        )


# Factory metadata for registration
FACTORY_META = {
    "base": AUTHORIZATION_POLICY_FACTORY_BASE_TYPE,
    "key": "BasicAuthorizationPolicy",
}
