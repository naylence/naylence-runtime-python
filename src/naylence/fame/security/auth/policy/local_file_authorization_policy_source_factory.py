"""
Factory for creating LocalFileAuthorizationPolicySource instances.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import ConfigDict

from naylence.fame.security.auth.policy.authorization_policy_factory import (
    AuthorizationPolicyConfig,
)
from naylence.fame.security.auth.policy.authorization_policy_source import (
    AuthorizationPolicySource,
)
from naylence.fame.security.auth.policy.authorization_policy_source_factory import (
    AUTHORIZATION_POLICY_SOURCE_FACTORY_BASE_TYPE,
    AuthorizationPolicySourceConfig,
    AuthorizationPolicySourceFactory,
)


class LocalFileAuthorizationPolicySourceConfig(AuthorizationPolicySourceConfig):
    """Configuration for LocalFileAuthorizationPolicySource."""

    model_config = ConfigDict(extra="allow")

    type: str = "LocalFileAuthorizationPolicySource"

    # Path to the policy file (YAML or JSON)
    path: str

    # Format of the policy file (auto-detects from file extension if not specified)
    format: Literal["yaml", "json", "auto"] = "auto"

    # Configuration for the policy factory to use when parsing the loaded file.
    # Determines which AuthorizationPolicy implementation is created.
    #
    # If not specified, the policy definition from the file is used directly
    # as the factory configuration (must include a 'type' field).
    policy_factory: AuthorizationPolicyConfig | dict[str, Any] | None = None


def _normalize_config(
    config: LocalFileAuthorizationPolicySourceConfig | dict[str, Any] | None,
) -> dict[str, Any]:
    """Normalize and validate configuration."""
    if not config:
        raise ValueError(
            "LocalFileAuthorizationPolicySourceFactory requires a "
            "configuration with a path"
        )

    if isinstance(config, LocalFileAuthorizationPolicySourceConfig):
        candidate = config.model_dump()
    else:
        candidate = config

    path = candidate.get("path")
    if not isinstance(path, str) or not path.strip():
        raise ValueError(
            "LocalFileAuthorizationPolicySourceConfig requires a non-empty path"
        )

    fmt = candidate.get("format", "auto")
    if fmt not in ("yaml", "json", "auto"):
        raise ValueError(
            f'Invalid format "{fmt}". Must be "yaml", "json", or "auto"'
        )

    policy_factory = candidate.get("policy_factory") or candidate.get("policyFactory")

    return {
        "path": path.strip(),
        "format": fmt,
        "policy_factory": policy_factory,
    }


class LocalFileAuthorizationPolicySourceFactory(
    AuthorizationPolicySourceFactory[LocalFileAuthorizationPolicySourceConfig]
):
    """
    Factory for creating LocalFileAuthorizationPolicySource instances.
    """

    type: str = "LocalFileAuthorizationPolicySource"

    async def create(
        self,
        config: LocalFileAuthorizationPolicySourceConfig | dict[str, Any] | None = None,
        **factory_args: Any,
    ) -> AuthorizationPolicySource:
        """
        Creates a LocalFileAuthorizationPolicySource from the given configuration.

        Args:
            config: Configuration specifying the policy file path and options
            **factory_args: Additional factory arguments (unused)

        Returns:
            The created policy source
        """
        normalized = _normalize_config(config)

        from naylence.fame.security.auth.policy.local_file_authorization_policy_source import (
            LocalFileAuthorizationPolicySource,
            LocalFileAuthorizationPolicySourceOptions,
        )

        return LocalFileAuthorizationPolicySource(
            LocalFileAuthorizationPolicySourceOptions(
                path=normalized["path"],
                format=normalized["format"],
                policy_factory=normalized["policy_factory"],
            )
        )


# Factory metadata for registration
FACTORY_META = {
    "base": AUTHORIZATION_POLICY_SOURCE_FACTORY_BASE_TYPE,
    "key": "LocalFileAuthorizationPolicySource",
}
