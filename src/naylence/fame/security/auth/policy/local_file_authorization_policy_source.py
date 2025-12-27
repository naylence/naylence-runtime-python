"""
Authorization policy source that loads policy definitions from a local file.

Supports YAML and JSON formats. The file must contain a valid policy
configuration object that can be used to create an AuthorizationPolicy
via the factory system.

This is a server-side only implementation that uses the filesystem.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any, Literal, Optional

import yaml

from naylence.fame.security.auth.policy.authorization_policy import (
    AuthorizationPolicy,
)
from naylence.fame.security.auth.policy.authorization_policy_factory import (
    AuthorizationPolicyConfig,
    AuthorizationPolicyFactory,
)
from naylence.fame.security.auth.policy.authorization_policy_source import (
    AuthorizationPolicySource,
)

logger = logging.getLogger(
    "naylence.fame.security.auth.policy.local_file_authorization_policy_source"
)

# Format of the policy file
PolicyFileFormat = Literal["yaml", "json", "auto"]


def _is_plain_object(value: Any) -> bool:
    """Check if value is a plain dict-like object."""
    return bool(value) and isinstance(value, dict)


def _parse_json(content: str) -> dict[str, Any]:
    """Parse JSON content as a policy object."""
    parsed = json.loads(content)
    if not _is_plain_object(parsed):
        raise ValueError("Parsed JSON policy must be an object")
    return parsed


def _parse_yaml(content: str) -> dict[str, Any]:
    """Parse YAML content as a policy object."""
    parsed = yaml.safe_load(content or "")
    if parsed is None:
        return {}
    if not _is_plain_object(parsed):
        raise ValueError("Parsed YAML policy must be an object")
    return parsed


def _detect_format(file_path: str) -> Literal["yaml", "json"]:
    """Detect file format from extension."""
    lower = file_path.lower()
    if lower.endswith(".yaml") or lower.endswith(".yml"):
        return "yaml"
    if lower.endswith(".json"):
        return "json"
    # Default to YAML for unknown extensions
    return "yaml"


@dataclass
class LocalFileAuthorizationPolicySourceOptions:
    """Configuration options for LocalFileAuthorizationPolicySource."""

    # Path to the policy file
    path: str

    # Format of the policy file (yaml, json, or auto-detect)
    format: PolicyFileFormat = "auto"

    # Configuration for the policy factory to use when parsing the loaded file.
    # Determines which AuthorizationPolicy implementation is created from the
    # loaded policy definition.
    #
    # If not specified, the policy definition from the file is used directly
    # as the factory configuration (must include a 'type' field).
    policy_factory: Optional[AuthorizationPolicyConfig | dict[str, Any]] = None


class LocalFileAuthorizationPolicySource(AuthorizationPolicySource):
    """
    An authorization policy source that loads policy definitions from a local file.

    Supports YAML and JSON formats. The file must contain a valid policy
    configuration object that can be used to create an AuthorizationPolicy
    via the factory system.
    """

    def __init__(self, options: LocalFileAuthorizationPolicySourceOptions):
        self._path = options.path
        self._format = options.format
        self._policy_factory_config = options.policy_factory
        self._cached_policy: Optional[AuthorizationPolicy] = None

    async def load_policy(self) -> AuthorizationPolicy:
        """
        Loads the authorization policy from the configured file.

        The file is read and parsed according to the configured format.
        The parsed content is then used to create an AuthorizationPolicy
        via the factory system.

        Returns:
            The loaded authorization policy
        """
        # Return cached policy if available
        if self._cached_policy is not None:
            return self._cached_policy

        logger.debug("loading_policy_from_file", extra={"path": self._path})

        # Read the file synchronously (file I/O is typically fast for config files)
        # This matches TypeScript's fs.promises.readFile behavior
        with open(self._path, encoding="utf-8") as f:
            content = f.read()

        # Determine format
        effective_format = (
            _detect_format(self._path)
            if self._format == "auto"
            else self._format
        )

        # Parse the content
        if effective_format == "json":
            policy_definition = _parse_json(content)
        else:
            policy_definition = _parse_yaml(content)

        logger.debug(
            "parsed_policy_definition",
            extra={
                "path": self._path,
                "format": effective_format,
                "has_type": "type" in policy_definition,
            },
        )

        # Determine the factory configuration to use
        factory_config: dict[str, Any] = (
            dict(self._policy_factory_config)
            if isinstance(self._policy_factory_config, dict)
            else (
                self._policy_factory_config.model_dump()
                if self._policy_factory_config is not None
                else dict(policy_definition)
            )
        )

        # Ensure we have a type field for the factory
        if "type" not in factory_config or not isinstance(
            factory_config["type"], str
        ):
            logger.warning(
                "policy_type_missing_defaulting_to_basic",
                extra={"path": self._path},
            )
            factory_config["type"] = "BasicAuthorizationPolicy"

        # Build the factory config with the policy definition
        # The file content IS the policy definition, so we extract the type
        # and wrap the remaining content as the policyDefinition
        file_type = policy_definition.get("type")
        rest_of_file = {k: v for k, v in policy_definition.items() if k != "type"}

        resolved_type = (
            file_type
            if isinstance(file_type, str) and file_type.strip()
            else factory_config.get("type")
        )

        if self._policy_factory_config is not None:
            merged_config = {
                **factory_config,
                "policyDefinition": policy_definition,
            }
        else:
            merged_config = {
                "type": resolved_type,
                "policyDefinition": rest_of_file,
            }

        # Create the policy using the factory system
        policy = await AuthorizationPolicyFactory.create_authorization_policy(
            merged_config
        )

        if not policy:
            raise ValueError(f"Failed to create authorization policy from {self._path}")

        self._cached_policy = policy
        logger.info(
            "loaded_policy_from_file",
            extra={
                "path": self._path,
                "policy_type": factory_config.get("type"),
            },
        )

        return policy

    def clear_cache(self) -> None:
        """Clears the cached policy, forcing a reload on the next load_policy() call."""
        self._cached_policy = None

    @property
    def path(self) -> str:
        """Returns the path to the policy file."""
        return self._path
