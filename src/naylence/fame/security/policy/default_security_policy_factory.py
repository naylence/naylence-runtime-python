"""
Factory for creating DefaultSecurityPolicy instances.
"""

from __future__ import annotations

from typing import Any, Optional

from pydantic import Field

from .security_policy import (
    EncryptionConfig,
    SecurityPolicy,
    SecurityPolicyConfig,
    SigningConfig,
)
from .security_policy_factory import SecurityPolicyFactory


class DefaultSecurityPolicyConfig(SecurityPolicyConfig):
    """Configuration for DefaultSecurityPolicy."""

    type: str = "DefaultSecurityPolicy"

    signing: Optional[SigningConfig] = Field(default=None)
    encryption: Optional[EncryptionConfig] = Field(default=None)


class DefaultSecurityPolicyFactory(SecurityPolicyFactory):
    """Factory for creating DefaultSecurityPolicy instances."""

    type: str = "DefaultSecurityPolicy"
    is_default: bool = True

    async def create(
        self,
        config: Optional[DefaultSecurityPolicyConfig | dict[str, Any]] = None,
        **kwargs: Any,
    ) -> SecurityPolicy:
        """Create a DefaultSecurityPolicy instance."""
        from .default_security_policy import DefaultSecurityPolicy

        if config is None:
            config = DefaultSecurityPolicyConfig()
        elif isinstance(config, dict):
            config = DefaultSecurityPolicyConfig(**config)

        encryption = config.encryption
        signing = config.signing

        # Allow runtime overrides from kwargs
        if "encryption" in kwargs:
            encryption = kwargs.pop("encryption")

        if "signing" in kwargs:
            signing = kwargs.pop("signing")

        return DefaultSecurityPolicy(encryption=encryption, signing=signing, **kwargs)
