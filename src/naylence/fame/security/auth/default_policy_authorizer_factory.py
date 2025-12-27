"""
Factory for creating DefaultPolicyAuthorizer instances.

This factory uses lazy loading patterns and supports configuration
of token verifiers, policies, and policy sources.
"""

from __future__ import annotations

from typing import Any, Optional, Union

from pydantic import ConfigDict

from naylence.fame.security.auth.authorizer import Authorizer
from naylence.fame.security.auth.authorizer_factory import (
    AUTHORIZER_FACTORY_BASE_TYPE,
    AuthorizerConfig,
    AuthorizerFactory,
)
from naylence.fame.security.auth.policy.authorization_policy import AuthorizationPolicy
from naylence.fame.security.auth.policy.authorization_policy_factory import (
    AuthorizationPolicyConfig,
    AuthorizationPolicyFactory,
)
from naylence.fame.security.auth.policy.authorization_policy_source import (
    AuthorizationPolicySource,
)
from naylence.fame.security.auth.policy.authorization_policy_source_factory import (
    AuthorizationPolicySourceConfig,
    AuthorizationPolicySourceFactory,
)
from naylence.fame.security.auth.token_verifier import TokenVerifier
from naylence.fame.security.auth.token_verifier_factory import (
    TokenVerifierConfig,
    TokenVerifierFactory,
)


class DefaultPolicyAuthorizerConfig(AuthorizerConfig):
    """Configuration for DefaultPolicyAuthorizer."""

    model_config = ConfigDict(extra="allow")

    type: str = "PolicyAuthorizer"

    verifier: Optional[Union[TokenVerifierConfig, dict[str, Any]]] = None
    """Token verifier configuration."""

    policy: Optional[Union[AuthorizationPolicyConfig, dict[str, Any]]] = None
    """Authorization policy configuration.
    Either policy or policy_source must be provided."""

    policy_source: Optional[
        Union[AuthorizationPolicySourceConfig, dict[str, Any]]
    ] = None
    """Authorization policy source configuration.
    Either policy or policy_source must be provided."""


def _is_token_verifier(candidate: Any) -> bool:
    """Check if candidate is a TokenVerifier instance."""
    return (
        candidate is not None
        and callable(getattr(candidate, "verify", None))
    )


def _is_authorization_policy(candidate: Any) -> bool:
    """Check if candidate is an AuthorizationPolicy instance."""
    return (
        candidate is not None
        and callable(getattr(candidate, "evaluate_request", None))
    )


def _is_authorization_policy_source(candidate: Any) -> bool:
    """Check if candidate is an AuthorizationPolicySource instance."""
    return (
        candidate is not None
        and callable(getattr(candidate, "load_policy", None))
    )


# Factory metadata for registration
FACTORY_META = {
    "base": AUTHORIZER_FACTORY_BASE_TYPE,
    "key": "PolicyAuthorizer",
}


class DefaultPolicyAuthorizerFactory(AuthorizerFactory[DefaultPolicyAuthorizerConfig]):
    """
    Factory for creating DefaultPolicyAuthorizer instances.

    This factory uses configuration to create authorizers with token
    verifiers and authorization policies/sources.
    """

    type: str = "PolicyAuthorizer"
    is_default: bool = True

    async def create(
        self,
        config: Optional[Union[DefaultPolicyAuthorizerConfig, dict[str, Any]]] = None,
        **factory_args: Any,
    ) -> Authorizer:
        """
        Creates a DefaultPolicyAuthorizer from the given configuration.

        Args:
            config: Configuration for the authorizer
            **factory_args: Additional factory arguments:
                - token_verifier: TokenVerifier instance
                - policy: AuthorizationPolicy instance
                - policy_source: AuthorizationPolicySource instance

        Returns:
            The created authorizer
        """
        from naylence.fame.security.auth.default_policy_authorizer import (
            DefaultPolicyAuthorizer,
            DefaultPolicyAuthorizerOptions,
        )

        # Normalize config
        if config is None:
            cfg: dict[str, Any] = {}
        elif isinstance(config, DefaultPolicyAuthorizerConfig):
            cfg = config.model_dump()
        else:
            cfg = config

        verifier_config = cfg.get("verifier")
        policy_config = cfg.get("policy")
        policy_source_config = cfg.get("policy_source")

        # Resolve token verifier from args or config
        token_verifier: Optional[TokenVerifier] = None
        for arg in factory_args.values():
            if _is_token_verifier(arg):
                token_verifier = arg
                break

        if factory_args.get("token_verifier"):
            token_verifier = factory_args["token_verifier"]

        if not token_verifier and verifier_config:
            if isinstance(verifier_config, dict) and verifier_config:
                token_verifier = await TokenVerifierFactory.create_token_verifier(
                    verifier_config
                )
            elif verifier_config:
                token_verifier = await TokenVerifierFactory.create_token_verifier(
                    verifier_config
                )

        if not token_verifier:
            raise ValueError(
                "PolicyAuthorizer requires a verifier configuration or instance"
            )

        # Resolve policy from args or config
        policy: Optional[AuthorizationPolicy] = None
        for arg in factory_args.values():
            if _is_authorization_policy(arg):
                policy = arg
                break

        if factory_args.get("policy"):
            policy = factory_args["policy"]

        if not policy and policy_config:
            if isinstance(policy_config, dict) and policy_config:
                policy = await AuthorizationPolicyFactory.create_authorization_policy(
                    policy_config
                )
            elif policy_config:
                policy = await AuthorizationPolicyFactory.create_authorization_policy(
                    policy_config
                )

        # Resolve policy source from args or config
        policy_source: Optional[AuthorizationPolicySource] = None
        for arg in factory_args.values():
            if _is_authorization_policy_source(arg):
                policy_source = arg
                break

        if factory_args.get("policy_source"):
            policy_source = factory_args["policy_source"]

        if not policy_source and policy_source_config:
            if isinstance(policy_source_config, dict) and policy_source_config:
                policy_source = (
                    await AuthorizationPolicySourceFactory.create_authorization_policy_source(
                        policy_source_config
                    )
                )
            elif policy_source_config:
                policy_source = (
                    await AuthorizationPolicySourceFactory.create_authorization_policy_source(
                        policy_source_config
                    )
                )

        # Validate that we have either policy or policy source
        if not policy and not policy_source:
            raise ValueError(
                "PolicyAuthorizer requires either a policy or policy_source configuration"
            )

        return DefaultPolicyAuthorizer(
            DefaultPolicyAuthorizerOptions(
                token_verifier=token_verifier,
                policy=policy,
                policy_source=policy_source,
            )
        )
