"""
Default node identity policy implementation.

This module provides the default implementation of NodeIdentityPolicy
that uses a priority-based approach for initial ID resolution and
attempts to extract identity from token providers during admission.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from naylence.fame.core import generate_id
from naylence.fame.node.node_identity_policy import (
    InitialIdentityContext,
    NodeIdentityPolicy,
    NodeIdentityPolicyContext,
)
from naylence.fame.security.auth.token_provider import is_identity_exposing_token_provider
from naylence.fame.security.auth.token_provider_factory import TokenProviderFactory
from naylence.fame.util.logging import getLogger

logger = getLogger(__name__)


class DefaultNodeIdentityPolicy(NodeIdentityPolicy):
    """
    Default implementation of NodeIdentityPolicy.

    Initial ID resolution priority:
    1. Configured ID (explicitly set by user)
    2. Persisted ID (from previous session)
    3. Generated fingerprint-based ID

    Admission ID resolution:
    - Attempts to extract identity from token providers in grants
    - Returns the subject if found, otherwise returns current node ID
    """

    async def resolve_initial_node_id(self, context: InitialIdentityContext) -> str:
        """
        Resolve initial node ID with priority: configured > persisted > generated.

        Args:
            context: The initial identity context

        Returns:
            The resolved node ID
        """
        if context.configured_id:
            logger.debug(
                "using_configured_node_id",
                node_id=context.configured_id,
            )
            return context.configured_id

        if context.persisted_id:
            logger.debug(
                "using_persisted_node_id",
                node_id=context.persisted_id,
            )
            return context.persisted_id

        generated_id = generate_id(mode="fingerprint")
        logger.debug(
            "generated_fingerprint_node_id",
            node_id=generated_id,
        )
        return generated_id

    async def resolve_admission_node_id(self, context: NodeIdentityPolicyContext) -> str:
        """
        Resolve admission node ID, attempting to extract identity from grants.

        Args:
            context: The admission context with grants

        Returns:
            The subject from token provider if found, otherwise current node ID
        """
        if context.grants:
            for grant in context.grants:
                try:
                    identity = await self._extract_identity_from_grant(grant)
                    if identity and identity.subject:
                        logger.debug(
                            "identity_extracted_from_grant",
                            identity_id=identity.subject,
                            grant_type=grant.get("type"),
                        )
                        return identity.subject
                except Exception as error:
                    logger.warning(
                        "identity_extraction_failed",
                        error=str(error),
                        grant_type=grant.get("type"),
                    )

        if not context.current_node_id:
            return generate_id(mode="fingerprint")

        return context.current_node_id

    async def _extract_identity_from_grant(
        self,
        grant: Dict[str, Any],
    ) -> Optional[Any]:
        """
        Extract identity from a grant's token provider configuration.

        Args:
            grant: The grant dictionary that may contain auth configuration

        Returns:
            AuthIdentity if extraction successful, None otherwise
        """
        auth = grant.get("auth")
        if not auth or not isinstance(auth, dict):
            return None

        token_provider_config = auth.get("tokenProvider") or auth.get("token_provider")
        if not token_provider_config or not isinstance(token_provider_config, dict):
            return None

        if not token_provider_config.get("type"):
            return None

        provider = await TokenProviderFactory.create_token_provider(token_provider_config)
        if provider and is_identity_exposing_token_provider(provider):
            return await provider.get_identity()

        return None


# Type assertion for protocol compliance
_: NodeIdentityPolicy = DefaultNodeIdentityPolicy()
