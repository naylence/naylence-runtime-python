"""
Token subject node identity policy implementation.

This module provides the TokenSubjectNodeIdentityPolicy that derives node IDs
from the subject claim of authentication tokens, prefixing the current node ID
with a hashed version of the subject.
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


class TokenSubjectNodeIdentityPolicy:
    """
    Node identity policy that derives IDs from token subjects.

    This policy creates node IDs by hashing the subject from an authentication
    token and prefixing it to the current node ID, creating a stable identity
    tied to the authenticated user/service.

    Initial ID resolution priority:
    1. Configured ID
    2. Persisted ID
    3. Generated random ID

    Admission ID resolution:
    - Attempts to extract identity from token providers in grants
    - If subject found: returns "{hashed_subject}-{current_node_id}"
    - Otherwise: returns current node ID unchanged
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
            return context.configured_id

        if context.persisted_id:
            return context.persisted_id

        return generate_id()

    async def resolve_admission_node_id(self, context: NodeIdentityPolicyContext) -> str:
        """
        Resolve admission node ID, prefixing with hashed subject if available.

        Args:
            context: The admission context with grants

        Returns:
            A prefixed node ID if subject found, otherwise current node ID
        """
        logger.debug(
            "resolve_admission_node_id_start",
            grants_count=len(context.grants) if context.grants else 0,
            current_node_id=context.current_node_id,
        )

        if context.grants:
            for grant in context.grants:
                try:
                    identity = await self._extract_identity_from_grant(grant)
                    if identity and identity.subject:
                        # Hash the subject for privacy and create prefixed ID
                        hashed_subject = generate_id(
                            mode="fingerprint",
                            material=identity.subject,
                            length=8,
                        )

                        new_node_id = f"{hashed_subject}-{context.current_node_id}"

                        logger.info(
                            "resolved_identity_from_token",
                            subject=identity.subject,
                            hashed_subject=hashed_subject,
                            new_node_id=new_node_id,
                        )
                        return new_node_id
                    else:
                        logger.debug("identity_missing_subject", identity=identity)
                except Exception as error:
                    logger.warning(
                        "failed_to_extract_identity_from_grant",
                        error=str(error),
                    )
        else:
            logger.debug("no_grants_available")

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
            logger.debug("skipping_grant_no_auth", grant_type=grant.get("type"))
            return None

        token_provider_config = auth.get("tokenProvider") or auth.get("token_provider")
        if not token_provider_config or not isinstance(token_provider_config, dict):
            logger.debug(
                "skipping_grant_invalid_token_provider_config",
                grant_type=grant.get("type"),
                config=token_provider_config,
            )
            return None

        if not token_provider_config.get("type"):
            logger.debug(
                "skipping_grant_invalid_token_provider_config",
                grant_type=grant.get("type"),
                config=token_provider_config,
            )
            return None

        logger.debug(
            "creating_token_provider",
            type=token_provider_config.get("type"),
        )

        provider = await TokenProviderFactory.create_token_provider(token_provider_config)

        is_exposing = is_identity_exposing_token_provider(provider)
        logger.debug(
            "token_provider_created",
            type=token_provider_config.get("type"),
            is_identity_exposing=is_exposing,
        )

        if provider and is_exposing:
            identity = await provider.get_identity()
            logger.debug("retrieved_identity", identity=identity)
            return identity

        return None


# Type assertion for protocol compliance
_: NodeIdentityPolicy = TokenSubjectNodeIdentityPolicy()
