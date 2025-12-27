"""
Default policy authorizer implementation.

An authorizer that combines token-based authentication with policy-based
authorization. The token verifier handles authentication (validating
credentials), while the authorization policy handles authorization
decisions (allow/deny based on the request context).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional, Union

from naylence.fame.core import (
    AuthorizationContext,
    FameDeliveryContext,
    FameEnvelope,
)
from naylence.fame.node.node_like import NodeLike
from naylence.fame.security.auth.authorizer import RouteAuthorizationResult
from naylence.fame.security.auth.policy.authorization_policy import (
    AuthorizationDecision,
    AuthorizationPolicy,
)
from naylence.fame.security.auth.policy.authorization_policy_definition import RuleAction
from naylence.fame.security.auth.policy.authorization_policy_source import (
    AuthorizationPolicySource,
)
from naylence.fame.security.auth.policy_authorizer import PolicyAuthorizer
from naylence.fame.security.auth.token_verifier import TokenVerifier
from naylence.fame.security.auth.token_verifier_provider import TokenVerifierProvider
from naylence.fame.util.logging import getLogger

logger = getLogger(__name__)


def _create_auth_context(**kwargs: Any) -> AuthorizationContext:
    """Create an AuthorizationContext from keyword arguments."""
    return AuthorizationContext(**kwargs)


def _extract_scopes_from_claims(claims: dict[str, Any]) -> list[str]:
    """
    Extract scopes from JWT claims and return as a list.

    Handles multiple scope claim formats:
    - 'scope': space-separated string (OAuth2 standard)
    - 'scopes': array of strings
    - 'scp': Azure AD style
    """
    scopes: list[str] = []

    # Handle 'scope' field (space-separated string - OAuth2 standard)
    scope_claim = claims.get("scope")
    if isinstance(scope_claim, str):
        scopes.extend(scope_claim.split())
    elif isinstance(scope_claim, list):
        scopes.extend(s for s in scope_claim if isinstance(s, str))

    # Handle 'scopes' field (array - some providers use this)
    scopes_claim = claims.get("scopes")
    if isinstance(scopes_claim, list):
        scopes.extend(s for s in scopes_claim if isinstance(s, str) and s not in scopes)

    # Handle 'scp' field (Azure AD style)
    scp_claim = claims.get("scp")
    if isinstance(scp_claim, list):
        scopes.extend(s for s in scp_claim if isinstance(s, str) and s not in scopes)
    elif isinstance(scp_claim, str):
        scopes.extend(s for s in scp_claim.split() if s not in scopes)

    return scopes


def _decode_credentials(credentials: bytes) -> str:
    """Decode credential bytes to string."""
    return credentials.decode("utf-8")


def _normalize_token(credentials: Union[str, bytes]) -> Optional[str]:
    """Normalize token from credentials string or bytes."""
    if isinstance(credentials, bytes):
        raw = _decode_credentials(credentials)
    else:
        raw = credentials

    trimmed = raw.strip()
    if len(trimmed) == 0:
        return None

    if trimmed.lower().startswith("bearer "):
        candidate = trimmed[7:].strip()
        return candidate if len(candidate) > 0 else None

    return trimmed


@dataclass
class DefaultPolicyAuthorizerOptions:
    """
    Options for creating a DefaultPolicyAuthorizer.

    Attributes:
        token_verifier: Token verifier for authenticating credentials.
        policy: The authorization policy to use for authorization decisions.
            Either policy or policy_source must be provided.
        policy_source: A source to load the authorization policy from.
            Either policy or policy_source must be provided.
    """

    token_verifier: Optional[TokenVerifier] = field(default=None)
    policy: Optional[AuthorizationPolicy] = field(default=None)
    policy_source: Optional[AuthorizationPolicySource] = field(default=None)


class DefaultPolicyAuthorizer(PolicyAuthorizer, TokenVerifierProvider):
    """
    An authorizer that delegates authorization decisions to a pluggable policy.

    This authorizer combines token-based authentication with policy-based
    authorization. The token verifier handles authentication (validating
    credentials), while the authorization policy handles authorization
    decisions (allow/deny based on the request context).
    """

    def __init__(
        self,
        options: Optional[DefaultPolicyAuthorizerOptions] = None,
        *,
        token_verifier: Optional[TokenVerifier] = None,
        policy: Optional[AuthorizationPolicy] = None,
        policy_source: Optional[AuthorizationPolicySource] = None,
    ):
        """
        Initialize DefaultPolicyAuthorizer.

        Args:
            options: Options object (alternative to keyword args)
            token_verifier: Token verifier for authenticating credentials
            policy: The authorization policy (either policy or policy_source required)
            policy_source: A source to load the authorization policy from
        """
        # Handle both options object and keyword arguments
        if options is not None:
            self._token_verifier_impl = options.token_verifier
            self._policy_impl = options.policy
            self._policy_source = options.policy_source
        else:
            self._token_verifier_impl = token_verifier
            self._policy_impl = policy
            self._policy_source = policy_source

        self._policy_loaded = self._policy_impl is not None

        # Validate that we have either a policy or a policy source
        if not self._policy_impl and not self._policy_source:
            raise ValueError(
                "DefaultPolicyAuthorizer requires either a policy or a policy_source"
            )

    @property
    def policy(self) -> AuthorizationPolicy:
        """The currently active authorization policy."""
        if not self._policy_impl:
            raise RuntimeError(
                "Authorization policy not loaded. Call ensure_policy_loaded() first."
            )
        return self._policy_impl

    @property
    def token_verifier(self) -> TokenVerifier:
        """The token verifier used for authentication."""
        if not self._token_verifier_impl:
            raise RuntimeError(
                "DefaultPolicyAuthorizer is not initialized properly, missing token_verifier"
            )
        return self._token_verifier_impl

    @token_verifier.setter
    def token_verifier(self, verifier: TokenVerifier) -> None:
        """Set the token verifier."""
        self._token_verifier_impl = verifier

    async def ensure_policy_loaded(self) -> None:
        """
        Ensures the authorization policy is loaded.
        If using a policy source, loads the policy from it.
        """
        if self._policy_loaded and self._policy_impl:
            return

        if not self._policy_source:
            raise RuntimeError("No policy source configured and no policy provided")

        logger.debug("loading_policy_from_source")
        self._policy_impl = await self._policy_source.load_policy()
        self._policy_loaded = True
        logger.info("policy_loaded_from_source")

    async def reload_policy(self) -> None:
        """
        Reloads the authorization policy from the policy source.
        Only works if a policy source was configured.
        """
        if not self._policy_source:
            raise RuntimeError("Cannot reload policy: no policy source configured")

        logger.debug("reloading_policy_from_source")
        self._policy_impl = await self._policy_source.load_policy()
        self._policy_loaded = True
        logger.info("policy_reloaded_from_source")

    async def authenticate(
        self, credentials: Union[str, bytes]
    ) -> Optional[AuthorizationContext]:
        """
        Authenticates credentials and returns an authorization context.

        Args:
            credentials: The credentials to authenticate (token string or bytes)

        Returns:
            The authorization context if authentication succeeds, None otherwise
        """
        token = _normalize_token(credentials)
        if not token:
            return None

        try:
            verifier = self.token_verifier
            context = await verifier.verify(token)

            # Extract scopes from JWT claims and set as granted_scopes
            granted_scopes = _extract_scopes_from_claims(context)

            return _create_auth_context(
                **{
                    **context,
                    "authenticated": True,
                    "authorized": False,  # Authorization happens in authorize()
                    "auth_method": context.get("auth_method", "jwt"),
                    "granted_scopes": granted_scopes,
                }
            )
        except Exception as error:
            logger.warning(
                "token_verification_failed",
                error=str(error),
            )
            return None

    async def authorize(
        self,
        node: NodeLike,
        envelope: FameEnvelope,
        context: Optional[FameDeliveryContext] = None,
    ) -> Optional[AuthorizationContext]:
        """
        Authorizes a request using the configured authorization policy.

        For NodeAttach frames, evaluates policy with action='Connect'.
        For other frames, this method performs basic authentication validation
        but does NOT infer send/receive actions. Route-level authorization
        is handled separately via authorize_route().

        Args:
            node: The node handling the request
            envelope: The FAME envelope being authorized
            context: Optional delivery context

        Returns:
            The authorization context if authorized, None if denied
        """
        authorization: Optional[dict[str, Any]] = None
        if context and context.security and context.security.authorization:
            auth_data = context.security.authorization
            # Convert Pydantic model to dict if needed
            if hasattr(auth_data, "model_dump"):
                authorization = auth_data.model_dump()
            elif isinstance(auth_data, dict):
                authorization = auth_data
            else:
                # Fallback: try to access as object with authenticated attribute
                authorization = {"authenticated": getattr(auth_data, "authenticated", False)}

        # Must be authenticated first
        if not authorization or not authorization.get("authenticated"):
            logger.debug("authorization_denied_not_authenticated")
            return None

        # Ensure policy is loaded
        await self.ensure_policy_loaded()

        # For NodeAttach frames, evaluate policy with 'Connect' action
        frame_type = envelope.frame.type if envelope.frame else None
        if frame_type == "NodeAttach":
            decision: AuthorizationDecision
            try:
                decision = await self.policy.evaluate_request(
                    node, envelope, context, "Connect"
                )
            except Exception as error:
                logger.error(
                    "policy_evaluation_failed",
                    error=str(error),
                    action="Connect",
                )
                return None

            if decision.effect == "allow":
                logger.debug(
                    "authorization_allowed",
                    matched_rule=decision.matched_rule,
                    reason=decision.reason,
                    action="Connect",
                )

                return _create_auth_context(
                    **{
                        **authorization,
                        "authorized": True,
                        "auth_method": authorization.get("auth_method", "policy"),
                    }
                )
            else:
                logger.debug(
                    "authorization_denied",
                    matched_rule=decision.matched_rule,
                    reason=decision.reason,
                    action="Connect",
                )
                return None

        # For non-NodeAttach frames, authentication is sufficient at this stage.
        # Route-level authorization is performed via authorize_route() after
        # the routing decision is made.
        logger.debug(
            "authorization_passed_authentication_only",
            envp_id=envelope.id,
            frame_type=frame_type,
        )

        return _create_auth_context(
            **{
                **authorization,
                "authorized": True,
                "auth_method": authorization.get("auth_method", "policy"),
            }
        )

    async def authorize_route(
        self,
        node: NodeLike,
        envelope: FameEnvelope,
        action: RuleAction,
        context: Optional[FameDeliveryContext] = None,
    ) -> Optional[RouteAuthorizationResult]:
        """
        Authorizes a routing action after the routing decision has been made.

        This method evaluates the authorization policy with the explicitly
        provided action token (ForwardUpstream, ForwardDownstream, ForwardPeer,
        DeliverLocal).

        Args:
            node: The node handling the request
            envelope: The FAME envelope being routed
            action: The authorization action token from the routing decision
            context: Optional delivery context

        Returns:
            RouteAuthorizationResult with authorization decision
        """
        authorization: Optional[dict[str, Any]] = None
        if context and context.security and context.security.authorization:
            auth_data = context.security.authorization
            # Convert Pydantic model to dict if needed
            if hasattr(auth_data, "model_dump"):
                authorization = auth_data.model_dump()
            elif isinstance(auth_data, dict):
                authorization = auth_data
            else:
                # Fallback: try to access as object with authenticated attribute
                authorization = {"authenticated": getattr(auth_data, "authenticated", False)}

        # If not authenticated, deny route authorization
        if not authorization or not authorization.get("authenticated"):
            logger.debug("route_authorization_denied_not_authenticated", action=action)
            return RouteAuthorizationResult(
                authorized=False,
                denial_reason="not_authenticated",
            )

        # Ensure policy is loaded
        await self.ensure_policy_loaded()

        # Evaluate the policy with the provided action
        decision: AuthorizationDecision
        try:
            decision = await self.policy.evaluate_request(node, envelope, context, action)
        except Exception as error:
            logger.error(
                "route_policy_evaluation_failed",
                error=str(error),
                action=action,
            )
            return RouteAuthorizationResult(
                authorized=False,
                denial_reason="policy_evaluation_error",
            )

        if decision.effect == "allow":
            logger.debug(
                "route_authorization_allowed",
                matched_rule=decision.matched_rule,
                reason=decision.reason,
                action=action,
            )

            return RouteAuthorizationResult(
                authorized=True,
                auth_context=_create_auth_context(
                    **{
                        **authorization,
                        "authorized": True,
                        "auth_method": authorization.get("auth_method", "policy"),
                    }
                ),
                matched_rule=decision.matched_rule,
            )
        else:
            logger.debug(
                "route_authorization_denied",
                matched_rule=decision.matched_rule,
                reason=decision.reason,
                action=action,
            )

            return RouteAuthorizationResult(
                authorized=False,
                denial_reason=decision.reason or "policy_denied",
                matched_rule=decision.matched_rule,
            )

    def create_reverse_authorization_config(self, node: NodeLike) -> Optional[Any]:
        """Create authorization configuration for reverse connections."""
        # Default implementation - no reverse auth support
        return None
