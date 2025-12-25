from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, Optional

from naylence.fame.core import (
    AuthorizationContext,
    FameDeliveryContext,
    FameEnvelope,
    NodeAttachFrame,
    generate_id,
)
from naylence.fame.node.node_context import FameNodeAuthorizationContext
from naylence.fame.node.node_event_listener import NodeEventListener
from naylence.fame.node.node_like import NodeLike
from naylence.fame.security.auth.authorizer import Authorizer
from naylence.fame.security.auth.token_issuer import TokenIssuer
from naylence.fame.security.auth.token_verifier import TokenVerifier
from naylence.fame.security.auth.token_verifier_provider import TokenVerifierProvider
from naylence.fame.util.logging import getLogger

if TYPE_CHECKING:
    pass

logger = getLogger(__name__)


class OAuth2Authorizer(NodeEventListener, Authorizer, TokenVerifierProvider):
    """
    OAuth2-specific authorizer for general-purpose OAuth2 providers.

    Unlike DefaultAuthorizer, this authorizer:
    - Only validates standard OAuth2 claims (audience, scopes, issuer, expiration)
    - Doesn't require custom claims like system_id, instance_id mapping
    - Suitable for Auth0, Okta, and other general-purpose OAuth2 providers
    - Uses the node attach frame values as the source of truth for system/instance IDs
    - Supports optional audience validation (defaults to node physical path if not specified)
    """

    def __init__(
        self,
        *,
        token_verifier: TokenVerifier,
        token_issuer: Optional[TokenIssuer] = None,
        audience: Optional[str] = None,
        required_scopes: Optional[list[str]] = None,
        require_scope: bool = True,
        default_ttl_sec: int = 3600,
        max_ttl_sec: int = 86400,
        reverse_auth_ttl_sec: int = 86400,
        enforce_token_subject_node_identity: bool = False,
        trusted_client_scope: str = "node.trusted",
    ):
        super().__init__()
        self._token_verifier = token_verifier
        self._audience = audience
        self._required_scopes = set(required_scopes) if required_scopes else set()
        self._require_scope = require_scope
        self._default_ttl_sec = default_ttl_sec
        self._max_ttl_sec = max_ttl_sec
        self._token_issuer = token_issuer
        self._reverse_auth_ttl_sec = reverse_auth_ttl_sec
        self._enforce_token_subject_node_identity = enforce_token_subject_node_identity
        self._trusted_client_scope = trusted_client_scope
        self._node: Optional[NodeLike] = None

    async def on_node_started(self, node: NodeLike) -> None:
        self._node = node

    @property
    def token_verifier(self) -> TokenVerifier:
        """Get the welcome token verifier used by this authorizer."""
        return self._token_verifier

    def create_reverse_authorization_config(self, node: NodeLike) -> Optional[Any]:
        """
        Create a bearer token configuration for reverse connections using TokenIssuer.

        Generates a token using the same issuer that would be used for welcome tokens,
        ensuring consistency in token format and validation.

        Returns:
            BearerTokenHeaderAuth instance or None if not configured
        """
        if not self._token_issuer:
            return None

        # Calculate expiration time
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=self._reverse_auth_ttl_sec)

        try:
            # Generate token using the welcome token issuer
            # We use a special system_id pattern to indicate this is for reverse connections
            token = self._token_issuer.issue(
                claims={
                    "iss": self._token_issuer.issuer,
                    "aud": self._audience or node.physical_path,  # Use node physical path as audience
                    "exp": int(expires_at.timestamp()),
                    "sub": f"reverse-auth-{node.id}",  # Unique subject for reverse auth
                    "instance_id": getattr(node, "instance_id", None),  # Include instance ID
                    "capabilities": (list(self._required_scopes) if self._required_scopes else []),
                }
            )

            logger.debug(
                "reverse_authorization_token_generated",
                node_id=node.id,
                expires_at=expires_at.isoformat(),
                capabilities=(list(self._required_scopes) if self._required_scopes else ["fame:connect"]),
            )

            # Create the proper Auth instance
            from naylence.fame.security.auth.bearer_token_header_auth_injection_strategy_factory import (
                BearerTokenHeaderAuthInjectionStrategyConfig,
            )
            from naylence.fame.security.auth.static_token_provider_factory import (
                StaticTokenProviderConfig,
            )

            static_token_config = StaticTokenProviderConfig(
                type="StaticTokenProvider", token=token, expires_at=expires_at
            )

            return BearerTokenHeaderAuthInjectionStrategyConfig(token_provider=static_token_config)

        except Exception as e:
            logger.warning("failed_to_generate_reverse_auth_token", node_id=node.id, error=str(e))
            return None

    async def authenticate(
        self,
        credentials: str | bytes,
    ) -> Optional[AuthorizationContext]:
        """Authenticate using OAuth2 JWT token."""
        # Extract token from credentials
        token = credentials
        if isinstance(credentials, bytes):
            token = credentials.decode("utf-8")

        # Strip "Bearer " prefix if present
        if isinstance(token, str) and token.lower().startswith("bearer "):
            token = token[7:]

        if not token:
            return None

        try:
            # Use configured audience, or fall back to target node physical path
            expected_audience = self._audience or (self._node.physical_path if self._node else None)
            raw_claims = await self._token_verifier.verify(
                str(token),  # Ensure token is string
                expected_audience=expected_audience,
            )
        except Exception as e:
            logger.warning("token_verification_failed", exc_info=e)
            return None

        # Validate scopes if required
        token_scopes = self._extract_scopes_from_claims(raw_claims)
        if self._require_scope and self._required_scopes:
            if not self._required_scopes.intersection(token_scopes):
                logger.warning(
                    f"Token scopes {token_scopes} do not include any of required scopes {
                        self._required_scopes
                    }"
                )
                return None

        # Create authorization context
        return AuthorizationContext(
            authenticated=True,
            principal=raw_claims.get("sub"),
            claims=raw_claims,
            granted_scopes=list(token_scopes),
            auth_method="oauth2_jwt",
        )

    async def authorize(
        self,
        node: NodeLike,
        envelope: FameEnvelope,
        context: Optional[FameDeliveryContext] = None,
    ) -> Optional[AuthorizationContext]:
        """
        Authorize access based on the current authentication context and operation.
        """

        if context and context.security and context.security.authorization:
            auth_context = context.security.authorization
        else:
            return None

        if auth_context.authorized is True:
            return auth_context

        # Check scopes if required and envelope is provided
        if self._require_scope and envelope:
            granted_scopes = set(auth_context.granted_scopes) if auth_context.granted_scopes else set()
            if self._required_scopes and not self._required_scopes.intersection(granted_scopes):
                return None

        # For OAuth2, if authenticated and scope checks pass, then authorized
        return auth_context

    def _extract_scopes_from_claims(self, claims: dict) -> set[str]:
        """Extract scopes from JWT claims. Handles both 'scope' and 'scopes' fields."""
        scopes = set()

        # Handle 'scope' field (space-separated string - OAuth2 standard)
        if "scope" in claims:
            scope_str = claims["scope"]
            if isinstance(scope_str, str):
                scopes.update(scope_str.split())

        # Handle 'scopes' field (array - some providers use this)
        if "scopes" in claims:
            scope_list = claims["scopes"]
            if isinstance(scope_list, list):
                scopes.update(scope_list)

        return scopes

    async def validate_node_attach_request(
        self,
        node: NodeLike,
        frame: NodeAttachFrame,
        auth_context: Optional[AuthorizationContext] = None,
    ) -> Optional[AuthorizationContext]:
        """
        Validate node attach request using the already-authenticated context.
        No longer uses attach_token from frame - relies on wire-level auth.
        """
        if not auth_context or not auth_context.authenticated:
            return None  # Must be authenticated via wire-level auth first

        # Extract claims from the auth context (set during authenticate())
        if not hasattr(auth_context, "claims") or not auth_context.claims:
            return None

        claims = auth_context.claims

        # Validate required scopes if scope checking is enabled
        token_scopes = self._extract_scopes_from_claims(claims)
        if self._require_scope and self._required_scopes:
            if not any(scope in token_scopes for scope in self._required_scopes):
                logger.warning(
                    "oauth2_attach_missing_required_scope",
                    required_scopes=list(self._required_scopes),
                    token_scopes=list(token_scopes),
                )
                return None

        # Enforce token subject node identity if enabled and not a trusted client
        if self._enforce_token_subject_node_identity:
            is_trusted_client = self._trusted_client_scope in token_scopes
            if is_trusted_client:
                logger.debug(
                    "oauth2_attach_trusted_client_bypass",
                    system_id=frame.system_id,
                    trusted_scope=self._trusted_client_scope,
                )
            else:
                validation_result = self._validate_token_subject_node_identity(
                    frame.system_id, claims
                )
                if not validation_result:
                    return None

        # Create node-specific authorization context
        return FameNodeAuthorizationContext(
            sub=claims.get("sub", frame.system_id),
            aud=node.id,
            instance_id=frame.instance_id,
            assigned_path=frame.assigned_path,
            accepted_capabilities=(list(frame.capabilities) if frame.capabilities else None),
            accepted_logicals=(list(frame.accepted_logicals) if frame.accepted_logicals else None),
            # Include additional OAuth2 claims
            scopes=list(token_scopes),
            claims=claims,
        )

    def _validate_token_subject_node_identity(
        self,
        system_id: str,
        claims: dict,
    ) -> bool:
        """
        Validate that the node's system_id is prefixed with a hash of the token subject.

        This enforces that nodes using OAuth2 authentication have identities
        that are cryptographically bound to their token subject claim.
        """
        sub = claims.get("sub")

        if not isinstance(sub, str) or not sub.strip():
            logger.warning(
                "oauth2_attach_missing_subject_claim",
                system_id=system_id,
            )
            return False

        expected_prefix = generate_id(
            mode="fingerprint",
            material=sub,
            length=8,
        )

        if not system_id.startswith(f"{expected_prefix}-"):
            logger.warning(
                "oauth2_attach_node_identity_mismatch",
                system_id=system_id,
                expected_prefix=expected_prefix,
                subject=sub,
            )
            return False

        logger.debug(
            "oauth2_attach_node_identity_verified",
            system_id=system_id,
            expected_prefix=expected_prefix,
        )

        return True
