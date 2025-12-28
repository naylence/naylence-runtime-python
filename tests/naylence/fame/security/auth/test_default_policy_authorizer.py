"""Tests for DefaultPolicyAuthorizer."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from naylence.fame.core import (
    AuthorizationContext,
    FameDeliveryContext,
    FameEnvelope,
)
from naylence.fame.security.auth.authorizer import RouteAuthorizationResult
from naylence.fame.security.auth.default_policy_authorizer import (
    DefaultPolicyAuthorizer,
    DefaultPolicyAuthorizerOptions,
    _normalize_token,
)
from naylence.fame.security.auth.policy.authorization_policy import (
    AuthorizationDecision,
    AuthorizationPolicy,
)
from naylence.fame.security.auth.policy.authorization_policy_source import (
    AuthorizationPolicySource,
)
from naylence.fame.security.auth.token_verifier import TokenVerifier


def mock_node():
    """Create a mock node."""
    node = MagicMock()
    node.id = "test-node"
    return node


def mock_envelope(to: str = "test://node/address", frame_type: str = "DataFrame"):
    """Create a mock envelope."""
    envelope = MagicMock(spec=FameEnvelope)
    envelope.id = "test-envelope"
    envelope.to = to
    envelope.frame = MagicMock()
    envelope.frame.type = frame_type
    return envelope


def mock_context(authenticated: bool = True, scopes: list = None):
    """Create a mock delivery context with authorization."""
    context = MagicMock(spec=FameDeliveryContext)
    context.security = MagicMock()
    context.security.authorization = {
        "authenticated": authenticated,
        "scopes": scopes or [],
        "auth_method": "jwt",
    }
    context.origin_type = "downstream"
    return context


def mock_token_verifier(success: bool = True, claims: dict = None):
    """Create a mock token verifier."""
    verifier = MagicMock(spec=TokenVerifier)

    async def verify(token: str):
        if success:
            return claims or {"sub": "test-user", "scopes": ["read", "write"]}
        raise ValueError("Invalid token")

    verifier.verify = AsyncMock(side_effect=verify)
    return verifier


def mock_policy(effect: str = "allow", reason: str = None, matched_rule: str = None):
    """Create a mock authorization policy."""
    policy = MagicMock(spec=AuthorizationPolicy)

    async def evaluate_request(node, envelope, context, action):
        return AuthorizationDecision(
            effect=effect,
            reason=reason or f"{effect}_reason",
            matched_rule=matched_rule or "test-rule",
        )

    policy.evaluate_request = AsyncMock(side_effect=evaluate_request)
    return policy


def mock_policy_source(policy: AuthorizationPolicy = None):
    """Create a mock authorization policy source."""
    source = MagicMock(spec=AuthorizationPolicySource)

    async def load_policy():
        return policy or mock_policy()

    source.load_policy = AsyncMock(side_effect=load_policy)
    return source


class TestNormalizeToken:
    """Tests for _normalize_token helper function."""

    def test_returns_none_for_empty_string(self):
        """Should return None for empty string."""
        assert _normalize_token("") is None

    def test_returns_none_for_whitespace_only(self):
        """Should return None for whitespace-only string."""
        assert _normalize_token("   ") is None

    def test_strips_whitespace(self):
        """Should strip leading/trailing whitespace."""
        assert _normalize_token("  token123  ") == "token123"

    def test_extracts_bearer_token(self):
        """Should extract token from Bearer prefix."""
        assert _normalize_token("Bearer mytoken") == "mytoken"

    def test_extracts_bearer_token_case_insensitive(self):
        """Should handle Bearer prefix case-insensitively."""
        assert _normalize_token("BEARER mytoken") == "mytoken"
        assert _normalize_token("bearer mytoken") == "mytoken"

    def test_handles_bearer_prefix_without_token(self):
        """Should handle Bearer prefix with no token after it.

        When the input is 'Bearer ' or 'Bearer' alone (after strip), it doesn't match
        the 'bearer ' pattern (with space), so it's returned as-is rather than None.
        This matches TypeScript behavior where 'Bearer' alone is treated as a literal token.
        """
        # "Bearer" alone is returned as-is (not recognized as bearer format)
        assert _normalize_token("Bearer") == "Bearer"
        # "Bearer " after strip becomes "Bearer" which is returned as-is
        assert _normalize_token("Bearer ") == "Bearer"
        # "Bearer  " after strip becomes "Bearer" which is returned as-is
        assert _normalize_token("Bearer  ") == "Bearer"

    def test_handles_bytes_input(self):
        """Should decode bytes to string."""
        assert _normalize_token(b"Bearer mytoken") == "mytoken"

    def test_handles_bytes_empty(self):
        """Should return None for empty bytes."""
        assert _normalize_token(b"") is None


class TestDefaultPolicyAuthorizerConstruction:
    """Tests for DefaultPolicyAuthorizer construction."""

    def test_requires_policy_or_source(self):
        """Should raise when neither policy nor source provided."""
        with pytest.raises(ValueError, match="requires either a policy or a policy_source"):
            DefaultPolicyAuthorizer()

    def test_accepts_policy(self):
        """Should accept a policy."""
        policy = mock_policy()
        authorizer = DefaultPolicyAuthorizer(policy=policy)
        assert authorizer.policy == policy

    def test_accepts_policy_source(self):
        """Should accept a policy source."""
        source = mock_policy_source()
        authorizer = DefaultPolicyAuthorizer(policy_source=source)
        assert authorizer._policy_source == source

    def test_accepts_options_object(self):
        """Should accept options object."""
        policy = mock_policy()
        verifier = mock_token_verifier()
        options = DefaultPolicyAuthorizerOptions(
            token_verifier=verifier,
            policy=policy,
        )
        authorizer = DefaultPolicyAuthorizer(options)
        assert authorizer.policy == policy
        assert authorizer.token_verifier == verifier

    def test_prefers_keyword_args_over_options(self):
        """Keyword args should work alongside options."""
        policy1 = mock_policy()
        options = DefaultPolicyAuthorizerOptions(policy=policy1)
        # When options provided, use options
        authorizer = DefaultPolicyAuthorizer(options)
        assert authorizer.policy == policy1


class TestDefaultPolicyAuthorizerPolicy:
    """Tests for policy access and loading."""

    def test_raises_when_policy_not_loaded(self):
        """Should raise when accessing policy before load."""
        source = mock_policy_source()
        authorizer = DefaultPolicyAuthorizer(policy_source=source)
        with pytest.raises(RuntimeError, match="policy not loaded"):
            _ = authorizer.policy

    @pytest.mark.asyncio
    async def test_ensure_policy_loaded_loads_from_source(self):
        """Should load policy from source."""
        policy = mock_policy()
        source = mock_policy_source(policy)
        authorizer = DefaultPolicyAuthorizer(policy_source=source)

        await authorizer.ensure_policy_loaded()

        assert authorizer.policy == policy
        source.load_policy.assert_called_once()

    @pytest.mark.asyncio
    async def test_ensure_policy_loaded_is_idempotent(self):
        """Should not reload if already loaded."""
        policy = mock_policy()
        source = mock_policy_source(policy)
        authorizer = DefaultPolicyAuthorizer(policy_source=source)

        await authorizer.ensure_policy_loaded()
        await authorizer.ensure_policy_loaded()

        source.load_policy.assert_called_once()

    @pytest.mark.asyncio
    async def test_reload_policy_reloads_from_source(self):
        """Should reload policy from source."""
        policy = mock_policy()
        source = mock_policy_source(policy)
        authorizer = DefaultPolicyAuthorizer(policy_source=source)

        await authorizer.ensure_policy_loaded()
        await authorizer.reload_policy()

        assert source.load_policy.call_count == 2

    @pytest.mark.asyncio
    async def test_reload_policy_raises_without_source(self):
        """Should raise when reloading without source."""
        policy = mock_policy()
        authorizer = DefaultPolicyAuthorizer(policy=policy)

        with pytest.raises(RuntimeError, match="no policy source"):
            await authorizer.reload_policy()


class TestDefaultPolicyAuthorizerTokenVerifier:
    """Tests for token verifier access."""

    def test_raises_when_verifier_not_set(self):
        """Should raise when token verifier not set."""
        policy = mock_policy()
        authorizer = DefaultPolicyAuthorizer(policy=policy)

        with pytest.raises(RuntimeError, match="missing token_verifier"):
            _ = authorizer.token_verifier

    def test_allows_setting_verifier(self):
        """Should allow setting token verifier."""
        policy = mock_policy()
        verifier = mock_token_verifier()
        authorizer = DefaultPolicyAuthorizer(policy=policy)

        authorizer.token_verifier = verifier
        assert authorizer.token_verifier == verifier


class TestDefaultPolicyAuthorizerAuthenticate:
    """Tests for authenticate method."""

    @pytest.mark.asyncio
    async def test_returns_none_for_empty_token(self):
        """Should return None for empty token."""
        policy = mock_policy()
        verifier = mock_token_verifier()
        authorizer = DefaultPolicyAuthorizer(
            policy=policy, token_verifier=verifier
        )

        result = await authorizer.authenticate("")
        assert result is None

    @pytest.mark.asyncio
    async def test_returns_context_on_successful_verify(self):
        """Should return auth context on successful verification."""
        policy = mock_policy()
        verifier = mock_token_verifier(success=True, claims={"sub": "user1"})
        authorizer = DefaultPolicyAuthorizer(
            policy=policy, token_verifier=verifier
        )

        result = await authorizer.authenticate("Bearer valid-token")

        assert result is not None
        assert result.authenticated is True
        assert result.authorized is False

    @pytest.mark.asyncio
    async def test_populates_claims_field_with_jwt_claims(self):
        """Should populate the claims field with JWT claims.

        This is critical for expression-based authorization policies
        that access claims via context.security.authorization.claims.
        """
        policy = mock_policy()
        jwt_claims = {
            "sub": "user1",
            "aud": "/test-audience",
            "scope": "read write",
            "custom_claim": "custom_value",
        }
        verifier = mock_token_verifier(success=True, claims=jwt_claims)
        authorizer = DefaultPolicyAuthorizer(
            policy=policy, token_verifier=verifier
        )

        result = await authorizer.authenticate("Bearer valid-token")

        assert result is not None
        # Verify the claims field contains the JWT claims
        assert result.claims == jwt_claims
        assert result.claims.get("sub") == "user1"
        assert result.claims.get("aud") == "/test-audience"
        assert result.claims.get("custom_claim") == "custom_value"
        # Verify principal is extracted from sub claim
        assert result.principal == "user1"

    @pytest.mark.asyncio
    async def test_extracts_granted_scopes_from_claims(self):
        """Should extract granted_scopes from JWT claims."""
        policy = mock_policy()
        jwt_claims = {
            "sub": "user1",
            "scope": "read write admin",
        }
        verifier = mock_token_verifier(success=True, claims=jwt_claims)
        authorizer = DefaultPolicyAuthorizer(
            policy=policy, token_verifier=verifier
        )

        result = await authorizer.authenticate("Bearer valid-token")

        assert result is not None
        assert result.granted_scopes == ["read", "write", "admin"]

    @pytest.mark.asyncio
    async def test_returns_none_on_verify_failure(self):
        """Should return None when verification fails."""
        policy = mock_policy()
        verifier = mock_token_verifier(success=False)
        authorizer = DefaultPolicyAuthorizer(
            policy=policy, token_verifier=verifier
        )

        result = await authorizer.authenticate("Bearer invalid-token")
        assert result is None


class TestDefaultPolicyAuthorizerAuthorize:
    """Tests for authorize method."""

    @pytest.mark.asyncio
    async def test_denies_when_not_authenticated(self):
        """Should deny when not authenticated."""
        policy = mock_policy()
        authorizer = DefaultPolicyAuthorizer(policy=policy)
        node = mock_node()
        envelope = mock_envelope()
        context = mock_context(authenticated=False)

        result = await authorizer.authorize(node, envelope, context)
        assert result is None

    @pytest.mark.asyncio
    async def test_evaluates_policy_for_node_attach(self):
        """Should evaluate policy for NodeAttach frames."""
        policy = mock_policy(effect="allow")
        authorizer = DefaultPolicyAuthorizer(policy=policy)
        node = mock_node()
        envelope = mock_envelope(frame_type="NodeAttach")
        context = mock_context(authenticated=True)

        result = await authorizer.authorize(node, envelope, context)

        assert result is not None
        assert result.authorized is True
        policy.evaluate_request.assert_called_once()

    @pytest.mark.asyncio
    async def test_denies_node_attach_when_policy_denies(self):
        """Should deny NodeAttach when policy denies."""
        policy = mock_policy(effect="deny")
        authorizer = DefaultPolicyAuthorizer(policy=policy)
        node = mock_node()
        envelope = mock_envelope(frame_type="NodeAttach")
        context = mock_context(authenticated=True)

        result = await authorizer.authorize(node, envelope, context)
        assert result is None

    @pytest.mark.asyncio
    async def test_allows_non_node_attach_when_authenticated(self):
        """Should allow non-NodeAttach when authenticated."""
        policy = mock_policy()
        authorizer = DefaultPolicyAuthorizer(policy=policy)
        node = mock_node()
        envelope = mock_envelope(frame_type="DataFrame")
        context = mock_context(authenticated=True)

        result = await authorizer.authorize(node, envelope, context)

        assert result is not None
        assert result.authorized is True
        # Policy not called for non-NodeAttach frames
        policy.evaluate_request.assert_not_called()


class TestDefaultPolicyAuthorizerAuthorizeRoute:
    """Tests for authorize_route method."""

    @pytest.mark.asyncio
    async def test_denies_when_not_authenticated(self):
        """Should deny route when not authenticated."""
        policy = mock_policy()
        authorizer = DefaultPolicyAuthorizer(policy=policy)
        node = mock_node()
        envelope = mock_envelope()
        context = mock_context(authenticated=False)

        result = await authorizer.authorize_route(
            node, envelope, "ForwardUpstream", context
        )

        assert result is not None
        assert result.authorized is False
        assert result.denial_reason == "not_authenticated"

    @pytest.mark.asyncio
    async def test_allows_when_policy_allows(self):
        """Should allow route when policy allows."""
        policy = mock_policy(effect="allow", matched_rule="allow-rule")
        authorizer = DefaultPolicyAuthorizer(policy=policy)
        node = mock_node()
        envelope = mock_envelope()
        context = mock_context(authenticated=True)

        result = await authorizer.authorize_route(
            node, envelope, "ForwardUpstream", context
        )

        assert result is not None
        assert result.authorized is True
        assert result.matched_rule == "allow-rule"
        assert result.auth_context is not None

    @pytest.mark.asyncio
    async def test_denies_when_policy_denies(self):
        """Should deny route when policy denies."""
        policy = mock_policy(effect="deny", reason="access_denied", matched_rule="deny-rule")
        authorizer = DefaultPolicyAuthorizer(policy=policy)
        node = mock_node()
        envelope = mock_envelope()
        context = mock_context(authenticated=True)

        result = await authorizer.authorize_route(
            node, envelope, "ForwardDownstream", context
        )

        assert result is not None
        assert result.authorized is False
        assert result.denial_reason == "access_denied"
        assert result.matched_rule == "deny-rule"

    @pytest.mark.asyncio
    async def test_returns_error_on_policy_exception(self):
        """Should return error result on policy exception."""
        policy = MagicMock(spec=AuthorizationPolicy)
        policy.evaluate_request = AsyncMock(side_effect=Exception("Policy error"))
        authorizer = DefaultPolicyAuthorizer(policy=policy)
        node = mock_node()
        envelope = mock_envelope()
        context = mock_context(authenticated=True)

        result = await authorizer.authorize_route(
            node, envelope, "DeliverLocal", context
        )

        assert result is not None
        assert result.authorized is False
        assert result.denial_reason == "policy_evaluation_error"

    @pytest.mark.asyncio
    async def test_evaluates_correct_action(self):
        """Should pass correct action to policy."""
        policy = mock_policy(effect="allow")
        authorizer = DefaultPolicyAuthorizer(policy=policy)
        node = mock_node()
        envelope = mock_envelope()
        context = mock_context(authenticated=True)

        await authorizer.authorize_route(node, envelope, "ForwardPeer", context)

        policy.evaluate_request.assert_called_once()
        call_args = policy.evaluate_request.call_args
        assert call_args[0][3] == "ForwardPeer"


class TestRouteAuthorizationResult:
    """Tests for RouteAuthorizationResult dataclass."""

    def test_authorized_result(self):
        """Should create authorized result."""
        result = RouteAuthorizationResult(
            authorized=True,
            matched_rule="allow-rule",
        )
        assert result.authorized is True
        assert result.matched_rule == "allow-rule"
        assert result.denial_reason is None

    def test_denied_result(self):
        """Should create denied result."""
        result = RouteAuthorizationResult(
            authorized=False,
            denial_reason="access_denied",
            matched_rule="deny-rule",
        )
        assert result.authorized is False
        assert result.denial_reason == "access_denied"
        assert result.matched_rule == "deny-rule"

    def test_with_auth_context(self):
        """Should include auth context."""

        ctx = AuthorizationContext(authenticated=True, authorized=True, principal="user1")
        result = RouteAuthorizationResult(
            authorized=True,
            auth_context=ctx,
        )
        assert result.auth_context == ctx
        assert result.auth_context.principal == "user1"
