from __future__ import annotations

from collections import deque
from typing import Any, Dict, Optional

from naylence.fame.security.auth.token_verifier import TokenVerifier
from naylence.fame.util.logging import getLogger

logger = getLogger(__name__)


def require_jwt():
    """Require PyJWT dependency for JWT functionality."""
    try:
        import jwt

        return jwt
    except ImportError:
        raise ImportError("PyJWT is required for JWT token functionality. Install with: pip install PyJWT")


class JWTTokenVerifier(TokenVerifier):
    """Generic JWT token verifier that can verify any JWT token."""

    def __init__(
        self,
        key: str,
        issuer: str,
        ttl_sec: int = 3600,
        revoked_capacity: int = 1000,
        required_scopes: Optional[list[str]] = None,
    ):
        """
        :param key: The verification key (public key for asymmetric, shared secret for symmetric)
        :param issuer: Expected issuer claim
        :param ttl_sec: Maximum token lifetime in seconds
        :param revoked_capacity: Maximum number of revoked tokens to track
        :param required_scopes: List of required scopes (if applicable)
        """
        self._key = key
        self._issuer = issuer
        self._ttl_sec = ttl_sec
        self._required_scopes = required_scopes or []
        self._revoked_tokens = deque(maxlen=revoked_capacity)

        logger.debug("jwt_token_verifier_initialized", trusted_issuer=self._issuer)

    def revoke(self, jti: str) -> None:
        """Mark a token ID as revoked. If we exceed capacity, remove the oldest."""
        self._revoked_tokens.append(jti)

    def _extract_scopes_from_claims(self, claims: dict) -> set[str]:
        """Extract scopes from JWT claims. Handles multiple scope claim formats."""
        scopes = set()

        # Handle 'scope' field (space-separated string - OAuth2 standard)
        if "scope" in claims:
            scope_str = claims["scope"]
            if isinstance(scope_str, str):
                scopes.update(scope_str.split())
            elif isinstance(scope_str, list):
                scopes.update(scope_str)

        # Handle 'scopes' field (array - some providers use this)
        if "scopes" in claims:
            scope_list = claims["scopes"]
            if isinstance(scope_list, list):
                scopes.update(scope_list)

        # Handle 'scp' field (array - common in OAuth2)
        if "scp" in claims:
            scp_list = claims["scp"]
            if isinstance(scp_list, list):
                scopes.update(scp_list)
            elif isinstance(scp_list, str):
                scopes.update(scp_list.split())

        return scopes

    async def verify(self, token: str, *, expected_audience: Optional[str] = None) -> Dict[str, Any]:
        """Verify and decode a JWT token."""
        jwt = require_jwt()

        try:
            # First decode without verification to check if token is revoked
            unverified_payload = jwt.decode(token, options={"verify_signature": False})
            jti = unverified_payload.get("jti")
            if jti and jti in self._revoked_tokens:
                raise jwt.InvalidTokenError("Token has been revoked")

            # Now verify the token fully
            payload = jwt.decode(
                token,
                self._key,
                algorithms=["EdDSA", "RS256", "HS256"],  # Support multiple algorithms
                issuer=self._issuer,
                audience=expected_audience,
            )

            # Verify required scopes if any
            if self._required_scopes:
                token_scopes = self._extract_scopes_from_claims(payload)
                if not all(scope in token_scopes for scope in self._required_scopes):
                    raise ValueError("Token missing required scopes")

            return payload

        except jwt.ExpiredSignatureError:
            raise jwt.InvalidTokenError("Token has expired")
        except jwt.InvalidAudienceError:
            raise jwt.InvalidTokenError("Invalid audience")
        except jwt.InvalidIssuerError:
            raise jwt.InvalidTokenError("Invalid issuer")
        except jwt.InvalidSignatureError:
            raise jwt.InvalidTokenError("Invalid signature")
        except jwt.DecodeError:
            raise jwt.InvalidTokenError("Token decode error")
