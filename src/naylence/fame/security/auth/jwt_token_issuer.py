from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional

from naylence.fame.security.auth.token_issuer import TokenIssuer
from naylence.fame.util.logging import getLogger

logger = getLogger(__name__)


def require_jwt():
    """Require PyJWT dependency for JWT functionality."""
    try:
        import jwt

        return jwt
    except ImportError:
        raise ImportError("PyJWT is required for JWT token functionality. Install with: pip install PyJWT")


class JWTTokenIssuer(TokenIssuer):
    """Generic JWT token issuer that accepts any claims."""

    def __init__(
        self,
        *,
        signing_key_pem: str,
        kid: str,
        issuer: str,
        algorithm: str = "EdDSA",
        ttl_sec: int = 3600,
        audience: Optional[str] = None,
    ):
        """
        :param signing_key_pem: Private key as PEM string for signing
        :param kid: Key ID to embed in the JWT header
        :param issuer: JWT issuer claim
        :param algorithm: Signing algorithm (EdDSA, RS256, HS256, etc.)
        :param ttl_sec: Time-to-live for issued tokens
        :param audience: Default audience claim
        """
        self._signing_key_pem = signing_key_pem
        self._kid = kid
        self._issuer = issuer
        self._algorithm = algorithm
        self._ttl_sec = ttl_sec
        self._audience = audience

        logger.debug(
            "created_jwt_token_issuer",
            issuer=issuer,
            kid=kid,
            audience=audience,
            algorithm=algorithm,
        )

    @property
    def issuer(self):
        return self._issuer

    def issue(self, claims: Dict[str, Any]) -> str:
        """Issue a JWT token with the provided claims."""
        jwt = require_jwt()

        # Set up standard JWT claims
        now = datetime.now(timezone.utc)
        token_claims = {
            "iss": self._issuer,
            "iat": now,
            "nbf": now,
            "exp": now.timestamp() + self._ttl_sec,
        }

        # Add audience if specified
        if self._audience:
            token_claims["aud"] = self._audience

        # Merge in the provided claims
        token_claims.update(claims)

        # Sign and return the token
        return jwt.encode(
            token_claims,
            self._signing_key_pem,
            algorithm=self._algorithm,
            headers={"kid": self._kid},
        )
