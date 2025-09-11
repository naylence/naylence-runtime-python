from __future__ import annotations

import json
from typing import Any, Dict, Optional

from naylence.fame.security.auth.token_verifier import TokenVerifier
from naylence.fame.util.logging import getLogger

logger = getLogger(__name__)


def require_jwks_dependencies():
    """Require PyJWT and PyJWKS dependencies for JWKS functionality."""
    try:
        import jwt
        from jwt import PyJWKClient

        return jwt, PyJWKClient
    except ImportError:
        raise ImportError(
            "PyJWT and PyJWKS are required for JWKS token functionality. "
            "Install with: pip install PyJWT[crypto] PyJWKS"
        )


class JWKSJWTTokenVerifier(TokenVerifier):
    """Verifies JWTs against a remote JWKS, using PyJWKClient for caching."""

    def __init__(self, issuer: str, jwks_url: str, cache_ttl_sec: int = 300) -> None:
        """
        :param issuer: Expected JWT issuer
        :param jwks_url: URL to fetch JWKS from
        :param cache_ttl_sec: JWKS cache TTL in seconds
        """
        jwt, PyJWKClient = require_jwks_dependencies()

        self._issuer = issuer
        self._jwks_url = jwks_url
        self._jwks_client = PyJWKClient(jwks_url)

        logger.debug("created_jwks_jwt_token_verifier", issuer=issuer, jwks_url=jwks_url)

    def _decode_token_without_verification(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Decode a JWT token without verification to extract claims for debugging.

        :param token: JWT token to decode
        :return: Token claims if decodable, None otherwise
        """
        jwt, _ = require_jwks_dependencies()

        try:
            # Decode without verification to get claims for error reporting
            return jwt.decode(token, verify=False, options={"verify_signature": False})
        except Exception:
            # If we can't even decode without verification, return None
            return None

    def _format_token_claims_for_error(self, token: str) -> str:
        claims = self._decode_token_without_verification(token)
        if claims is None:
            return " [Token claims could not be decoded]"

        return json.dumps(claims)

    async def verify(
        self,
        token: str,
        *,
        expected_audience: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Validate token and return its claims if trusted.
        Uses PyJWKClient.get_signing_key_from_jwt (with built-in caching) before decode.
        """
        jwt, _ = require_jwks_dependencies()

        try:
            # Get the signing key from the token header
            signing_key = self._jwks_client.get_signing_key_from_jwt(token)

            # Verify and decode the token
            payload = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256", "ES256", "EdDSA"],  # Common JWKS algorithms
                issuer=self._issuer,
                audience=expected_audience,
                options={"verify_aud": expected_audience is not None},
            )

            return payload

        except jwt.ExpiredSignatureError:
            claims_info = self._format_token_claims_for_error(token)
            raise jwt.InvalidTokenError(f"Token has expired{claims_info}")
        except jwt.InvalidAudienceError:
            claims_info = self._format_token_claims_for_error(token)
            raise jwt.InvalidTokenError(f"Invalid audience: {claims_info}")
        except jwt.InvalidIssuerError:
            claims_info = self._format_token_claims_for_error(token)
            raise jwt.InvalidTokenError(f"Invalid issuer: {claims_info}")
        except jwt.InvalidSignatureError:
            claims_info = self._format_token_claims_for_error(token)
            raise jwt.InvalidTokenError(f"Invalid signature: {claims_info}")
        except jwt.DecodeError as e:
            raise jwt.InvalidTokenError(f"Token decode error: {e}")
        except Exception as e:
            claims_info = self._format_token_claims_for_error(token)
            raise jwt.InvalidTokenError(f"Token validation failed: {e}{claims_info}")
