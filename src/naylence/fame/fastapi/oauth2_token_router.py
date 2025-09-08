"""
This module provides a FastAPI router that implements OAuth2 client credentials grant flow
as a simple token server during local development and testing.
"""

from __future__ import annotations

import os
from typing import Optional

from pydantic import BaseModel

from fastapi import APIRouter, Depends, Form, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials

DEFAULT_PREFIX = "/oauth"

ENV_VAR_CLIENT_ID = "FAME_JWT_CLIENT_ID"
ENV_VAR_CLIENT_SECRET = "FAME_JWT_CLIENT_SECRET"
ENV_VAR_ALLOWED_SCOPES = "FAME_JWT_ALLOWED_SCOPES"

# NOTE: this variable is not the same as FAME_JWT_TRUSTED_ISSUER
ENV_VAR_JWT_ISSUER = "FAME_JWT_ISSUER"

ENV_VAR_JWT_ALGORITHM = "FAME_JWT_ALGORITHM"

ENV_VAR_JWT_AUDIENCE = "FAME_JWT_AUDIENCE"

DEFAULT_JWT_ALGORITHM = "EdDSA"


class TokenResponse(BaseModel):
    """OAuth2 token response model."""

    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    scope: Optional[str] = None


def create_oauth2_token_router(
    *,
    prefix: str = DEFAULT_PREFIX,
    issuer: Optional[str] = None,
    audience: Optional[str] = None,
    token_ttl_sec: int = 3600,
    allowed_scopes: Optional[list[str]] = None,
    algorithm: Optional[str] = None,
) -> APIRouter:
    """
    Create an OAuth2 token server router for local testing.

    This router implements the OAuth2 client credentials grant flow and can be used
    as a replacement for Auth0 during local development and testing.

    Args:
        prefix: URL prefix for the router endpoints
        client_id_env_var: Environment variable name for client ID (default: FAME_CLIENT_ID)
        client_secret_env_var: Environment variable name for client secret (default: FAME_CLIENT_SECRET)
        issuer: JWT issuer claim (defaults to "https://auth.fame.local")
        audience: JWT audience claim (defaults to "fame-api")
        token_ttl_sec: Token time-to-live in seconds (default: 3600)
        allowed_scopes: List of allowed scopes (defaults to ["read", "write"])
        algorithm: JWT signing algorithm (default: EdDSA)

    Returns:
        APIRouter configured with OAuth2 endpoints

    Environment Variables:
        FAME_JWT_CLIENT_ID: OAuth2 client identifier
        FAME_JWT_CLIENT_SECRET: OAuth2 client secret

    Endpoints:
        POST /oauth/token - OAuth2 token endpoint
    """
    router = APIRouter(prefix=prefix)

    # Default values
    default_issuer = os.getenv(ENV_VAR_JWT_ISSUER) or issuer or "https://auth.fame.fabric"
    default_audience = os.getenv(ENV_VAR_JWT_AUDIENCE) or audience or "fame-fabric"

    algorithm = algorithm or os.getenv(ENV_VAR_JWT_ALGORITHM, DEFAULT_JWT_ALGORITHM)

    env_allowed_scopes = os.getenv(ENV_VAR_ALLOWED_SCOPES)
    if env_allowed_scopes:
        allowed_scopes = [
            scope.strip() for scope in env_allowed_scopes.replace(",", " ").split() if scope.strip()
        ]
    allowed_scopes = allowed_scopes or ["node.connect"]

    # HTTP Basic Auth for client credentials in Authorization header
    security = HTTPBasic(auto_error=False)

    def get_configured_client_credentials() -> tuple[str, str]:
        """Get client credentials from environment variables."""
        client_id = os.environ.get(ENV_VAR_CLIENT_ID)
        client_secret = os.environ.get(ENV_VAR_CLIENT_SECRET)

        if not client_id or not client_secret:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Server configuration error: {ENV_VAR_CLIENT_ID} "
                f"and {ENV_VAR_CLIENT_SECRET} must be set",
            )

        return client_id, client_secret

    def verify_client_credentials(
        request_client_id: str,
        request_client_secret: str,
        configured_client_id: str,
        configured_client_secret: str,
    ) -> bool:
        """Verify client credentials."""
        return (
            request_client_id == configured_client_id and request_client_secret == configured_client_secret
        )

    def get_token_issuer():
        """Get or create a JWT token issuer."""
        try:
            from naylence.fame.security.auth.jwt_token_issuer import JWTTokenIssuer
            from naylence.fame.security.crypto.providers.crypto_provider import (
                get_crypto_provider,
            )

            crypto_provider = get_crypto_provider()

            return JWTTokenIssuer(
                signing_key_pem=crypto_provider.signing_private_pem,
                kid=crypto_provider.signature_key_id,
                issuer=default_issuer,
                algorithm=algorithm,
                ttl_sec=token_ttl_sec,
                audience=default_audience,
            )
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to initialize token issuer: {str(e)}",
            )

    def validate_scope(requested_scope: Optional[str]) -> list[str]:
        """Validate and return granted scopes."""
        if not requested_scope:
            return allowed_scopes

        requested_scopes = requested_scope.split()
        granted_scopes = []

        granted_scopes = [scope for scope in requested_scopes if scope in allowed_scopes]

        return granted_scopes if granted_scopes else allowed_scopes

    @router.post("/token", response_model=TokenResponse)
    async def token_endpoint(
        grant_type: str = Form(...),
        client_id: Optional[str] = Form(None),
        client_secret: Optional[str] = Form(None),
        scope: Optional[str] = Form(None),
        audience: Optional[str] = Form(None),
        basic_credentials: Optional[HTTPBasicCredentials] = Depends(security),
    ):
        """
        OAuth2 token endpoint implementing client credentials grant.

        Supports client authentication via:
        1. HTTP Basic Authentication (Authorization header)
        2. Form parameters (client_id and client_secret in request body)
        """
        # Validate grant type
        if grant_type != "client_credentials":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="unsupported_grant_type",
                headers={"Content-Type": "application/json"},
            )

        # Get configured credentials
        configured_client_id, configured_client_secret = get_configured_client_credentials()

        # Extract client credentials from request
        request_client_id = None
        request_client_secret = None

        # Try Basic Auth first
        if basic_credentials:
            request_client_id = basic_credentials.username
            request_client_secret = basic_credentials.password
        # Fall back to form parameters
        elif client_id and client_secret:
            request_client_id = client_id
            request_client_secret = client_secret

        if not request_client_id or not request_client_secret:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="invalid_client",
                headers={"WWW-Authenticate": "Basic"},
            )

        # Verify client credentials
        if not verify_client_credentials(
            request_client_id,
            request_client_secret,
            configured_client_id,
            configured_client_secret,
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="invalid_client",
                headers={"WWW-Authenticate": "Basic"},
            )

        # Validate and determine granted scopes
        granted_scopes = validate_scope(scope)

        # Get token issuer and issue token
        token_issuer = get_token_issuer()

        # Build JWT claims
        claims = {
            "sub": request_client_id,  # Subject (client_id)
            "client_id": request_client_id,
            "scope": " ".join(granted_scopes),
        }

        if audience:
            claims["aud"] = audience
        elif default_audience:
            claims["aud"] = default_audience

        # Issue the token
        access_token = token_issuer.issue(claims)

        return TokenResponse(
            access_token=access_token,
            token_type="Bearer",
            expires_in=token_ttl_sec,
            scope=" ".join(granted_scopes) if granted_scopes else None,
        )

    # @router.get("/.well-known/jwks.json")
    # async def jwks_endpoint():
    #     """
    #     JWKS endpoint for token verification.

    #     Returns the JSON Web Key Set that can be used to verify tokens
    #     issued by this server.
    #     """
    #     try:
    #         from naylence.fame.security.crypto.providers.crypto_provider import get_crypto_provider

    #         crypto_provider = get_crypto_provider()
    #         return crypto_provider.get_jwks()

    #     except Exception as e:
    #         raise HTTPException(
    #             status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
    #             detail=f"Failed to retrieve JWKS: {str(e)}",
    #         )

    return router
