"""
This module provides a FastAPI router that serves OpenID Connect Discovery configuration
for OAuth2/OIDC clients to auto-discover endpoints and capabilities.
"""

from __future__ import annotations

import os
from typing import Optional

from pydantic import BaseModel

from fastapi import APIRouter

DEFAULT_PREFIX = ""

ENV_VAR_JWT_ISSUER = "FAME_JWT_ISSUER"
ENV_VAR_JWT_AUDIENCE = "FAME_JWT_AUDIENCE"
ENV_VAR_ALLOWED_SCOPES = "FAME_JWT_ALLOWED_SCOPES"
ENV_VAR_JWT_ALGORITHM = "FAME_JWT_ALGORITHM"

DEFAULT_JWT_ALGORITHM = "EdDSA"


class OpenIDConfiguration(BaseModel):
    """OpenID Connect Discovery configuration model."""

    issuer: str
    authorization_endpoint: Optional[str] = None
    token_endpoint: str
    jwks_uri: str
    scopes_supported: list[str]
    response_types_supported: list[str] = ["token"]
    grant_types_supported: list[str] = ["client_credentials"]
    token_endpoint_auth_methods_supported: list[str] = ["client_secret_basic", "client_secret_post"]
    subject_types_supported: list[str] = ["public"]
    id_token_signing_alg_values_supported: list[str] = ["EdDSA"]


def create_openid_configuration_router(
    *,
    prefix: str = DEFAULT_PREFIX,
    issuer: Optional[str] = None,
    base_url: Optional[str] = None,
    token_endpoint_path: str = "/oauth/token",
    jwks_endpoint_path: str = "/.well-known/jwks.json",
    allowed_scopes: Optional[list[str]] = None,
    algorithm: Optional[str] = None,
) -> APIRouter:
    """
    Create an OpenID Connect Discovery configuration router.

    This router serves the OpenID Connect Discovery document that allows OAuth2/OIDC
    clients to auto-discover the server's endpoints and capabilities.

    Args:
        prefix: URL prefix for the router endpoints
        issuer: JWT issuer claim (defaults to environment variable or "https://auth.fame.fabric")
        base_url: Base URL for the server (defaults to issuer value)
        token_endpoint_path: Path to the token endpoint (default: "/oauth/token")
        jwks_endpoint_path: Path to the JWKS endpoint (default: "/.well-known/jwks.json")
        allowed_scopes: List of allowed scopes (defaults to ["node.connect"])

    Returns:
        APIRouter configured with OpenID configuration endpoint

    Environment Variables:
        FAME_JWT_ISSUER: JWT issuer claim
        FAME_JWT_AUDIENCE: JWT audience claim
        FAME_JWT_ALLOWED_SCOPES: Comma or space-separated list of allowed scopes

    Endpoints:
        GET /.well-known/openid-configuration - OpenID Connect Discovery endpoint
    """
    router = APIRouter(prefix=prefix)

    # Get configuration values
    default_issuer = os.getenv(ENV_VAR_JWT_ISSUER) or issuer or "https://auth.fame.fabric"
    default_base_url = base_url or default_issuer

    algorithm = algorithm or os.getenv(ENV_VAR_JWT_ALGORITHM, DEFAULT_JWT_ALGORITHM)

    # Parse allowed scopes from environment or use defaults
    env_allowed_scopes = os.getenv(ENV_VAR_ALLOWED_SCOPES)
    if env_allowed_scopes:
        allowed_scopes = [
            scope.strip() for scope in env_allowed_scopes.replace(",", " ").split() if scope.strip()
        ]
    allowed_scopes = allowed_scopes or ["node.connect"]

    @router.get("/.well-known/openid-configuration", response_model=OpenIDConfiguration)
    async def openid_configuration():
        """
        OpenID Connect Discovery endpoint.

        Returns the OpenID Connect Discovery document that describes the
        server's endpoints and capabilities according to RFC 8414.
        """
        # Construct absolute URLs for endpoints
        token_endpoint = f"{default_base_url.rstrip('/')}{token_endpoint_path}"
        jwks_uri = f"{default_base_url.rstrip('/')}{jwks_endpoint_path}"

        return OpenIDConfiguration(
            issuer=default_issuer,
            token_endpoint=token_endpoint,
            jwks_uri=jwks_uri,
            scopes_supported=allowed_scopes,
            response_types_supported=["token"],
            grant_types_supported=["client_credentials"],
            token_endpoint_auth_methods_supported=["client_secret_basic", "client_secret_post"],
            subject_types_supported=["public"],
            id_token_signing_alg_values_supported=[algorithm],
        )

    return router
