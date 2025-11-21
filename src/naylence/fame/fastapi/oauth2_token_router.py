"""
OAuth2 client credentials and authorization code (PKCE) grant router for FastAPI

Provides /oauth/token and /oauth/authorize endpoints for local development and testing.
Implements OAuth2 client credentials grant with JWT token issuance and
OAuth2 authorization code grant with PKCE verification.
"""

from __future__ import annotations

import base64
import hashlib
import os
import secrets
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional
from urllib.parse import unquote, urlparse

from pydantic import BaseModel

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from naylence.fame.util.logging import getLogger

logger = getLogger("naylence.fame.fastapi.oauth2_token_router")

DEFAULT_PREFIX = "/oauth"

ENV_VAR_CLIENT_ID = "FAME_JWT_CLIENT_ID"
ENV_VAR_CLIENT_SECRET = "FAME_JWT_CLIENT_SECRET"
ENV_VAR_ALLOWED_SCOPES = "FAME_JWT_ALLOWED_SCOPES"
ENV_VAR_JWT_ISSUER = "FAME_JWT_ISSUER"
ENV_VAR_JWT_ALGORITHM = "FAME_JWT_ALGORITHM"
ENV_VAR_JWT_AUDIENCE = "FAME_JWT_AUDIENCE"
ENV_VAR_ENABLE_PKCE = "FAME_OAUTH_ENABLE_PKCE"
ENV_VAR_ALLOW_PUBLIC_CLIENTS = "FAME_OAUTH_ALLOW_PUBLIC_CLIENTS"
ENV_VAR_AUTHORIZATION_CODE_TTL = "FAME_OAUTH_CODE_TTL_SEC"
ENV_VAR_ENABLE_DEV_LOGIN = "FAME_OAUTH_ENABLE_DEV_LOGIN"
ENV_VAR_DEV_LOGIN_USERNAME = "FAME_OAUTH_DEV_USERNAME"
ENV_VAR_DEV_LOGIN_PASSWORD = "FAME_OAUTH_DEV_PASSWORD"
ENV_VAR_SESSION_TTL = "FAME_OAUTH_SESSION_TTL_SEC"
ENV_VAR_SESSION_COOKIE_NAME = "FAME_OAUTH_SESSION_COOKIE_NAME"
ENV_VAR_SESSION_SECURE_COOKIE = "FAME_OAUTH_SESSION_SECURE"
ENV_VAR_LOGIN_TITLE = "FAME_OAUTH_LOGIN_TITLE"

DEFAULT_JWT_ALGORITHM = "EdDSA"
DEFAULT_AUTHORIZATION_CODE_TTL_SEC = 300
DEFAULT_SESSION_TTL_SEC = 3600
DEFAULT_SESSION_COOKIE_NAME = "naylence_dev_session"
DEFAULT_LOGIN_TITLE = "Developer Login"


class TokenResponse(BaseModel):
    """OAuth2 token response model."""

    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    scope: Optional[str] = None


@dataclass
class AuthorizationCodeRecord:
    """Record for an issued authorization code."""

    code: str
    client_id: str
    redirect_uri: str
    scope: list[str]
    code_challenge: str
    code_challenge_method: str
    expires_at: float
    requested_state: Optional[str] = None


@dataclass
class DevLoginSession:
    """Developer login session record."""

    id: str
    username: str
    expires_at: float


def _coerce_string(value: Any) -> Optional[str]:
    """Coerce value to a non-empty string."""
    if not isinstance(value, str):
        return None
    trimmed = value.strip()
    return trimmed if len(trimmed) > 0 else None


def _coerce_number(value: Any) -> Optional[int | float]:
    """Coerce value to a number."""
    if isinstance(value, int | float) and not isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip():
        try:
            return int(value) if "." not in value else float(value)
        except ValueError:
            return None
    return None


def _coerce_boolean(value: Any) -> Optional[bool]:
    """Coerce value to a boolean."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in ("true", "1", "yes"):
            return True
        if normalized in ("false", "0", "no"):
            return False
    if isinstance(value, int | float) and not isinstance(value, bool):
        if value == 0:
            return False
        if value == 1:
            return True
    return None


def _coerce_string_array(value: Any) -> Optional[list[str]]:
    """Coerce value to a list of non-empty strings."""
    if isinstance(value, list):
        entries = [_coerce_string(entry) for entry in value]
        entries = [e for e in entries if e is not None]
        return entries if entries else None

    text = _coerce_string(value)
    if text:
        import re

        entries = re.split(r"[\s,]+", text)
        entries = [e.strip() for e in entries if e.strip()]
        return entries if entries else None

    return None


def _base64_url_encode(data: bytes) -> str:
    """Base64 URL encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _compute_s256_challenge(verifier: str) -> str:
    """Compute SHA256 code challenge from verifier."""
    digest = hashlib.sha256(verifier.encode("utf-8")).digest()
    return _base64_url_encode(digest)


def _safe_timing_equal(expected: str, actual: str) -> bool:
    """Constant-time string comparison."""
    return secrets.compare_digest(expected.encode(), actual.encode())


def _is_valid_code_verifier(value: Optional[str]) -> bool:
    """Check if value is a valid PKCE code verifier."""
    if not value:
        return False
    if not (43 <= len(value) <= 128):
        return False
    import re

    return bool(re.match(r"^[A-Za-z0-9\-._~]+$", value))


def _is_valid_code_challenge(value: Optional[str]) -> bool:
    """Check if value is a valid PKCE code challenge."""
    if not value:
        return False
    if not (43 <= len(value) <= 128):
        return False
    import re

    return bool(re.match(r"^[A-Za-z0-9\-._~]+$", value))


def _generate_authorization_code() -> str:
    """Generate a secure authorization code."""
    return _base64_url_encode(secrets.token_bytes(32))


def _generate_session_id() -> str:
    """Generate a secure session ID."""
    return _base64_url_encode(secrets.token_bytes(32))


def _cleanup_authorization_codes(store: dict[str, AuthorizationCodeRecord], now_ms: float) -> None:
    """Remove expired authorization codes."""
    expired_keys = [code for code, record in store.items() if record.expires_at <= now_ms]
    for key in expired_keys:
        del store[key]


def _cleanup_login_sessions(store: dict[str, DevLoginSession], now_ms: float) -> None:
    """Remove expired login sessions."""
    expired_keys = [key for key, record in store.items() if record.expires_at <= now_ms]
    for key in expired_keys:
        del store[key]


def _parse_cookies(cookie_header: Optional[str]) -> dict[str, str]:
    """Parse cookie header into a dictionary."""
    if not cookie_header:
        return {}

    cookies = {}
    for entry in cookie_header.split(";"):
        parts = entry.split("=", 1)
        if len(parts) != 2:
            continue
        name = parts[0].strip()
        value = parts[1].strip()
        if name:
            try:
                cookies[name] = unquote(value)
            except Exception:
                cookies[name] = value
    return cookies


def _get_active_session(
    request: Request,
    store: dict[str, DevLoginSession],
    cookie_name: str,
    session_ttl_ms: float,
) -> Optional[DevLoginSession]:
    """Get and refresh active login session."""
    cookies = _parse_cookies(request.headers.get("cookie"))
    session_id = cookies.get(cookie_name)
    if not session_id:
        return None

    record = store.get(session_id)
    if not record:
        return None

    now = datetime.now().timestamp() * 1000
    if record.expires_at <= now:
        del store[session_id]
        return None

    record.expires_at = now + session_ttl_ms
    store[session_id] = record
    return record


def _sanitize_return_to(value: Optional[str], allowed_prefix: str, fallback: str) -> str:
    """Sanitize return_to URL parameter."""
    if not value:
        return fallback

    try:
        parsed = urlparse(value)
        if parsed.scheme or parsed.netloc:
            return fallback
        if not parsed.path.startswith(allowed_prefix):
            return fallback
        result = parsed.path
        if parsed.query:
            result += f"?{parsed.query}"
        if parsed.fragment:
            result += f"#{parsed.fragment}"
        return result
    except Exception:
        return fallback


def _escape_html(text: Optional[str]) -> str:
    """Escape HTML special characters."""
    if not text:
        return ""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def _render_login_page(
    title: str,
    prefix: str,
    return_to: str,
    username: Optional[str] = None,
    error_message: Optional[str] = None,
) -> str:
    """Render the developer login page."""
    error_html = f'<div class="error">{_escape_html(error_message)}</div>' if error_message else ""
    username_value = _escape_html(username or "")

    return f"""<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>{_escape_html(title)}</title>
    <style>
      :root {{ color-scheme: light dark; }}
      body {{ margin: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      background: #0f172a; min-height: 100vh; display: flex; align-items: center; justify-content: center;
      padding: 16px; }}
      .card {{ width: min(360px, 100%); background: rgba(15, 23, 42, 0.92);
        border-radius: 16px; padding: 32px; box-shadow: 0 20px 45px rgba(15, 23, 42, 0.25);
        color: #e2e8f0; backdrop-filter: blur(20px); }}
      h1 {{ margin: 0 0 24px; font-size: 24px; font-weight: 600; text-align: center; }}
      label {{ display: block; font-size: 14px; margin-bottom: 8px; color: #cbd5f5; }}
      input[type="text"], input[type="password"] {{ width: 100%; padding: 12px 14px; border-radius: 10px;
      border: 1px solid rgba(148, 163, 184, 0.4); background: rgba(15, 23, 42, 0.6); color: inherit;
      font-size: 15px; transition: border-color 0.2s, box-shadow 0.2s; }}
      input[type="text"]:focus, input[type="password"]:focus {{ outline: none; border-color: #38bdf8;
      box-shadow: 0 0 0 3px rgba(56, 189, 248, 0.25); }}
      .field {{ margin-bottom: 18px; }}
      button {{ width: 100%; padding: 12px 14px; border-radius: 10px; border: none;
      background: linear-gradient(135deg, #38bdf8, #818cf8); color: #0f172a; font-weight: 600;
      font-size: 15px; cursor: pointer; transition: transform 0.15s, box-shadow 0.15s; }}
      button:hover {{ transform: translateY(-1px); box-shadow: 0 10px 25px rgba(129, 140, 248, 0.35); }}
      .error {{ margin-bottom: 18px; padding: 12px 14px; border-radius: 10px;
      background: rgba(239, 68, 68, 0.18); color: #fecaca; font-size: 13px; }}
      .support {{ margin-top: 16px; font-size: 12px;
      text-align: center; color: rgba(148, 163, 184, 0.75); }}
      a {{ color: #38bdf8; text-decoration: none; }}
      a:hover {{ text-decoration: underline; }}
      .brand {{ text-align: center; font-size: 14px; letter-spacing: 0.08em;
      text-transform: uppercase; color: rgba(148, 163, 184, 0.9); margin-bottom: 12px; }}
    </style>
  </head>
  <body>
    <main class="card">
      <div class="brand">NAYLENCE</div>
      <h1>{_escape_html(title)}</h1>
      {error_html}
      <form method="post" action="{_escape_html(f"{prefix}/login")}">
        <div class="field">
          <label for="username">Username</label>
          <input
            id="username"
            name="username"
            type="text"
            autocomplete="username"
            value="{username_value}"
            required
          />
        </div>
        <div class="field">
          <label for="password">Password</label>
          <input
            id="password"
            name="password"
            type="password"
            autocomplete="current-password"
            required
          />
        </div>
        <input type="hidden" name="return_to" value="{_escape_html(return_to)}" />
        <button type="submit">Sign in</button>
      </form>
      <p class="support">Cookies are used to keep your session active in this local environment.</p>
    </main>
  </body>
</html>"""


def _normalize_cookie_path(prefix: str) -> str:
    """Normalize cookie path from prefix."""
    if not prefix or prefix == "/":
        return "/"
    return prefix[:-1] if prefix.endswith("/") and len(prefix) > 1 else prefix


def _set_no_cache_headers(response: Response) -> None:
    """Set headers to prevent caching."""
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"


def _ensure_positive_integer(value: Optional[int | float]) -> Optional[int]:
    """Ensure value is a positive integer."""
    if isinstance(value, int | float) and value > 0:
        return int(value)
    return None


def create_oauth2_token_router(
    *,
    crypto_provider: Any = None,
    prefix: str = DEFAULT_PREFIX,
    issuer: Optional[str] = None,
    audience: Optional[str] = None,
    token_ttl_sec: int = 3600,
    allowed_scopes: Optional[list[str]] = None,
    algorithm: Optional[str] = None,
    enable_pkce: Optional[bool] = None,
    allow_public_clients: Optional[bool] = None,
    authorization_code_ttl_sec: Optional[int] = None,
    enable_dev_login: Optional[bool] = None,
    dev_login_username: Optional[str] = None,
    dev_login_password: Optional[str] = None,
    dev_login_session_ttl_sec: Optional[int] = None,
    dev_login_cookie_name: Optional[str] = None,
    dev_login_secure_cookie: Optional[bool] = None,
    dev_login_title: Optional[str] = None,
) -> APIRouter:
    """
    Create a Fastify plugin that implements OAuth2 token and authorization endpoints
    with support for client credentials and authorization code (PKCE) grants.

    Args:
        crypto_provider: Crypto provider for JWT signing (required)
        prefix: Router prefix (default: /oauth)
        issuer: JWT issuer claim (environment variable FAME_JWT_ISSUER takes priority)
        audience: JWT audience claim (environment variable FAME_JWT_AUDIENCE takes priority)
        token_ttl_sec: Token TTL in seconds (default: 3600)
        allowed_scopes: Allowed scopes (environment variable FAME_JWT_ALLOWED_SCOPES takes priority)
        algorithm: JWT signing algorithm (environment variable FAME_JWT_ALGORITHM takes priority)
        enable_pkce: Enable PKCE authorization code grant (default: True)
        allow_public_clients: Allow public clients (no client_secret) for PKCE exchange (default: True)
        authorization_code_ttl_sec: Authorization code TTL in seconds (default: 300)
        enable_dev_login: Enable developer login experience for authorization flows (default: False)
        dev_login_username: Developer login username (required if enable_dev_login is True)
        dev_login_password: Developer login password (required if enable_dev_login is True)
        dev_login_session_ttl_sec: Developer login session TTL in seconds (default: 3600)
        dev_login_cookie_name: Cookie name for developer login session (default: naylence_dev_session)
        dev_login_secure_cookie: Whether to mark the developer login cookie as secure (default: False)
        dev_login_title: Custom title for the developer login page (default: Developer Login)

    Returns:
        APIRouter configured with OAuth2 endpoints

    Environment Variables:
        FAME_JWT_CLIENT_ID: OAuth2 client identifier
        FAME_JWT_CLIENT_SECRET: OAuth2 client secret
        FAME_JWT_ISSUER: JWT issuer claim (optional)
        FAME_JWT_AUDIENCE: JWT audience claim (optional)
        FAME_JWT_ALGORITHM: JWT signing algorithm (optional, default: EdDSA)
        FAME_JWT_ALLOWED_SCOPES: Allowed scopes (optional, default: node.connect)
        FAME_OAUTH_ENABLE_PKCE: Enable PKCE authorization endpoints (optional, default: true)
        FAME_OAUTH_ALLOW_PUBLIC_CLIENTS: Allow PKCE exchanges without client_secret
            (optional, default: true)
        FAME_OAUTH_CODE_TTL_SEC: Authorization code TTL in seconds (optional, default: 300)
    """
    if not crypto_provider:
        raise ValueError("crypto_provider is required to create OAuth2 token router")

    provider = crypto_provider

    # Configuration
    default_issuer = os.getenv(ENV_VAR_JWT_ISSUER) or issuer or "https://auth.fame.fabric"
    default_audience = os.getenv(ENV_VAR_JWT_AUDIENCE) or audience or "fame-fabric"
    algorithm = os.getenv(ENV_VAR_JWT_ALGORITHM) or algorithm or DEFAULT_JWT_ALGORITHM

    env_allowed_scopes = os.getenv(ENV_VAR_ALLOWED_SCOPES)
    if env_allowed_scopes:
        allowed_scopes = _coerce_string_array(env_allowed_scopes)
    if not allowed_scopes:
        allowed_scopes = ["node.connect"]

    resolved_token_ttl_sec = token_ttl_sec or 3600

    enable_pkce_resolved = _coerce_boolean(os.getenv(ENV_VAR_ENABLE_PKCE))
    if enable_pkce_resolved is None:
        enable_pkce_resolved = enable_pkce if enable_pkce is not None else True

    allow_public_clients_resolved = _coerce_boolean(os.getenv(ENV_VAR_ALLOW_PUBLIC_CLIENTS))
    if allow_public_clients_resolved is None:
        allow_public_clients_resolved = allow_public_clients if allow_public_clients is not None else True

    authorization_code_ttl_sec_resolved = (
        _ensure_positive_integer(_coerce_number(os.getenv(ENV_VAR_AUTHORIZATION_CODE_TTL)))
        or authorization_code_ttl_sec
        or DEFAULT_AUTHORIZATION_CODE_TTL_SEC
    )

    dev_login_explicitly_enabled = _coerce_boolean(os.getenv(ENV_VAR_ENABLE_DEV_LOGIN))
    if dev_login_explicitly_enabled is None:
        dev_login_explicitly_enabled = enable_dev_login

    dev_login_username_resolved = (
        _coerce_string(os.getenv(ENV_VAR_DEV_LOGIN_USERNAME)) or dev_login_username
    )
    dev_login_password_resolved = (
        _coerce_string(os.getenv(ENV_VAR_DEV_LOGIN_PASSWORD)) or dev_login_password
    )

    dev_login_session_ttl_sec_resolved = (
        _ensure_positive_integer(_coerce_number(os.getenv(ENV_VAR_SESSION_TTL)))
        or dev_login_session_ttl_sec
        or DEFAULT_SESSION_TTL_SEC
    )

    dev_login_cookie_name_resolved = (
        _coerce_string(os.getenv(ENV_VAR_SESSION_COOKIE_NAME))
        or dev_login_cookie_name
        or DEFAULT_SESSION_COOKIE_NAME
    )

    dev_login_secure_cookie_resolved = _coerce_boolean(os.getenv(ENV_VAR_SESSION_SECURE_COOKIE))
    if dev_login_secure_cookie_resolved is None:
        dev_login_secure_cookie_resolved = (
            dev_login_secure_cookie if dev_login_secure_cookie is not None else False
        )

    dev_login_title_resolved = (
        _coerce_string(os.getenv(ENV_VAR_LOGIN_TITLE)) or dev_login_title or DEFAULT_LOGIN_TITLE
    )

    dev_login_credentials_configured = bool(dev_login_username_resolved and dev_login_password_resolved)
    dev_login_enabled = (dev_login_explicitly_enabled or False) or dev_login_credentials_configured

    if dev_login_enabled and not dev_login_credentials_configured:
        raise ValueError("Developer login is enabled but credentials are not configured")

    session_cookie_path = _normalize_cookie_path(prefix)
    authorization_redirect_path = f"{prefix}/authorize" if prefix.endswith("/") else f"{prefix}/authorize"
    dev_login_session_ttl_ms = dev_login_session_ttl_sec_resolved * 1000

    logger.debug(
        "oauth2_router_created",
        extra={
            "prefix": prefix,
            "issuer": default_issuer,
            "audience": default_audience,
            "algorithm": algorithm,
            "allowedScopes": allowed_scopes,
            "tokenTtlSec": resolved_token_ttl_sec,
            "enablePkce": enable_pkce_resolved,
            "allowPublicClients": allow_public_clients_resolved,
            "authorizationCodeTtlSec": authorization_code_ttl_sec_resolved,
            "devLoginEnabled": dev_login_enabled,
            "devLoginSessionTtlSec": dev_login_session_ttl_sec_resolved,
            "devLoginCookieName": dev_login_cookie_name_resolved,
            "devLoginSecureCookie": dev_login_secure_cookie_resolved,
        },
    )

    # Stateful storage
    authorization_codes: dict[str, AuthorizationCodeRecord] = {}
    login_sessions: dict[str, DevLoginSession] = {}

    if dev_login_enabled:
        logger.info(
            "oauth2_dev_login_enabled",
            extra={
                "loginTitle": dev_login_title_resolved,
                "cookieName": dev_login_cookie_name_resolved,
                "sessionTtlSec": dev_login_session_ttl_sec_resolved,
                "secureCookie": dev_login_secure_cookie_resolved,
            },
        )

    router = APIRouter(prefix=prefix)
    security = HTTPBasic(auto_error=False)

    def get_configured_client_credentials() -> tuple[str, str]:
        """Get client credentials from environment variables."""
        client_id = os.environ.get(ENV_VAR_CLIENT_ID)
        client_secret = os.environ.get(ENV_VAR_CLIENT_SECRET)

        if not client_id or not client_secret:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Server configuration error: {ENV_VAR_CLIENT_ID}"
                " and {ENV_VAR_CLIENT_SECRET} must be set",
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

    def validate_scope(requested_scope: Optional[str]) -> list[str]:
        """Validate and return granted scopes."""
        if not requested_scope:
            return allowed_scopes

        requested_scopes = requested_scope.split()
        granted_scopes = [scope for scope in requested_scopes if scope in allowed_scopes]

        return granted_scopes if granted_scopes else allowed_scopes

    def respond_invalid_client(response: Response) -> None:
        """Send invalid_client error response."""
        response.status_code = status.HTTP_401_UNAUTHORIZED
        response.headers["WWW-Authenticate"] = "Basic"

    async def issue_token_response(
        client_id: str, scopes: list[str], aud: Optional[str] = None
    ) -> TokenResponse:
        """Issue a JWT token response."""
        from naylence.fame.security.auth.jwt_token_issuer import JWTTokenIssuer

        if not provider.signing_private_pem or not provider.signature_key_id:
            logger.error(
                "oauth2_missing_keys",
                extra={
                    "hasPrivateKey": bool(provider.signing_private_pem),
                    "hasKeyId": bool(provider.signature_key_id),
                },
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Server cryptographic configuration error",
            )

        token_issuer = JWTTokenIssuer(
            signing_key_pem=provider.signing_private_pem,
            kid=provider.signature_key_id,
            issuer=default_issuer,
            algorithm=algorithm,
            ttl_sec=resolved_token_ttl_sec,
            audience=aud or default_audience,
        )

        claims = {
            "sub": client_id,
            "client_id": client_id,
            "scope": " ".join(scopes),
        }

        access_token = token_issuer.issue(claims)

        logger.debug(
            "oauth2_token_issued",
            extra={
                "clientId": client_id,
                "scopes": scopes,
                "algorithm": algorithm,
            },
        )

        response = TokenResponse(
            access_token=access_token,
            token_type="Bearer",
            expires_in=resolved_token_ttl_sec,
        )

        if scopes:
            response.scope = " ".join(scopes)

        return response

    # PKCE Authorization Endpoint
    @router.get("/authorize")
    async def authorize_endpoint(
        request: Request,
        response_type: str = Query(...),
        client_id: str = Query(...),
        redirect_uri: str = Query(...),
        scope: Optional[str] = Query(None),
        code_challenge: str = Query(...),
        code_challenge_method: Optional[str] = Query("S256"),
        state: Optional[str] = Query(None),
    ):
        """OAuth2 authorization endpoint for PKCE flow."""
        if not enable_pkce_resolved:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "error": "endpoint_disabled",
                    "error_description": "PKCE authorization endpoint is disabled",
                },
            )

        now = datetime.now().timestamp() * 1000
        _cleanup_authorization_codes(authorization_codes, now)

        # Check developer login session if enabled
        if dev_login_enabled:
            _cleanup_login_sessions(login_sessions, now)
            active_session = _get_active_session(
                request, login_sessions, dev_login_cookie_name_resolved, dev_login_session_ttl_ms
            )
            if not active_session:
                from urllib.parse import quote

                return_to = _sanitize_return_to(
                    str(request.url.path) + (f"?{request.url.query}" if request.url.query else ""),
                    session_cookie_path,
                    authorization_redirect_path,
                )
                login_location = f"{prefix}/login?return_to={quote(return_to)}"
                response = RedirectResponse(url=login_location, status_code=status.HTTP_302_FOUND)
                _set_no_cache_headers(response)
                return response

        # Validate response_type
        if response_type != "code":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error": "unsupported_response_type",
                    "error_description": "Only authorization code response type is supported",
                },
            )

        # Validate client_id
        try:
            configured_client_id, _ = get_configured_client_credentials()
        except HTTPException as e:
            logger.error("oauth2_config_error", extra={"error": str(e.detail)})
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={"error": "server_error", "error_description": "Server configuration error"},
            )

        if client_id != configured_client_id:
            logger.warning("oauth2_authorize_invalid_client", extra={"clientId": client_id})
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"error": "invalid_client", "error_description": "Invalid client credentials"},
                headers={"WWW-Authenticate": "Basic"},
            )

        # Validate redirect_uri
        try:
            redirect_url = urlparse(redirect_uri)
            if not redirect_url.scheme or not redirect_url.netloc:
                raise ValueError("Invalid URL")
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error": "invalid_request",
                    "error_description": "redirect_uri must be a valid absolute URL",
                },
            )

        # Validate scopes
        granted_scopes = validate_scope(scope)

        # Validate code_challenge
        if not _is_valid_code_challenge(code_challenge):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error": "invalid_request",
                    "error_description": "code_challenge is invalid or missing",
                },
            )

        code_challenge_method_normalized = (code_challenge_method or "S256").upper()
        if code_challenge_method_normalized not in ("S256", "PLAIN"):
            code_challenge_method_normalized = "S256"

        # Generate authorization code
        authorization_code = _generate_authorization_code()
        expires_at = now + (authorization_code_ttl_sec_resolved * 1000)

        authorization_codes[authorization_code] = AuthorizationCodeRecord(
            code=authorization_code,
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope=granted_scopes,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method_normalized,
            expires_at=expires_at,
            requested_state=state,
        )

        logger.debug(
            "oauth2_authorization_code_issued",
            extra={
                "clientId": client_id,
                "scope": granted_scopes,
                "method": code_challenge_method_normalized,
                "expiresAt": expires_at,
            },
        )

        # Build redirect URL
        redirect_url_parsed = urlparse(redirect_uri)
        from urllib.parse import parse_qs, urlencode, urlunparse

        query_params = parse_qs(redirect_url_parsed.query)
        query_params["code"] = [authorization_code]
        if state:
            query_params["state"] = [state]
        if granted_scopes:
            query_params["scope"] = [" ".join(granted_scopes)]

        redirect_location = urlunparse(
            (
                redirect_url_parsed.scheme,
                redirect_url_parsed.netloc,
                redirect_url_parsed.path,
                redirect_url_parsed.params,
                urlencode(query_params, doseq=True),
                redirect_url_parsed.fragment,
            )
        )

        response = RedirectResponse(url=redirect_location, status_code=status.HTTP_302_FOUND)
        _set_no_cache_headers(response)
        return response

    # Developer Login GET
    @router.get("/login", response_class=HTMLResponse)
    async def login_get_endpoint(request: Request, return_to: Optional[str] = Query(None)):
        """Developer login page (GET)."""
        if not dev_login_enabled:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"error": "endpoint_disabled", "error_description": "Developer login is disabled"},
            )

        now = datetime.now().timestamp() * 1000
        _cleanup_login_sessions(login_sessions, now)
        return_to_sanitized = _sanitize_return_to(
            return_to, session_cookie_path, authorization_redirect_path
        )

        session = _get_active_session(
            request, login_sessions, dev_login_cookie_name_resolved, dev_login_session_ttl_ms
        )

        if session:
            response = RedirectResponse(url=return_to_sanitized, status_code=status.HTTP_302_FOUND)
            _set_no_cache_headers(response)
            return response

        html = _render_login_page(
            title=dev_login_title_resolved,
            prefix=prefix,
            return_to=return_to_sanitized,
            username=None,
            error_message=None,
        )
        response = HTMLResponse(content=html, status_code=status.HTTP_200_OK)
        _set_no_cache_headers(response)
        return response

    # Developer Login POST
    @router.post("/login", response_class=HTMLResponse)
    async def login_post_endpoint(
        request: Request,
        username: str = Form(...),
        password: str = Form(...),
        return_to: str = Form(...),
    ):
        """Developer login form submission (POST)."""
        if not dev_login_enabled:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"error": "endpoint_disabled", "error_description": "Developer login is disabled"},
            )

        now = datetime.now().timestamp() * 1000
        _cleanup_login_sessions(login_sessions, now)
        return_to_sanitized = _sanitize_return_to(
            return_to, session_cookie_path, authorization_redirect_path
        )

        username_str = _coerce_string(username)
        password_str = _coerce_string(password)

        if not username_str or not password_str:
            html = _render_login_page(
                title=dev_login_title_resolved,
                prefix=prefix,
                return_to=return_to_sanitized,
                username=username_str,
                error_message="Username and password are required.",
            )
            response = HTMLResponse(content=html, status_code=status.HTTP_400_BAD_REQUEST)
            _set_no_cache_headers(response)
            return response

        if username_str != dev_login_username_resolved or password_str != dev_login_password_resolved:
            logger.warning("oauth2_dev_login_failed", extra={"username": username_str})
            html = _render_login_page(
                title=dev_login_title_resolved,
                prefix=prefix,
                return_to=return_to_sanitized,
                username=username_str,
                error_message="Invalid username or password.",
            )
            response = HTMLResponse(content=html, status_code=status.HTTP_401_UNAUTHORIZED)
            _set_no_cache_headers(response)
            return response

        # Create session
        session_id = _generate_session_id()
        expires_at = now + dev_login_session_ttl_ms
        login_sessions[session_id] = DevLoginSession(
            id=session_id,
            username=username_str,
            expires_at=expires_at,
        )

        # Set cookie and redirect
        response = RedirectResponse(url=return_to_sanitized, status_code=status.HTTP_302_FOUND)
        from urllib.parse import quote

        cookie_value = quote(session_id)
        max_age = int(dev_login_session_ttl_ms / 1000)
        cookie_header = f"{dev_login_cookie_name_resolved}={cookie_value};" \
            " Path={session_cookie_path}; HttpOnly; SameSite=Lax; Max-Age={max_age}"
        if dev_login_secure_cookie_resolved:
            cookie_header += "; Secure"

        response.set_cookie(
            key=dev_login_cookie_name_resolved,
            value=session_id,
            max_age=max_age,
            path=session_cookie_path,
            httponly=True,
            samesite="lax",
            secure=dev_login_secure_cookie_resolved,
        )

        logger.info("oauth2_dev_login_success", extra={"username": username_str})
        _set_no_cache_headers(response)
        return response

    # Developer Logout
    @router.post("/logout")
    @router.get("/logout")
    async def logout_endpoint(request: Request):
        """Developer logout endpoint."""
        if not dev_login_enabled:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"error": "endpoint_disabled", "error_description": "Developer login is disabled"},
            )

        now = datetime.now().timestamp() * 1000
        _cleanup_login_sessions(login_sessions, now)

        cookies = _parse_cookies(request.headers.get("cookie"))
        session_id = cookies.get(dev_login_cookie_name_resolved)
        if session_id and session_id in login_sessions:
            del login_sessions[session_id]

        response = RedirectResponse(url=f"{prefix}/login", status_code=status.HTTP_302_FOUND)
        response.delete_cookie(key=dev_login_cookie_name_resolved, path=session_cookie_path)
        _set_no_cache_headers(response)
        return response

    # Token Endpoint
    @router.post("/token", response_model=TokenResponse)
    async def token_endpoint(
        request: Request,
        response: Response,
        grant_type: str = Form(...),
        client_id: Optional[str] = Form(None),
        client_secret: Optional[str] = Form(None),
        scope: Optional[str] = Form(None),
        audience: Optional[str] = Form(None),
        code: Optional[str] = Form(None),
        redirect_uri: Optional[str] = Form(None),
        code_verifier: Optional[str] = Form(None),
        basic_credentials: Optional[HTTPBasicCredentials] = Depends(security),
    ):
        """OAuth2 token endpoint for client_credentials and authorization_code grants."""
        try:
            now = datetime.now().timestamp() * 1000
            _cleanup_authorization_codes(authorization_codes, now)

            # Validate grant_type
            if grant_type not in ("client_credentials", "authorization_code"):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail={
                        "error": "unsupported_grant_type",
                        "error_description": "Only client_credentials and authorization_code grant types"
                        " are supported",
                    },
                )

            # Get configured credentials
            try:
                configured_client_id, configured_client_secret = get_configured_client_credentials()
            except HTTPException as e:
                logger.error("oauth2_config_error", extra={"error": str(e.detail)})
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail={"error": "server_error", "error_description": "Server configuration error"},
                )

            # Extract client credentials
            request_client_id = None
            request_client_secret = None

            if basic_credentials:
                request_client_id = basic_credentials.username
                request_client_secret = basic_credentials.password
            elif client_id and client_secret:
                request_client_id = client_id
                request_client_secret = client_secret
            elif client_id:
                request_client_id = client_id

            if not request_client_id:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail={"error": "invalid_request", "error_description": "client_id is required"},
                )

            # Verify client_id
            if request_client_id != configured_client_id:
                logger.warning("oauth2_invalid_client_id", extra={"clientId": request_client_id})
                respond_invalid_client(response)
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail={"error": "invalid_client", "error_description": "Invalid client credentials"},
                    headers={"WWW-Authenticate": "Basic"},
                )

            # Authenticate client
            client_authenticated = False
            if request_client_secret is not None:
                client_authenticated = verify_client_credentials(
                    request_client_id, request_client_secret, configured_client_id, configured_client_secret
                )
                if not client_authenticated:
                    logger.warning("oauth2_invalid_credentials", extra={"clientId": request_client_id})
                    respond_invalid_client(response)
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail={
                            "error": "invalid_client",
                            "error_description": "Invalid client credentials",
                        },
                        headers={"WWW-Authenticate": "Basic"},
                    )

            # Handle client_credentials grant
            if grant_type == "client_credentials":
                if not client_authenticated:
                    respond_invalid_client(response)
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail={
                            "error": "invalid_client",
                            "error_description": "Invalid client credentials",
                        },
                        headers={"WWW-Authenticate": "Basic"},
                    )

                if not provider.signing_private_pem or not provider.signature_key_id:
                    logger.error(
                        "oauth2_missing_keys",
                        extra={
                            "hasPrivateKey": bool(provider.signing_private_pem),
                            "hasKeyId": bool(provider.signature_key_id),
                        },
                    )
                    raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        detail={
                            "error": "server_error",
                            "error_description": "Server cryptographic configuration error",
                        },
                    )

                granted_scopes = validate_scope(scope)
                token_response = await issue_token_response(
                    client_id=request_client_id,
                    scopes=granted_scopes,
                    aud=_coerce_string(audience),
                )

                _set_no_cache_headers(response)
                return token_response

            # Handle authorization_code grant (PKCE)
            if not enable_pkce_resolved:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail={
                        "error": "unsupported_grant_type",
                        "error_description": "PKCE support is disabled",
                    },
                )

            if not client_authenticated and not allow_public_clients_resolved:
                respond_invalid_client(response)
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail={"error": "invalid_client", "error_description": "Invalid client credentials"},
                    headers={"WWW-Authenticate": "Basic"},
                )

            authorization_code_str = _coerce_string(code)
            redirect_uri_str = _coerce_string(redirect_uri)
            verifier = _coerce_string(code_verifier)

            if not authorization_code_str or not redirect_uri_str or not _is_valid_code_verifier(verifier):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail={
                        "error": "invalid_request",
                        "error_description": "code, redirect_uri, and a valid code_verifier"
                        " are required for PKCE",
                    },
                )

            # Validate redirect_uri
            try:
                redirect_url = urlparse(redirect_uri_str)
                if not redirect_url.scheme or not redirect_url.netloc:
                    raise ValueError("Invalid URL")
            except Exception:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail={
                        "error": "invalid_request",
                        "error_description": "redirect_uri must be a valid absolute URL",
                    },
                )

            # Retrieve authorization code record
            record = authorization_codes.get(authorization_code_str)
            if not record:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail={
                        "error": "invalid_grant",
                        "error_description": "Authorization code is invalid or expired",
                    },
                )

            if record.expires_at <= now:
                del authorization_codes[authorization_code_str]
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail={
                        "error": "invalid_grant",
                        "error_description": "Authorization code has expired",
                    },
                )

            if record.client_id != request_client_id:
                del authorization_codes[authorization_code_str]
                respond_invalid_client(response)
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail={"error": "invalid_client", "error_description": "Invalid client credentials"},
                    headers={"WWW-Authenticate": "Basic"},
                )

            if record.redirect_uri != redirect_uri_str:
                del authorization_codes[authorization_code_str]
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail={
                        "error": "invalid_grant",
                        "error_description": "redirect_uri does not match authorization request",
                    },
                )

            # Verify PKCE
            pkce_valid = False
            if record.code_challenge_method == "S256":
                expected = record.code_challenge
                # verifier is guaranteed to be str at this point due to validation above
                actual = _compute_s256_challenge(verifier)  # type: ignore[arg-type]
                pkce_valid = _safe_timing_equal(expected, actual)
            else:
                pkce_valid = _safe_timing_equal(record.code_challenge, verifier)  # type: ignore[arg-type]

            if not pkce_valid:
                del authorization_codes[authorization_code_str]
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail={
                        "error": "invalid_grant",
                        "error_description": "code_verifier does not match code_challenge",
                    },
                )

            # Delete authorization code (single use)
            del authorization_codes[authorization_code_str]

            if not provider.signing_private_pem or not provider.signature_key_id:
                logger.error(
                    "oauth2_missing_keys",
                    extra={
                        "hasPrivateKey": bool(provider.signing_private_pem),
                        "hasKeyId": bool(provider.signature_key_id),
                    },
                )
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail={
                        "error": "server_error",
                        "error_description": "Server cryptographic configuration error",
                    },
                )

            token_response = await issue_token_response(
                client_id=request_client_id,
                scopes=record.scope,
                aud=_coerce_string(audience),
            )

            _set_no_cache_headers(response)
            return token_response

        except HTTPException:
            raise
        except Exception as e:
            logger.error("oauth2_token_error", extra={"error": str(e)})
            raise

    return router
