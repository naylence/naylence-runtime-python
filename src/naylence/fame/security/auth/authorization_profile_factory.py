"""
Authorization profile factory.

Provides pre-configured authorization profiles that can be selected by name.
This allows for easy configuration of common authorization patterns.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from naylence.fame.profile import RegisterProfileOptions, get_profile, register_profile
from naylence.fame.security.auth.authorizer import Authorizer
from naylence.fame.security.auth.authorizer_factory import AuthorizerConfig, AuthorizerFactory

logger = logging.getLogger(
    "naylence.fame.security.auth.authorization_profile_factory"
)

# Base type for authorizer factory registration
AUTHORIZER_FACTORY_BASE_TYPE = "Authorizer"


class AuthorizationProfileConfig(AuthorizerConfig):
    """Configuration for authorization profile selection."""

    type: str = "AuthorizationProfile"
    profile: Optional[str] = None


# Profile name constants
PROFILE_NAME_DEFAULT = "jwt"
PROFILE_NAME_OAUTH2 = "oauth2"
PROFILE_NAME_OAUTH2_GATED = "oauth2-gated"
PROFILE_NAME_OAUTH2_CALLBACK = "oauth2-callback"
PROFILE_NAME_POLICY_LOCALFILE = "policy-localfile"
PROFILE_NAME_NOOP = "noop"

# Environment variable names (for expression evaluation)
ENV_VAR_JWT_TRUSTED_ISSUER = "FAME_JWT_TRUSTED_ISSUER"
ENV_VAR_JWT_ALGORITHM = "FAME_JWT_ALGORITHM"
ENV_VAR_JWT_AUDIENCE = "FAME_JWT_AUDIENCE"
ENV_VAR_JWKS_URL = "FAME_JWKS_URL"
ENV_VAR_ENFORCE_TOKEN_SUBJECT_NODE_IDENTITY = "FAME_ENFORCE_TOKEN_SUBJECT_NODE_IDENTITY"
ENV_VAR_TRUSTED_CLIENT_SCOPE = "FAME_TRUSTED_CLIENT_SCOPE"
ENV_VAR_AUTH_POLICY_PATH = "FAME_AUTH_POLICY_PATH"
ENV_VAR_AUTH_POLICY_FORMAT = "FAME_AUTH_POLICY_FORMAT"
ENV_VAR_JWT_REVERSE_AUTH_TRUSTED_ISSUER = "FAME_JWT_REVERSE_AUTH_TRUSTED_ISSUER"
ENV_VAR_JWT_REVERSE_AUTH_AUDIENCE = "FAME_JWT_REVERSE_AUTH_AUDIENCE"
ENV_VAR_HMAC_SECRET = "FAME_HMAC_SECRET"

DEFAULT_REVERSE_AUTH_ISSUER = "reverse-auth.naylence.ai"
DEFAULT_REVERSE_AUTH_AUDIENCE = "dev.naylence.ai"

# Profile configurations
# Note: In Python we don't have expression evaluation like TypeScript's Expressions.env()
# These are simplified versions - actual env resolution happens at runtime

DEFAULT_PROFILE: dict[str, Any] = {
    "type": "DefaultAuthorizer",
    "verifier": {
        "type": "JWKSJWTTokenVerifier",
        # These would be resolved from env at runtime
        "jwks_url_env": ENV_VAR_JWKS_URL,
        "issuer_env": ENV_VAR_JWT_TRUSTED_ISSUER,
    },
}

OAUTH2_PROFILE: dict[str, Any] = {
    "type": "OAuth2Authorizer",
    "issuer_env": ENV_VAR_JWT_TRUSTED_ISSUER,
    "required_scopes": ["node.connect"],
    "require_scope": True,
    "default_ttl_sec": 3600,
    "max_ttl_sec": 86400,
    "algorithm_env": ENV_VAR_JWT_ALGORITHM,
    "algorithm_default": "RS256",
    "audience_env": ENV_VAR_JWT_AUDIENCE,
}

OAUTH2_GATED_PROFILE: dict[str, Any] = {
    **OAUTH2_PROFILE,
    "enforce_token_subject_node_identity_env": ENV_VAR_ENFORCE_TOKEN_SUBJECT_NODE_IDENTITY,
    "enforce_token_subject_node_identity_default": "false",
    "trusted_client_scope_env": ENV_VAR_TRUSTED_CLIENT_SCOPE,
    "trusted_client_scope_default": "node.trusted",
}

OAUTH2_CALLBACK_PROFILE: dict[str, Any] = {
    "type": "OAuth2Authorizer",
    "issuer_env": ENV_VAR_JWT_REVERSE_AUTH_TRUSTED_ISSUER,
    "issuer_default": DEFAULT_REVERSE_AUTH_ISSUER,
    "audience_env": ENV_VAR_JWT_REVERSE_AUTH_AUDIENCE,
    "require_scope": True,
    "default_ttl_sec": 3600,
    "max_ttl_sec": 86400,
    "reverse_auth_ttl_sec": 86400,
    "token_verifier_config": {
        "type": "JWTTokenVerifier",
        "algorithm": "HS256",
        "hmac_secret_env": ENV_VAR_HMAC_SECRET,
        "issuer_env": ENV_VAR_JWT_REVERSE_AUTH_TRUSTED_ISSUER,
        "issuer_default": DEFAULT_REVERSE_AUTH_ISSUER,
        "ttl_sec": 86400,
    },
    "token_issuer_config": {
        "type": "JWTTokenIssuer",
        "algorithm": "HS256",
        "hmac_secret_env": ENV_VAR_HMAC_SECRET,
        "kid": "hmac-reverse-auth-key",
        "issuer_env": ENV_VAR_JWT_REVERSE_AUTH_TRUSTED_ISSUER,
        "issuer_default": DEFAULT_REVERSE_AUTH_ISSUER,
        "ttl_sec": 86400,
        "audience_env": ENV_VAR_JWT_REVERSE_AUTH_AUDIENCE,
        "audience_default": DEFAULT_REVERSE_AUTH_AUDIENCE,
    },
}

NOOP_PROFILE: dict[str, Any] = {
    "type": "NoopAuthorizer",
}

DEFAULT_VERIFIER_CONFIG: dict[str, Any] = {
    "type": "JWKSJWTTokenVerifier",
    "jwks_url_env": ENV_VAR_JWKS_URL,
    "issuer_env": ENV_VAR_JWT_TRUSTED_ISSUER,
}

DEFAULT_POLICY_SOURCE: dict[str, Any] = {
    "type": "LocalFileAuthorizationPolicySource",
    "path_env": ENV_VAR_AUTH_POLICY_PATH,
    "path_default": "./auth-policy.yaml",
    "format_env": ENV_VAR_AUTH_POLICY_FORMAT,
    "format_default": "auto",
}

POLICY_LOCALFILE_PROFILE: dict[str, Any] = {
    "type": "PolicyAuthorizer",
    "verifier": DEFAULT_VERIFIER_CONFIG,
    "policySource": DEFAULT_POLICY_SOURCE,
}

# Register all profiles
_profiles_registered = False


def _ensure_profiles_registered() -> None:
    """Ensure all built-in profiles are registered."""
    global _profiles_registered
    if _profiles_registered:
        return

    opts = RegisterProfileOptions(source="authorization-profile-factory")

    register_profile(
        AUTHORIZER_FACTORY_BASE_TYPE,
        PROFILE_NAME_DEFAULT,
        DEFAULT_PROFILE,
        opts,
    )
    register_profile(
        AUTHORIZER_FACTORY_BASE_TYPE,
        PROFILE_NAME_OAUTH2,
        OAUTH2_PROFILE,
        opts,
    )
    register_profile(
        AUTHORIZER_FACTORY_BASE_TYPE,
        PROFILE_NAME_OAUTH2_GATED,
        OAUTH2_GATED_PROFILE,
        opts,
    )
    register_profile(
        AUTHORIZER_FACTORY_BASE_TYPE,
        PROFILE_NAME_OAUTH2_CALLBACK,
        OAUTH2_CALLBACK_PROFILE,
        opts,
    )
    register_profile(
        AUTHORIZER_FACTORY_BASE_TYPE,
        PROFILE_NAME_POLICY_LOCALFILE,
        POLICY_LOCALFILE_PROFILE,
        opts,
    )
    register_profile(
        AUTHORIZER_FACTORY_BASE_TYPE,
        PROFILE_NAME_NOOP,
        NOOP_PROFILE,
        opts,
    )

    _profiles_registered = True


# Profile aliases for flexible naming
PROFILE_ALIASES: dict[str, str] = {
    "jwt": PROFILE_NAME_DEFAULT,
    "jwks": PROFILE_NAME_DEFAULT,
    "default": PROFILE_NAME_DEFAULT,
    "oauth2": PROFILE_NAME_OAUTH2,
    "oidc": PROFILE_NAME_OAUTH2,
    "oauth2-gated": PROFILE_NAME_OAUTH2_GATED,
    "oauth2_gated": PROFILE_NAME_OAUTH2_GATED,
    "oauth2-callback": PROFILE_NAME_OAUTH2_CALLBACK,
    "oauth2_callback": PROFILE_NAME_OAUTH2_CALLBACK,
    "reverse-auth": PROFILE_NAME_OAUTH2_CALLBACK,
    "policy": PROFILE_NAME_POLICY_LOCALFILE,
    "policy-localfile": PROFILE_NAME_POLICY_LOCALFILE,
    "policy_localfile": PROFILE_NAME_POLICY_LOCALFILE,
    "noop": PROFILE_NAME_NOOP,
    "no-op": PROFILE_NAME_NOOP,
    "no_op": PROFILE_NAME_NOOP,
}


def _coerce_profile_string(value: Any) -> Optional[str]:
    """Coerce a value to a profile string."""
    if not isinstance(value, str):
        return None
    trimmed = value.strip()
    return trimmed if trimmed else None


def _canonicalize_profile_name(value: str) -> str:
    """Canonicalize a profile name using aliases."""
    # Replace underscores/spaces with hyphens and lowercase
    normalized = value.replace(" ", "-").replace("_", "-").lower()
    return PROFILE_ALIASES.get(normalized, normalized)


def _resolve_profile_name(candidate: dict[str, Any]) -> str:
    """Resolve the profile name from a config dict."""
    # Check direct 'profile' field
    direct = _coerce_profile_string(candidate.get("profile"))
    if direct:
        return direct

    # Check legacy keys
    legacy_keys = ("profile_name", "profileName")
    for legacy_key in legacy_keys:
        legacy_value = _coerce_profile_string(candidate.get(legacy_key))
        if legacy_value:
            return legacy_value

    # Default to oauth2
    return PROFILE_NAME_OAUTH2


def _normalize_config(
    config: Optional[AuthorizationProfileConfig | dict[str, Any]],
) -> dict[str, str]:
    """Normalize the configuration to extract profile name."""
    if not config:
        return {"profile": PROFILE_NAME_OAUTH2}

    if isinstance(config, AuthorizationProfileConfig):
        candidate = config.__dict__
    else:
        candidate = config

    profile_value = _resolve_profile_name(candidate)
    canonical_profile = _canonicalize_profile_name(profile_value)

    return {"profile": canonical_profile}


def _resolve_profile_config(profile_name: str) -> dict[str, Any]:
    """Resolve the profile configuration by name."""
    _ensure_profiles_registered()

    profile = get_profile(AUTHORIZER_FACTORY_BASE_TYPE, profile_name)
    if profile is None:
        raise ValueError(f"Unknown authorization profile: {profile_name}")

    return profile


class AuthorizationProfileFactory(AuthorizerFactory[AuthorizationProfileConfig]):
    """
    Factory for creating authorizers from named profiles.

    Profiles provide pre-configured authorization settings that can be
    selected by name, simplifying common authorization patterns.
    """

    type: str = "AuthorizationProfile"

    async def create(
        self,
        config: Optional[AuthorizationProfileConfig | dict[str, Any]] = None,
        **kwargs: Any,
    ) -> Authorizer:
        """
        Create an authorizer from a profile configuration.

        Args:
            config: Configuration specifying the profile to use
            **kwargs: Additional arguments passed to the authorizer factory

        Returns:
            An Authorizer instance configured according to the profile

        Raises:
            ValueError: If the profile name is unknown
        """
        normalized = _normalize_config(config)
        profile_config = _resolve_profile_config(normalized["profile"])

        logger.debug(
            "enabling_authorization_profile",
            extra={"profile": normalized["profile"]},
        )

        # Create the authorizer using the profile config
        authorizer = await AuthorizerFactory.create_authorizer(
            profile_config,
            **kwargs,
        )

        if authorizer is None:
            raise ValueError(
                f"Failed to create authorizer for profile: {normalized['profile']}"
            )

        return authorizer


# Factory metadata
FACTORY_META = {
    "base": AUTHORIZER_FACTORY_BASE_TYPE,
    "key": "AuthorizationProfile",
}
