from __future__ import annotations

from typing import Any, Optional

from naylence.fame.factory import Expressions, create_resource
from naylence.fame.profile import RegisterProfileOptions, get_profile, register_profile
from naylence.fame.profile.profile_discovery import discover_profile
from naylence.fame.security.default_security_manager_factory import (
    DefaultSecurityManagerConfig,
)
from naylence.fame.security.security_manager_config import SecurityProfile
from naylence.fame.security.security_manager_factory import (
    SECURITY_MANAGER_FACTORY_BASE_TYPE,
    SecurityManagerFactory,
)
from naylence.fame.util.logging import getLogger

from .security_manager import SecurityManager

logger = getLogger(__name__)


# Environment variables - exported for external use
ENV_VAR_JWT_TRUSTED_ISSUER = "FAME_JWT_TRUSTED_ISSUER"
ENV_VAR_JWT_ALGORITHM = "FAME_JWT_ALGORITHM"
ENV_VAR_JWT_AUDIENCE = "FAME_JWT_AUDIENCE"
ENV_VAR_JWKS_URL = "FAME_JWKS_URL"
ENV_VAR_DEFAULT_ENCRYPTION_LEVEL = "FAME_DEFAULT_ENCRYPTION_LEVEL"
ENV_VAR_HMAC_SECRET = "FAME_HMAC_SECRET"
ENV_VAR_JWT_REVERSE_AUTH_TRUSTED_ISSUER = "FAME_JWT_REVERSE_AUTH_TRUSTED_ISSUER"
ENV_VAR_JWT_REVERSE_AUTH_AUDIENCE = "FAME_JWT_REVERSE_AUTH_AUDIENCE"
ENV_VAR_ENFORCE_TOKEN_SUBJECT_NODE_IDENTITY = "FAME_ENFORCE_TOKEN_SUBJECT_NODE_IDENTITY"
ENV_VAR_TRUSTED_CLIENT_SCOPE = "FAME_TRUSTED_CLIENT_SCOPE"
ENV_VAR_AUTHORIZATION_PROFILE = "FAME_AUTHORIZATION_PROFILE"


PROFILE_NAME_OVERLAY = "overlay"
PROFILE_NAME_OVERLAY_CALLBACK = "overlay-callback"
PROFILE_NAME_GATED = "gated"
PROFILE_NAME_GATED_CALLBACK = "gated-callback"
PROFILE_NAME_OPEN = "open"


OVERLAY_PROFILE = {
    "type": "DefaultSecurityManager",
    "security_policy": {
        "type": "DefaultSecurityPolicy",
        "signing": {
            "signing_material": "raw-key",
            "inbound": {
                "signature_policy": "required",
                "unsigned_violation_action": "nack",
                "invalid_signature_action": "nack",
            },
            "response": {
                "mirror_request_signing": True,
                "always_sign_responses": False,
                "sign_error_responses": True,
            },
            "outbound": {
                "default_signing": True,
                "sign_sensitive_operations": True,
                "sign_if_recipient_expects": True,
            },
        },
        "encryption": {
            "inbound": {
                "allow_plaintext": True,
                "allow_channel": False,
                "allow_sealed": False,
                "plaintext_violation_action": "nack",
                "channel_violation_action": "nack",
                "sealed_violation_action": "nack",
            },
            "response": {
                "mirror_request_level": False,
                "minimum_response_level": "plaintext",
                "escalate_sealed_responses": False,
            },
            "outbound": {
                "default_level": "plaintext",
                "escalate_if_peer_supports": False,
                "prefer_sealed_for_sensitive": False,
            },
        },
    },
    "authorizer": {
        "type": "AuthorizationProfile",
        "profile": Expressions.env(ENV_VAR_AUTHORIZATION_PROFILE, default="oauth2"),
    },
}

OVERLAY_CALLBACK_PROFILE = {
    "type": "DefaultSecurityManager",
    "security_policy": {
        "type": "DefaultSecurityPolicy",
        "signing": {
            "signing_material": "raw-key",
            "inbound": {
                "signature_policy": "required",
                "unsigned_violation_action": "nack",
                "invalid_signature_action": "nack",
            },
            "response": {
                "mirror_request_signing": True,
                "always_sign_responses": False,
                "sign_error_responses": True,
            },
            "outbound": {
                "default_signing": True,
                "sign_sensitive_operations": True,
                "sign_if_recipient_expects": True,
            },
        },
        "encryption": {
            "inbound": {
                "allow_plaintext": True,
                "allow_channel": False,
                "allow_sealed": False,
                "plaintext_violation_action": "nack",
                "channel_violation_action": "nack",
                "sealed_violation_action": "nack",
            },
            "response": {
                "mirror_request_level": False,
                "minimum_response_level": "plaintext",
                "escalate_sealed_responses": False,
            },
            "outbound": {
                "default_level": "plaintext",
                "escalate_if_peer_supports": False,
                "prefer_sealed_for_sensitive": False,
            },
        },
    },
    "authorizer": {
        "type": "AuthorizationProfile",
        "profile": Expressions.env(ENV_VAR_AUTHORIZATION_PROFILE, default="oauth2-callback"),
    },
}

GATED_PROFILE = {
    "type": "DefaultSecurityManager",
    "security_policy": {
        "type": "DefaultSecurityPolicy",
        "signing": {
            "inbound": {
                "signature_policy": "disabled",
                "unsigned_violation_action": "allow",
                "invalid_signature_action": "allow",
            },
            "response": {
                "mirror_request_signing": False,
                "always_sign_responses": False,
                "sign_error_responses": False,
            },
            "outbound": {
                "default_signing": False,
                "sign_sensitive_operations": False,
                "sign_if_recipient_expects": False,
            },
        },
        "encryption": {
            "inbound": {
                "allow_plaintext": True,
                "allow_channel": False,
                "allow_sealed": False,
                "plaintext_violation_action": "allow",
                "channel_violation_action": "nack",
                "sealed_violation_action": "nack",
            },
            "response": {
                "mirror_request_level": True,
                "minimum_response_level": "plaintext",
                "escalate_sealed_responses": False,
            },
            "outbound": {
                "default_level": "plaintext",
                "escalate_if_peer_supports": False,
                "prefer_sealed_for_sensitive": False,
            },
        },
    },
    "authorizer": {
        "type": "AuthorizationProfile",
        "profile": Expressions.env(ENV_VAR_AUTHORIZATION_PROFILE, default="oauth2-gated"),
    },
}


GATED_CALLBACK_PROFILE = {
    "type": "DefaultSecurityManager",
    "security_policy": {
        "type": "DefaultSecurityPolicy",
        "signing": {
            "inbound": {
                "signature_policy": "disabled",
                "unsigned_violation_action": "allow",
                "invalid_signature_action": "allow",
            },
            "response": {
                "mirror_request_signing": False,
                "always_sign_responses": False,
                "sign_error_responses": False,
            },
            "outbound": {
                "default_signing": False,
                "sign_sensitive_operations": False,
                "sign_if_recipient_expects": False,
            },
        },
        "encryption": {
            "inbound": {
                "allow_plaintext": True,
                "allow_channel": False,
                "allow_sealed": False,
                "plaintext_violation_action": "allow",
                "channel_violation_action": "nack",
                "sealed_violation_action": "nack",
            },
            "response": {
                "mirror_request_level": True,
                "minimum_response_level": "plaintext",
                "escalate_sealed_responses": False,
            },
            "outbound": {
                "default_level": "plaintext",
                "escalate_if_peer_supports": False,
                "prefer_sealed_for_sensitive": False,
            },
        },
    },
    "authorizer": {
        "type": "AuthorizationProfile",
        "profile": Expressions.env(ENV_VAR_AUTHORIZATION_PROFILE, default="oauth2-callback"),
    },
}

OPEN_PROFILE = {
    "type": "DefaultSecurityManager",
    "security_policy": {
        "type": "NoSecurityPolicy",
    },
    "authorizer": {
        "type": "AuthorizationProfile",
        "profile": Expressions.env(ENV_VAR_AUTHORIZATION_PROFILE, default="noop"),
    },
}


# Profile registration state
_PROFILE_SOURCE = "node-security-profile-factory"
_profiles_registered = False


def _ensure_builtin_profiles_registered() -> None:
    """Ensure built-in security profiles are registered.

    This function is idempotent and can be called multiple times safely.
    It re-registers profiles if they were cleared (e.g., during testing).
    """
    global _profiles_registered

    # Check if already registered by looking for a known profile
    if get_profile(SECURITY_MANAGER_FACTORY_BASE_TYPE, PROFILE_NAME_OVERLAY) is not None:
        return

    opts = RegisterProfileOptions(source=_PROFILE_SOURCE)

    register_profile(
        SECURITY_MANAGER_FACTORY_BASE_TYPE,
        PROFILE_NAME_OVERLAY,
        OVERLAY_PROFILE,
        opts,
    )
    register_profile(
        SECURITY_MANAGER_FACTORY_BASE_TYPE,
        PROFILE_NAME_OVERLAY_CALLBACK,
        OVERLAY_CALLBACK_PROFILE,
        opts,
    )
    register_profile(
        SECURITY_MANAGER_FACTORY_BASE_TYPE,
        PROFILE_NAME_GATED,
        GATED_PROFILE,
        opts,
    )
    register_profile(
        SECURITY_MANAGER_FACTORY_BASE_TYPE,
        PROFILE_NAME_GATED_CALLBACK,
        GATED_CALLBACK_PROFILE,
        opts,
    )
    register_profile(
        SECURITY_MANAGER_FACTORY_BASE_TYPE,
        PROFILE_NAME_OPEN,
        OPEN_PROFILE,
        opts,
    )
    _profiles_registered = True


# Register built-in security profiles at module load time
_ensure_builtin_profiles_registered()


def _normalize_profile(
    config: Optional[SecurityProfile | dict[str, Any]],
) -> str:
    """Normalize profile configuration to a profile name string."""
    if config is None:
        return PROFILE_NAME_OVERLAY

    if isinstance(config, SecurityProfile):
        profile = config.profile
    elif isinstance(config, dict):
        # Support multiple key variants for profile name
        profile = (
            config.get("profile")
            or config.get("profile_name")
            or config.get("profileName")
            or PROFILE_NAME_OVERLAY
        )
    else:
        return PROFILE_NAME_OVERLAY

    if not isinstance(profile, str) or not profile.strip():
        return PROFILE_NAME_OVERLAY

    return profile.lower()


def _resolve_profile_config(profile_name: str) -> dict[str, Any]:
    """Resolve a profile name to its configuration dict."""
    # Ensure profiles are registered before lookup (handles test cleanup scenarios)
    _ensure_builtin_profiles_registered()

    template = get_profile(SECURITY_MANAGER_FACTORY_BASE_TYPE, profile_name)
    if template is not None:
        return template

    # Profile not found in registry - try to discover from entry points
    # This allows external packages (e.g., naylence-advanced-security) to provide profiles
    discover_profile(SECURITY_MANAGER_FACTORY_BASE_TYPE, profile_name)

    # Try again after discovery
    template = get_profile(SECURITY_MANAGER_FACTORY_BASE_TYPE, profile_name)
    if template is None:
        raise ValueError(f"Unknown security profile: {profile_name}")
    return template


class SecurityProfileFactory(SecurityManagerFactory):
    async def create(
        self, config: Optional[SecurityProfile | dict[str, Any]] = None, **kwargs: Any
    ) -> SecurityManager:
        profile = _normalize_profile(config)
        profile_config = _resolve_profile_config(profile)

        logger.debug("enabling_security_profile", profile=profile)  # type: ignore

        security_config = DefaultSecurityManagerConfig(**profile_config)
        return await create_resource(SecurityManagerFactory, security_config, **kwargs)
