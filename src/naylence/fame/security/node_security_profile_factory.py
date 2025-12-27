from __future__ import annotations

from typing import Any, Optional

from naylence.fame.factory import Expressions, create_resource
from naylence.fame.security.default_security_manager_factory import (
    DefaultSecurityManagerConfig,
)
from naylence.fame.security.security_manager_config import SecurityProfile
from naylence.fame.security.security_manager_factory import SecurityManagerFactory
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


PROFILE_NAME_STRICT_OVERLAY = "strict-overlay"
PROFILE_NAME_OVERLAY = "overlay"
PROFILE_NAME_OVERLAY_CALLBACK = "overlay-callback"
PROFILE_NAME_GATED = "gated"
PROFILE_NAME_GATED_CALLBACK = "gated-callback"
PROFILE_NAME_OPEN = "open"


STRICT_OVERLAY_PROFILE = {
    "type": "DefaultSecurityManager",
    "security_policy": {
        "type": "DefaultSecurityPolicy",
        "signing": {
            "signing_material": "x509-chain",
            "require_cert_sid_match": True,
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
                "allow_channel": True,
                "allow_sealed": True,
                "plaintext_violation_action": "nack",
                "channel_violation_action": "nack",
                "sealed_violation_action": "nack",
            },
            "response": {
                "mirror_request_level": True,
                "minimum_response_level": "plaintext",
                "escalate_sealed_responses": False,
            },
            "outbound": {
                "default_level": Expressions.env(ENV_VAR_DEFAULT_ENCRYPTION_LEVEL, default="plaintext"),
                "escalate_if_peer_supports": False,
                "prefer_sealed_for_sensitive": False,
            },
        },
    },
    "authorizer": {
        "type": "AuthorizationProfile",
        "profile": Expressions.env(ENV_VAR_AUTHORIZATION_PROFILE, default="jwt"),
    },
}

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


class SecurityProfileFactory(SecurityManagerFactory):
    async def create(
        self, config: Optional[SecurityProfile | dict[str, Any]] = None, **kwargs: Any
    ) -> SecurityManager:
        if isinstance(config, dict):
            config = SecurityProfile(**config)
        elif config is None:
            config = SecurityProfile(profile=PROFILE_NAME_OVERLAY)

        profile = config.profile

        if profile == PROFILE_NAME_OVERLAY:
            security_config = DefaultSecurityManagerConfig(**OVERLAY_PROFILE)
        elif profile == PROFILE_NAME_OVERLAY_CALLBACK:
            security_config = DefaultSecurityManagerConfig(**OVERLAY_CALLBACK_PROFILE)
        elif profile == PROFILE_NAME_STRICT_OVERLAY:
            security_config = DefaultSecurityManagerConfig(**STRICT_OVERLAY_PROFILE)
        elif profile == PROFILE_NAME_GATED:
            security_config = DefaultSecurityManagerConfig(**GATED_PROFILE)
        elif profile == PROFILE_NAME_GATED_CALLBACK:
            security_config = DefaultSecurityManagerConfig(**GATED_CALLBACK_PROFILE)
        elif profile == PROFILE_NAME_OPEN:
            security_config = DefaultSecurityManagerConfig(**OPEN_PROFILE)
        else:
            raise ValueError(f"Unknown security profile: {profile}")

        logger.debug("enabling_security_profile", profile=profile)  # type: ignore

        return await create_resource(SecurityManagerFactory, security_config, **kwargs)
