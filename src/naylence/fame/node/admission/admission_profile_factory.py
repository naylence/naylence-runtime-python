from __future__ import annotations

from typing import Any, Optional

from pydantic import Field

from naylence.fame.constants.ttl_constants import DEFAULT_ADMISSION_TTL_SEC
from naylence.fame.factory import Expressions, create_resource
from naylence.fame.grants.grant import GRANT_PURPOSE_NODE_ATTACH
from naylence.fame.node.admission.admission_client import AdmissionClient
from naylence.fame.node.admission.admission_client_factory import (
    AdmissionClientFactory,
    AdmissionConfig,
)
from naylence.fame.util.logging import getLogger

logger = getLogger(__name__)

ENV_VAR_IS_ROOT = "FAME_ROOT"
ENV_VAR_JWT_TRUSTED_ISSUER = "FAME_JWT_TRUSTED_ISSUER"
ENV_VAR_JWT_ALGORITHM = "FAME_JWT_ALGORITHM"
ENV_VAR_JWT_AUDIENCE = "FAME_JWT_AUDIENCE"
ENV_VAR_JWKS_URL = "FAME_JWKS_URL"
ENV_VAR_ADMISSION_TOKEN_URL = "FAME_ADMISSION_TOKEN_URL"
ENV_VAR_ADMISSION_CLIENT_ID = "FAME_ADMISSION_CLIENT_ID"
ENV_VAR_ADMISSION_CLIENT_SECRET = "FAME_ADMISSION_CLIENT_SECRET"
ENV_VAR_DIRECT_ADMISSION_URL = "FAME_DIRECT_ADMISSION_URL"
ENV_VAR_ADMISSION_SERVICE_URL = "FAME_ADMISSION_SERVICE_URL"
ENV_VAR_ADMISSION_TTL = "FAME_ADMISSSION_TTL"

PROFILE_NAME_WELCOME = "welcome"
PROFILE_NAME_DIRECT = "direct"
PROFILE_NAME_DIRECT_HTTP = "direct-http"
PROFILE_NAME_OPEN = "open"
PROFILE_NAME_NOOP = "noop"
PROFILE_NAME_NONE = "none"

# Use centralized constant instead of hardcoded value
DEFAULT_ADMISSION_TTL = DEFAULT_ADMISSION_TTL_SEC

WELCOME_SERVICE_PROFILE = {
    "type": "WelcomeServiceClient",
    "is_root": Expressions.env(ENV_VAR_IS_ROOT, default="false"),
    "url": Expressions.env(ENV_VAR_ADMISSION_SERVICE_URL),
    "supported_transports": ["websocket"],
    "auth": {
        "type": "BearerTokenHeaderAuth",
        "token_provider": {
            "type": "OAuth2ClientCredentialsTokenProvider",
            "token_url": Expressions.env(ENV_VAR_ADMISSION_TOKEN_URL),
            "client_id": Expressions.env(ENV_VAR_ADMISSION_CLIENT_ID),
            "client_secret": Expressions.env(ENV_VAR_ADMISSION_CLIENT_SECRET),
            "scopes": ["node.connect"],
            "audience": Expressions.env(ENV_VAR_JWT_AUDIENCE),
        },
    },
}

DIRECT_PROFILE = {
    "type": "DirectAdmissionClient",
    "connection_grants": [
        {
            "type": "WebSocketConnectionGrant",
            "purpose": GRANT_PURPOSE_NODE_ATTACH,
            "url": Expressions.env(ENV_VAR_DIRECT_ADMISSION_URL),
            "auth": {
                "type": "WebSocketSubprotocolAuth",
                "token_provider": {
                    "type": "OAuth2ClientCredentialsTokenProvider",
                    "token_url": Expressions.env(ENV_VAR_ADMISSION_TOKEN_URL),
                    "client_id": Expressions.env(ENV_VAR_ADMISSION_CLIENT_ID),
                    "client_secret": Expressions.env(ENV_VAR_ADMISSION_CLIENT_SECRET),
                    "scopes": ["node.connect"],
                    "audience": Expressions.env(ENV_VAR_JWT_AUDIENCE),
                },
            },
            "ttl": 0,
            "durable": False,
        }
    ],
}


DIRECT_HTTP_PROFILE = {
    "type": "DirectAdmissionClient",
    "connection_grants": [
        {
            "type": "HttpConnectionGrant",
            "purpose": GRANT_PURPOSE_NODE_ATTACH,
            "url": Expressions.env(ENV_VAR_DIRECT_ADMISSION_URL),
            "auth": {
                "type": "BearerTokenHeaderAuth",
                "token_provider": {
                    "type": "OAuth2ClientCredentialsTokenProvider",
                    "token_url": Expressions.env(ENV_VAR_ADMISSION_TOKEN_URL),
                    "client_id": Expressions.env(ENV_VAR_ADMISSION_CLIENT_ID),
                    "client_secret": Expressions.env(ENV_VAR_ADMISSION_CLIENT_SECRET),
                    "scopes": ["node.connect"],
                    "audience": Expressions.env(ENV_VAR_JWT_AUDIENCE),
                },
            },
            "ttl": 0,
            "durable": False,
        }
    ],
}


OPEN_PROFILE = {
    "type": "DirectAdmissionClient",
    "connection_grants": [
        {
            "type": "WebSocketConnectionGrant",
            "purpose": GRANT_PURPOSE_NODE_ATTACH,
            "url": Expressions.env(ENV_VAR_DIRECT_ADMISSION_URL),
            "auth": {
                "type": "NoAuth",
            },
            "ttl": 0,
            "durable": False,
        }
    ],
}


NOOP_PROFILE = {
    "type": "NoopAdmissionClient",
    "auto_accept_logicals": True,
}


class AdmissionProfileConfig(AdmissionConfig):
    type: str = "AdmissionProfile"

    profile: Optional[str] = Field(default=None, description="Admission profile name")


class AdmissionProfileFactory(AdmissionClientFactory):
    async def create(
        self,
        config: Optional[AdmissionProfileConfig | dict[str, Any]] = None,
        **kwargs: Any,
    ) -> AdmissionClient:
        if isinstance(config, dict):
            config = AdmissionProfileConfig(**config)
        elif config is None:
            config = AdmissionProfileConfig(profile=PROFILE_NAME_DIRECT)

        profile = config.profile

        if profile in [PROFILE_NAME_NOOP, PROFILE_NAME_NONE]:
            from naylence.fame.node.admission.noop_admission_client_factory import (
                NoopAdmissionConfig,
            )

            admission_config = NoopAdmissionConfig(**NOOP_PROFILE)
        elif profile == PROFILE_NAME_DIRECT:
            from naylence.fame.node.admission.direct_admission_client_factory import (
                DirectNodeAdmissionConfig,
            )

            admission_config = DirectNodeAdmissionConfig(**DIRECT_PROFILE)
        elif profile == PROFILE_NAME_DIRECT_HTTP:
            from naylence.fame.node.admission.direct_admission_client_factory import (
                DirectNodeAdmissionConfig,
            )

            admission_config = DirectNodeAdmissionConfig(**DIRECT_HTTP_PROFILE)
        elif profile == PROFILE_NAME_OPEN:
            from naylence.fame.node.admission.direct_admission_client_factory import (
                DirectNodeAdmissionConfig,
            )

            admission_config = DirectNodeAdmissionConfig(**OPEN_PROFILE)
        elif profile == PROFILE_NAME_WELCOME:
            from naylence.fame.node.admission.welcome_service_client_factory import (
                WelcomeServiceClientConfig,
            )

            admission_config = WelcomeServiceClientConfig(**WELCOME_SERVICE_PROFILE)
        else:
            raise ValueError(f"Unknown admission profile: {profile}")

        logger.debug("enabling_admission_profile", profile=profile)  # type: ignore

        return await create_resource(AdmissionClientFactory, admission_config, **kwargs)
