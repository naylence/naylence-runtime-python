import os

import uvicorn

from fastapi import FastAPI
from naylence.fame.fastapi.jwks_api_router import create_jwks_router
from naylence.fame.fastapi.oauth2_token_router import create_oauth2_token_router
from naylence.fame.fastapi.openid_configuration_router import create_openid_configuration_router
from naylence.fame.security.crypto.providers.crypto_provider import get_crypto_provider
from naylence.fame.util.logging import enable_logging

ENV_VAR_LOG_LEVEL = "FAME_LOG_LEVEL"

enable_logging(log_level=os.getenv(ENV_VAR_LOG_LEVEL, "trace"))


def create_app() -> FastAPI:
    app = FastAPI()
    crypto_provider = get_crypto_provider()
    app.include_router(create_oauth2_token_router(crypto_provider=crypto_provider))
    app.include_router(create_jwks_router())
    app.include_router(create_openid_configuration_router())
    return app


if __name__ == "__main__":
    app = create_app()
    host = os.getenv("APP_HOST", "0.0.0.0")
    port = int(os.getenv("APP_PORT", 8099))
    uvicorn.run(app, host=host, port=port, log_level="info")
