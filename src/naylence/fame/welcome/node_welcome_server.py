import os
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI

from naylence.fame.fastapi.jwks_api_router import create_jwks_router
from naylence.fame.util.logging import enable_logging

from .node_welcome_fastapi_router import create_node_welcome_fastapi_router
from .welcome_service_factory import WelcomeServiceFactory

ENV_VAR_LOG_LEVEL = "FAME_LOG_LEVEL"
ENV_VAR_FAME_APP_HOST = "FAME_APP_HOST"
ENV_VAR_FAME_APP_PORT = "FAME_APP_PORT"

enable_logging(log_level=os.getenv(ENV_VAR_LOG_LEVEL, "warning"))


@asynccontextmanager
async def lifespan(app: FastAPI):
    welcome_service = await WelcomeServiceFactory.create_welcome_service()
    app.include_router(create_node_welcome_fastapi_router(welcome_service=welcome_service))
    app.include_router(create_jwks_router(prefix="/fame/welcome"))
    yield


if __name__ == "__main__":
    app = FastAPI(lifespan=lifespan)
    host = os.getenv(ENV_VAR_FAME_APP_HOST, "0.0.0.0")
    port = int(os.getenv(ENV_VAR_FAME_APP_PORT, 8090))
    uvicorn.run(app, host=host, port=port, log_level="info")
