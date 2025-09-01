from typing import Any, Optional, TypeVar

from pydantic import ConfigDict

from naylence.fame.factory import ResourceConfig, ResourceFactory, create_default_resource, create_resource
from naylence.fame.welcome.welcome_service import WelcomeService


class WelcomeServiceConfig(ResourceConfig):
    type: str = "WelcomeService"

    model_config = ConfigDict(extra="allow")


C = TypeVar("C", bound=WelcomeServiceConfig)


class WelcomeServiceFactory(ResourceFactory[WelcomeService, C]):
    @staticmethod
    async def create_welcome_service(
        config: Optional[WelcomeServiceConfig | dict[str, Any]] = None,
        **kwargs: dict[str, Any],
    ) -> WelcomeService:
        if not config:
            from naylence.fame.config.config import ExtendedFameConfig, get_fame_config

            fame_config = get_fame_config()
            assert isinstance(fame_config, ExtendedFameConfig)
            config = fame_config.welcome

        if isinstance(config, dict):
            if "type" not in config:
                service = await create_default_resource(WelcomeServiceFactory, config, **kwargs)
                assert service is not None
                return service
            else:
                config = WelcomeServiceConfig(**config)

        return await create_resource(WelcomeServiceFactory, config, **kwargs)
