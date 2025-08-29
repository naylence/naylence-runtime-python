from typing import Any, Optional, TypeVar

from pydantic import Field

from naylence.fame.factory import ResourceConfig, ResourceFactory, create_default_resource, create_resource
from naylence.fame.node.node_like import NodeLike


class NodeLikeConfig(ResourceConfig):
    type: str = "NodeLike"

    storage_provider: Optional[Any] = Field(
        default=None,
        description="Storage provider configuration for key-value stores",
    )


C = TypeVar("C", bound=NodeLikeConfig)


class NodeLikeFactory(ResourceFactory[NodeLike, C]):
    @staticmethod
    async def create_node(config: Optional[NodeLikeConfig | dict[str, Any]] = None, **kwargs) -> NodeLike:
        if not config:
            from naylence.fame.config.config import ExtendedFameConfig, get_fame_config

            fame_config = get_fame_config()
            assert isinstance(fame_config, ExtendedFameConfig)
            config = fame_config.node

        if config is None:
            node = await create_default_resource(NodeLikeFactory, **kwargs)
            assert node, "Failed to create default NodeLike resource"
            return node

        elif isinstance(config, dict):
            if "type" not in config:
                node = await create_default_resource(NodeLikeFactory, config, **kwargs)
                assert node, "Failed to create default NodeLike resource"
                return node
            else:
                config = NodeLikeConfig(**config)

        return await create_resource(NodeLikeFactory, config)
