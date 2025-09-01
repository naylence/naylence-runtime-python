from __future__ import annotations

from abc import abstractmethod
from typing import TYPE_CHECKING, Any, Dict, List, Optional, TypeVar, Union

from naylence.fame.connector.connector_config import ConnectorConfig
from naylence.fame.core import FameConnector
from naylence.fame.factory import ExtensionManager, ResourceFactory, create_resource
from naylence.fame.util.logging import getLogger

if TYPE_CHECKING:
    from naylence.fame.grants.connection_grant import ConnectionGrant

C = TypeVar("C", bound=ConnectorConfig)

logger = getLogger(__name__)


class ConnectorFactory(ResourceFactory[FameConnector, C]):
    """
    Base factory for creating FameConnector instances from either ConnectorConfig or ConnectionGrant.

    Concrete implementations must define supported grant types and provide grant-to-connector
    conversion logic.
    """

    @classmethod
    @abstractmethod
    def supported_grant_types(cls) -> List[str]:
        """
        Return list of connection grant types that this factory can handle.

        Returns:
            List of grant type strings (e.g., ["WebSocketConnectionGrant", "WebSocketConnector"])
        """
        pass

    @classmethod
    @abstractmethod
    def config_from_grant(cls, grant: Union[ConnectionGrant, Dict[str, Any]]) -> ConnectorConfig:
        """
        Create a ConnectorConfig instance from a connection grant or dictionary.

        Args:
            grant: The connection grant or dictionary representation to convert to a config

        Returns:
            ConnectorConfig instance
        """
        pass

    @staticmethod
    async def create_connector(
        config_or_grant: Union[ConnectorConfig, ConnectionGrant, Dict[str, Any]], **kwargs: Any
    ) -> FameConnector:
        """
        Create a connector from either a ConnectorConfig or ConnectionGrant.

        This method uses the extension discovery mechanism to find an appropriate
        factory that supports the given grant type.

        Args:
            config_or_grant: Either a ConnectorConfig, ConnectionGrant, or dict representation
            **kwargs: Additional arguments passed to the factory

        Returns:
            FameConnector instance

        Raises:
            ValueError: If no suitable factory is found for the grant/config type
            RuntimeError: If multiple factories claim to support the same grant type
        """
        # Handle ConnectorConfig case - use existing resource creation mechanism
        if isinstance(config_or_grant, ConnectorConfig):
            return await create_resource(ConnectorFactory, config_or_grant, **kwargs)

        # Handle ConnectionGrant case - find appropriate factory via extension discovery
        from naylence.fame.grants.connection_grant import ConnectionGrant

        connector_config: Optional[ConnectorConfig] = None
        grant_type: Optional[str] = None

        if isinstance(config_or_grant, dict):
            # Check if this is a grant type by testing known factories
            grant_type = config_or_grant.get("type")
        elif isinstance(config_or_grant, ConnectionGrant):
            grant_type = config_or_grant.type

        if not connector_config:
            if not grant_type:
                raise ValueError("Missing 'type' field in configuration")

            factories = ExtensionManager.get_extensions_by_type(ConnectorFactory)
            for factory_class in factories.values():
                try:
                    # Ensure factory_class is a subclass of ConnectorFactory
                    # before calling supported_grant_types
                    if (
                        issubclass(factory_class, ConnectorFactory)
                        and grant_type in factory_class.supported_grant_types()
                    ):
                        # We found a factory that supports this grant type
                        # Let the factory handle the grant/dict conversion directly
                        connector_config = factory_class.config_from_grant(config_or_grant)
                        break
                except Exception as e:
                    logger.warning(f"Failed to create connector config from grant: {e}")
                    # Skip factories that can't be found or introspected
                    continue

        if not connector_config:
            raise ValueError("No suitable connector configuration found")

        return await create_resource(ConnectorFactory, connector_config, **kwargs)
