"""
Connector Selection Policy for choosing the appropriate connector type when handling NodeAttach frames.

This module addresses the architectural concerns about hardcoded connector selection
by providing a pluggable policy system that considers:
- Client's supported inbound connectors
- Node preferences
- Inbound connector type that received the request
- Fallback strategies
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Protocol

from naylence.fame.util.logging import getLogger

if TYPE_CHECKING:
    from naylence.fame.connector.connector_config import ConnectorConfig
    from naylence.fame.core import NodeAttachFrame
    from naylence.fame.node.routing_node_like import RoutingNodeLike

logger = getLogger(__name__)


class ConnectorType(Enum):
    """Known connector types."""

    HTTP_STATELESS = "HttpStatelessConnector"
    WEBSOCKET_STATELESS = "WebSocketStatelessConnector"
    WEBSOCKET = "WebSocketConnector"


@dataclass
class ConnectorSelectionContext:
    """Context information for connector selection decisions."""

    child_id: str
    attach_frame: NodeAttachFrame
    inbound_connector_type: str  # Type of connector that received the attach request
    node: RoutingNodeLike

    @property
    def client_supported_connectors(self) -> List[Dict[str, Any]]:
        """Get the list of connectors supported by the client."""
        if not self.attach_frame.supported_inbound_connectors:
            return []

        # Convert any connector config objects to dicts for uniform processing
        result = []
        for connector in self.attach_frame.supported_inbound_connectors:
            if isinstance(connector, dict):
                result.append(connector)
            else:
                # Assume it's a ConnectorConfig with model_dump method
                result.append(connector.model_dump(by_alias=True))
        return result


class ConnectorSelectionResult:
    """Result of connector selection containing the chosen config and metadata."""

    def __init__(
        self,
        connector_config: ConnectorConfig,
        selection_reason: str,
        fallback_used: bool = False,
    ):
        self.connector_config = connector_config
        self.selection_reason = selection_reason
        self.fallback_used = fallback_used

    def __repr__(self) -> str:
        return (
            f"ConnectorSelectionResult("
            f"type={self.connector_config.type}, "
            f"reason='{self.selection_reason}', "
            f"fallback={self.fallback_used})"
        )


class ConnectorSelectionStrategy(Protocol):
    """Protocol for connector selection strategies."""

    def select_connector(self, context: ConnectorSelectionContext) -> Optional[ConnectorSelectionResult]:
        """
        Select a connector configuration based on the context.

        Returns:
            ConnectorSelectionResult if a suitable connector is found, None otherwise
        """
        ...


class ConnectorSelectionPolicy:
    """
    Main policy class that orchestrates connector selection using pluggable strategies.

    This addresses the TODO comments by providing a flexible, configurable approach
    to connector selection that considers client preferences, node policies, and
    fallback strategies.
    """

    def __init__(self, strategies: Optional[List[ConnectorSelectionStrategy]] = None):
        self.strategies = strategies or [
            PreferSameTypeStrategy(),
            PreferHttpStrategy(),
            ClientPreferenceStrategy(),
        ]

    def select_connector(self, context: ConnectorSelectionContext) -> ConnectorSelectionResult:
        """
        Select the best connector for the given context.

        Iterates through strategies until one returns a result.
        Raises ValueError if no suitable connector can be found.
        """
        logger.debug(
            "selecting_connector",
            child=context.child_id,
            inbound_type=context.inbound_connector_type,
            client_connectors=[c.get("type") for c in context.client_supported_connectors],
        )

        for strategy in self.strategies:
            result = strategy.select_connector(context)
            if result:
                logger.debug(
                    "connector_selected",
                    child=context.child_id,
                    selected_type=result.connector_config.type,
                    strategy=strategy.__class__.__name__,
                    reason=result.selection_reason,
                    fallback=result.fallback_used,
                )
                return result

        # No suitable connector found - raise error with detailed information
        supported_types = [c.get("type") for c in context.client_supported_connectors]
        error_msg = (
            f"No suitable connector found for child {context.child_id}. "
            f"Client supports: {supported_types}, "
            f"inbound type: {context.inbound_connector_type}"
        )

        logger.warning(
            "connector_selection_failed",
            child=context.child_id,
            client_connectors=supported_types,
            inbound_type=context.inbound_connector_type,
            reason="No matching strategy found",
        )

        raise ValueError(error_msg)


class PreferSameTypeStrategy:
    """Strategy that prefers to use the same connector type as the inbound connection."""

    def select_connector(self, context: ConnectorSelectionContext) -> Optional[ConnectorSelectionResult]:
        """Select connector matching the inbound connector type if available."""
        target_type = context.inbound_connector_type

        for connector_dict in context.client_supported_connectors:
            if connector_dict.get("type") == target_type:
                config = self._create_config_from_dict(connector_dict)
                if config:
                    return ConnectorSelectionResult(
                        connector_config=config,
                        selection_reason=f"Matching inbound connector type: {target_type}",
                    )

        return None

    def _create_config_from_dict(self, connector_dict: Dict[str, Any]) -> Optional[ConnectorConfig]:
        """Create a connector config from a dictionary representation."""
        connector_type = connector_dict.get("type")

        if connector_type == ConnectorType.HTTP_STATELESS.value:
            return self._create_http_config(connector_dict)
        elif connector_type in [
            ConnectorType.WEBSOCKET.value,
            ConnectorType.WEBSOCKET_STATELESS.value,
        ]:
            return self._create_websocket_config(connector_dict)

        return None

    def _create_http_config(self, connector_dict: Dict[str, Any]) -> Optional[ConnectorConfig]:
        """Create HTTP connector config from dict."""
        from naylence.fame.connector.http_stateless_connector_factory import (
            HttpStatelessConnectorConfig,
        )

        # Extract URL from the dict
        url = connector_dict.get("url") or connector_dict.get("params", {}).get("url")
        if not url:
            return None

        return HttpStatelessConnectorConfig(
            url=url,
            max_queue=connector_dict.get("max_queue", 1024),
            auth=connector_dict.get("auth"),
        )

    def _create_websocket_config(self, connector_dict: Dict[str, Any]) -> Optional[ConnectorConfig]:
        """Create WebSocket connector config from dict."""
        from naylence.fame.connector.websocket_connector_factory import (
            WebSocketConnectorConfig,
        )

        params = connector_dict.get("params", {})
        if not params:
            return None

        return WebSocketConnectorConfig(
            type=connector_dict.get("type", "WebSocketConnector"),
            params=params,
            auth=connector_dict.get("auth"),
        )


class PreferHttpStrategy:
    """Strategy that prefers HTTP connectors when available."""

    def select_connector(self, context: ConnectorSelectionContext) -> Optional[ConnectorSelectionResult]:
        """Select HTTP connector if available."""
        for connector_dict in context.client_supported_connectors:
            if connector_dict.get("type") == ConnectorType.HTTP_STATELESS.value:
                config = self._create_http_config(connector_dict)
                if config:
                    return ConnectorSelectionResult(
                        connector_config=config,
                        selection_reason="Preferred HTTP connector type",
                    )

        return None

    def _create_http_config(self, connector_dict: Dict[str, Any]) -> Optional[ConnectorConfig]:
        """Create HTTP connector config from dict."""
        from naylence.fame.connector.http_stateless_connector_factory import (
            HttpStatelessConnectorConfig,
        )

        url = connector_dict.get("url") or connector_dict.get("params", {}).get("url")
        if not url:
            return None

        return HttpStatelessConnectorConfig(
            url=url,
            max_queue=connector_dict.get("max_queue", 1024),
            auth=connector_dict.get("auth"),
        )


class ClientPreferenceStrategy:
    """Strategy that uses the first connector provided by the client."""

    def select_connector(self, context: ConnectorSelectionContext) -> Optional[ConnectorSelectionResult]:
        """Select the first available connector from the client's list."""
        if not context.client_supported_connectors:
            return None

        first_connector = context.client_supported_connectors[0]
        config = self._create_config_from_dict(first_connector)

        if config:
            return ConnectorSelectionResult(
                connector_config=config,
                selection_reason=f"Client's first preference: {first_connector.get('type')}",
            )

        return None

    def _create_config_from_dict(self, connector_dict: Dict[str, Any]) -> Optional[ConnectorConfig]:
        """Create a connector config from a dictionary representation."""
        # Reuse the logic from PreferSameTypeStrategy
        strategy = PreferSameTypeStrategy()
        return strategy._create_config_from_dict(connector_dict)


# Default policy instance
default_connector_selection_policy = ConnectorSelectionPolicy()
