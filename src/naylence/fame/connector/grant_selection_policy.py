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

from naylence.fame.grants.connection_grant import ConnectionGrant
from naylence.fame.grants.grant import GRANT_PURPOSE_NODE_ATTACH
from naylence.fame.grants.http_connection_grant import HttpConnectionGrant
from naylence.fame.util.logging import getLogger

if TYPE_CHECKING:
    from naylence.fame.core import NodeAttachFrame
    from naylence.fame.node.routing_node_like import RoutingNodeLike

logger = getLogger(__name__)


class ConnectorType(Enum):
    """Known connector types."""

    HTTP_STATELESS = "HttpStatelessConnector"
    WEBSOCKET_STATELESS = "WebSocketStatelessConnector"
    WEBSOCKET = "WebSocketConnector"


@dataclass
class GrantSelectionContext:
    """Context information for connector selection decisions."""

    child_id: str
    attach_frame: NodeAttachFrame
    callback_grant_type: str  # Type of connector that received the attach request
    node: RoutingNodeLike

    @property
    def client_supported_callback_grants(self) -> List[Dict[str, Any]]:
        """Get the list of connectors supported by the client."""
        if not self.attach_frame.callback_grants:
            return []

        # Convert any connector config objects to dicts for uniform processing
        result = []
        for connector in self.attach_frame.callback_grants:
            if isinstance(connector, dict):
                result.append(connector)
            else:
                # Assume it's a ConnectorConfig with model_dump method
                result.append(connector.model_dump(by_alias=True))
        return result


class GrantSelectionResult:
    """Result of connector selection containing the chosen config and metadata."""

    def __init__(
        self,
        grant: ConnectionGrant,
        selection_reason: str,
        fallback_used: bool = False,
    ):
        self.grant = grant
        self.selection_reason = selection_reason
        self.fallback_used = fallback_used

    def __repr__(self) -> str:
        return (
            f"GrantSelectionResult("
            f"type={self.grant.type}, "
            f"reason='{self.selection_reason}', "
            f"fallback={self.fallback_used})"
        )


class GrantSelectionStrategy(Protocol):
    """Protocol for connector selection strategies."""

    def select_callback_grant(self, context: GrantSelectionContext) -> Optional[GrantSelectionResult]:
        """
        Select a connector configuration based on the context.

        Returns:
            GrantSelectionResult if a suitable connector is found, None otherwise
        """
        ...


class GrantSelectionPolicy:
    """
    Main policy class that orchestrates connector selection using pluggable strategies.

    This addresses the TODO comments by providing a flexible, configurable approach
    to connector selection that considers client preferences, node policies, and
    fallback strategies.
    """

    def __init__(self, strategies: Optional[List[GrantSelectionStrategy]] = None):
        self.strategies = strategies or [
            PreferSameTypeStrategy(),
            PreferHttpStrategy(),
            ClientPreferenceStrategy(),
        ]

    def select_callback_grant(self, context: GrantSelectionContext) -> Optional[GrantSelectionResult]:
        """
        Select the best connector for the given context.

        Iterates through strategies until one returns a result.
        Raises ValueError if no suitable connector can be found.
        """
        logger.debug(
            "selecting_connector",
            child=context.child_id,
            inbound_type=context.callback_grant_type,
            client_grants=[c.get("type") for c in context.client_supported_callback_grants],
        )

        for strategy in self.strategies:
            result = strategy.select_callback_grant(context)
            if result:
                logger.debug(
                    "connector_selected",
                    child=context.child_id,
                    selected_type=result.grant.type,
                    strategy=strategy.__class__.__name__,
                    reason=result.selection_reason,
                    fallback=result.fallback_used,
                )
                return result

        # No suitable connector found - raise error with detailed information
        supported_types = [c.get("type") for c in context.client_supported_callback_grants]
        error_msg = (
            f"No suitable connector found for child {context.child_id}. "
            f"Client supports: {supported_types}, "
            f"inbound type: {context.callback_grant_type}"
        )

        logger.warning(
            "connector_selection_failed",
            child=context.child_id,
            client_connectors=supported_types,
            inbound_type=context.callback_grant_type,
            reason="No matching strategy found",
        )

        raise ValueError(error_msg)


class PreferSameTypeStrategy(GrantSelectionStrategy):
    """Strategy that prefers to use the same connector type as the inbound connection."""

    def select_callback_grant(self, context: GrantSelectionContext) -> Optional[GrantSelectionResult]:
        """Select connector matching the inbound connector type if available."""
        target_type = context.callback_grant_type

        for grant_dict in context.client_supported_callback_grants:
            if grant_dict.get("type") == target_type:
                config = self._crate_grant_from_dict(grant_dict)
                if config:
                    return GrantSelectionResult(
                        grant=config,
                        selection_reason=f"Matching inbound connector type: {target_type}",
                    )

        return None

    def _crate_grant_from_dict(self, grant_dict: Dict[str, Any]) -> Optional[ConnectionGrant]:
        """Create a connector config from a dictionary representation."""
        grant_type = grant_dict.get("type")

        if grant_type == "HttpConnectionGrant":
            return self._create_http_config(grant_dict)
        elif grant_type == "WebSocketConnectionGrant":
            return self._create_websocket_config(grant_dict)

        return None

    def _create_http_config(self, connector_dict: Dict[str, Any]) -> Optional[ConnectionGrant]:
        """Create HTTP connector config from dict."""

        # Extract URL from the dict
        url = connector_dict.get("url") or connector_dict.get("params", {}).get("url")
        if not url:
            return None

        return HttpConnectionGrant(
            url=url,
            purpose=connector_dict.get("purpose", GRANT_PURPOSE_NODE_ATTACH),
            # max_queue=connector_dict.get("max_queue", 1024),
            auth=connector_dict.get("auth"),
        )

    def _create_websocket_config(self, connector_dict: Dict[str, Any]) -> Optional[ConnectionGrant]:
        """Create WebSocket connector config from dict."""

        params = connector_dict.get("params", {})
        if not params:
            return None

        from naylence.fame.grants.websocket_connection_grant import WebSocketConnectionGrant

        return WebSocketConnectionGrant(
            type=connector_dict.get("type", "WebSocketConnectionGrant"),
            purpose=connector_dict.get("purpose", GRANT_PURPOSE_NODE_ATTACH),
            # params=params,
            auth=connector_dict.get("auth"),
        )


class PreferHttpStrategy(GrantSelectionStrategy):
    """Strategy that prefers HTTP connectors when available."""

    def select_callback_grant(self, context: GrantSelectionContext) -> Optional[GrantSelectionResult]:
        """Select HTTP connector if available."""
        for connector_dict in context.client_supported_callback_grants:
            if connector_dict.get("type") == "HttpConnectionGrant":
                config = self._create_http_config(connector_dict)
                if config:
                    return GrantSelectionResult(
                        grant=config,
                        selection_reason="Preferred HTTP connector type",
                    )

        return None

    def _create_http_config(self, connector_dict: Dict[str, Any]) -> Optional[ConnectionGrant]:
        """Create HTTP connector config from dict."""

        url = connector_dict.get("url") or connector_dict.get("params", {}).get("url")
        if not url:
            return None

        return HttpConnectionGrant(
            url=url,
            purpose=connector_dict.get("purpose", GRANT_PURPOSE_NODE_ATTACH),
            # max_queue=connector_dict.get("max_queue", 1024),
            auth=connector_dict.get("auth"),
        )


class ClientPreferenceStrategy(GrantSelectionStrategy):
    """Strategy that uses the first connector provided by the client."""

    def select_callback_grant(self, context: GrantSelectionContext) -> Optional[GrantSelectionResult]:
        """Select the first available connector from the client's list."""
        if not context.client_supported_callback_grants:
            return None

        first_connector = context.client_supported_callback_grants[0]
        config = self._create_config_from_dict(first_connector)

        if config:
            return GrantSelectionResult(
                grant=config,
                selection_reason=f"Client's first preference: {first_connector.get('type')}",
            )

        return None

    def _create_config_from_dict(self, grant_dict: Dict[str, Any]) -> Optional[ConnectionGrant]:
        """Create a connector config from a dictionary representation."""
        # Reuse the logic from PreferSameTypeStrategy
        strategy = PreferSameTypeStrategy()
        return strategy._crate_grant_from_dict(grant_dict)


# Default policy instance
default_grant_selection_policy = GrantSelectionPolicy()
