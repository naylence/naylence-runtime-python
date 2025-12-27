"""
Node event listener interface for clean, event-driven node lifecycle management.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Optional, Protocol, runtime_checkable

from naylence.fame.core import (
    FameAddress,
    FameConnector,
    FameDeliveryContext,
    FameEnvelope,
    NodeWelcomeFrame,
)
from naylence.fame.node.admission.node_attach_client import AttachInfo

if TYPE_CHECKING:
    from naylence.fame.node.node_like import NodeLike
    from naylence.fame.sentinel.router import RouterState, RoutingAction


@runtime_checkable
class NodeEventListener(Protocol):
    """
    Protocol for components that need to respond to node lifecycle events.

    This protocol enables clean, event-driven initialization and management of
    various node subsystems (security, routing, monitoring, etc.), replacing
    ad-hoc initialization patterns with a structured event-based approach.

    Components implementing this protocol can be registered with nodes to
    receive lifecycle events and perform their specific setup, processing,
    and cleanup tasks at the appropriate times.

    All methods have default implementations (empty/pass-through), so implementing
    classes only need to override the events they care about.
    """

    @property
    def priority(self) -> int:
        """
        The priority of this event listener for ordering during event dispatch.

        Lower values mean higher priority (executed first). Event listeners with
        the same priority are ordered according to their original placement in
        the event_listeners list.

        Default priority is 1000 to allow both higher priority (< 1000) and
        lower priority (> 1000) listeners to be easily added.

        Returns:
            Priority value (default: 1000)
        """
        return 1000

    async def on_node_started(self, node: NodeLike) -> None:
        """
        Called when a node has been started and is ready for operation.

        This event is dispatched after the node has:
        - Established its physical path and SID
        - Connected to upstream (if applicable)
        - Completed handshake (if applicable)
        - Set up accepted logicals

        Args:
            node: The node that has been started
        """
        pass

    async def on_welcome(self, welcome_frame: NodeWelcomeFrame) -> None:
        """
        Called when a child node receives a welcome frame during admission.

        This event allows components to handle setup and initialization
        based on the welcome frame from the parent.

        Args:
            welcome_frame: The NodeWelcomeFrame received during admission
        """
        # Default implementation does nothing
        pass

    async def on_heartbeat_received(self, envelope: FameEnvelope) -> None:
        """
        Called when a heartbeat acknowledgment is received from upstream.

        This event allows components to perform processing on heartbeat frames
        as needed by their specific requirements.

        Args:
            envelope: The heartbeat envelope to process
        """
        # Default implementation does nothing
        pass

    async def on_heartbeat_sent(self, envelope: FameEnvelope) -> None:
        """
        Called when a heartbeat is sent to upstream.

        Args:
            envelope: The heartbeat envelope to process
        """
        # Default implementation does nothing
        pass

    async def on_node_initialized(self, node: NodeLike) -> None:
        """
        Called when a node has been fully initialized but before it starts.

        This event is dispatched after the node has completed construction,
        including all sub-components like routing capabilities, but before
        the node actually starts operating. This is the ideal place to:
        - Perform final configuration based on node capabilities
        - Set up cross-component dependencies
        - Initialize subsystem contexts with node information

        Args:
            node: The node that has been initialized
        """
        # Default implementation does nothing - this is an optional lifecycle event
        pass

    # async def before_node_attach_to_peer(
    #     self, node: NodeLike, envelope: FameEnvelope
    # ) -> None:
    #     pass

    async def on_node_attach_to_peer(
        self, node: NodeLike, attach_info: AttachInfo, connector: FameConnector
    ) -> None:
        """
        Called when a sentinel successfully attaches to a peer.

        This event is dispatched after the sentinel has:
        - Successfully connected to a peer
        - Received peer attachment information
        - But before normal peer-to-peer operation begins

        This is the ideal place to handle peer-specific setup, including:
        - Processing peer information and capabilities
        - Setting up peer-specific configurations
        - Updating subsystems with peer routing information

        Args:
            node: The sentinel node that attached to the peer
            attach_info: The attachment information received from peer
            connector: The connector used for peer communication
        """
        # Default implementation does nothing - this is an optional lifecycle event
        pass

    # async def before_node_attach_to_upstream(self, node: NodeLike, env: FameEnvelope) -> None:
    #     pass

    async def on_node_attach_to_upstream(self, node: NodeLike, attach_info: AttachInfo) -> None:
        """
        Called when a child node successfully attaches to an upstream parent.

        This event is dispatched after the node has:
        - Received attachment information from the parent
        - Updated its physical path and SID
        - But before normal operation begins

        This is the ideal place to handle parent-specific setup, policy
        validation, and other attach-specific initialization logic.

        Args:
            node: The node that attached to upstream
            attach_info: The attachment information received from parent
        """
        # Default implementation does nothing - this is an optional lifecycle event
        pass

    async def on_envelope_received(
        self, node: NodeLike, envelope: FameEnvelope, context: Optional[FameDeliveryContext] = None
    ) -> Optional[FameEnvelope]:
        """
        Called when a heartbeat acknowledgment is received from upstream.

        This event allows components to perform processing on heartbeat frames
        as needed by their specific requirements.

        Args:
            envelope: The heartbeat envelope to process
            context: The delivery context (if any)
        """
        return envelope

    async def on_deliver_local(
        self,
        node: NodeLike,
        address: FameAddress,
        envelope: FameEnvelope,
        context: Optional[FameDeliveryContext] = None,
    ) -> Optional[FameEnvelope]:
        """
        Called when a node is about to deliver an envelope locally.

        This event allows components to process, transform, or filter
        envelopes before local delivery. Components can:
        - Apply validation policies (security, routing, content validation)
        - Transform or decrypt envelope content
        - Log or monitor delivery events
        - Reject envelopes by returning None

        Args:
            node: The node performing local delivery
            address: The target address for delivery
            envelope: The envelope to be delivered
            context: The delivery context

        Returns:
            Transformed envelope for continued processing, or None to halt delivery
        """
        # Default implementation passes envelope through unchanged
        return envelope

    async def on_deliver(
        self,
        node: NodeLike,
        envelope: FameEnvelope,
        context: Optional[FameDeliveryContext],
    ) -> Optional[FameEnvelope]:
        """
        Called when a node is about to process an envelope for delivery.

        This event allows components to handle all envelope processing
        including validation, transformation, and other inbound processing.
        Components can:
        - Decrypt or transform envelopes and frames
        - Verify signatures or apply validation policies
        - Log or monitor envelope processing
        - Transform envelope content
        - Reject envelopes by returning None

        Args:
            node: The node processing the envelope
            envelope: The envelope to be processed
            context: The delivery context

        Returns:
            Transformed envelope for continued processing, or None to halt delivery
        """
        # Default implementation passes envelope through unchanged
        return envelope

    async def on_routing_action_selected(
        self,
        node: NodeLike,
        envelope: FameEnvelope,
        selected: RoutingAction,
        state: RouterState,
        context: Optional[FameDeliveryContext] = None,
    ) -> Optional[RoutingAction]:
        """
        Called after routing policy has selected a RoutingAction but before it executes.

        This hook provides a single, centralized entry point for route authorization.
        It is invoked AFTER `routing_policy.decide(...)` returns a RoutingAction and
        BEFORE `action.execute(...)` is called.

        Components implementing this hook can:
        - Authorize the selected routing action (ForwardUpstream, ForwardDownstream, etc.)
        - Replace the action with a Deny/Drop action to block unauthorized routes
        - Apply route-level security policies
        - Log or audit routing decisions

        Return semantics:
        - Return the RoutingAction to execute (either the `selected` action or a replacement).
        - If the hook returns `None` or throws, the router will execute a
          Drop action (envelope is dropped with NO_ROUTE nack).

        To allow the originally selected action, return `selected` directly.
        To deny/block, return a `Drop` or `Deny` action.

        Args:
            node: The node performing the routing
            envelope: The envelope being routed
            selected: The RoutingAction selected by the routing policy
            state: The current router state (for context, not modification)
            context: Optional delivery context

        Returns:
            The RoutingAction to execute (None => Drop)
        """
        # Default implementation passes action through unchanged
        return selected

    async def on_forward_upstream(
        self,
        node: NodeLike,
        envelope: FameEnvelope,
        context: Optional[FameDeliveryContext] = None,
    ) -> Optional[FameEnvelope]:
        """
        Called when a node is about to forward an envelope upstream.

        This event allows components to handle outbound processing
        including transformation, validation, and other outbound processing.
        Components can:
        - Encrypt or transform envelopes for upstream transmission
        - Sign envelopes or apply validation
        - Apply outbound policies and monitoring
        - Transform envelope content
        - Reject forwarding by returning None

        Args:
            node: The node forwarding the envelope
            envelope: The envelope to be forwarded
            context: The delivery context

        Returns:
            Transformed envelope for continued processing, or None to halt forwarding
        """
        # Default implementation passes envelope through unchanged
        return envelope

    async def on_forward_to_route(
        self,
        node: NodeLike,
        next_segment: str,
        envelope: FameEnvelope,
        context: Optional[FameDeliveryContext] = None,
    ) -> Optional[FameEnvelope]:
        """
        Called when a sentinel is about to forward an envelope to a downstream route.

        This event allows components to handle outbound processing
        for routing-specific forwarding including transformation, validation, and other
        outbound processing for downstream routes.
        Components can:
        - Transform or encrypt envelopes for downstream transmission
        - Apply validation and routing policies
        - Monitor and log routing operations
        - Transform envelope content
        - Reject forwarding by returning None

        Args:
            node: The sentinel node forwarding the envelope
            next_segment: The target route segment
            envelope: The envelope to be forwarded
            context: The delivery context

        Returns:
            Transformed envelope for continued processing, or None to halt forwarding
        """
        # Default implementation passes envelope through unchanged
        return envelope

    async def on_forward_to_peer(
        self,
        node: NodeLike,
        peer_segment: str,
        envelope: FameEnvelope,
        context: Optional[FameDeliveryContext] = None,
    ) -> Optional[FameEnvelope]:
        """
        Called when a sentinel is about to forward an envelope to a peer.

        This event allows components to handle outbound processing
        for peer forwarding including transformation, validation, and other outbound
        processing for peer-to-peer communication.
        Components can:
        - Transform or encrypt envelopes for peer transmission
        - Apply validation and peer-specific policies
        - Monitor and log peer communications
        - Transform envelope content
        - Reject forwarding by returning None

        Args:
            node: The sentinel node forwarding the envelope
            peer_segment: The target peer segment
            envelope: The envelope to be forwarded
            context: The delivery context

        Returns:
            Transformed envelope for continued processing, or None to halt forwarding
        """
        # Default implementation passes envelope through unchanged
        return envelope

    async def on_forward_upstream_complete(
        self,
        node: NodeLike,
        envelope: FameEnvelope,
        result: Optional[Any] = None,
        error: Optional[Exception] = None,
        context: Optional[FameDeliveryContext] = None,
    ) -> Optional[FameEnvelope]:
        """
        Called after a node completes forwarding an envelope upstream.

        This event allows components to handle post-forwarding processing
        including cleanup, logging, metrics collection, and error handling.
        Components can:
        - Log forwarding completion and status
        - Collect metrics and monitoring data
        - Handle errors and perform cleanup
        - Update state based on forwarding results
        - Perform audit logging

        Args:
            node: The node that forwarded the envelope
            envelope: The envelope that was forwarded
            result: The result of the forwarding operation (if successful)
            error: The exception that occurred (if failed)
            context: The delivery context
        """
        # Default implementation does nothing
        return envelope

    async def on_forward_to_route_complete(
        self,
        node: NodeLike,
        next_segment: str,
        envelope: FameEnvelope,
        result: Optional[Any] = None,
        error: Optional[Exception] = None,
        context: Optional[FameDeliveryContext] = None,
    ) -> Optional[FameEnvelope]:
        """
        Called after a sentinel completes forwarding an envelope to a downstream route.

        This event allows components to handle post-forwarding processing
        for routing-specific operations including cleanup, logging, and error handling.
        Components can:
        - Log routing completion and status
        - Collect routing metrics and monitoring data
        - Handle routing errors and perform cleanup
        - Update routing state based on results
        - Perform routing audit logging

        Args:
            node: The sentinel node that forwarded the envelope
            next_segment: The target route segment
            envelope: The envelope that was forwarded
            result: The result of the forwarding operation (if successful)
            error: The exception that occurred (if failed)
            context: The delivery context
        """
        # Default implementation does nothing
        return envelope

    async def on_forward_to_peer_complete(
        self,
        node: NodeLike,
        peer_segment: str,
        envelope: FameEnvelope,
        result: Optional[Any] = None,
        error: Optional[Exception] = None,
        context: Optional[FameDeliveryContext] = None,
    ) -> Optional[FameEnvelope]:
        """
        Called after a sentinel completes forwarding an envelope to a peer.

        This event allows components to handle post-forwarding processing
        for peer communication including cleanup, logging, and error handling.
        Components can:
        - Log peer communication completion and status
        - Collect peer metrics and monitoring data
        - Handle peer communication errors and perform cleanup
        - Update peer state based on results
        - Perform peer audit logging

        Args:
            node: The sentinel node that forwarded the envelope
            peer_segment: The target peer segment
            envelope: The envelope that was forwarded
            result: The result of the forwarding operation (if successful)
            error: The exception that occurred (if failed)
            context: The delivery context
        """
        # Default implementation does nothing
        return envelope

    async def on_forward_to_peers(
        self,
        node: NodeLike,
        envelope: FameEnvelope,
        peers: Any,
        exclude_peers: Any,
        context: Optional[FameDeliveryContext] = None,
    ) -> Optional[FameEnvelope]:
        """
        Called when a sentinel is about to forward an envelope to multiple peers.

        This event allows components to handle outbound processing
        for multi-peer forwarding including transformation, validation, and other outbound
        processing for broadcast-style peer communication.
        Components can:
        - Transform or encrypt envelopes for peer transmission
        - Apply validation and broadcast policies
        - Monitor and log broadcast operations
        - Transform envelope content
        - Reject forwarding by returning None

        Args:
            node: The sentinel node forwarding the envelope
            envelope: The envelope to be forwarded
            peers: The list of target peers (or None for all)
            exclude_peers: The list of peers to exclude (or None)
            context: The delivery context

        Returns:
            Transformed envelope for continued processing, or None to halt forwarding
        """
        # Default implementation passes envelope through unchanged
        return envelope

    async def on_forward_to_peers_complete(
        self,
        node: NodeLike,
        envelope: FameEnvelope,
        peers: Any,
        exclude_peers: Any,
        result: Optional[Any] = None,
        error: Optional[Exception] = None,
        context: Optional[FameDeliveryContext] = None,
    ) -> Optional[FameEnvelope]:
        """
        Called after a sentinel completes forwarding an envelope to multiple peers.

        This event allows components to handle post-forwarding processing
        for multi-peer communication including cleanup, logging, and error handling.
        Components can:
        - Log broadcast completion and status
        - Collect broadcast metrics and monitoring data
        - Handle broadcast errors and perform cleanup
        - Update peer state based on results
        - Perform broadcast audit logging

        Args:
            node: The sentinel node that forwarded the envelope
            envelope: The envelope that was forwarded
            peers: The list of target peers (or None for all)
            exclude_peers: The list of peers to exclude (or None)
            result: The result of the forwarding operation (if successful)
            error: The exception that occurred (if failed)
            context: The delivery context
        """
        # Default implementation does nothing
        return envelope

    async def on_child_attach(
        self,
        *,
        child_system_id: str,
        child_keys: Any,
        node_like: NodeLike,
        origin_type: Any = None,
        assigned_path: Optional[str] = None,
        old_assigned_path: Optional[str] = None,
        is_rebind: bool = False,
    ) -> None:
        """
        Called when a child node is attaching to handle security validation.

        This event allows components to validate keys and security compatibility
        between the parent (us) and the attaching child node.

        Args:
            child_system_id: System ID of the attaching child
            child_keys: Keys provided by the child (if any)
            node_like: The routing node instance
            origin_type: Type of origin (DOWNSTREAM or PEER)
            assigned_path: The assigned path for the child
            old_assigned_path: The old path if this is a rebind
            is_rebind: Whether this is a rebind operation
        """
        # Default implementation does nothing - this is an optional lifecycle event
        pass

    async def on_epoch_change(self, node: NodeLike, epoch: str) -> None:
        """
        Called when the node receives an epoch change notification.

        This event is dispatched when the node's epoch changes, which typically
        happens when the upstream parent's routing state changes. This is an
        ideal place to handle:
        - State updates and re-announcements to upstream
        - Address rebinding and capability re-advertisement
        - Routing table updates
        - Any epoch-specific subsystem state updates

        Args:
            node: The node that received the epoch change
            epoch: The new epoch identifier
        """
        # Default implementation does nothing - this is an optional lifecycle event
        pass

    async def on_node_preparing_to_stop(self, node: NodeLike) -> None:
        """
        Called when a node is preparing to stop but has not yet fully shut down.

        This event is dispatched before the node begins its shutdown sequence,
        allowing components to perform pre-shutdown tasks such as:
        - Flushing caches or buffers
        - Notifying dependent services
        - Preparing for resource cleanup

        Args:
            node: The node that is preparing to stop
        """
        # Default implementation does nothing - this is an optional lifecycle event
        pass

    async def on_node_stopped(self, node: NodeLike) -> None:
        """
        Called when a node is being stopped and should clean up resources.

        This event is dispatched during node shutdown, allowing components
        to clean up resources, stop background tasks, and gracefully shut down
        their services (monitoring, security, routing, etc.).

        Args:
            node: The node that is being stopped
        """
        # Default implementation does nothing - this is an optional lifecycle event
        pass
