"""
Simple Stickiness Manager for Sentinels.
"""

from __future__ import annotations

from typing import Optional, Sequence

from naylence.fame.core import FameEnvelope, Stickiness
from naylence.fame.node.node_event_listener import NodeEventListener
from naylence.fame.stickiness.load_balancer_stickiness_manager import (
    LoadBalancerStickinessManager,
)
from naylence.fame.stickiness.simple_load_balancer_stickiness_manager_factory import (
    SimpleLoadBalanderStickinessManagerConfig,
)
from naylence.fame.util.logging import getLogger

logger = getLogger(__name__)


class SimpleLoadBalancerStickinessManager(NodeEventListener, LoadBalancerStickinessManager):
    """ """

    def __init__(self, config: Optional[SimpleLoadBalanderStickinessManagerConfig] = None):
        self.config = config

        logger.debug("simple_load_balancer_stickiness_manager_initialized")

    # SentinelStickinessManager implementation
    def negotiate(self, stickiness: Optional[Stickiness]) -> Optional[Stickiness]:
        """Negotiate stickiness policy with a child based on local config and child offer.

        Returns an Optional[Stickiness] to be placed into NodeAttachAck. If config is disabled, return
        a disabled policy when an offer exists, else None for minimal wire.
        """
        # If no offer from child:
        # - If sentinel stickiness is enabled, advertise attribute mode which requires
        #   no replica participation.
        # - Otherwise, keep the handshake lean and send nothing.
        if stickiness is None:
            if self.config:
                logger.debug("stickiness_negotiated_no_offer_attr_fallback")
                return Stickiness(enabled=True, mode="attr", version=1)
            return None

        if not self.config:
            logger.debug("stickiness_negotiation_disabled_by_config")
            return Stickiness(enabled=False, version=stickiness.version or 1)

        # Prefer AFT if child supports it and verifier exists
        child_modes = set(
            stickiness.supported_modes or ([] if stickiness.mode is None else [stickiness.mode])
        )
        # Fallback to attribute-based if child indicated it
        if "attr" in child_modes:
            policy = Stickiness(enabled=True, mode="attr", version=stickiness.version or 1)
            logger.debug("stickiness_negotiated", mode=policy.mode)
            return policy

        # If nothing compatible, explicitly disable
        logger.debug("stickiness_negotiation_no_common_mode")
        return Stickiness(enabled=False, version=stickiness.version or 1)

    def get_sticky_replica_segment(
        self, envelope: FameEnvelope, segments: Optional[Sequence[str]] = None
    ) -> Optional[str]:
        """
        Handle an inbound envelope that may have an AFT for routing.

        Args:
            envelope: The inbound envelope
            segments: Available segments for deterministic fallback (optional)

        Returns:
            Replica ID to route to, or None for default routing
        """
        if not self.config:
            logger.debug("stickiness_disabled", envelope_id=envelope.id)
            return None

        # Deterministic SID-based fallback when segments are provided
        if envelope.sid and segments and len(segments) > 0:
            import hashlib

            sid_bytes = envelope.sid.encode("utf-8")
            idx = int(hashlib.sha256(sid_bytes).hexdigest(), 16) % len(segments)
            chosen = segments[idx]
            logger.debug(
                "sid_based_deterministic_choice",
                envelope_id=envelope.id,
                sid=envelope.sid,
                chosen=chosen,
                routing_type="sid_deterministic",
            )
            return chosen

        logger.debug(
            "no_stickiness_routing",
            envelope_id=envelope.id,
            has_aft=envelope.aft is not None,
            has_sid=envelope.sid is not None,
        )
        return None
