from typing import Any, Dict, List, Literal, Optional

from pydantic import Field

from naylence.fame.connector.transport_listener_config import TransportListenerConfig
from naylence.fame.delivery.delivery_policy_factory import DeliveryPolicyConfig
from naylence.fame.node.admission.admission_client_factory import AdmissionConfig
from naylence.fame.node.connection_retry_policy_factory import ConnectionRetryPolicyConfig
from naylence.fame.node.node_identity_policy_factory import NodeIdentityPolicyConfig
from naylence.fame.node.node_like_factory import NodeLikeConfig
from naylence.fame.security.keys.attachment_key_validator_factory import (
    AttachmentKeyValidatorConfig,
)
from naylence.fame.security.keys.key_store_factory import KeyStoreConfig
from naylence.fame.security.security_manager_config import SecurityManagerConfig
from naylence.fame.storage.storage_provider_factory import StorageProviderConfig
from naylence.fame.telemetry.trace_emitter_factory import TraceEmitterConfig


class FameNodeConfig(NodeLikeConfig):
    type: str = "Node"

    mode: Literal["dev", "prod"] = "prod"

    id: Optional[str] = Field(default=None)

    direct_parent_url: Optional[str] = Field(default=None)

    admission: Optional[AdmissionConfig] = Field(
        default=None,
        description="Admission client config",
    )

    requested_logicals: Optional[List[str]] = Field(
        default_factory=list,
        description="List of logicals the node requests",
    )

    delivery: Optional[DeliveryPolicyConfig] = Field(
        default=None,
        description="Message delivery policy configuration",
    )

    env_context: Optional[Dict[str, Any]] = Field(
        default_factory=dict,
        description="Arbitrary environment context",
    )

    services: List[Any] = Field(default_factory=list, description="List of default node services")

    has_parent: bool = Field(default=False, description="Whether this node has a parent node")

    security: Optional[SecurityManagerConfig] = Field(
        default=None,
        description="Security configuration for the node",
    )

    listeners: List[TransportListenerConfig] = Field(
        default_factory=list,
        description="List of transport listeners for ingress endpoints",
    )

    public_url: Optional[str] = Field(
        default=None,
        description="Base URL that other nodes should use to reach this node "
        "(e.g., 'https://api.example.com:8080'). "
        "Used for containerized deployments, load balancers, and reverse proxies. "
        "Listeners will adapt the scheme as needed (HTTP uses as-is, "
        "WebSocket converts http→ws/https→wss). "
        "If not specified, uses the actual server binding address.",
    )

    key_store: Optional[KeyStoreConfig] = Field(
        default=None,
        description="Key store configuration",
    )

    storage: Optional[StorageProviderConfig] = Field(
        default=None,
        description="Storage provider configuration for key-value stores",
    )

    attachment_key_validator: Optional[AttachmentKeyValidatorConfig] = Field(
        default=None,
        description="Attachment key validator configuration for certificate validation"
        " during node handshake",
    )

    telemetry: Optional[TraceEmitterConfig] = Field(
        default=None,
        description="Telemetry configuration",
    )

    connection_retry_policy: Optional[ConnectionRetryPolicyConfig] = Field(
        default=None,
        description="Retry policy for upstream connection attempts before first successful attach. "
        "Controls behavior when initial connection fails: "
        "1 (default) = fail immediately, 0 = unlimited retries, N = retry up to N times.",
    )

    identity_policy: Optional[NodeIdentityPolicyConfig] = Field(
        default=None,
        description="Node identity policy for resolving node IDs during initialization and admission. "
        "Supports 'DefaultNodeIdentityPolicy' (priority: configured > persisted > fingerprint), "
        "'TokenSubjectNodeIdentityPolicy' (derives ID from token subject), "
        "or 'NodeIdentityPolicyProfile' with profile names like 'default' or 'token-subject'.",
    )
