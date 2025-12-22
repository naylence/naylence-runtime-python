from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, List, Optional

from naylence.fame.connector.transport_listener import TransportListener
from naylence.fame.connector.transport_listener_factory import TransportListenerFactory
from naylence.fame.delivery.delivery_policy import DeliveryPolicy
from naylence.fame.delivery.delivery_policy_factory import DeliveryPolicyConfig, DeliveryPolicyFactory
from naylence.fame.delivery.delivery_tracker import DeliveryTracker
from naylence.fame.delivery.delivery_tracker_factory import DeliveryTrackerFactory
from naylence.fame.factory import create_default_resource, create_resource
from naylence.fame.node.admission.admission_client import AdmissionClient
from naylence.fame.node.admission.admission_client_factory import AdmissionClientFactory
from naylence.fame.node.admission.default_node_attach_client import (
    DefaultNodeAttachClient,
)
from naylence.fame.node.connection_retry_policy import ConnectionRetryPolicy
from naylence.fame.node.connection_retry_policy_factory import ConnectionRetryPolicyFactory
from naylence.fame.node.default_node_identity_policy import DefaultNodeIdentityPolicy
from naylence.fame.node.node_config import FameNodeConfig
from naylence.fame.node.node_identity_policy import (
    InitialIdentityContext,
    NodeIdentityPolicy,
)
from naylence.fame.node.node_identity_policy_factory import NodeIdentityPolicyFactory
from naylence.fame.node.node_meta import NodeMeta
from naylence.fame.security.keys.attachment_key_validator import AttachmentKeyValidator
from naylence.fame.security.keys.attachment_key_validator_factory import (
    AttachmentKeyValidatorFactory,
)
from naylence.fame.security.keys.key_store_factory import KeyStoreFactory
from naylence.fame.storage.storage_provider import StorageProvider
from naylence.fame.storage.storage_provider_factory import StorageProviderFactory
from naylence.fame.telemetry.trace_emitter_factory import TraceEmitterFactory
from naylence.fame.util.logging import getLogger

if TYPE_CHECKING:
    from naylence.fame.node.node_event_listener import NodeEventListener
    from naylence.fame.security.security_manager import SecurityManager


logger = getLogger(__name__)


async def make_common_opts(cfg: FameNodeConfig) -> Dict[str, Any]:
    """
    Builds the big kwargs dict that both factories pass to the
    FameNode / RoutingNode constructors.
    """
    # --- bootstrap pluggable components ---

    # Stickiness managers
    from naylence.fame.stickiness.replica_stickiness_manager_factory import (
        ReplicaStickinessManagerFactory,
    )

    # Create storage provider - default to in-memory if not configured
    if cfg.storage:
        storage_provider: StorageProvider = await create_resource(StorageProviderFactory, cfg.storage)
    else:
        from naylence.fame.storage.in_memory_storage_provider_factory import (
            InMemoryStorageProviderConfig,
        )

        default_storage_config = InMemoryStorageProviderConfig()
        storage_provider: StorageProvider = await create_resource(
            StorageProviderFactory, default_storage_config
        )

    assert storage_provider is not None, "Storage provider must be created"

    node_meta_store = await storage_provider.get_kv_store(NodeMeta, namespace="__node_meta")

    node_meta = await node_meta_store.get("self")
    logger.debug(
        "node_meta_store_loaded",
        node_meta=node_meta,
        node_id=node_meta.id if node_meta else None,
    )

    # Resolve identity policy first (needed for admission client)
    identity_policy: Optional[NodeIdentityPolicy] = None
    if cfg.identity_policy:
        try:
            identity_policy = await NodeIdentityPolicyFactory.create_node_identity_policy(
                cfg.identity_policy
            )
        except Exception as error:
            logger.warning(
                "node_identity_policy_creation_failed",
                error=str(error),
            )

    effective_identity_policy = identity_policy or DefaultNodeIdentityPolicy()

    # Create admission client with identity policy
    admission_client: AdmissionClient = await create_resource(
        AdmissionClientFactory, cfg.admission, node_identity_policy=effective_identity_policy
    )

    # Resolve initial node ID using identity policy
    node_id = await effective_identity_policy.resolve_initial_node_id(
        InitialIdentityContext(
            configured_id=cfg.id,
            persisted_id=node_meta.id if node_meta else None,
        )
    )

    event_listeners = []

    delivery_policy = await create_delivery_policy(cfg.delivery)

    delivery_tracker = await create_delivery_tracker(cfg, storage_provider=storage_provider)

    if delivery_tracker:
        event_listeners.append(delivery_tracker)

    # Auto-register admission client as event listener if it implements the protocol
    if admission_client:
        from naylence.fame.node.node_event_listener import NodeEventListener

        if isinstance(admission_client, NodeEventListener):
            event_listeners.append(admission_client)

    # Create transport listeners if configured
    transport_listeners: list[TransportListener] = []
    if cfg.listeners:
        for listener_config in cfg.listeners:
            # Skip disabled listeners (enabled defaults to True if not specified)
            if isinstance(listener_config, dict):
                if listener_config.get("enabled") is False:
                    continue
            elif hasattr(listener_config, "enabled") and listener_config.enabled is False:
                continue

            transport_listener = await create_resource(TransportListenerFactory, listener_config)
            transport_listeners.append(transport_listener)
            event_listeners.append(transport_listener)

    has_parent = (
        cfg.has_parent
        or cfg.direct_parent_url is not None
        or (admission_client is not None and admission_client.has_upstream)
    )

    # Heuristic: only enable replica-side stickiness when node acts as a child (has_parent)
    # and it requests wildcard logicals (e.g., "*.fame.com"), which signals LB participation.
    requested_logicals = cfg.requested_logicals or []
    has_wildcard_logicals = any(
        isinstance(logical, str) and logical.strip().startswith("*.") for logical in requested_logicals
    )

    replica_stickiness_manager = None
    if has_parent and has_wildcard_logicals:
        logger.debug(
            "replica_stickiness_manager_condition_met",
            has_parent=has_parent,
            has_wildcard_logicals=has_wildcard_logicals,
            requested_logicals=requested_logicals,
        )
        replica_stickiness_manager = (
            await ReplicaStickinessManagerFactory.create_replica_stickiness_manager()
        )
        if replica_stickiness_manager:
            event_listeners.append(replica_stickiness_manager)
            logger.debug(
                "replica_stickiness_manager_registered",
                type=type(replica_stickiness_manager).__name__,
            )
        else:
            logger.debug("replica_stickiness_manager_not_available")
    else:
        logger.debug(
            "replica_stickiness_manager_condition_not_met",
            has_parent=has_parent,
            has_wildcard_logicals=has_wildcard_logicals,
            requested_logicals=requested_logicals,
        )

    if cfg.key_store:
        key_store = await KeyStoreFactory.create_key_store(cfg.key_store, storage_provider=storage_provider)
    else:
        from naylence.fame.security.keys.storage_backed_keystore_factory import (
            StorageBackedKeyStoreConfig,
        )

        key_store_config = StorageBackedKeyStoreConfig(namespace="__keystore")
        key_store = await KeyStoreFactory.create_key_store(
            key_store_config, storage_provider=storage_provider
        )

    from naylence.fame.node.binding_manager import BindingStoreEntry

    binding_store = await storage_provider.get_kv_store(BindingStoreEntry, namespace="__binding_store")

    key_validator = None
    # Create attachment key validator
    if cfg.attachment_key_validator:
        key_validator = await create_resource(AttachmentKeyValidatorFactory, cfg.attachment_key_validator)
    else:
        key_validator = await create_default_resource(AttachmentKeyValidatorFactory)

    security_manager = await create_security_manager(
        cfg, key_store=key_store, key_validator=key_validator, event_listeners=event_listeners
    )

    # security_requirements = security_manager.policy.requirements()
    # if key_validator is None and (
    #     security_requirements.minimum_crypto_level != CryptoLevel.PLAINTEXT
    #     or security_requirements.encryption_required
    #     or security_requirements.decryption_required
    # ):
    #     # Handle security requirements
    #     key_validator = await create_resource(
    #         AttachmentKeyValidatorFactory, {"type": "AttachmentCertValidator"}
    #     )

    node_attach_client = DefaultNodeAttachClient(
        attachment_key_validator=key_validator,
        replica_stickiness_manager=replica_stickiness_manager,
    )

    telemetry_config = cfg.telemetry
    if telemetry_config is not None:
        trace_emitter = await create_resource(TraceEmitterFactory, telemetry_config)
    else:
        trace_emitter = await create_default_resource(TraceEmitterFactory)

    from naylence.fame.node.node_event_listener import NodeEventListener

    if isinstance(trace_emitter, NodeEventListener):
        event_listeners.append(trace_emitter)

    # Create connection retry policy
    connection_retry_policy = await create_connection_retry_policy(cfg)

    return {
        "system_id": node_id,
        "has_parent": has_parent,
        "delivery_tracker": delivery_tracker,
        "admission_client": admission_client,
        "attach_client": node_attach_client,
        "attachment_key_validator": key_validator,
        "requested_logicals": cfg.requested_logicals,
        "service_configs": cfg.services,
        "env_context": cfg.env_context,
        "event_listeners": event_listeners,
        "public_url": cfg.public_url,
        "storage_provider": storage_provider,
        "binding_store": binding_store,
        "key_store": key_store,
        "node_meta_store": node_meta_store,
        "security_manager": security_manager,
        "transport_listeners": transport_listeners,
        "delivery_policy": delivery_policy,
        "connection_retry_policy": connection_retry_policy,
        "identity_policy": effective_identity_policy,
    }


async def create_delivery_tracker(
    cfg: FameNodeConfig, storage_provider: StorageProvider
) -> Optional[DeliveryTracker]:
    return await create_default_resource(DeliveryTrackerFactory, storage_provider=storage_provider)


async def create_delivery_policy(
    cfg: DeliveryPolicyConfig | dict[str, Any] | None = None,
) -> Optional[DeliveryPolicy]:
    if cfg:
        return await create_resource(DeliveryPolicyFactory, cfg)

    return await create_default_resource(DeliveryPolicyFactory)


async def create_connection_retry_policy(
    cfg: FameNodeConfig,
) -> Optional[ConnectionRetryPolicy]:
    """Create a connection retry policy from configuration.

    Args:
        cfg: Node configuration containing retry policy settings

    Returns:
        ConnectionRetryPolicy instance, or None if creation fails
    """
    if cfg.connection_retry_policy is not None:
        return await create_resource(
            ConnectionRetryPolicyFactory,
            cfg.connection_retry_policy,
        )

    # Create default policy
    return await create_default_resource(ConnectionRetryPolicyFactory)


async def create_security_manager(
    cfg: FameNodeConfig,
    key_store,
    authorizer=None,
    key_validator: Optional[AttachmentKeyValidator] = None,
    event_listeners: Optional[List[NodeEventListener]] = None,
) -> SecurityManager:
    """Create SecurityManager using the factory pattern.

    Args:
        cfg: Node configuration containing security settings
        key_store: KeyStore instance
        authorizer: Optional authorizer for sentinel nodes

    Returns:
        SecurityManager instance
    """

    from naylence.fame.security.security_manager_factory import SecurityManagerFactory

    if cfg.security is not None:
        return await create_resource(
            SecurityManagerFactory,
            cfg.security,
            key_validator=key_validator,
            key_store=key_store,
            event_listeners=event_listeners,
        )

    # Create with default implementation, optionally with authorizer
    kwargs = {"key_store": key_store}
    if authorizer is not None:
        kwargs["authorizer"] = authorizer

    security_manager = await create_default_resource(
        SecurityManagerFactory, key_validator=key_validator, **kwargs
    )

    assert security_manager is not None, "SecurityManager must be created"

    return security_manager
