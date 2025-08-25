from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, Optional

from naylence.fame.connector.transport_listener_factory import TransportListenerFactory
from naylence.fame.constants.ttl_constants import TTL_NEVER_EXPIRES
from naylence.fame.core import create_default_resource, create_resource, generate_id
from naylence.fame.node.admission.admission_client_factory import AdmissionClientFactory
from naylence.fame.node.admission.default_node_attach_client import (
    DefaultNodeAttachClient,
)
from naylence.fame.node.node_config import FameNodeConfig
from naylence.fame.node.node_meta import NodeMeta
from naylence.fame.security.auth.none_token_provider_factory import (
    NoneTokenProviderConfig,
)
from naylence.fame.security.keys.attachment_key_validator_factory import (
    AttachmentKeyValidatorFactory,
)
from naylence.fame.security.keys.key_store_factory import KeyStoreFactory
from naylence.fame.security.policy.security_policy import CryptoLevel
from naylence.fame.storage.storage_provider import StorageProvider
from naylence.fame.storage.storage_provider_factory import StorageProviderFactory
from naylence.fame.tracking.delivery_tracker import DeliveryTracker
from naylence.fame.tracking.delivery_tracker_factory import DeliveryTrackerFactory
from naylence.fame.util.logging import getLogger

if TYPE_CHECKING:
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

    node_meta_store = await storage_provider.get_kv_store(NodeMeta, namespace="node_meta")

    admission_client = await create_resource(AdmissionClientFactory, cfg.admission)

    node_meta = await node_meta_store.get("self")
    logger.debug(
        "node_meta_store_loaded",
        node_meta=node_meta,
        system_id=node_meta.id if node_meta else None,
    )

    system_id = cfg.system_id or (node_meta.id if node_meta else None) or generate_id(mode="fingerprint")

    if cfg.mode == "dev":
        if system_id is None and not cfg.has_parent:
            system_id = generate_id(mode="fingerprint")

        if admission_client is None and cfg.direct_parent_url:
            from naylence.fame.connector.websocket_connector_factory import (
                WebSocketConnectorConfig,
            )
            from naylence.fame.node.admission.direct_admission_client import (
                DirectAdmissionClient,
            )
            from naylence.fame.security.auth.auth_config import WebSocketSubprotocolAuth

            if system_id is None:
                system_id = generate_id(mode="fingerprint")

            connector_directive = WebSocketConnectorConfig(
                url=cfg.direct_parent_url,
                auth=WebSocketSubprotocolAuth(token_provider=NoneTokenProviderConfig()),
            )
            admission_client = DirectAdmissionClient(
                connector_directive.model_dump(), ttl_sec=TTL_NEVER_EXPIRES
            )

    event_listeners = []

    delivery_tracker = await create_delivery_tracker(cfg)

    if delivery_tracker:
        event_listeners.append(delivery_tracker)

    # Auto-register admission client as event listener if it implements the protocol
    if admission_client:
        from naylence.fame.node.node_event_listener import NodeEventListener

        if isinstance(admission_client, NodeEventListener):
            event_listeners.append(admission_client)

    # Create transport listeners if configured
    if cfg.listeners:
        for listener_config in cfg.listeners:
            transport_listener = await create_resource(TransportListenerFactory, listener_config)
            event_listeners.append(transport_listener)

    has_parent = cfg.has_parent or cfg.direct_parent_url is not None or admission_client is not None

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

        key_store_config = StorageBackedKeyStoreConfig(namespace="keystore")
        key_store = await KeyStoreFactory.create_key_store(
            key_store_config, storage_provider=storage_provider
        )

    from naylence.fame.node.binding_manager import BindingStoreEntry

    binding_store = await storage_provider.get_kv_store(BindingStoreEntry, namespace="binding_store")

    security_manager = await create_security_manager(cfg, key_store)

    attachment_key_validator = None
    # Create attachment key validator
    if cfg.attachment_key_validator:
        attachment_key_validator = await create_resource(
            AttachmentKeyValidatorFactory, cfg.attachment_key_validator
        )

    security_requirements = security_manager.policy.requirements()
    if attachment_key_validator is None and (
        security_requirements.minimum_crypto_level != CryptoLevel.PLAINTEXT
        or security_requirements.encryption_required
        or security_requirements.decryption_required
    ):
        # Handle security requirements
        attachment_key_validator = await create_resource(
            AttachmentKeyValidatorFactory, {"type": "AttachmentCertValidator"}
        )

    node_attach_client = DefaultNodeAttachClient(
        attachment_key_validator=attachment_key_validator,
        replica_stickiness_manager=replica_stickiness_manager,
    )

    return {
        "system_id": system_id,
        "has_parent": has_parent,
        "delivery_tracker": delivery_tracker,
        "admission_client": admission_client,
        "attach_client": node_attach_client,
        "attachment_key_validator": attachment_key_validator,
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
    }


async def create_delivery_tracker(cfg: FameNodeConfig) -> Optional[DeliveryTracker]:
    return await create_default_resource(DeliveryTrackerFactory)


async def create_security_manager(cfg: FameNodeConfig, key_store, authorizer=None) -> SecurityManager:
    """Create SecurityManager using the factory pattern.

    Args:
        cfg: Node configuration containing security settings
        key_store: KeyStore instance
        authorizer: Optional authorizer for sentinel nodes

    Returns:
        SecurityManager instance
    """
    from naylence.fame.core import create_default_resource, create_resource
    from naylence.fame.security.security_manager_factory import SecurityManagerFactory

    if cfg.security is not None:
        return await create_resource(SecurityManagerFactory, cfg.security, key_store=key_store)

    # Create with default implementation, optionally with authorizer
    kwargs = {"key_store": key_store}
    if authorizer is not None:
        kwargs["authorizer"] = authorizer

    security_manager = await create_default_resource(SecurityManagerFactory, **kwargs)

    assert security_manager is not None, "SecurityManager must be created"

    return security_manager
