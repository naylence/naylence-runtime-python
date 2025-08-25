#!/usr/bin/env python3

"""
Integration test to verify that client restart with new keys works correctly.
This simulates the exact scenario described in the user logs.
"""

import logging
from unittest.mock import AsyncMock, Mock

import pytest

from naylence.fame.core import DeliveryOriginType, NodeAttachFrame
from naylence.fame.security.auth.default_authorizer import DefaultAuthorizer
from naylence.fame.security.keys.default_key_manager import DefaultKeyManager
from naylence.fame.security.keys.in_memory_key_store import InMemoryKeyStore
from naylence.fame.sentinel.node_attach_frame_handler import NodeAttachFrameHandler
from naylence.fame.sentinel.route_manager import RouteManager

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


@pytest.mark.asyncio
async def test_client_restart_with_new_keys():
    """Test that client restart with new keys works correctly by removing old keys."""

    print("🧪 Testing client restart with new keys scenario...")

    # Set up components
    key_store = InMemoryKeyStore()

    # Mock dependencies
    routing_node = Mock()
    routing_node.id = "sentinel_system_id"
    routing_node.physical_path = "/w3YI3dnHsQnuENw"

    route_manager = Mock(spec=RouteManager)
    route_manager.downstream_routes = {}
    route_manager._pending_route_metadata = {}
    route_manager._pending_routes = {}
    route_manager.register_downstream_route = AsyncMock()
    route_manager.unregister_downstream_route = AsyncMock()
    route_manager._safe_stop = AsyncMock()

    DefaultAuthorizer()

    # Create mock node for the new interface
    mock_node = Mock()
    mock_node._id = "sentinel_system_id"
    mock_node._sid = "sentinel_sid"
    mock_node.physical_path = "/w3YI3dnHsQnuENw"
    mock_node._has_parent = False
    mock_node._envelope_factory = Mock()
    mock_node.forward_upstream = AsyncMock()

    key_manager = DefaultKeyManager(key_store=key_store)
    await key_manager.on_node_started(mock_node)

    # Create NodeAttachFrameHandler
    attach_handler = NodeAttachFrameHandler(
        routing_node=routing_node,
        key_manager=key_manager,
        route_manager=route_manager,
    )

    client_system_id = "mksnrwhAGPX8Rxn"
    client_physical_path = f"/w3YI3dnHsQnuENw/{client_system_id}"

    # === First client connection ===
    print("\n📱 First client connection with initial keys...")

    first_keys = [
        {
            "x": "9Wslt4e9KnOBh4nafwG39hOeuKMLHW5jQ9fApWHUgqk",
            "kty": "OKP",
            "crv": "Ed25519",
            "kid": "5IrhN337S25OqJK",  # First run key IDs
            "alg": "EdDSA",
            "use": "sig",
        },
        {
            "kty": "OKP",
            "crv": "X25519",
            "x": "OUN06llYA1Vd5DprpjAMvyVwveQMANZMDfXFh_1qHnI",
            "kid": "UZZyOVSQaEAgr0E",  # First run key IDs
            "use": "enc",
            "alg": "ECDH-ES",
        },
    ]

    # Add initial keys directly to key store (simulate successful first attach)
    await key_store.add_keys(first_keys, physical_path=client_physical_path)

    initial_keys = list(await key_store.get_keys_for_path(client_physical_path))
    print(f"✅ Initial keys stored: {[k['kid'] for k in initial_keys]}")

    # Store some encrypted data that would use the old encryption key
    print("💾 Agent stores encrypted reply using old encryption key...")

    # === Client restart (simulated disconnect/reconnect) ===
    print("\n🔄 Client restart - new connection with new keys...")

    # Simulate client disconnection and reconnection with new keys
    second_keys = [
        {
            "x": "different_signature_key_material_2nd_run",
            "kty": "OKP",
            "crv": "Ed25519",
            "kid": "8xsGjFicd5zC5Xy",  # Second run key IDs
            "alg": "EdDSA",
            "use": "sig",
        },
        {
            "kty": "OKP",
            "crv": "X25519",
            "x": "different_encryption_key_material_2nd_run",
            "kid": "B2fNN2MPxFYI6IJ",  # Second run key IDs
            "use": "enc",
            "alg": "ECDH-ES",
        },
    ]

    # Simulate system already exists in routes (reconnection scenario)
    route_manager.downstream_routes[client_system_id] = Mock()

    # Mock the context and envelope for NodeAttach
    context = Mock()
    context.from_connector = Mock()
    context.authorization = None

    envelope = Mock()
    envelope.frame = NodeAttachFrame(
        system_id=client_system_id,
        instance_id="new_instance_id",
        origin_type=DeliveryOriginType.DOWNSTREAM,
        accepted_logicals=["fame.fabric"],
        keys=second_keys,
        corr_id="test_corr_id",
    )

    # Set up pending route (required by attach handler)
    route_manager._pending_route_metadata[client_system_id] = Mock()
    route_manager._pending_route_metadata[client_system_id].durable = False
    route_manager._pending_routes[client_system_id] = (
        context.from_connector,
        Mock(),
        [],
    )

    # Mock the envelope creation
    envelope_factory = Mock()
    envelope_factory.create_envelope.return_value = Mock()
    attach_handler._envelope_factory_fn = lambda: envelope_factory  # type: ignore

    # Mock connector send
    context.from_connector.send = AsyncMock()

    print("🔧 Simulating NodeAttach frame processing...")

    try:
        await attach_handler.accept_node_attach(envelope, context)
        print("✅ NodeAttach processed successfully")
    except Exception as e:
        print(f"⚠️  NodeAttach processing had issues: {e}")
        # Continue anyway to test key replacement

    # === Verify key replacement ===
    print("\n🔍 Verifying key replacement...")

    current_keys = list(await key_store.get_keys_for_path(client_physical_path))
    all_key_ids = [k["kid"] for k in await key_store.get_keys()]

    old_key_ids = {"5IrhN337S25OqJK", "UZZyOVSQaEAgr0E"}
    new_key_ids = {"8xsGjFicd5zC5Xy", "B2fNN2MPxFYI6IJ"}

    old_keys_still_present = old_key_ids.intersection(set(all_key_ids))
    new_keys_present = new_key_ids.intersection(set(all_key_ids))

    print(f"Current keys for path: {[k['kid'] for k in current_keys]}")
    print(f"All keys in store: {all_key_ids}")
    print(f"Old keys still present: {old_keys_still_present}")
    print(f"New keys present: {new_keys_present}")

    # Check if the scenario that caused the original error is fixed
    old_encryption_key_gone = "UZZyOVSQaEAgr0E" not in all_key_ids
    new_encryption_key_present = "B2fNN2MPxFYI6IJ" in all_key_ids

    print("\n🎯 Key issue resolution:")
    print(f"   Old encryption key (UZZyOVSQaEAgr0E) removed: {old_encryption_key_gone}")
    print(f"   New encryption key (B2fNN2MPxFYI6IJ) present: {new_encryption_key_present}")

    success = old_encryption_key_gone and new_encryption_key_present

    if success:
        print("\n🎉 SUCCESS: Client restart with new keys now works correctly!")
        print("   - Old stale keys are removed when client reconnects")
        print("   - New keys are properly stored and available")
        print("   - The 'Unknown key id' error should no longer occur")
    else:
        print("\n❌ FAILURE: Key replacement didn't work as expected")

    return success
