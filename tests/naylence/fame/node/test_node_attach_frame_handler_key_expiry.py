"""
Tests for NodeAttachFrameHandler key expiration validation functionality.

This module tests the logic that ensures attachment TTL does not exceed
the expiration time of any validated keys.
"""

import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from naylence.fame.connector.connector_config import ConnectorConfig
from naylence.fame.core import DeliveryOriginType, FameEnvelope, NodeAttachFrame
from naylence.fame.node.node_context import FameDeliveryContext
from naylence.fame.security.keys.attachment_key_validator import (
    AttachmentKeyValidator,
    KeyInfo,
    KeyValidationError,
)
from naylence.fame.sentinel.node_attach_frame_handler import NodeAttachFrameHandler


class MockConnectorConfig(ConnectorConfig):
    """Minimal connector config for testing."""

    type: str = "test"
    ttl: int = 3600
    durable: bool = False


class MockAttachmentKeyValidator(AttachmentKeyValidator):
    """Mock key validator for testing."""

    def __init__(self, key_infos: list[KeyInfo] = None, should_fail: bool = False):
        self.key_infos = key_infos or []
        self.should_fail = should_fail

    async def validate_key(self, key: dict) -> KeyInfo:
        """Validate a single key and return corresponding KeyInfo."""
        if self.should_fail:
            raise KeyValidationError("TEST_ERROR", "Test validation failure", kid="test-kid")

        # Return the first available KeyInfo or create a default one
        if self.key_infos:
            return self.key_infos[0]
        else:
            return KeyInfo(kid=key.get("kid", "default-kid"))

    async def validate_keys(self, keys: list[dict]) -> list[KeyInfo]:
        if self.should_fail:
            raise KeyValidationError("TEST_ERROR", "Test validation failure", kid="test-kid")
        return self.key_infos

    async def validate_child_attachment_logicals(
        self,
        child_keys: list[dict],
        authorized_logicals: list[str],
        child_id: str,
    ) -> tuple[bool, str]:
        """Mock implementation of logical validation."""
        return True, ""


@pytest.mark.asyncio
async def test_attachment_ttl_limited_by_earliest_key_expiry():
    """Test that attachment TTL is limited to the earliest key expiration."""

    # Setup times
    now = datetime.now(timezone.utc)
    max_ttl_sec = 3600  # 1 hour

    # Create keys with different expiration times
    early_expire = now + timedelta(minutes=30)  # Expires in 30 minutes
    late_expire = now + timedelta(hours=2)  # Expires in 2 hours

    key_infos = [
        KeyInfo(kid="key1", expires_at=late_expire, has_certificate=True),
        KeyInfo(kid="key2", expires_at=early_expire, has_certificate=True),  # This should limit TTL
        KeyInfo(kid="key3", expires_at=None),  # No expiry
    ]

    # Create mocks
    mock_routing_node = MagicMock()
    mock_routing_node.id = "test-sentinel"
    mock_routing_node.physical_path = "/test/sentinel"
    mock_routing_node.routing_epoch = "1"
    mock_routing_node._dispatch_event = AsyncMock()
    mock_routing_node.security_manager = None

    mock_route_manager = MagicMock()
    mock_route_manager._pending_route_metadata = {}
    mock_route_manager._pending_routes = {}
    mock_route_manager.downstream_route_store = AsyncMock()
    mock_route_manager.register_downstream_route = AsyncMock()

    # Set up pending route data
    mock_connector = AsyncMock()
    mock_attached = MagicMock()
    mock_buffer = []

    attached_system_id = "test-system"
    connector_config = MockConnectorConfig()

    mock_route_manager._pending_route_metadata[attached_system_id] = connector_config
    mock_route_manager._pending_routes[attached_system_id] = (mock_connector, mock_attached, mock_buffer)

    # Create key validator that returns our test keys
    key_validator = MockAttachmentKeyValidator(key_infos=key_infos)

    # Create handler with key validator and max TTL
    handler = NodeAttachFrameHandler(
        routing_node=mock_routing_node,
        route_manager=mock_route_manager,
        attachment_key_validator=key_validator,
        max_ttl_sec=max_ttl_sec,
    )

    # Create attach frame with keys
    attach_frame = NodeAttachFrame(
        system_id=attached_system_id,
        instance_id="test-instance",
        origin_type=DeliveryOriginType.DOWNSTREAM,
        keys=[{"kid": "key1"}, {"kid": "key2"}, {"kid": "key3"}],
    )

    envelope = FameEnvelope(frame=attach_frame, corr_id="test-correlation-id")
    context = FameDeliveryContext(
        from_connector=mock_connector,
        from_system_id=attached_system_id,
        origin_type=DeliveryOriginType.DOWNSTREAM,
    )

    # Call the handler
    await handler.accept_node_attach(envelope, context)

    # Verify that positive acknowledgment was sent
    assert mock_connector.send.called, "Acknowledgment should have been sent"
    sent_envelope = mock_connector.send.call_args[0][0]
    assert sent_envelope.frame.ok, "Acknowledgment should indicate success"

    # Verify that expires_at was limited to the earliest key expiry
    actual_expires_at = sent_envelope.frame.expires_at
    assert actual_expires_at is not None, "expires_at should be set"

    # Should be limited to early_expire (30 minutes), not the original 1 hour
    assert abs((actual_expires_at - early_expire).total_seconds()) < 1, (
        f"Expected expires_at to be limited to {early_expire}, got {actual_expires_at}"
    )


@pytest.mark.asyncio
async def test_attachment_ttl_not_limited_when_keys_expire_later():
    """Test that attachment TTL is not limited when all keys expire after max TTL."""

    # Setup times
    now = datetime.now(timezone.utc)
    max_ttl_sec = 1800  # 30 minutes
    calculated_expire = now + timedelta(seconds=max_ttl_sec)

    # Create keys that expire after the max TTL
    key_infos = [
        KeyInfo(kid="key1", expires_at=now + timedelta(hours=1), has_certificate=True),
        KeyInfo(kid="key2", expires_at=now + timedelta(hours=2), has_certificate=True),
    ]

    # Create mocks (similar setup as above)
    mock_routing_node = MagicMock()
    mock_routing_node.id = "test-sentinel"
    mock_routing_node.physical_path = "/test/sentinel"
    mock_routing_node.routing_epoch = "1"
    mock_routing_node._dispatch_event = AsyncMock()
    mock_routing_node.security_manager = None

    mock_route_manager = MagicMock()
    mock_route_manager._pending_route_metadata = {}
    mock_route_manager._pending_routes = {}
    mock_route_manager.downstream_route_store = AsyncMock()
    mock_route_manager.register_downstream_route = AsyncMock()

    mock_connector = AsyncMock()
    mock_attached = MagicMock()
    mock_buffer = []

    attached_system_id = "test-system"
    connector_config = MockConnectorConfig()

    mock_route_manager._pending_route_metadata[attached_system_id] = connector_config
    mock_route_manager._pending_routes[attached_system_id] = (mock_connector, mock_attached, mock_buffer)

    key_validator = MockAttachmentKeyValidator(key_infos=key_infos)

    handler = NodeAttachFrameHandler(
        routing_node=mock_routing_node,
        route_manager=mock_route_manager,
        attachment_key_validator=key_validator,
        max_ttl_sec=max_ttl_sec,
    )

    attach_frame = NodeAttachFrame(
        system_id=attached_system_id,
        instance_id="test-instance",
        origin_type=DeliveryOriginType.DOWNSTREAM,
        keys=[{"kid": "key1"}, {"kid": "key2"}],
    )

    envelope = FameEnvelope(frame=attach_frame, corr_id="test-correlation-id")
    context = FameDeliveryContext(
        from_connector=mock_connector,
        from_system_id=attached_system_id,
        origin_type=DeliveryOriginType.DOWNSTREAM,
    )

    # Call the handler
    await handler.accept_node_attach(envelope, context)

    # Verify that positive acknowledgment was sent
    assert mock_connector.send.called, "Acknowledgment should have been sent"
    sent_envelope = mock_connector.send.call_args[0][0]
    assert sent_envelope.frame.ok, "Acknowledgment should indicate success"

    # Verify that expires_at uses the original max TTL (not limited by keys)
    actual_expires_at = sent_envelope.frame.expires_at
    assert actual_expires_at is not None, "expires_at should be set"

    # Should be close to the original calculated expiry (within 1 second tolerance)
    assert abs((actual_expires_at - calculated_expire).total_seconds()) < 1, (
        f"Expected expires_at to be around {calculated_expire}, got {actual_expires_at}"
    )


@pytest.mark.asyncio
async def test_attachment_ttl_with_no_max_ttl_but_keys_have_expiry():
    """Test that key expiry is used when no max TTL is configured but keys expire."""

    # Setup times
    now = datetime.now(timezone.utc)
    key_expire_time = now + timedelta(minutes=30)  # Keys expire in 30 minutes

    # Create keys with expiration times
    key_infos = [
        KeyInfo(kid="key1", expires_at=key_expire_time, has_certificate=True),
        KeyInfo(kid="key2", expires_at=now + timedelta(hours=1), has_certificate=True),
    ]

    # Create mocks (similar setup as above, but no max_ttl_sec)
    mock_routing_node = MagicMock()
    mock_routing_node.id = "test-sentinel"
    mock_routing_node.physical_path = "/test/sentinel"
    mock_routing_node.routing_epoch = "1"
    mock_routing_node._dispatch_event = AsyncMock()
    mock_routing_node.security_manager = None

    mock_route_manager = MagicMock()
    mock_route_manager._pending_route_metadata = {}
    mock_route_manager._pending_routes = {}
    mock_route_manager.downstream_route_store = AsyncMock()
    mock_route_manager.register_downstream_route = AsyncMock()

    mock_connector = AsyncMock()
    mock_attached = MagicMock()
    mock_buffer = []

    attached_system_id = "test-system"
    connector_config = MockConnectorConfig()

    mock_route_manager._pending_route_metadata[attached_system_id] = connector_config
    mock_route_manager._pending_routes[attached_system_id] = (mock_connector, mock_attached, mock_buffer)

    key_validator = MockAttachmentKeyValidator(key_infos=key_infos)

    # Create handler WITHOUT max_ttl_sec
    handler = NodeAttachFrameHandler(
        routing_node=mock_routing_node,
        route_manager=mock_route_manager,
        attachment_key_validator=key_validator,
        # max_ttl_sec=None (default)
    )

    attach_frame = NodeAttachFrame(
        system_id=attached_system_id,
        instance_id="test-instance",
        origin_type=DeliveryOriginType.DOWNSTREAM,
        keys=[{"kid": "key1"}, {"kid": "key2"}],
    )

    envelope = FameEnvelope(frame=attach_frame, corr_id="test-correlation-id")
    context = FameDeliveryContext(
        from_connector=mock_connector,
        from_system_id=attached_system_id,
        origin_type=DeliveryOriginType.DOWNSTREAM,
    )

    # Call the handler
    await handler.accept_node_attach(envelope, context)

    # Verify that positive acknowledgment was sent
    assert mock_connector.send.called, "Acknowledgment should have been sent"
    sent_envelope = mock_connector.send.call_args[0][0]
    assert sent_envelope.frame.ok, "Acknowledgment should indicate success"

    # Verify that expires_at is set to the earliest key expiry (even though no max TTL is configured)
    actual_expires_at = sent_envelope.frame.expires_at
    assert actual_expires_at is not None, "expires_at should be set based on key expiry"

    # Should be set to the earliest key expiry (30 minutes)
    assert abs((actual_expires_at - key_expire_time).total_seconds()) < 1, (
        f"Expected expires_at to be set to earliest key expiry {key_expire_time}, got {actual_expires_at}"
    )


@pytest.mark.asyncio
async def test_attachment_ttl_with_no_max_ttl_and_no_key_expiry():
    """Test that no TTL is set when no max TTL is configured and keys have no expiry."""

    # Create keys without expiration times
    key_infos = [
        KeyInfo(kid="key1", expires_at=None, has_certificate=True),
    ]

    # Create mocks (similar setup as above, but no max_ttl_sec)
    mock_routing_node = MagicMock()
    mock_routing_node.id = "test-sentinel"
    mock_routing_node.physical_path = "/test/sentinel"
    mock_routing_node.routing_epoch = "1"
    mock_routing_node._dispatch_event = AsyncMock()
    mock_routing_node.security_manager = None

    mock_route_manager = MagicMock()
    mock_route_manager._pending_route_metadata = {}
    mock_route_manager._pending_routes = {}
    mock_route_manager.downstream_route_store = AsyncMock()
    mock_route_manager.register_downstream_route = AsyncMock()

    mock_connector = AsyncMock()
    mock_attached = MagicMock()
    mock_buffer = []

    attached_system_id = "test-system"
    connector_config = MockConnectorConfig()

    mock_route_manager._pending_route_metadata[attached_system_id] = connector_config
    mock_route_manager._pending_routes[attached_system_id] = (mock_connector, mock_attached, mock_buffer)

    key_validator = MockAttachmentKeyValidator(key_infos=key_infos)

    # Create handler WITHOUT max_ttl_sec
    handler = NodeAttachFrameHandler(
        routing_node=mock_routing_node,
        route_manager=mock_route_manager,
        attachment_key_validator=key_validator,
        # max_ttl_sec=None (default)
    )

    attach_frame = NodeAttachFrame(
        system_id=attached_system_id,
        instance_id="test-instance",
        origin_type=DeliveryOriginType.DOWNSTREAM,
        keys=[{"kid": "key1"}],
    )

    envelope = FameEnvelope(frame=attach_frame, corr_id="test-correlation-id")
    context = FameDeliveryContext(
        from_connector=mock_connector,
        from_system_id=attached_system_id,
        origin_type=DeliveryOriginType.DOWNSTREAM,
    )

    # Call the handler
    await handler.accept_node_attach(envelope, context)

    # Verify that positive acknowledgment was sent
    assert mock_connector.send.called, "Acknowledgment should have been sent"
    sent_envelope = mock_connector.send.call_args[0][0]
    assert sent_envelope.frame.ok, "Acknowledgment should indicate success"

    # Verify that expires_at is None (no TTL configured)
    actual_expires_at = sent_envelope.frame.expires_at
    assert actual_expires_at is None, "expires_at should be None when no max TTL is configured"


@pytest.mark.asyncio
async def test_attachment_ttl_with_keys_without_expiry():
    """Test that attachment TTL is not affected by keys without expiration."""

    # Setup times
    now = datetime.now(timezone.utc)
    max_ttl_sec = 3600  # 1 hour
    calculated_expire = now + timedelta(seconds=max_ttl_sec)

    # Create keys without expiration times
    key_infos = [
        KeyInfo(kid="key1", expires_at=None, has_certificate=False),  # No expiry
        KeyInfo(kid="key2", expires_at=None, has_certificate=True),  # No expiry
    ]

    # Create mocks
    mock_routing_node = MagicMock()
    mock_routing_node.id = "test-sentinel"
    mock_routing_node.physical_path = "/test/sentinel"
    mock_routing_node.routing_epoch = "1"
    mock_routing_node._dispatch_event = AsyncMock()
    mock_routing_node.security_manager = None

    mock_route_manager = MagicMock()
    mock_route_manager._pending_route_metadata = {}
    mock_route_manager._pending_routes = {}
    mock_route_manager.downstream_route_store = AsyncMock()
    mock_route_manager.register_downstream_route = AsyncMock()

    mock_connector = AsyncMock()
    mock_attached = MagicMock()
    mock_buffer = []

    attached_system_id = "test-system"
    connector_config = MockConnectorConfig()

    mock_route_manager._pending_route_metadata[attached_system_id] = connector_config
    mock_route_manager._pending_routes[attached_system_id] = (mock_connector, mock_attached, mock_buffer)

    key_validator = MockAttachmentKeyValidator(key_infos=key_infos)

    handler = NodeAttachFrameHandler(
        routing_node=mock_routing_node,
        route_manager=mock_route_manager,
        attachment_key_validator=key_validator,
        max_ttl_sec=max_ttl_sec,
    )

    attach_frame = NodeAttachFrame(
        system_id=attached_system_id,
        instance_id="test-instance",
        origin_type=DeliveryOriginType.DOWNSTREAM,
        keys=[{"kid": "key1"}, {"kid": "key2"}],
    )

    envelope = FameEnvelope(frame=attach_frame, corr_id="test-correlation-id")
    context = FameDeliveryContext(
        from_connector=mock_connector,
        from_system_id=attached_system_id,
        origin_type=DeliveryOriginType.DOWNSTREAM,
    )

    # Call the handler
    await handler.accept_node_attach(envelope, context)

    # Verify that positive acknowledgment was sent
    assert mock_connector.send.called, "Acknowledgment should have been sent"
    sent_envelope = mock_connector.send.call_args[0][0]
    assert sent_envelope.frame.ok, "Acknowledgment should indicate success"

    # Verify that expires_at uses the original max TTL (not affected by keys without expiry)
    actual_expires_at = sent_envelope.frame.expires_at
    assert actual_expires_at is not None, "expires_at should be set"

    # Should be close to the original calculated expiry
    assert abs((actual_expires_at - calculated_expire).total_seconds()) < 1, (
        f"Expected expires_at to be around {calculated_expire}, got {actual_expires_at}"
    )


@pytest.mark.asyncio
async def test_attachment_ttl_with_no_keys():
    """Test that attachment TTL works normally when no keys are provided."""

    # Setup times
    now = datetime.now(timezone.utc)
    max_ttl_sec = 3600  # 1 hour
    calculated_expire = now + timedelta(seconds=max_ttl_sec)

    # No keys provided
    key_infos = []

    # Create mocks
    mock_routing_node = MagicMock()
    mock_routing_node.id = "test-sentinel"
    mock_routing_node.physical_path = "/test/sentinel"
    mock_routing_node.routing_epoch = "1"
    mock_routing_node._dispatch_event = AsyncMock()
    mock_routing_node.security_manager = None

    mock_route_manager = MagicMock()
    mock_route_manager._pending_route_metadata = {}
    mock_route_manager._pending_routes = {}
    mock_route_manager.downstream_route_store = AsyncMock()
    mock_route_manager.register_downstream_route = AsyncMock()

    mock_connector = AsyncMock()
    mock_attached = MagicMock()
    mock_buffer = []

    attached_system_id = "test-system"
    connector_config = MockConnectorConfig()

    mock_route_manager._pending_route_metadata[attached_system_id] = connector_config
    mock_route_manager._pending_routes[attached_system_id] = (mock_connector, mock_attached, mock_buffer)

    key_validator = MockAttachmentKeyValidator(key_infos=key_infos)

    handler = NodeAttachFrameHandler(
        routing_node=mock_routing_node,
        route_manager=mock_route_manager,
        attachment_key_validator=key_validator,
        max_ttl_sec=max_ttl_sec,
    )

    attach_frame = NodeAttachFrame(
        system_id=attached_system_id,
        instance_id="test-instance",
        origin_type=DeliveryOriginType.DOWNSTREAM,
        keys=[],  # Empty keys
    )

    envelope = FameEnvelope(frame=attach_frame, corr_id="test-correlation-id")
    context = FameDeliveryContext(
        from_connector=mock_connector,
        from_system_id=attached_system_id,
        origin_type=DeliveryOriginType.DOWNSTREAM,
    )

    # Call the handler
    await handler.accept_node_attach(envelope, context)

    # Verify that positive acknowledgment was sent
    assert mock_connector.send.called, "Acknowledgment should have been sent"
    sent_envelope = mock_connector.send.call_args[0][0]
    assert sent_envelope.frame.ok, "Acknowledgment should indicate success"

    # Verify that expires_at uses the original max TTL
    actual_expires_at = sent_envelope.frame.expires_at
    assert actual_expires_at is not None, "expires_at should be set"

    # Should be close to the original calculated expiry
    assert abs((actual_expires_at - calculated_expire).total_seconds()) < 1, (
        f"Expected expires_at to be around {calculated_expire}, got {actual_expires_at}"
    )


@pytest.mark.asyncio
async def test_attachment_ttl_with_no_validator():
    """Test that attachment TTL works normally when no key validator is configured."""

    # Setup times
    now = datetime.now(timezone.utc)
    max_ttl_sec = 3600  # 1 hour
    calculated_expire = now + timedelta(seconds=max_ttl_sec)

    # Create mocks
    mock_routing_node = MagicMock()
    mock_routing_node.id = "test-sentinel"
    mock_routing_node.physical_path = "/test/sentinel"
    mock_routing_node.routing_epoch = "1"
    mock_routing_node._dispatch_event = AsyncMock()
    mock_routing_node.security_manager = None

    mock_route_manager = MagicMock()
    mock_route_manager._pending_route_metadata = {}
    mock_route_manager._pending_routes = {}
    mock_route_manager.downstream_route_store = AsyncMock()
    mock_route_manager.register_downstream_route = AsyncMock()

    mock_connector = AsyncMock()
    mock_attached = MagicMock()
    mock_buffer = []

    attached_system_id = "test-system"
    connector_config = MockConnectorConfig()

    mock_route_manager._pending_route_metadata[attached_system_id] = connector_config
    mock_route_manager._pending_routes[attached_system_id] = (mock_connector, mock_attached, mock_buffer)

    # Create handler WITHOUT key validator
    handler = NodeAttachFrameHandler(
        routing_node=mock_routing_node,
        route_manager=mock_route_manager,
        # attachment_key_validator=None (default)
        max_ttl_sec=max_ttl_sec,
    )

    attach_frame = NodeAttachFrame(
        system_id=attached_system_id,
        instance_id="test-instance",
        origin_type=DeliveryOriginType.DOWNSTREAM,
        keys=[{"kid": "key1"}],
    )

    envelope = FameEnvelope(frame=attach_frame, corr_id="test-correlation-id")
    context = FameDeliveryContext(
        from_connector=mock_connector,
        from_system_id=attached_system_id,
        origin_type=DeliveryOriginType.DOWNSTREAM,
    )

    # Call the handler
    await handler.accept_node_attach(envelope, context)

    # Verify that positive acknowledgment was sent
    assert mock_connector.send.called, "Acknowledgment should have been sent"
    sent_envelope = mock_connector.send.call_args[0][0]
    assert sent_envelope.frame.ok, "Acknowledgment should indicate success"

    # Verify that expires_at uses the original max TTL
    actual_expires_at = sent_envelope.frame.expires_at
    assert actual_expires_at is not None, "expires_at should be set"

    # Should be close to the original calculated expiry
    assert abs((actual_expires_at - calculated_expire).total_seconds()) < 1, (
        f"Expected expires_at to be around {calculated_expire}, got {actual_expires_at}"
    )


@pytest.mark.asyncio
async def test_key_validation_failure_still_rejects_attachment():
    """Test that key validation failures still properly reject the attachment."""

    # Create mocks
    mock_routing_node = MagicMock()
    mock_routing_node.id = "test-sentinel"
    mock_routing_node.physical_path = "/test/sentinel"
    mock_routing_node.routing_epoch = "1"

    mock_route_manager = MagicMock()
    mock_route_manager._pending_route_metadata = {}
    mock_route_manager._pending_routes = {}

    mock_connector = AsyncMock()
    mock_attached = MagicMock()
    mock_buffer = []

    attached_system_id = "test-system"
    connector_config = MockConnectorConfig()

    mock_route_manager._pending_route_metadata[attached_system_id] = connector_config
    mock_route_manager._pending_routes[attached_system_id] = (mock_connector, mock_attached, mock_buffer)

    # Create key validator that fails
    key_validator = MockAttachmentKeyValidator(should_fail=True)

    handler = NodeAttachFrameHandler(
        routing_node=mock_routing_node,
        route_manager=mock_route_manager,
        attachment_key_validator=key_validator,
        max_ttl_sec=3600,
    )

    attach_frame = NodeAttachFrame(
        system_id=attached_system_id,
        instance_id="test-instance",
        origin_type=DeliveryOriginType.DOWNSTREAM,
        keys=[{"kid": "invalid-key"}],
    )

    envelope = FameEnvelope(frame=attach_frame, corr_id="test-correlation-id")
    context = FameDeliveryContext(
        from_connector=mock_connector,
        from_system_id=attached_system_id,
        origin_type=DeliveryOriginType.DOWNSTREAM,
    )

    # Call the handler
    await handler.accept_node_attach(envelope, context)

    # Verify that negative acknowledgment was sent
    assert mock_connector.send.called, "Acknowledgment should have been sent"
    sent_envelope = mock_connector.send.call_args[0][0]
    assert not sent_envelope.frame.ok, "Acknowledgment should indicate failure"
    assert "Certificate validation failed" in sent_envelope.frame.reason
    assert sent_envelope.corr_id == "test-correlation-id"


if __name__ == "__main__":
    # Run tests individually for debugging
    import asyncio

    print("🧪 Running key expiry validation tests...")

    asyncio.run(test_attachment_ttl_limited_by_earliest_key_expiry())
    print("✅ test_attachment_ttl_limited_by_earliest_key_expiry passed")

    asyncio.run(test_attachment_ttl_not_limited_when_keys_expire_later())
    print("✅ test_attachment_ttl_not_limited_when_keys_expire_later passed")

    asyncio.run(test_attachment_ttl_with_no_max_ttl_but_keys_have_expiry())
    print("✅ test_attachment_ttl_with_no_max_ttl_but_keys_have_expiry passed")

    asyncio.run(test_attachment_ttl_with_no_max_ttl_and_no_key_expiry())
    print("✅ test_attachment_ttl_with_no_max_ttl_and_no_key_expiry passed")

    asyncio.run(test_attachment_ttl_with_keys_without_expiry())
    print("✅ test_attachment_ttl_with_keys_without_expiry passed")

    asyncio.run(test_attachment_ttl_with_no_keys())
    print("✅ test_attachment_ttl_with_no_keys passed")

    asyncio.run(test_attachment_ttl_with_no_validator())
    print("✅ test_attachment_ttl_with_no_validator passed")

    asyncio.run(test_key_validation_failure_still_rejects_attachment())
    print("✅ test_key_validation_failure_still_rejects_attachment passed")

    print("🎉 All key expiry validation tests passed!")
