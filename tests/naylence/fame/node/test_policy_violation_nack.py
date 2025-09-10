"""
Test security policy violation handling with NACK responses.
"""

import asyncio
from unittest.mock import MagicMock

import pytest

from naylence.fame.core import (
    DataFrame,
    DeliveryAckFrame,
    DeliveryOriginType,
    FameAddress,
    create_fame_envelope,
)
from naylence.fame.node.node import FameNode
from naylence.fame.node.node_meta import NodeMeta
from naylence.fame.security.policy.default_security_policy import DefaultSecurityPolicy
from naylence.fame.security.policy.security_policy import (
    EncryptionConfig,
    InboundCryptoRules,
    InboundSigningRules,
    SecurityAction,
    SignaturePolicy,
    SigningConfig,
)
from naylence.fame.storage.in_memory_key_value_store import InMemoryKVStore


@pytest.fixture
async def mock_node():
    """Create a node with mocked components for testing."""
    from naylence.fame.security.policy.default_security_policy import (
        DefaultSecurityPolicy,
    )
    from naylence.fame.security.security_manager_factory import SecurityManagerFactory

    # Create a node with minimal security setup
    node_security = await SecurityManagerFactory.create_security_manager(policy=DefaultSecurityPolicy())

    from naylence.fame.delivery.default_delivery_tracker_factory import (
        DefaultDeliveryTrackerFactory,
    )
    from naylence.fame.storage.in_memory_storage_provider import InMemoryStorageProvider

    storage_provider = InMemoryStorageProvider()
    node_meta_store = InMemoryKVStore[NodeMeta](NodeMeta)
    delivery_tracker_factory = DefaultDeliveryTrackerFactory()
    delivery_tracker = await delivery_tracker_factory.create(storage_provider=storage_provider)
    node = FameNode(
        security_manager=node_security,
        system_id="test-node",
        storage_provider=storage_provider,
        node_meta_store=node_meta_store,
        delivery_tracker=delivery_tracker,
    )

    # Initialize the SID that's needed for NACK sending
    node._sid = "test-sid"

    # Mock the envelope factory to create proper NACK envelopes
    node._envelope_factory = MagicMock()

    def create_nack_envelope(**kwargs):
        frame = kwargs.get("frame")
        return create_fame_envelope(trace_id=kwargs.get("trace_id"), frame=frame, to=kwargs.get("to"))

    node._envelope_factory.create_envelope.side_effect = create_nack_envelope

    # Mock the binding manager to avoid "No local binding" errors
    node._binding_manager = MagicMock()
    mock_binding = MagicMock()
    mock_channel = MagicMock()
    mock_binding.channel = mock_channel
    node._binding_manager.get_binding.return_value = mock_binding

    # Mock the deliver method to capture NACK responses
    node._delivered_envelopes = []

    async def mock_deliver(envelope, context=None):
        node._delivered_envelopes.append((envelope, context))
        # Don't call original_deliver to avoid complex initialization
        return None

    node.deliver = mock_deliver
    return node


@pytest.fixture
def strict_crypto_policy():
    """Create a security policy that requires encryption."""
    config = EncryptionConfig(
        inbound=InboundCryptoRules(
            allow_plaintext=False,  # Reject plaintext messages
            allow_channel=True,
            allow_sealed=True,
            plaintext_violation_action=SecurityAction.NACK,
        )
    )
    return DefaultSecurityPolicy(encryption=config)


@pytest.fixture
def strict_signing_policy():
    """Create a security policy that requires signatures."""
    config = SigningConfig(
        inbound=InboundSigningRules(
            signature_policy=SignaturePolicy.REQUIRED,  # Require signatures
            unsigned_violation_action=SecurityAction.NACK,
            invalid_signature_action=SecurityAction.NACK,
        )
    )
    return DefaultSecurityPolicy(signing=config)


@pytest.mark.asyncio
async def test_crypto_level_violation_sends_nack(mock_node, strict_crypto_policy):
    """Test that crypto level violations trigger NACK responses."""
    # Setup - set the policy on the node's security manager
    mock_node._security_manager.policy = strict_crypto_policy

    # Create a plaintext envelope (violates policy)
    envelope = create_fame_envelope(
        frame=DataFrame(payload={"test": "data"}),
        reply_to=FameAddress("sender@test"),
    )
    # Ensure envelope has no encryption (plaintext)
    envelope.sec = None

    address = FameAddress("recipient@test")

    # Execute
    await mock_node.deliver_local(address, envelope)

    # Verify NACK was sent
    assert len(mock_node._delivered_envelopes) == 1
    nack_envelope, nack_context = mock_node._delivered_envelopes[0]

    # Check that it's a NACK
    assert isinstance(nack_envelope.frame, DeliveryAckFrame)
    assert nack_envelope.frame.ok is False
    assert "crypto_level_violation" in nack_envelope.frame.code

    # Check that it goes to the original sender
    assert nack_envelope.to == envelope.reply_to

    # Check that it's marked as local origin
    assert nack_context.origin_type == DeliveryOriginType.LOCAL


@pytest.mark.asyncio
async def test_unsigned_message_violation_sends_nack(mock_node, strict_signing_policy):
    """Test that unsigned message violations trigger NACK responses."""
    # Setup - set the policy on the node's security manager
    mock_node._security_manager.policy = strict_signing_policy

    # Create an unsigned envelope (violates policy)
    envelope = create_fame_envelope(
        frame=DataFrame(payload={"test": "data"}),
        reply_to=FameAddress("sender@test"),
    )
    # Ensure envelope has no signature
    if envelope.sec:
        envelope.sec.sig = None

    address = FameAddress("recipient@test")

    # Execute
    await mock_node.deliver_local(address, envelope)

    # Verify NACK was sent
    assert len(mock_node._delivered_envelopes) == 1
    nack_envelope, nack_context = mock_node._delivered_envelopes[0]

    # Check that it's a NACK
    assert isinstance(nack_envelope.frame, DeliveryAckFrame)
    assert nack_envelope.frame.ok is False
    assert "signature_required" in nack_envelope.frame.code


@pytest.mark.asyncio
async def test_invalid_signature_violation_sends_nack(mock_node, strict_signing_policy):
    """Test that invalid signature violations trigger NACK responses."""
    # Setup - set the policy on the node's security manager
    mock_node._security_manager.policy = strict_signing_policy

    # Mock envelope verifier to simulate verification failure
    mock_verifier = MagicMock()
    mock_verifier.verify_envelope.side_effect = ValueError("Invalid signature")
    mock_node._security_manager.envelope_verifier = mock_verifier

    # Create a signed envelope
    envelope = create_fame_envelope(
        frame=DataFrame(payload={"test": "data"}),
        reply_to=FameAddress("sender@test"),
    )
    # Add a mock signature
    from naylence.fame.core.protocol.security_header import (
        SecurityHeader,
        SignatureHeader,
    )

    envelope.sec = SecurityHeader(sig=SignatureHeader(alg="test", kid="test-key", val="invalid"))

    address = FameAddress("recipient@test")

    # Execute
    await mock_node.deliver_local(address, envelope)

    # Verify NACK was sent
    assert len(mock_node._delivered_envelopes) == 1
    nack_envelope, nack_context = mock_node._delivered_envelopes[0]

    # Check that it's a NACK
    assert isinstance(nack_envelope.frame, DeliveryAckFrame)
    assert nack_envelope.frame.ok is False
    assert "signature_verification_failed" in nack_envelope.frame.code


@pytest.mark.asyncio
async def test_no_nack_when_no_reply_to_address(mock_node, strict_crypto_policy):
    """Test that no NACK is sent when there's no reply-to address."""
    # Setup - set the policy on the node's security manager
    mock_node._security_manager.policy = strict_crypto_policy

    # Create a plaintext envelope without reply_to (violates policy but can't NACK)
    envelope = create_fame_envelope(
        frame=DataFrame(payload={"test": "data"}),
        # No reply_to address
    )
    # Ensure envelope has no encryption (plaintext)
    envelope.sec = None

    address = FameAddress("recipient@test")

    # Execute
    await mock_node.deliver_local(address, envelope)

    # Verify no NACK was sent (can't send without reply_to)
    assert len(mock_node._delivered_envelopes) == 0


@pytest.mark.asyncio
async def test_reject_action_drops_message_silently(mock_node):
    """Test that REJECT action drops messages without sending NACK."""
    # Setup policy with REJECT action
    config = EncryptionConfig(
        inbound=InboundCryptoRules(
            allow_plaintext=False,
            plaintext_violation_action=SecurityAction.REJECT,  # REJECT instead of NACK
        )
    )
    policy = DefaultSecurityPolicy(encryption=config)
    # Setup - set the policy on the node's security manager
    mock_node._security_manager.policy = policy

    # Create a plaintext envelope (violates policy)
    envelope = create_fame_envelope(
        frame=DataFrame(payload={"test": "data"}),
        reply_to=FameAddress("sender@test"),
    )
    envelope.sec = None

    address = FameAddress("recipient@test")

    # Execute
    await mock_node.deliver_local(address, envelope)

    # Verify no NACK was sent (REJECT policy)
    assert len(mock_node._delivered_envelopes) == 0


if __name__ == "__main__":
    # Run a quick test
    asyncio.run(test_crypto_level_violation_sends_nack(mock_node(), strict_crypto_policy()))
    print("✅ Policy violation NACK tests implemented!")
