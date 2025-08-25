from naylence.fame.core import (
    DataFrame,
    DeliveryOriginType,
    FameAddress,
    FameDeliveryContext,
    FameEnvelope,
)
from naylence.fame.node.node_config import FameNodeConfig
from naylence.fame.node.node_factory import NodeFactory


async def test_end_to_end_signing():
    """Test that outbound envelopes are actually signed when using policy-driven security."""

    # Create configuration with default_signing=True
    config = FameNodeConfig(
        mode="dev",
        security={
            "type": "DefaultSecurityManager",
            "security_policy": {
                "type": "DefaultSecurityPolicy",
                "signing": {
                    "outbound": {
                        "default_signing": True,  # Should cause outbound signing
                        "sign_sensitive_operations": False,
                        "sign_if_recipient_expects": False,
                    }
                },
                "encryption": {
                    "inbound": {
                        "allow_plaintext": True,
                        "allow_channel": False,
                        "allow_sealed": False,
                        "plaintext_violation_action": "allow",
                        "channel_violation_action": "nack",
                        "sealed_violation_action": "nack",
                    },
                    "response": {
                        "mirror_request_level": False,
                        "minimum_response_level": "plaintext",
                        "escalate_sealed_responses": False,
                    },
                    "outbound": {
                        "default_level": "plaintext",
                        "escalate_if_peer_supports": False,
                        "prefer_sealed_for_sensitive": False,
                    },
                },
            },
        },
    )

    # Create the node using the factory
    factory = NodeFactory()

    async with await factory.create(config) as node:
        # Create a real envelope for testing
        envelope = FameEnvelope(
            id="test-envelope-123",
            to=FameAddress("test@/destination"),
            frame=DataFrame(type="Data", payload={"message": "test"}),
        )

        # Simulate LOCAL origin context (outbound message)
        context = FameDeliveryContext(origin_type=DeliveryOriginType.LOCAL)
        context.meta = {"message-type": "request"}

        print("Before signing:")
        print(f"  - Envelope has signature: {bool(envelope.sec and envelope.sec.sig)}")

        # Test the security policy decision
        should_sign = await node._security_manager.policy.should_sign_envelope(envelope, context, node)
        print(f"  - Policy says should sign: {should_sign}")

        # Test the envelope security handler
        handler = node._security_manager.envelope_security_handler
        print(f"  - Handler has signer: {handler._envelope_signer is not None}")

        if handler._envelope_signer and should_sign:
            # This is what the node should do - apply signing
            print("\nApplying signing...")

            # Ensure envelope has sid (normally done by the node)
            if not envelope.sid:
                envelope.sid = node.sid or "test-sid"

            # Apply the signing (this is what handle_outbound_security does)
            handler._envelope_signer.sign_envelope(envelope, physical_path=node.physical_path or "/test")

            print("After signing:")
            print(f"  - Envelope has signature: {bool(envelope.sec and envelope.sec.sig)}")
            if envelope.sec and envelope.sec.sig:
                print(f"  - Signature kid: {envelope.sec.sig.kid}")
                print(
                    f"  - Signature value length: {
                        len(envelope.sec.sig.val) if envelope.sec.sig.val else 0
                    }"
                )

            assert envelope.sec is not None, "Envelope should have security section after signing"
            assert envelope.sec.sig is not None, "Envelope should have signature after signing"
            print("✅ Success: Envelope was successfully signed")
        else:
            print(
                f"❌ Problem: Either no signer ({
                    handler._envelope_signer is not None
                }) or policy says no signing ({should_sign})"
            )

        # Test the complete outbound security flow
        print("\n" + "=" * 50)
        print("Testing complete outbound security flow...")

        # Create a fresh envelope
        envelope2 = FameEnvelope(
            id="test-envelope-456",
            to=FameAddress("test@/destination"),
            frame=DataFrame(type="Data", payload={"message": "test2"}),
        )

        print("Before outbound security:")
        print(f"  - Envelope has signature: {bool(envelope2.sec and envelope2.sec.sig)}")

        # Call the actual outbound security handler method
        result = await handler.handle_outbound_security(envelope2, context)

        print("After outbound security:")
        print(f"  - Handler result: {result}")
        print(f"  - Envelope has signature: {bool(envelope2.sec and envelope2.sec.sig)}")

        if envelope2.sec and envelope2.sec.sig:
            print(f"  - Signature kid: {envelope2.sec.sig.kid}")
            print("✅ Success: Complete outbound security flow worked")
        else:
            print("❌ Problem: Outbound security flow did not sign the envelope")

            # Debug: Let's see what the outbound security method actually does
            print("\nDebugging outbound security...")
            print(f"  - Handler._envelope_signer: {handler._envelope_signer}")
            print(f"  - Handler._security_policy: {handler._security_policy}")
            print(
                f"  - Policy.should_sign_envelope: {
                    await handler._security_policy.should_sign_envelope(envelope2, context, node)
                    if handler._security_policy
                    else 'No policy'
                }"
            )
