"""
Security fixtures for comprehensive integration testing.

These fixtures provide realistic security components and configurations
for testing security manager integration scenarios.
"""

from unittest.mock import MagicMock
from uuid import uuid4

import pytest

from naylence.fame.core import FameEnvelope
from naylence.fame.core.protocol.frames import DataFrame
from naylence.fame.security.policy.default_security_policy import DefaultSecurityPolicy


class TestCryptoProvider:
    """Test crypto provider with realistic key management."""

    def __init__(self):
        self.signature_key_id = "test-sig-key-" + str(uuid4())[:8]
        self.encryption_key_id = "test-enc-key-" + str(uuid4())[:8]
        self._node_jwk = None
        self._jwks = None

    def node_jwk(self):
        if not self._node_jwk:
            self._node_jwk = {
                "kid": self.signature_key_id,
                "kty": "OKP",
                "crv": "Ed25519",
                "use": "sig",
                "alg": "EdDSA",
            }
        return self._node_jwk

    def get_jwks(self):
        if not self._jwks:
            self._jwks = {
                "keys": [
                    self.node_jwk(),
                    {"kid": self.encryption_key_id, "kty": "OKP", "crv": "X25519", "use": "enc"},
                ]
            }
        return self._jwks


class TestKeyManager:
    """Test key manager with state tracking."""

    def __init__(self):
        self.started = False
        self.stopped = False
        self.initialized = False
        self.keys_added = []
        self.keys_removed = []
        self.key_announcements = []

    async def on_node_started(self, node):
        self.started = True

    async def on_node_stopped(self, node):
        self.stopped = True

    async def on_node_initialized(self, node):
        self.initialized = True

    async def add_keys(self, keys, physical_path, system_id, origin):
        entry = {
            "keys": keys,
            "physical_path": physical_path,
            "system_id": system_id,
            "origin": origin,
            "timestamp": None,  # Could add real timestamp if needed
        }
        self.keys_added.append(entry)

    async def remove_keys_for_path(self, path):
        self.keys_removed.append(path)
        return len([r for r in self.keys_removed if r == path])

    async def announce_keys_to_upstream(self):
        announcement = {
            "timestamp": None,  # Could add real timestamp
            "keys_count": len(self.keys_added),
        }
        self.key_announcements.append(announcement)


class TestCertificateManager:
    """Test certificate manager with configurable behavior."""

    def __init__(self, should_fail=False, fail_with_validation_error=False):
        self.started = False
        self.stopped = False
        self.initialized = False
        self.welcome_calls = []
        self.should_fail = should_fail
        self.fail_with_validation_error = fail_with_validation_error

    async def on_node_started(self, node):
        self.started = True

    async def on_node_stopped(self, node):
        self.stopped = True

    async def on_node_initialized(self, node):
        self.initialized = True

    async def on_welcome(self, welcome_frame):
        self.welcome_calls.append(welcome_frame)

        if self.should_fail:
            if self.fail_with_validation_error:
                raise RuntimeError("certificate validation failed: test error")
            else:
                raise Exception("General certificate error")


class TestNodeLike:
    """Test node implementation with full interface."""

    def __init__(self, node_id: str = None, is_sentinel: bool = False):
        self.id = node_id or str(uuid4())
        self.sid = f"sid-{self.id}"
        self.envelope_factory = MagicMock()
        self.envelope_factory.create_envelope.return_value = FameEnvelope(
            frame=DataFrame(payload={}, codec="json")
        )
        self._event_listeners = []
        self.deliver_calls = []
        self.spawn_calls = []
        self._security_policy = None

        # Sentinel-specific attributes
        if is_sentinel:
            self._route_manager = MagicMock()
            self._binding_manager = MagicMock()

    async def deliver(self, envelope, context=None):
        """Mock deliver method that records calls."""
        self.deliver_calls.append((envelope, context))

    def spawn(self, coro):
        """Mock spawn method that records and executes coroutines."""
        import asyncio

        task = asyncio.create_task(coro)
        self.spawn_calls.append(task)
        return task

    def add_event_listener(self, listener):
        """Add event listener."""
        self._event_listeners.append(listener)

    def remove_event_listener(self, listener):
        """Remove event listener."""
        if listener in self._event_listeners:
            self._event_listeners.remove(listener)


class TestSecurityPolicy:
    """Test security policy with configurable behavior."""

    def __init__(self, require_signatures=False, require_encryption=False, strict_validation=False):
        self.require_signatures = require_signatures
        self.require_encryption = require_encryption
        self.strict_validation = strict_validation
        self._requirements = None

    def requirements(self):
        if not self._requirements:
            from naylence.fame.security.policy.security_policy import SecurityRequirements

            self._requirements = SecurityRequirements(
                require_signing_key_exchange=self.require_signatures,
                require_encryption_key_exchange=self.require_encryption,
                verification_required=self.strict_validation,
            )
        return self._requirements

    def validate_attach_security_compatibility(self, peer_keys, peer_requirements, node_like):
        if self.strict_validation and not peer_keys:
            return False, "No keys provided but required by policy"
        return True, "Valid"

    def is_signature_required(self, envelope, context):
        return self.require_signatures

    async def should_verify_signature(self, envelope, context):
        return self.strict_validation

    def classify_message_crypto_level(self, envelope, context):
        from naylence.fame.security.policy.security_policy import CryptoLevel

        return CryptoLevel.PLAINTEXT

    def is_inbound_crypto_level_allowed(self, crypto_level, envelope, context):
        return True

    def get_inbound_violation_action(self, crypto_level, envelope, context):
        from naylence.fame.security.policy.security_policy import SecurityAction

        return SecurityAction.ALLOW

    def get_unsigned_violation_action(self, envelope, context):
        from naylence.fame.security.policy.security_policy import SecurityAction

        return SecurityAction.ALLOW if not self.require_signatures else SecurityAction.REJECT


def get_security_fixture_data():
    """Get security fixture data for testing."""
    return {
        "valid_security_data": {"key": "test_key", "encryption_method": "AES", "security_level": "high"},
        "invalid_security_data": {"key": "", "encryption_method": "None", "security_level": "low"},
        "test_jwk_signing": {
            "kid": "test-signing-key",
            "kty": "OKP",
            "crv": "Ed25519",
            "use": "sig",
            "alg": "EdDSA",
        },
        "test_jwk_encryption": {"kid": "test-encryption-key", "kty": "OKP", "crv": "X25519", "use": "enc"},
    }


# Legacy fixture data for backward compatibility
security_fixtures = get_security_fixture_data()


@pytest.fixture
def test_crypto_provider():
    """Provide a test crypto provider."""
    return TestCryptoProvider()


@pytest.fixture
def test_key_manager():
    """Provide a test key manager."""
    return TestKeyManager()


@pytest.fixture
def test_certificate_manager():
    """Provide a test certificate manager."""
    return TestCertificateManager()


@pytest.fixture
def failing_certificate_manager():
    """Provide a certificate manager that fails."""
    return TestCertificateManager(should_fail=True)


@pytest.fixture
def validation_failing_certificate_manager():
    """Provide a certificate manager that fails with validation error."""
    return TestCertificateManager(should_fail=True, fail_with_validation_error=True)


@pytest.fixture
def test_child_node():
    """Provide a test child node."""
    return TestNodeLike(node_id="test-child-node")


@pytest.fixture
def test_sentinel_node():
    """Provide a test sentinel node."""
    return TestNodeLike(node_id="test-sentinel-node", is_sentinel=True)


@pytest.fixture
def permissive_security_policy():
    """Provide a permissive security policy."""
    return TestSecurityPolicy(require_signatures=False, require_encryption=False, strict_validation=False)


@pytest.fixture
def strict_security_policy():
    """Provide a strict security policy."""
    return TestSecurityPolicy(require_signatures=True, require_encryption=True, strict_validation=True)


@pytest.fixture
def default_security_policy():
    """Provide the default security policy."""
    return DefaultSecurityPolicy()
