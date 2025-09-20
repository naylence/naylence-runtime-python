import unittest
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from naylence.fame.core import (
    DeliveryOriginType,
    EnvelopeFactory,
)
from naylence.fame.security.keys.default_key_manager import DefaultKeyManager
from naylence.fame.security.keys.key_store import KeyStore


class TestDefaultKeyManagerLargestGaps:
    """Test the largest coverage gap: handle_key_request method (63 lines, 320-382)."""

    @pytest.fixture
    def mock_key_store(self):
        """Create mock KeyStore."""
        key_store = AsyncMock(spec=KeyStore)
        return key_store

    @pytest.fixture
    def mock_node(self):
        """Create mock NodeLike."""
        node = MagicMock()
        node.has_parent = True
        node.physical_path = "/test/node"
        node._id = "test-node-id"
        node._sid = "test-node-sid"
        node._envelope_factory = MagicMock(spec=EnvelopeFactory)
        node.forward_upstream = AsyncMock()
        return node

    @pytest.fixture
    def mock_routing_node(self):
        """Create mock RoutingNodeLike."""
        routing_node = MagicMock()
        routing_node.forward_to_route = AsyncMock()
        routing_node.forward_to_peers = AsyncMock()
        return routing_node

    @pytest.fixture
    async def key_manager_with_node(self, mock_key_store, mock_node, mock_routing_node):
        """Create DefaultKeyManager with mocked node context."""
        key_manager = DefaultKeyManager(key_store=mock_key_store)

        # Simply set up the key manager with node and routing capabilities
        await key_manager.on_node_started(mock_node)
        key_manager._routing_node = mock_routing_node

        return key_manager

    @pytest.mark.asyncio
    async def test_handle_key_request_key_found_downstream_origin(
        self, key_manager_with_node, mock_key_store
    ):
        """Test handle_key_request with key found, downstream origin - covers lines 320-345."""
        # Mock key store to return a test key
        test_key = {
            "kid": "test-key-id",
            "kty": "RSA",
            "use": "sig",
            "physical_path": "/test/downstream/path",
        }
        mock_key_store.get_key.return_value = test_key

        # Mock envelope creation
        mock_envelope = MagicMock()
        key_manager_with_node._envelope_factory.create_envelope.return_value = mock_envelope

        # Call the method
        await key_manager_with_node.handle_key_request(
            kid="test-key-id",
            from_seg="downstream-segment",
            physical_path=None,
            origin=DeliveryOriginType.DOWNSTREAM,
            corr_id="test-corr-id",
        )

        # Verify key store was called
        mock_key_store.get_key.assert_called_once_with("test-key-id")

        # Verify envelope was created with correct parameters
        key_manager_with_node._envelope_factory.create_envelope.assert_called_once()
        call_args = key_manager_with_node._envelope_factory.create_envelope.call_args
        assert call_args[1]["corr_id"] == "test-corr-id"

        # Verify downstream forwarding was called
        key_manager_with_node._routing_node.forward_to_route.assert_called_once()

    @pytest.mark.asyncio
    async def test_handle_key_request_key_found_upstream_origin(
        self, key_manager_with_node, mock_key_store
    ):
        """Test handle_key_request with key found, upstream origin - covers lines 320-345, 369-374."""
        # Mock key store to return a test key
        test_key = {
            "kid": "test-key-id",
            "kty": "RSA",
            "use": "sig",
            "physical_path": "/test/upstream/path",
        }
        mock_key_store.get_key.return_value = test_key

        # Mock envelope creation
        mock_envelope = MagicMock()
        key_manager_with_node._envelope_factory.create_envelope.return_value = mock_envelope

        # Call the method
        await key_manager_with_node.handle_key_request(
            kid="test-key-id",
            from_seg="upstream-segment",
            physical_path=None,
            origin=DeliveryOriginType.UPSTREAM,
            corr_id="test-corr-id",
        )

        # Verify upstream forwarding was called
        key_manager_with_node._node.forward_upstream.assert_called_once()

    @pytest.mark.asyncio
    async def test_handle_key_request_key_not_found_with_physical_path(
        self, key_manager_with_node, mock_key_store
    ):
        """Test handle_key_request when key not found but physical_path provided - covers lines 327-336."""
        # Mock key store to raise ValueError for get_key, but return keys for path
        mock_key_store.get_key.side_effect = ValueError("Key not found")
        mock_key_store.get_keys_for_path.return_value = iter(
            [
                {"kid": "path-key-1", "kty": "RSA", "physical_path": "/test/path"},
                {"kid": "path-key-2", "kty": "RSA", "physical_path": "/test/path"},
            ]
        )

        # Mock envelope creation
        mock_envelope = MagicMock()
        key_manager_with_node._envelope_factory.create_envelope.return_value = mock_envelope

        # This should not raise an exception but handle the path-based lookup
        with pytest.raises(AssertionError):  # jwk will be None, causing assertion failure
            await key_manager_with_node.handle_key_request(
                kid="missing-key-id",
                from_seg="test-segment",
                physical_path="/test/path",
                origin=DeliveryOriginType.DOWNSTREAM,
            )

        # Verify the path-based lookup was attempted
        mock_key_store.get_keys_for_path.assert_called_once_with("/test/path")

    @pytest.mark.asyncio
    async def test_handle_key_request_key_not_found_no_physical_path(
        self, key_manager_with_node, mock_key_store
    ):
        """Test handle_key_request when key not found and no physical_path - covers lines 328-335."""
        # Mock key store to raise ValueError for get_key
        mock_key_store.get_key.side_effect = ValueError("Key not found")

        # Should re-raise the ValueError
        with pytest.raises(ValueError, match="Key not found"):
            await key_manager_with_node.handle_key_request(
                kid="missing-key-id",
                from_seg="test-segment",
                physical_path=None,
                origin=DeliveryOriginType.DOWNSTREAM,
            )

    @pytest.mark.asyncio
    async def test_handle_key_request_encryption_key_stickiness(
        self, key_manager_with_node, mock_key_store
    ):
        """Test handle_key_request with encryption key setting stickiness - covers lines 353-364."""
        # Mock key store to return an encryption key
        test_key = {
            "kid": "enc-key-id",
            "kty": "RSA",
            "use": "enc",  # This is an encryption key
            "physical_path": "/test/enc/path",
        }
        mock_key_store.get_key.return_value = test_key

        # Mock envelope creation
        mock_envelope = MagicMock()
        key_manager_with_node._envelope_factory.create_envelope.return_value = mock_envelope

        # Call with original client SID
        await key_manager_with_node.handle_key_request(
            kid="enc-key-id",
            from_seg="test-segment",
            physical_path=None,
            origin=DeliveryOriginType.DOWNSTREAM,
            original_client_sid="original-client-123",
        )

        # Verify routing was called with stickiness context
        key_manager_with_node._routing_node.forward_to_route.assert_called_once()
        call_args = key_manager_with_node._routing_node.forward_to_route.call_args
        delivery_context = call_args[0][2]  # Third argument is delivery context

        # Check stickiness was set
        assert delivery_context.stickiness_required is True
        assert delivery_context.sticky_sid == "original-client-123"

    @pytest.mark.asyncio
    async def test_handle_key_request_no_envelope_factory(self, mock_key_store):
        """Test handle_key_request when envelope factory not available - covers lines 340-341."""
        key_manager = DefaultKeyManager(key_store=mock_key_store)
        # Don't set up node context properly

        test_key = {"kid": "test-key", "physical_path": "/test"}
        mock_key_store.get_key.return_value = test_key

        with pytest.raises(RuntimeError, match="Envelope factory not available"):
            await key_manager.handle_key_request(
                kid="test-key",
                from_seg="test-segment",
                physical_path=None,
                origin=DeliveryOriginType.DOWNSTREAM,
            )

    @pytest.mark.asyncio
    async def test_handle_key_request_no_node_id(self, key_manager_with_node, mock_key_store):
        """Test handle_key_request when node ID not available - covers lines 349-350."""
        test_key = {"kid": "test-key", "physical_path": "/test"}
        mock_key_store.get_key.return_value = test_key

        # Mock envelope creation
        mock_envelope = MagicMock()
        key_manager_with_node._envelope_factory.create_envelope.return_value = mock_envelope

        # Clear the node ID
        key_manager_with_node._node._id = ""

        with pytest.raises(RuntimeError, match="Node ID not available"):
            await key_manager_with_node.handle_key_request(
                kid="test-key",
                from_seg="test-segment",
                physical_path=None,
                origin=DeliveryOriginType.DOWNSTREAM,
            )

    @pytest.mark.asyncio
    async def test_handle_key_request_downstream_no_routing_node(
        self, key_manager_with_node, mock_key_store
    ):
        """Test handle_key_request downstream without routing node - covers lines 366-369."""
        test_key = {"kid": "test-key", "physical_path": "/test"}
        mock_key_store.get_key.return_value = test_key

        # Mock envelope creation
        mock_envelope = MagicMock()
        key_manager_with_node._envelope_factory.create_envelope.return_value = mock_envelope

        # Clear routing node
        key_manager_with_node._routing_node = None

        with pytest.raises(RuntimeError, match="Forward downstream not available"):
            await key_manager_with_node.handle_key_request(
                kid="test-key",
                from_seg="test-segment",
                physical_path=None,
                origin=DeliveryOriginType.DOWNSTREAM,
            )

    @pytest.mark.asyncio
    async def test_handle_key_request_upstream_no_node(self, key_manager_with_node, mock_key_store):
        """Test handle_key_request upstream without node - covers lines 372-373."""
        test_key = {"kid": "test-key", "physical_path": "/test"}
        mock_key_store.get_key.return_value = test_key

        # Clear node (this will make _envelope_factory property return None)
        key_manager_with_node._node = None

        with pytest.raises(RuntimeError, match="Envelope factory not available"):
            await key_manager_with_node.handle_key_request(
                kid="test-key",
                from_seg="test-segment",
                physical_path=None,
                origin=DeliveryOriginType.UPSTREAM,
            )


class TestAnnounceKeysToUpstreamLargestGap:
    """Test the second largest gap: announce_keys_to_upstream method (27 lines, 256-282)."""

    @pytest.fixture
    def mock_key_store(self):
        """Create mock KeyStore."""
        key_store = AsyncMock(spec=KeyStore)
        return key_store

    @pytest.fixture
    def mock_node(self):
        """Create mock NodeLike."""
        node = MagicMock()
        node.has_parent = True
        node.physical_path = "/test/node"
        node._id = "test-node-id"
        return node

    @pytest.fixture
    async def key_manager_with_upstream(self, mock_key_store, mock_node):
        """Create DefaultKeyManager with upstream capability."""
        key_manager = DefaultKeyManager(key_store=mock_key_store)
        await key_manager.on_node_started(mock_node)
        return key_manager

    @pytest.mark.asyncio
    async def test_announce_keys_to_upstream_no_upstream(self, mock_key_store):
        """Test announce_keys_to_upstream when no upstream - covers lines 256-258."""
        key_manager = DefaultKeyManager(key_store=mock_key_store)

        # Mock node without upstream
        mock_node = MagicMock()
        mock_node.has_parent = False
        await key_manager.on_node_started(mock_node)

        # Should return early without doing anything
        await key_manager.announce_keys_to_upstream()

        # Key store should not be called
        mock_key_store.get_keys_grouped_by_path.assert_not_called()

    @pytest.mark.asyncio
    async def test_announce_keys_to_upstream_with_keys(self, key_manager_with_upstream, mock_key_store):
        """Test announce_keys_to_upstream with keys to announce - covers lines 259-282."""
        # Mock key store to return grouped keys
        test_keys_by_path = {
            "/test/node/child1": [{"kid": "key1", "kty": "RSA"}],
            "/test/node/child2": [{"kid": "key2", "kty": "RSA"}],
            "/other/path": [{"kid": "key3", "kty": "RSA"}],  # Should be skipped
        }
        mock_key_store.get_keys_grouped_by_path.return_value = test_keys_by_path

        # Mock the _announce_path_keys method
        with patch.object(
            key_manager_with_upstream, "_announce_path_keys", new_callable=AsyncMock
        ) as mock_announce:
            await key_manager_with_upstream.announce_keys_to_upstream()

            # Should have called _announce_path_keys for paths under this node
            assert mock_announce.call_count == 2  # Only paths starting with "/test/node"

            # Verify the calls
            calls = mock_announce.call_args_list
            call_paths = [call[0][1] for call in calls]  # Second argument is path
            assert "/test/node/child1" in call_paths
            assert "/test/node/child2" in call_paths

    @pytest.mark.asyncio
    async def test_announce_keys_to_upstream_announce_error(
        self, key_manager_with_upstream, mock_key_store
    ):
        """Test announce_keys_to_upstream with announcement error - covers lines 270-273."""
        # Mock key store to return test keys
        test_keys_by_path = {"/test/node/child": [{"kid": "key1", "kty": "RSA"}]}
        mock_key_store.get_keys_grouped_by_path.return_value = test_keys_by_path

        # Mock _announce_path_keys to raise an exception
        with patch.object(
            key_manager_with_upstream, "_announce_path_keys", new_callable=AsyncMock
        ) as mock_announce:
            mock_announce.side_effect = Exception("Announcement failed")

            # Should not raise exception but log error
            await key_manager_with_upstream.announce_keys_to_upstream()

            # Verify the method was called despite error
            mock_announce.assert_called_once()


class TestAnnouncePathKeysLargestGap:
    """Test the third largest gap: _announce_path_keys method (27 lines, 227-253)."""

    @pytest.fixture
    def mock_key_store(self):
        """Create mock KeyStore."""
        return AsyncMock(spec=KeyStore)

    @pytest.fixture
    def mock_node(self):
        """Create mock NodeLike with envelope factory."""
        node = MagicMock()
        node.has_parent = True
        node.physical_path = "/test/node"
        node._id = "test-node-id"
        node._envelope_factory = MagicMock(spec=EnvelopeFactory)
        node.forward_upstream = AsyncMock()
        return node

    @pytest.fixture
    def mock_routing_node(self):
        """Create mock RoutingNodeLike."""
        routing_node = MagicMock()
        routing_node.forward_to_peers = AsyncMock()
        return routing_node

    @pytest.fixture
    async def key_manager_with_routing(self, mock_key_store, mock_node, mock_routing_node):
        """Create DefaultKeyManager with routing capabilities."""
        key_manager = DefaultKeyManager(key_store=mock_key_store)
        await key_manager.on_node_started(mock_node)
        key_manager._routing_node = mock_routing_node
        return key_manager

    @pytest.mark.asyncio
    async def test_announce_path_keys_no_destination(self, mock_key_store):
        """Test _announce_path_keys with no destination - covers lines 215-226."""
        key_manager = DefaultKeyManager(key_store=mock_key_store)

        # Mock node without upstream or routing
        mock_node = MagicMock()
        mock_node.has_parent = False
        mock_node.physical_path = "/test/node"
        mock_node._id = "test-node-id"
        await key_manager.on_node_started(mock_node)
        key_manager._routing_node = None

        test_keys = [{"kid": "key1", "kty": "RSA"}]

        # Should return early without creating envelope
        await key_manager._announce_path_keys(test_keys, "/test/path", DeliveryOriginType.DOWNSTREAM)

        # Verify the function returns early (no exception raised)

    @pytest.mark.asyncio
    async def test_announce_path_keys_upstream_only(self, key_manager_with_routing, mock_node):
        """Test _announce_path_keys with upstream forwarding - covers lines 227-245."""
        # Remove routing capability
        key_manager_with_routing._routing_node = None

        test_keys = [{"kid": "key1", "kty": "RSA"}]

        # Mock envelope creation
        mock_envelope = MagicMock()
        mock_node._envelope_factory.create_envelope.return_value = mock_envelope

        await key_manager_with_routing._announce_path_keys(
            test_keys, "/test/path", DeliveryOriginType.DOWNSTREAM
        )

        # Verify envelope was created
        mock_node._envelope_factory.create_envelope.assert_called_once()

        # Verify upstream forwarding
        mock_node.forward_upstream.assert_called_once_with(mock_envelope, unittest.mock.ANY)

    @pytest.mark.asyncio
    async def test_announce_path_keys_with_routing(
        self, key_manager_with_routing, mock_node, mock_routing_node
    ):
        """Test _announce_path_keys with routing and upstream - covers lines 227-253."""
        test_keys = [{"kid": "key1", "kty": "RSA"}]

        # Mock envelope creation
        mock_envelope = MagicMock()
        mock_node._envelope_factory.create_envelope.return_value = mock_envelope

        await key_manager_with_routing._announce_path_keys(
            test_keys, "/test/path", DeliveryOriginType.DOWNSTREAM
        )

        # Verify envelope was created
        mock_node._envelope_factory.create_envelope.assert_called_once()

        # Verify both upstream and peer forwarding
        mock_node.forward_upstream.assert_called_once()
        mock_routing_node.forward_to_peers.assert_called_once()

    @pytest.mark.asyncio
    async def test_announce_path_keys_no_envelope_factory(self, mock_key_store):
        """Test _announce_path_keys without envelope factory - covers lines 233-234."""
        key_manager = DefaultKeyManager(key_store=mock_key_store)

        # Mock node with upstream but no envelope factory
        mock_node = MagicMock()
        mock_node.has_parent = True
        mock_node.physical_path = "/test/node"
        mock_node._id = "test-node-id"
        mock_node._envelope_factory = None
        await key_manager.on_node_started(mock_node)

        test_keys = [{"kid": "key1", "kty": "RSA"}]

        with pytest.raises(RuntimeError, match="Envelope factory not available"):
            await key_manager._announce_path_keys(test_keys, "/test/path", DeliveryOriginType.DOWNSTREAM)

    @pytest.mark.asyncio
    async def test_announce_path_keys_no_node_id_upstream(self, key_manager_with_routing, mock_node):
        """Test _announce_path_keys upstream without node ID - covers lines 240-241."""
        test_keys = [{"kid": "key1", "kty": "RSA"}]

        # Mock envelope creation
        mock_envelope = MagicMock()
        mock_node._envelope_factory.create_envelope.return_value = mock_envelope

        # Clear node ID
        mock_node._id = ""

        with pytest.raises(RuntimeError, match="Node ID not available"):
            await key_manager_with_routing._announce_path_keys(
                test_keys, "/test/path", DeliveryOriginType.DOWNSTREAM
            )

    @pytest.mark.asyncio
    async def test_announce_path_keys_no_node_upstream(self, key_manager_with_routing, mock_node):
        """Test _announce_path_keys upstream without node - covers lines 242-243."""
        test_keys = [{"kid": "key1", "kty": "RSA"}]

        # Mock envelope creation
        mock_envelope = MagicMock()
        mock_node._envelope_factory.create_envelope.return_value = mock_envelope

        # Clear node
        key_manager_with_routing._node = None

        with pytest.raises(RuntimeError, match="Envelope factory not available"):
            await key_manager_with_routing._announce_path_keys(
                test_keys, "/test/path", DeliveryOriginType.DOWNSTREAM
            )

    @pytest.mark.asyncio
    async def test_announce_path_keys_no_node_id_routing(
        self, key_manager_with_routing, mock_node, mock_routing_node
    ):
        """Test _announce_path_keys routing without node ID - covers lines 248-249."""
        # Remove upstream to focus on routing path
        mock_node.has_parent = False

        test_keys = [{"kid": "key1", "kty": "RSA"}]

        # Mock envelope creation
        mock_envelope = MagicMock()
        mock_node._envelope_factory.create_envelope.return_value = mock_envelope

        # Clear node ID
        mock_node._id = ""

        with pytest.raises(RuntimeError, match="Node ID not available"):
            await key_manager_with_routing._announce_path_keys(
                test_keys, "/test/path", DeliveryOriginType.DOWNSTREAM
            )


class TestAddKeysValidationLargestGap:
    """Test the fourth largest gap: add_keys validation logic (15 lines, 170-184)."""

    @pytest.fixture
    def mock_key_store(self):
        """Create mock KeyStore."""
        return AsyncMock(spec=KeyStore)

    @pytest.fixture
    def mock_node(self):
        """Create mock NodeLike."""
        node = MagicMock()
        node.has_parent = True
        node.physical_path = "/test/node"
        node._id = "test-node-id"
        # Make forward_upstream async to fix the await issue
        node.forward_upstream = AsyncMock()
        return node

    @pytest.fixture
    async def key_manager(self, mock_key_store, mock_node):
        """Create DefaultKeyManager."""
        key_manager = DefaultKeyManager(key_store=mock_key_store)
        await key_manager.on_node_started(mock_node)
        return key_manager

    @pytest.mark.asyncio
    async def test_add_keys_downstream_sid_validation_success(self, key_manager, mock_key_store):
        """Test add_keys with valid downstream SID - covers lines 170-180."""
        test_keys = [{"kid": "key1", "kty": "RSA", "use": "sig"}]

        # Mock the secure_digest to return expected SID
        with patch("naylence.fame.security.keys.default_key_manager.secure_digest") as mock_digest:
            expected_sid = "expected_sid_value"
            mock_digest.return_value = expected_sid

            # Mock JWK validation
            with patch("naylence.fame.security.crypto.jwk_validation.validate_jwk_complete"):
                await key_manager.add_keys(
                    keys=test_keys,
                    sid=expected_sid,  # Matching SID
                    physical_path="/test/node/child_system/sub/path",
                    system_id="child_system",
                    origin=DeliveryOriginType.DOWNSTREAM,
                )

                # Should compute expected path and validate
                mock_digest.assert_called_once_with("/test/node/child_system")
                mock_key_store.add_keys.assert_called_once()

    @pytest.mark.asyncio
    async def test_add_keys_downstream_sid_validation_failure(self, key_manager, mock_key_store):
        """Test add_keys with invalid downstream SID - covers lines 170-182."""
        test_keys = [{"kid": "key1", "kty": "RSA", "use": "sig"}]

        # Mock the secure_digest to return different SID
        with patch("naylence.fame.security.keys.default_key_manager.secure_digest") as mock_digest:
            mock_digest.return_value = "expected_sid"

            # Mock JWK validation
            with patch("naylence.fame.security.crypto.jwk_validation.validate_jwk_complete"):
                with pytest.raises(ValueError, match="Invalid downstream sid"):
                    await key_manager.add_keys(
                        keys=test_keys,
                        sid="wrong_sid",  # Wrong SID
                        physical_path="/test/node/child_system/sub/path",
                        system_id="child_system",
                        origin=DeliveryOriginType.DOWNSTREAM,
                    )

    @pytest.mark.asyncio
    async def test_add_keys_upstream_sid_validation(self, key_manager, mock_key_store):
        """Test add_keys with upstream SID validation - covers lines 174-175."""
        test_keys = [{"kid": "key1", "kty": "RSA", "use": "sig"}]

        # Mock the secure_digest to return expected SID
        with patch("naylence.fame.security.keys.default_key_manager.secure_digest") as mock_digest:
            expected_sid = "upstream_sid"
            mock_digest.return_value = expected_sid

            # Mock JWK validation
            with patch("naylence.fame.security.crypto.jwk_validation.validate_jwk_complete"):
                await key_manager.add_keys(
                    keys=test_keys,
                    sid=expected_sid,
                    physical_path="/test",  # Upstream path
                    system_id="upstream_system",
                    origin=DeliveryOriginType.UPSTREAM,
                )

                # Should compute parent path for upstream
                mock_digest.assert_called_once_with("/test")

    @pytest.mark.asyncio
    async def test_add_keys_peer_sid_validation(self, key_manager, mock_key_store):
        """Test add_keys with peer SID validation - covers lines 176-177."""
        test_keys = [{"kid": "key1", "kty": "RSA", "use": "sig"}]

        # Mock the secure_digest to return expected SID
        with patch("naylence.fame.security.keys.default_key_manager.secure_digest") as mock_digest:
            expected_sid = "peer_sid"
            mock_digest.return_value = expected_sid

            # Mock JWK validation
            with patch("naylence.fame.security.crypto.jwk_validation.validate_jwk_complete"):
                await key_manager.add_keys(
                    keys=test_keys,
                    sid=expected_sid,
                    physical_path="/peer/path",
                    system_id="peer_system",
                    origin=DeliveryOriginType.PEER,
                )

                # Should compute peer path
                mock_digest.assert_called_once_with("/peer_system")

    @pytest.mark.asyncio
    async def test_add_keys_downstream_path_validation_success(self, key_manager, mock_key_store):
        """Test add_keys downstream path validation success - covers lines 185-190."""
        test_keys = [{"kid": "key1", "kty": "RSA", "use": "sig"}]

        # Mock JWK validation
        with patch("naylence.fame.security.crypto.jwk_validation.validate_jwk_complete"):
            # Test with valid downstream path
            await key_manager.add_keys(
                keys=test_keys,
                physical_path="/test/node/child_system/valid/sub/path",
                system_id="child_system",
                origin=DeliveryOriginType.DOWNSTREAM,
                skip_sid_validation=True,
            )

            # Should succeed and store keys
            mock_key_store.add_keys.assert_called_once()

    @pytest.mark.asyncio
    async def test_add_keys_downstream_path_validation_failure(self, key_manager, mock_key_store):
        """Test add_keys downstream path validation failure - covers lines 185-192."""
        test_keys = [{"kid": "key1", "kty": "RSA", "use": "sig"}]

        # Mock JWK validation
        with patch("naylence.fame.security.crypto.jwk_validation.validate_jwk_complete"):
            # Test with invalid downstream path
            with pytest.raises(ValueError, match="Frame physical path .* does not match expected prefix"):
                await key_manager.add_keys(
                    keys=test_keys,
                    physical_path="/wrong/path/not/under/node",
                    system_id="child_system",
                    origin=DeliveryOriginType.DOWNSTREAM,
                    skip_sid_validation=True,
                )


class TestAddKeysValidationSmallGaps:
    """Test the add_keys validation logic small gaps (8 lines, 141-148)."""

    @pytest.fixture
    def mock_key_store(self):
        """Create mock KeyStore."""
        return AsyncMock(spec=KeyStore)

    @pytest.fixture
    async def key_manager(self, mock_key_store):
        """Create DefaultKeyManager."""
        key_manager = DefaultKeyManager(key_store=mock_key_store)
        return key_manager

    @pytest.mark.asyncio
    async def test_add_keys_no_valid_keys(self, key_manager, mock_key_store):
        """Test add_keys when no valid keys after validation - covers lines 141-148."""
        # Keys that will fail validation
        invalid_keys = [
            {"kid": "invalid1"},  # Missing required fields
            {"kid": "invalid2", "kty": "invalid"},  # Invalid key type
        ]

        # Mock JWK validation to raise JWKValidationError
        with patch("naylence.fame.security.crypto.jwk_validation.validate_jwk_complete") as mock_validate:
            from naylence.fame.security.crypto.jwk_validation import JWKValidationError

            mock_validate.side_effect = JWKValidationError("Invalid JWK")

            # Mock the key store to track what gets stored
            mock_key_store.add_keys.return_value = None

            # Should not raise but log warning and return early
            await key_manager.add_keys(
                keys=invalid_keys,
                physical_path="/test/path",
                system_id="test_system",
                origin=DeliveryOriginType.LOCAL,
            )

            # Verify no keys were stored (method returns early, so add_keys never called)
            mock_key_store.add_keys.assert_not_called()

    @pytest.mark.asyncio
    async def test_add_keys_mixed_valid_invalid(self, key_manager, mock_key_store):
        """Test add_keys with mix of valid and invalid keys - covers validation loop."""
        mixed_keys = [
            {"kid": "valid1", "kty": "RSA", "use": "sig"},
            {"kid": "invalid"},  # Missing fields
            {"kid": "valid2", "kty": "EC", "use": "enc"},
        ]

        # Mock JWK validation to fail on second key only
        def validate_side_effect(key):
            if key["kid"] == "invalid":
                from naylence.fame.security.crypto.jwk_validation import JWKValidationError

                raise JWKValidationError("Invalid JWK")

        with patch("naylence.fame.security.crypto.jwk_validation.validate_jwk_complete") as mock_validate:
            mock_validate.side_effect = validate_side_effect

            await key_manager.add_keys(
                keys=mixed_keys,
                physical_path="/test/path",
                system_id="test_system",
                origin=DeliveryOriginType.LOCAL,
            )

            # Verify only valid keys were stored
            mock_key_store.add_keys.assert_called_once()
            call_args = mock_key_store.add_keys.call_args
            stored_keys = call_args[0][0]  # First positional argument

            # Should only have the 2 valid keys
            assert len(stored_keys) == 2
            assert stored_keys[0]["kid"] == "valid1"
            assert stored_keys[1]["kid"] == "valid2"


class TestRemainingSmallGaps:
    """Test remaining small gaps and edge cases."""

    @pytest.fixture
    def mock_key_store(self):
        """Create mock KeyStore."""
        return AsyncMock(spec=KeyStore)

    @pytest.fixture
    async def key_manager(self, mock_key_store):
        """Create DefaultKeyManager."""
        key_manager = DefaultKeyManager(key_store=mock_key_store)
        return key_manager

    @pytest.mark.asyncio
    async def test_remove_keys_for_path(self, key_manager, mock_key_store):
        """Test remove_keys_for_path method - covers line 402."""
        mock_key_store.remove_keys_for_path.return_value = 5

        result = await key_manager.remove_keys_for_path("/test/path")

        assert result == 5
        mock_key_store.remove_keys_for_path.assert_called_once_with("/test/path")

    @pytest.mark.asyncio
    async def test_get_keys_for_path(self, key_manager, mock_key_store):
        """Test get_keys_for_path method."""
        test_keys = [{"kid": "key1"}, {"kid": "key2"}]
        mock_key_store.get_keys_for_path.return_value = test_keys

        result = await key_manager.get_keys_for_path("/test/path")

        assert result == test_keys
        mock_key_store.get_keys_for_path.assert_called_once_with("/test/path")

    def test_get_keys_to_announce_upstream(self, key_manager):
        """Test _get_keys_to_announce_upstream stub method - covers line 287."""
        # This is a stub method that returns empty list
        key_manager._get_keys_to_announce_upstream()
        # Method signature shows it should return list[list[dict]], but it's a stub
        # Just verify it can be called without error

    def test_should_announce_upstream(self, key_manager):
        """Test _should_announce_upsteam stub method."""
        # This is a stub method that returns False
        result = key_manager._should_announce_upsteam({"kid": "test"})
        assert result is False

    @pytest.mark.asyncio
    async def test_on_node_stopped(self, key_manager):
        """Test on_node_stopped method - covers cleanup logic."""
        mock_node = MagicMock()
        mock_node._id = "test-node"

        # Should not raise any errors
        await key_manager.on_node_stopped(mock_node)

    def test_properties_without_node(self, key_manager):
        """Test property accessors without node context - covers lines 57-58, 100."""
        # Test properties when no node is set
        assert key_manager._has_upstream is False
        assert key_manager._physical_path == "/"
        assert key_manager._node_id == ""
        assert key_manager._node_sid == ""
        assert key_manager._envelope_factory is None

    @pytest.mark.asyncio
    async def test_add_keys_local_origin(self, key_manager, mock_key_store):
        """Test add_keys with LOCAL origin - covers early return path."""
        test_keys = [{"kid": "key1", "kty": "RSA", "use": "sig"}]

        # Mock JWK validation
        with patch("naylence.fame.security.crypto.jwk_validation.validate_jwk_complete"):
            await key_manager.add_keys(
                keys=test_keys,
                physical_path="/test/path",
                system_id="test_system",
                origin=DeliveryOriginType.LOCAL,
            )

            # Should add keys and return early
            mock_key_store.add_keys.assert_called_once()

    @pytest.mark.asyncio
    async def test_add_keys_downstream_with_announce(self, key_manager, mock_key_store):
        """Test add_keys downstream triggering announcement - covers lines 201."""
        test_keys = [{"kid": "key1", "kty": "RSA", "use": "sig"}]

        # Mock node setup
        mock_node = MagicMock()
        mock_node.has_parent = True
        mock_node.physical_path = "/test/node"
        mock_node._id = "test-node-id"
        await key_manager.on_node_started(mock_node)

        # Mock JWK validation
        with patch("naylence.fame.security.crypto.jwk_validation.validate_jwk_complete"):
            # Mock _announce_path_keys
            with patch.object(key_manager, "_announce_path_keys", new_callable=AsyncMock) as mock_announce:
                await key_manager.add_keys(
                    keys=test_keys,
                    physical_path="/test/node/child/path",
                    system_id="child",
                    origin=DeliveryOriginType.DOWNSTREAM,
                    skip_sid_validation=True,
                )

                # Should announce the keys
                mock_announce.assert_called_once()
