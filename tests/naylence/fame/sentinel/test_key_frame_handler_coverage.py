"""
Comprehensive coverage test suite for KeyFrameHandler targeting largest gaps.

This test suite focuses on improving coverage from 57.09% baseline by targeting:
1. Lines 309-384: _handle_key_request_by_address route handling (76 lines)
2. Lines 412-441: Path extraction and key lookup logic (30 lines)
3. Lines 162-169: KeyRequest validation and error handling (8 lines)
4. Lines 295-302: Address route info handling (8 lines)

Using systematic largest-gap-first approach proven effective with upstream_session_manager.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from naylence.fame.core import (
    DeliveryOriginType,
    FameAddress,
    FameDeliveryContext,
    KeyRequestFrame,
)
from naylence.fame.sentinel.key_frame_handler import KeyFrameHandler
from naylence.fame.sentinel.route_manager import AddressRouteInfo


class TestKeyFrameHandlerCoverage:
    """Test suite for KeyFrameHandler coverage improvement."""

    def setup_method(self):
        """Set up comprehensive test fixtures."""
        # Mock routing node
        self.routing_node = MagicMock()
        self.routing_node.id = "test-sentinel"
        self.routing_node.physical_path = "/test/sentinel"
        self.routing_node.envelope_factory.create_envelope = MagicMock()
        self.routing_node.forward_to_route = AsyncMock()

        # Mock route manager
        self.route_manager = MagicMock()
        self.route_manager.downstream_routes = {"child-1", "child-2"}
        self.route_manager._peer_routes = {"peer-1": "/peer/1"}
        self.route_manager._downstream_addresses_routes = {}
        self.route_manager._peer_addresses_routes = {}

        # Mock binding manager
        self.binding_manager = MagicMock()
        self.binding_manager.get_binding.return_value = None

        # Mock key manager with comprehensive async methods
        self.key_manager = AsyncMock()
        self.key_manager.handle_key_request = AsyncMock()
        self.key_manager.get_keys_for_path = AsyncMock()

        # Mock parent handler
        self.accept_key_announce_parent = AsyncMock()

        # Create handler instance
        self.handler = KeyFrameHandler(
            routing_node=self.routing_node,
            route_manager=self.route_manager,
            binding_manager=self.binding_manager,
            accept_key_announce_parent=self.accept_key_announce_parent,
            key_manager=self.key_manager,
        )

    @pytest.mark.asyncio
    async def test_handle_key_request_step3_encryption_key_id_route_no_segment(self):
        """Test lines 309-384: Step 3 route handling with encryption_key_id but no segment."""
        # Target lines 309-384: When route_info exists but has no segment (empty string)
        address = FameAddress("test@/test/path")

        # Mock no local binding to get past Step 2
        self.binding_manager.get_binding.return_value = None

        # Set up route_info with empty segment (so Step 1 doesn't early return)
        # but with encryption_key_id for Step 3 handling
        route_info = AddressRouteInfo(
            segment="",  # Empty segment won't trigger early return
            physical_path="/test/physical",
            encryption_key_id="test-key-123",
        )
        self.route_manager._downstream_addresses_routes[address] = route_info

        context = FameDeliveryContext(origin_type=DeliveryOriginType.DOWNSTREAM, from_system_id="child-1")

        envelope = MagicMock()
        envelope.sid = "test-sid"

        # Test successful key lookup with route encryption_key_id in Step 3
        result = await self.handler._handle_key_request_by_address(
            address=address,
            from_seg="child-1",
            physical_path=None,
            delivery_context=context,
            corr_id="test-corr",
            original_envelope=envelope,
        )

        # Should handle locally with encryption_key_id from route
        assert result is True

        # Should set stickiness for encryption key delivery
        assert context.stickiness_required is True
        assert context.sticky_sid == "test-sid"

        # Should call key manager with encryption_key_id
        self.key_manager.handle_key_request.assert_called_once_with(
            kid="test-key-123",
            from_seg="child-1",
            physical_path="/test/physical",
            origin=DeliveryOriginType.DOWNSTREAM,
            corr_id="test-corr",
            original_client_sid="test-sid",
        )

    @pytest.mark.asyncio
    async def test_handle_key_request_encryption_key_id_lookup_failure(self):
        """Test lines 332-340: Encryption key ID lookup failure with exception."""
        # Target coverage for exception handling in encryption_key_id lookup
        address = FameAddress("test@/test/path")

        # Mock no local binding
        self.binding_manager.get_binding.return_value = None

        route_info = AddressRouteInfo(
            segment="",  # Empty segment to avoid early return
            physical_path="/test/physical",
            encryption_key_id="invalid-key",
        )
        self.route_manager._downstream_addresses_routes[address] = route_info

        context = FameDeliveryContext(origin_type=DeliveryOriginType.DOWNSTREAM, from_system_id="child-1")

        # Make key manager raise ValueError for invalid key
        self.key_manager.handle_key_request.side_effect = ValueError("Invalid key")

        result = await self.handler._handle_key_request_by_address(
            address=address,
            from_seg="child-1",
            physical_path=None,
            delivery_context=context,
            corr_id="test-corr",
            original_envelope=None,
        )

        # Should fall through to subsequent logic (return False)
        assert result is False

        # Should have attempted key lookup
        self.key_manager.handle_key_request.assert_called_once()

    @pytest.mark.asyncio
    async def test_handle_key_request_physical_path_lookup_success(self):
        """Test lines 343-384: Physical path lookup with encryption keys found."""
        # Target lines 343-384: route_info.physical_path lookup with encryption keys
        address = FameAddress("test@/test/path")

        # Mock no local binding
        self.binding_manager.get_binding.return_value = None

        route_info = AddressRouteInfo(
            segment="",  # Empty segment to avoid early return
            physical_path="/test/physical/path",
            encryption_key_id=None,  # No encryption_key_id, will try physical path
        )
        self.route_manager._downstream_addresses_routes[address] = route_info

        # Mock encryption keys from physical path
        encryption_keys = [{"kid": "enc-key-1", "use": "enc"}, {"kid": "enc-key-2", "use": "enc"}]
        self.key_manager.get_keys_for_path.return_value = encryption_keys

        context = FameDeliveryContext(origin_type=DeliveryOriginType.DOWNSTREAM, from_system_id="child-1")

        envelope = MagicMock()
        envelope.sid = "envelope-sid"

        result = await self.handler._handle_key_request_by_address(
            address=address,
            from_seg="child-1",
            physical_path="/original/path",
            delivery_context=context,
            corr_id="test-corr",
            original_envelope=envelope,
        )

        # Should handle locally
        assert result is True

        # Should set stickiness
        assert context.stickiness_required is True
        assert context.sticky_sid == "envelope-sid"

        # Should lookup keys by physical path from route info
        self.key_manager.get_keys_for_path.assert_called_once_with("/test/physical/path")

        # Should handle key request with first encryption key
        self.key_manager.handle_key_request.assert_called_once_with(
            kid="enc-key-1",
            from_seg="child-1",
            physical_path="/test/physical/path",
            origin=DeliveryOriginType.DOWNSTREAM,
            corr_id="test-corr",
            original_client_sid="envelope-sid",
        )

    @pytest.mark.asyncio
    async def test_handle_key_request_physical_path_no_encryption_keys(self):
        """Test physical path lookup with no encryption keys (only signing keys)."""
        # Test when get_keys_for_path returns non-encryption keys
        address = FameAddress("test@/test/path")

        # Mock no local binding
        self.binding_manager.get_binding.return_value = None

        route_info = AddressRouteInfo(
            segment="",  # Empty segment to avoid early return
            physical_path="/test/physical/path",
            encryption_key_id=None,
        )
        self.route_manager._downstream_addresses_routes[address] = route_info

        # Mock only signing keys (no encryption keys)
        signing_keys = [{"kid": "sig-key-1", "use": "sig"}, {"kid": "sig-key-2", "use": "sig"}]
        self.key_manager.get_keys_for_path.return_value = signing_keys

        context = FameDeliveryContext(origin_type=DeliveryOriginType.DOWNSTREAM, from_system_id="child-1")

        result = await self.handler._handle_key_request_by_address(
            address=address,
            from_seg="child-1",
            physical_path=None,
            delivery_context=context,
            corr_id="test-corr",
            original_envelope=None,
        )

        # Should fall through to return False (no encryption keys found)
        assert result is False

        # Should lookup keys by physical path
        self.key_manager.get_keys_for_path.assert_called_once_with("/test/physical/path")

        # Should NOT call handle_key_request since no encryption keys
        self.key_manager.handle_key_request.assert_not_called()

    @pytest.mark.asyncio
    async def test_handle_key_request_physical_path_lookup_exception(self):
        """Test physical path lookup with exception handling."""
        # Target exception handling in physical path lookup
        address = FameAddress("test@/test/path")

        # Mock no local binding
        self.binding_manager.get_binding.return_value = None

        route_info = AddressRouteInfo(
            segment="",  # Empty segment to avoid early return
            physical_path="/invalid/path",
            encryption_key_id=None,
        )
        self.route_manager._downstream_addresses_routes[address] = route_info

        # Make key manager raise exception
        self.key_manager.get_keys_for_path.side_effect = ValueError("Invalid path")

        context = FameDeliveryContext(origin_type=DeliveryOriginType.DOWNSTREAM, from_system_id="child-1")

        result = await self.handler._handle_key_request_by_address(
            address=address,
            from_seg="child-1",
            physical_path=None,
            delivery_context=context,
            corr_id="test-corr",
            original_envelope=None,
        )

        # Should handle exception and fall through
        assert result is False

        # Should have attempted key lookup
        self.key_manager.get_keys_for_path.assert_called_once_with("/invalid/path")

    @pytest.mark.asyncio
    async def test_handle_key_request_address_path_extraction_success(self):
        """Test lines 412-441: Address path extraction and key lookup success."""
        # Target lines 412-441: extract physical path from address
        address = FameAddress("service@/extracted/physical/path")  # Has @ with physical path

        # No route info, so will try path extraction
        context = FameDeliveryContext(origin_type=DeliveryOriginType.DOWNSTREAM, from_system_id="child-1")

        # Mock encryption keys for extracted path
        encryption_keys = [{"kid": "extracted-key", "use": "enc"}]
        self.key_manager.get_keys_for_path.return_value = encryption_keys

        envelope = MagicMock()
        envelope.sid = "test-sid"

        result = await self.handler._handle_key_request_by_address(
            address=address,
            from_seg="child-1",
            physical_path="/original/path",
            delivery_context=context,
            corr_id="test-corr",
            original_envelope=envelope,
        )

        # Should handle locally with extracted path
        assert result is True

        # Should set stickiness
        assert context.stickiness_required is True
        assert context.sticky_sid == "test-sid"

        # Should lookup keys by extracted path
        self.key_manager.get_keys_for_path.assert_called_once_with("/extracted/physical/path")

        # Should handle key request with extracted key
        self.key_manager.handle_key_request.assert_called_once_with(
            kid="extracted-key",
            from_seg="child-1",
            physical_path="/extracted/physical/path",
            origin=DeliveryOriginType.DOWNSTREAM,
            corr_id="test-corr",
            original_client_sid="test-sid",
        )

    @pytest.mark.asyncio
    async def test_handle_key_request_address_path_extraction_no_encryption_keys(self):
        """Test address path extraction with no encryption keys found."""
        # Test address with @ but no encryption keys in extracted path
        address = FameAddress("service@/path/without/enc/keys")

        context = FameDeliveryContext(origin_type=DeliveryOriginType.DOWNSTREAM, from_system_id="child-1")

        # Mock only signing keys for extracted path
        signing_keys = [{"kid": "sig-key", "use": "sig"}]
        self.key_manager.get_keys_for_path.return_value = signing_keys

        result = await self.handler._handle_key_request_by_address(
            address=address,
            from_seg="child-1",
            physical_path=None,
            delivery_context=context,
            corr_id="test-corr",
            original_envelope=None,
        )

        # Should fall through since no encryption keys
        assert result is False

        # Should have tried key lookup
        self.key_manager.get_keys_for_path.assert_called_once_with("/path/without/enc/keys")
        self.key_manager.handle_key_request.assert_not_called()

    @pytest.mark.asyncio
    async def test_handle_key_request_address_path_extraction_exception(self):
        """Test address path extraction with exception handling."""
        # Target exception handling in extracted path lookup
        address = FameAddress("service@/invalid/extracted/path")

        context = FameDeliveryContext(origin_type=DeliveryOriginType.DOWNSTREAM, from_system_id="child-1")

        # Make key manager raise exception for extracted path
        self.key_manager.get_keys_for_path.side_effect = AttributeError("Path error")

        result = await self.handler._handle_key_request_by_address(
            address=address,
            from_seg="child-1",
            physical_path=None,
            delivery_context=context,
            corr_id="test-corr",
            original_envelope=None,
        )

        # Should handle exception and fall through
        assert result is False

        # Should have attempted extracted path lookup
        self.key_manager.get_keys_for_path.assert_called_once_with("/invalid/extracted/path")

    @pytest.mark.asyncio
    async def test_handle_key_request_address_no_at_symbol_fallback(self):
        """Test address without valid path extraction (delegates to routing)."""
        # Test with address that has @ but no valid path format for extraction
        address = FameAddress("simple@host-without-path")

        context = FameDeliveryContext(origin_type=DeliveryOriginType.DOWNSTREAM, from_system_id="child-1")

        result = await self.handler._handle_key_request_by_address(
            address=address,
            from_seg="child-1",
            physical_path=None,
            delivery_context=context,
            corr_id="test-corr",
            original_envelope=None,
        )

        # Should delegate to routing pipeline
        assert result is False

        # Should not attempt any key lookups
        self.key_manager.get_keys_for_path.assert_not_called()
        self.key_manager.handle_key_request.assert_not_called()

    @pytest.mark.asyncio
    async def test_handle_key_request_address_invalid_path_format(self):
        """Test address with @ but invalid path format (doesn't start with /)."""
        # Address with @ but path doesn't start with /
        address = FameAddress("service@invalid-path-format")

        context = FameDeliveryContext(origin_type=DeliveryOriginType.DOWNSTREAM, from_system_id="child-1")

        result = await self.handler._handle_key_request_by_address(
            address=address,
            from_seg="child-1",
            physical_path=None,
            delivery_context=context,
            corr_id="test-corr",
            original_envelope=None,
        )

        # Should delegate to routing pipeline (no path extraction attempted)
        assert result is False

        # Should not attempt key lookups for invalid path format
        self.key_manager.get_keys_for_path.assert_not_called()

    @pytest.mark.asyncio
    async def test_accept_key_request_missing_origin_sid(self):
        """Test lines 162-169: Missing origin system ID validation."""
        # Target lines 162-169: error handling for missing origin sid
        frame = KeyRequestFrame(address=FameAddress("test@/path"), physical_path=None)

        envelope = MagicMock()
        envelope.frame = frame
        envelope.corr_id = "test-corr"

        # Context without from_system_id to trigger error
        context = FameDeliveryContext(origin_type=DeliveryOriginType.DOWNSTREAM, from_system_id=None)

        with pytest.raises(ValueError, match="Missing origin sid"):
            await self.handler.accept_key_request(envelope, context)

    @pytest.mark.asyncio
    async def test_accept_key_request_kid_with_physical_path_stickiness(self):
        """Test KID request with physical path setting stickiness."""
        # Target stickiness logic for KID requests with physical path
        frame = KeyRequestFrame(kid="test-key-123", physical_path="/test/physical/path")

        envelope = MagicMock()
        envelope.frame = frame
        envelope.sid = "client-sid"
        envelope.corr_id = "test-corr"

        context = FameDeliveryContext(origin_type=DeliveryOriginType.DOWNSTREAM, from_system_id="child-1")

        # Mock encryption keys to trigger stickiness
        encryption_keys = [{"kid": "test-key-123", "use": "enc"}]
        self.key_manager.get_keys_for_path.return_value = encryption_keys

        result = await self.handler.accept_key_request(envelope, context)

        # Should handle locally
        assert result is True

        # Should set stickiness
        assert context.stickiness_required is True
        assert context.sticky_sid == "client-sid"

        # Should call key manager
        self.key_manager.handle_key_request.assert_called_once_with(
            kid="test-key-123",
            from_seg="child-1",
            physical_path="/test/physical/path",
            origin=DeliveryOriginType.DOWNSTREAM,
            corr_id="test-corr",
            original_client_sid="client-sid",
        )

    @pytest.mark.asyncio
    async def test_accept_key_request_kid_stickiness_check_exception(self):
        """Test KID request when stickiness check raises exception."""
        # Test exception handling in stickiness check
        frame = KeyRequestFrame(kid="test-key-123", physical_path="/test/path")

        envelope = MagicMock()
        envelope.frame = frame
        envelope.sid = "client-sid"
        envelope.corr_id = "test-corr"

        context = FameDeliveryContext(origin_type=DeliveryOriginType.DOWNSTREAM, from_system_id="child-1")

        # Make get_keys_for_path raise exception
        self.key_manager.get_keys_for_path.side_effect = ValueError("Path error")

        result = await self.handler.accept_key_request(envelope, context)

        # Should still handle locally (exception is caught)
        assert result is True

        # Stickiness should not be set due to exception
        assert not hasattr(context, "stickiness_required") or not context.stickiness_required

        # Should still call key manager
        self.key_manager.handle_key_request.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_address_route_info_peer_routes(self):
        """Test lines 295-302: _get_address_route_info peer route handling."""
        # Target lines 295-302: peer route lookup
        address = FameAddress("peer@/peer/path")

        # Set up peer route
        self.route_manager._peer_addresses_routes[address] = "peer-segment"

        route_info = self.handler._get_address_route_info(address)

        # Should return AddressRouteInfo for peer route
        assert route_info is not None
        assert route_info.segment == "peer-segment"
        assert route_info.physical_path is None
        assert route_info.encryption_key_id is None

    @pytest.mark.asyncio
    async def test_get_address_route_info_downstream_priority(self):
        """Test that downstream routes take priority over peer routes."""
        # Test downstream route priority when both exist
        address = FameAddress("conflict@/path")

        # Set up both downstream and peer routes for same address
        downstream_route = AddressRouteInfo(
            segment="downstream-seg", physical_path="/down/path", encryption_key_id="down-key"
        )
        self.route_manager._downstream_addresses_routes[address] = downstream_route
        self.route_manager._peer_addresses_routes[address] = "peer-seg"

        route_info = self.handler._get_address_route_info(address)

        # Should return downstream route (has priority)
        assert route_info == downstream_route
        assert route_info.segment == "downstream-seg"

    @pytest.mark.asyncio
    async def test_get_address_route_info_no_route(self):
        """Test _get_address_route_info when no route exists."""
        # Test when address has no route
        address = FameAddress("unknown@/path")

        route_info = self.handler._get_address_route_info(address)

        # Should return None
        assert route_info is None

    @pytest.mark.asyncio
    async def test_handle_key_request_local_binding_success(self):
        """Test local binding handling with encryption keys."""
        # Test local binding path with encryption keys
        address = FameAddress("local@/local/path")

        # Set up local binding
        mock_binding = MagicMock()
        self.binding_manager.get_binding.return_value = mock_binding

        # Mock encryption keys for local physical path
        encryption_keys = [{"kid": "local-key", "use": "enc"}]
        self.key_manager.get_keys_for_path.return_value = encryption_keys

        context = FameDeliveryContext(origin_type=DeliveryOriginType.DOWNSTREAM, from_system_id="child-1")

        envelope = MagicMock()
        envelope.sid = "test-sid"

        result = await self.handler._handle_key_request_by_address(
            address=address,
            from_seg="child-1",
            physical_path=None,
            delivery_context=context,
            corr_id="test-corr",
            original_envelope=envelope,
        )

        # Should handle locally
        assert result is True

        # Should lookup binding
        self.binding_manager.get_binding.assert_called_once_with(address)

        # Should lookup keys with local physical path
        self.key_manager.get_keys_for_path.assert_called_once_with("/test/sentinel")

        # Should set stickiness and handle key request
        assert context.stickiness_required is True
        assert context.sticky_sid == "test-sid"

    @pytest.mark.asyncio
    async def test_handle_key_request_local_binding_no_encryption_keys(self):
        """Test local binding with no encryption keys."""
        # Test local binding but no encryption keys found
        address = FameAddress("local@/local/path")

        mock_binding = MagicMock()
        self.binding_manager.get_binding.return_value = mock_binding

        # Mock only signing keys (no encryption) for local path
        signing_keys = [{"kid": "sig-key", "use": "sig"}]
        self.key_manager.get_keys_for_path.return_value = signing_keys

        context = FameDeliveryContext(origin_type=DeliveryOriginType.DOWNSTREAM, from_system_id="child-1")

        result = await self.handler._handle_key_request_by_address(
            address=address,
            from_seg="child-1",
            physical_path=None,
            delivery_context=context,
            corr_id="test-corr",
            original_envelope=None,
        )

        # Should fall through since no encryption keys in local binding
        assert result is False

        # Should have checked local binding and keys
        self.binding_manager.get_binding.assert_called_once_with(address)
        # Should only call get_keys_for_path once (for local binding check)
        self.key_manager.get_keys_for_path.assert_called_with("/local/path")
        self.key_manager.handle_key_request.assert_not_called()

    @pytest.mark.asyncio
    async def test_handle_key_request_route_needs_forwarding(self):
        """Test when route exists and needs forwarding through pipeline."""
        # Test when route_info exists with segment (needs routing) - Step 1 early return
        address = FameAddress("route@/route/path")
        route_info = AddressRouteInfo(
            segment="target-seg", physical_path="/target/path", encryption_key_id=None
        )
        self.route_manager._downstream_addresses_routes[address] = route_info

        context = FameDeliveryContext(origin_type=DeliveryOriginType.DOWNSTREAM, from_system_id="child-1")

        result = await self.handler._handle_key_request_by_address(
            address=address,
            from_seg="child-1",
            physical_path=None,
            delivery_context=context,
            corr_id="test-corr",
            original_envelope=None,
        )

        # Should return False to indicate routing needed (Step 1 early return)
        assert result is False

        # Should not attempt local key lookups since routing is needed
        self.key_manager.handle_key_request.assert_not_called()
        self.key_manager.get_keys_for_path.assert_not_called()
        self.binding_manager.get_binding.assert_not_called()
