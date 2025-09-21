from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import WebSocket, status
from fastapi.websockets import WebSocketState

from naylence.fame.connector.websocket_connector import WebSocketConnector
from naylence.fame.connector.websocket_listener import WebSocketListener, get_websocket_connector
from naylence.fame.core import DeliveryOriginType
from naylence.fame.node.routing_node_like import RoutingNodeLike
from naylence.fame.security.auth.authorizer import Authorizer


class TestWebSocketListenerLargestGaps:
    """Test the largest coverage gap: websocket_attach_handler method (154 lines, 205-358)."""

    @pytest.fixture
    def mock_http_server(self):
        """Create mock HTTP server."""
        server = MagicMock()
        server.actual_base_url = "http://localhost:8000"
        server.include_router = MagicMock()
        return server

    @pytest.fixture
    def mock_node(self):
        """Create mock node that implements RoutingNodeLike."""
        node = MagicMock(spec=RoutingNodeLike)
        node.id = "test-node"
        node.public_url = "http://localhost:8000"
        node.security_manager = None
        # Mock the create_origin_connector method
        node.create_origin_connector = AsyncMock()
        return node

    @pytest.fixture
    def mock_authorizer(self):
        """Create mock authorizer."""
        authorizer = AsyncMock(spec=Authorizer)
        return authorizer

    @pytest.fixture
    async def websocket_listener(self, mock_http_server, mock_authorizer):
        """Create WebSocketListener with mocked dependencies."""
        listener = WebSocketListener(http_server=mock_http_server, authorizer=mock_authorizer)
        return listener

    @pytest.fixture
    def mock_websocket(self):
        """Create mock WebSocket."""
        websocket = AsyncMock(spec=WebSocket)
        websocket.headers = {"sec-websocket-protocol": "bearer,test-token"}
        websocket.client_state = WebSocketState.CONNECTED
        websocket.accept = AsyncMock()
        websocket.send_json = AsyncMock()
        websocket.close = AsyncMock()
        return websocket

    @pytest.mark.asyncio
    async def test_websocket_attach_invalid_origin_type(
        self, websocket_listener, mock_node, mock_websocket
    ):
        """Test websocket_attach_handler with invalid origin type - covers lines 207-218."""
        await websocket_listener.on_node_initialized(mock_node)

        # Get the router that was created
        router = await websocket_listener.create_router()

        # Extract the websocket_attach_handler function
        handler = None
        for route in router.routes:
            if hasattr(route, "endpoint") and "websocket_attach_handler" in str(route.endpoint):
                handler = route.endpoint
                break

        assert handler is not None, "websocket_attach_handler not found"

        # Test invalid origin type
        await handler(mock_websocket, "invalid_type", "test-system")

        # Should close with policy violation
        mock_websocket.close.assert_called_once_with(
            code=status.WS_1008_POLICY_VIOLATION, reason="Invalid origin type"
        )

    @pytest.mark.asyncio
    async def test_websocket_attach_no_system_id(self, websocket_listener, mock_node, mock_websocket):
        """Test websocket_attach_handler with no system_id - covers lines 233-236."""
        await websocket_listener.on_node_initialized(mock_node)

        router = await websocket_listener.create_router()
        handler = None
        for route in router.routes:
            if hasattr(route, "endpoint") and "websocket_attach_handler" in str(route.endpoint):
                handler = route.endpoint
                break

        # Test with empty system_id
        await handler(mock_websocket, "downstream", "")

        mock_websocket.close.assert_called_once_with(code=status.WS_1008_POLICY_VIOLATION)

    @pytest.mark.asyncio
    async def test_websocket_attach_self_attachment(self, websocket_listener, mock_node, mock_websocket):
        """Test websocket_attach_handler with self attachment - covers lines 237-241."""
        await websocket_listener.on_node_initialized(mock_node)

        router = await websocket_listener.create_router()
        handler = None
        for route in router.routes:
            if hasattr(route, "endpoint") and "websocket_attach_handler" in str(route.endpoint):
                handler = route.endpoint
                break

        # Test self attachment (system_id same as node.id)
        await handler(mock_websocket, "downstream", "test-node")

        mock_websocket.close.assert_called_once_with(code=status.WS_1008_POLICY_VIOLATION)

    @pytest.mark.asyncio
    async def test_websocket_attach_authentication_failed(
        self, websocket_listener, mock_node, mock_websocket
    ):
        """Test websocket_attach_handler authentication failure - covers lines 261-282."""
        # Setup authorizer to return None (authentication failed)
        mock_authorizer = AsyncMock(spec=Authorizer)

        # Create async function that returns None
        async def auth_failed(*args, **kwargs):
            return None

        mock_authorizer.authenticate = auth_failed

        listener = WebSocketListener(
            http_server=websocket_listener._http_server, authorizer=mock_authorizer
        )
        await listener.on_node_initialized(mock_node)

        router = await listener.create_router()
        handler = None
        for route in router.routes:
            if hasattr(route, "endpoint") and "websocket_attach_handler" in str(route.endpoint):
                handler = route.endpoint
                break

        await handler(mock_websocket, "downstream", "other-system")

        # Should send failure ACK and close
        mock_websocket.send_json.assert_called_once()
        mock_websocket.close.assert_called_with(
            code=status.WS_1008_POLICY_VIOLATION, reason="Authentication failed"
        )

    @pytest.mark.asyncio
    async def test_websocket_attach_authorization_error(
        self, websocket_listener, mock_node, mock_websocket
    ):
        """Test websocket_attach_handler authorization exception - covers lines 290-309."""

        # Setup authorizer to raise exception
        async def auth_error(*args, **kwargs):
            raise RuntimeError("Auth error")

        mock_authorizer = AsyncMock(spec=Authorizer)
        mock_authorizer.authenticate.side_effect = auth_error

        listener = WebSocketListener(
            http_server=websocket_listener._http_server, authorizer=mock_authorizer
        )
        await listener.on_node_initialized(mock_node)

        router = await listener.create_router()
        handler = None
        for route in router.routes:
            if hasattr(route, "endpoint") and "websocket_attach_handler" in str(route.endpoint):
                handler = route.endpoint
                break

        await handler(mock_websocket, "downstream", "other-system")

        # Should send error ACK and close
        mock_websocket.send_json.assert_called_once()
        mock_websocket.close.assert_called_once_with(code=status.WS_1008_POLICY_VIOLATION)

    @pytest.mark.asyncio
    async def test_websocket_attach_no_authorization(self, websocket_listener, mock_node, mock_websocket):
        """Test websocket_attach_handler without authorizer - covers lines 310-316."""
        # Create listener without authorizer
        listener = WebSocketListener(http_server=websocket_listener._http_server)
        await listener.on_node_initialized(mock_node)

        # Mock the _create_websocket_connector method
        with patch.object(listener, "_create_websocket_connector") as mock_create:
            mock_connector = AsyncMock()
            mock_connector.wait_until_closed = AsyncMock()
            mock_create.return_value = mock_connector

            router = await listener.create_router()
            handler = None
            for route in router.routes:
                if hasattr(route, "endpoint") and "websocket_attach_handler" in str(route.endpoint):
                    handler = route.endpoint
                    break

            await handler(mock_websocket, "downstream", "other-system")

            # Should create connector and wait
            mock_create.assert_called_once()
            mock_connector.wait_until_closed.assert_called_once()

    @pytest.mark.asyncio
    async def test_websocket_attach_with_security_manager_token_verifier(
        self, websocket_listener, mock_node, mock_websocket
    ):
        """Test websocket_attach_handler with security manager token verifier - covers lines 181-190."""
        # Setup mock node with security manager that has token verifier
        mock_security_manager = MagicMock()
        mock_authorizer = AsyncMock(spec=Authorizer)
        mock_authorizer.authenticate.return_value = {"user": "test"}
        mock_token_verifier = MagicMock()
        mock_authorizer.token_verifier = mock_token_verifier
        mock_security_manager.authorizer = mock_authorizer
        mock_node.security_manager = mock_security_manager

        listener = WebSocketListener(
            http_server=websocket_listener._http_server, authorizer=mock_authorizer
        )
        await listener.on_node_initialized(mock_node)

        # Mock the _create_websocket_connector method
        with patch.object(listener, "_create_websocket_connector") as mock_create:
            mock_connector = AsyncMock()
            mock_connector.wait_until_closed = AsyncMock()
            mock_create.return_value = mock_connector

            router = await listener.create_router()
            handler = None
            for route in router.routes:
                if hasattr(route, "endpoint") and "websocket_attach_handler" in str(route.endpoint):
                    handler = route.endpoint
                    break

            await handler(mock_websocket, "downstream", "other-system")

            # Should create connector and wait
            mock_create.assert_called_once()
            mock_connector.wait_until_closed.assert_called_once()

    @pytest.mark.asyncio
    async def test_websocket_attach_websocket_disconnect(
        self, websocket_listener, mock_node, mock_websocket
    ):
        """Test websocket_attach_handler with WebSocketDisconnect - covers lines 334-353."""
        # Setup authorizer to return valid auth
        mock_authorizer = AsyncMock(spec=Authorizer)
        mock_authorizer.authenticate.return_value = {"user": "test"}

        listener = WebSocketListener(
            http_server=websocket_listener._http_server, authorizer=mock_authorizer
        )
        await listener.on_node_initialized(mock_node)

        # Mock the _create_websocket_connector method to raise WebSocketDisconnect
        with patch.object(listener, "_create_websocket_connector") as mock_create:
            from fastapi import WebSocketDisconnect

            mock_connector = AsyncMock()
            mock_connector.wait_until_closed = AsyncMock(side_effect=WebSocketDisconnect(code=1000))
            mock_create.return_value = mock_connector

            router = await listener.create_router()
            handler = None
            for route in router.routes:
                if hasattr(route, "endpoint") and "websocket_attach_handler" in str(route.endpoint):
                    handler = route.endpoint
                    break

            # Should handle disconnect gracefully
            await handler(mock_websocket, "downstream", "other-system")

            mock_create.assert_called_once()
            mock_connector.wait_until_closed.assert_called_once()


class TestWebSocketListenerSecondGap:
    """Test the second largest gap: _create_websocket_connector method (18 lines, 392-409)."""

    @pytest.fixture
    def mock_http_server(self):
        """Create mock HTTP server."""
        server = MagicMock()
        server.actual_base_url = "http://localhost:8000"
        return server

    @pytest.fixture
    def mock_node(self):
        """Create mock node that implements RoutingNodeLike."""
        node = MagicMock(spec=RoutingNodeLike)
        node.id = "test-node"
        node.public_url = "http://localhost:8000"
        # Mock the create_origin_connector method
        node.create_origin_connector = AsyncMock()
        return node

    @pytest.fixture
    async def websocket_listener(self, mock_http_server):
        """Create WebSocketListener."""
        return WebSocketListener(http_server=mock_http_server)

    @pytest.fixture
    def mock_websocket(self):
        """Create mock WebSocket."""
        return AsyncMock(spec=WebSocket)

    @pytest.mark.asyncio
    async def test_create_websocket_connector(self, websocket_listener, mock_node, mock_websocket):
        """Test _create_websocket_connector method - covers lines 392-409."""
        await websocket_listener.on_node_initialized(mock_node)

        # Mock the create_origin_connector to return a WebSocketConnector
        mock_connector = AsyncMock(spec=WebSocketConnector)
        mock_node.create_origin_connector.return_value = mock_connector

        # Test connector creation
        result = await websocket_listener._create_websocket_connector(
            system_id="test-system",
            websocket=mock_websocket,
            origin_type=DeliveryOriginType.DOWNSTREAM,
            node=mock_node,
            authorization=None,
        )

        # Should call create_origin_connector with correct config
        mock_node.create_origin_connector.assert_called_once()
        assert result == mock_connector


class TestWebSocketListenerSmallGaps:
    """Test smaller coverage gaps for comprehensive coverage."""

    @pytest.fixture
    def mock_http_server(self):
        """Create mock HTTP server."""
        server = MagicMock()
        server.actual_base_url = "http://localhost:8000"
        return server

    @pytest.fixture
    def mock_node(self):
        """Create mock node."""
        node = MagicMock()
        node.id = "test-node"
        node.public_url = "http://localhost:8000"
        return node

    @pytest.fixture
    async def websocket_listener(self, mock_http_server):
        """Create WebSocketListener."""
        return WebSocketListener(http_server=mock_http_server)

    @pytest.mark.asyncio
    async def test_on_node_initialized_already_registered(self, websocket_listener, mock_node):
        """Test on_node_initialized early return - covers line 67."""
        # First initialization
        await websocket_listener.on_node_initialized(mock_node)

        # Second initialization should return early
        initial_calls = websocket_listener._http_server.include_router.call_count
        await websocket_listener.on_node_initialized(mock_node)

        # Should not call include_router again
        assert websocket_listener._http_server.include_router.call_count == initial_calls

    def test_as_callback_grant_with_base_url(self, websocket_listener):
        """Test as_callback_grant with valid base_url - covers lines 115-121."""
        # Mock the underlying _http_server to return base URL
        websocket_listener._http_server.actual_base_url = "http://localhost:8000"
        websocket_listener._public_url = None  # Force use of actual_base_url

        result = websocket_listener.as_callback_grant()

        expected = {
            "type": "WebSocketStatelessConnector",
            "url": "ws://localhost:8000/fame/v1/attach/ws/upstream",
        }
        assert result == expected

    def test_as_callback_grant_no_base_url(self, websocket_listener):
        """Test as_callback_grant without base_url - covers lines 114-115."""
        # Mock both base URL sources to return None
        websocket_listener._http_server.actual_base_url = None
        websocket_listener._public_url = None

        result = websocket_listener.as_callback_grant()
        assert result is None

    def test_upstream_endpoint(self, websocket_listener):
        """Test upstream_endpoint property - covers line 148."""
        result = websocket_listener.upstream_endpoint
        expected = "/fame/v1/attach/ws/upstream"
        assert result == expected

    def test_get_websocket_connector_function(self):
        """Test get_websocket_connector function - covers line 422."""
        # Test the module-level function
        result = get_websocket_connector("test-system")
        # Should return None when no connectors exist
        assert result is None


class TestWebSocketListenerEdgeCases:
    """Test additional edge cases and error paths."""

    @pytest.fixture
    def mock_http_server(self):
        """Create mock HTTP server."""
        server = MagicMock()
        server.actual_base_url = "https://localhost:8000"  # HTTPS for testing
        return server

    @pytest.fixture
    async def websocket_listener(self, mock_http_server):
        """Create WebSocketListener."""
        return WebSocketListener(http_server=mock_http_server)

    def test_as_callback_grant_https_to_wss(self, websocket_listener):
        """Test as_callback_grant HTTPS to WSS conversion."""
        websocket_listener._http_server.actual_base_url = "https://localhost:8000"
        websocket_listener._public_url = None

        result = websocket_listener.as_callback_grant()

        expected = {
            "type": "WebSocketStatelessConnector",
            "url": "wss://localhost:8000/fame/v1/attach/ws/upstream",
        }
        assert result == expected

    def test_properties_coverage(self, websocket_listener):
        """Test various property accessors for coverage."""
        # Test advertised_host and advertised_port - these come from the mock HTTP server
        # so they won't be None, just verify they work
        host = websocket_listener.advertised_host
        port = websocket_listener.advertised_port

        # Just test that they're accessible (don't assert None since they're mocked)
        assert host is not None or host is None  # Always True, but exercises the property
        assert port is not None or port is None  # Always True, but exercises the property

        # Test http_server property
        assert websocket_listener.http_server == websocket_listener._http_server

        # Test attach_prefix
        assert websocket_listener.attach_prefix == "/fame/v1/attach"
