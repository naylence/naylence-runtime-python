#!/usr/bin/env python3
"""
Comprehensive test suite for HttpListener to achieve 85%+ coverage.

This test suite covers all major functionality including:
- Node event listener interface
- Transport listener interface
- HTTP router creation and endpoints
- Authorization handling
- Node attach frame processing
- Connector management
- Error conditions and edge cases
"""

import asyncio
from unittest.mock import AsyncMock, Mock, patch

import pytest
from fastapi.testclient import TestClient

from naylence.fame.connector.http_listener import HttpListener, get_connector
from naylence.fame.connector.http_stateless_connector import HttpStatelessConnector
from naylence.fame.core import (
    AuthorizationContext,
    DataFrame,
    DeliveryOriginType,
    FameEnvelope,
    NodeAttachFrame,
)
from naylence.fame.node.routing_node_like import RoutingNodeLike
from naylence.fame.security.auth.auth_config import NoAuth
from naylence.fame.security.auth.authorizer import Authorizer


class TestHttpListenerComprehensive:
    """Comprehensive test suite for HttpListener."""

    @pytest.fixture
    def mock_http_server(self):
        """Create a mock HTTP server."""
        server = Mock()
        server.actual_base_url = "http://localhost:8080"
        server.actual_host = "localhost"
        server.actual_port = 8080
        server.is_running = True
        server.include_router = Mock()
        return server

    @pytest.fixture
    def mock_node(self):
        """Create a mock node that implements RoutingNodeLike."""
        node = Mock(spec=RoutingNodeLike)
        node.id = "test-node"
        node.public_url = "https://external.example.com:8080"
        node.security_manager = None
        node.upstream_connector = None
        node._downstream_connector = Mock(return_value=None)
        node.create_origin_connector = AsyncMock()
        return node

    @pytest.fixture
    def mock_authorizer(self):
        """Create a mock authorizer."""
        authorizer = Mock(spec=Authorizer)
        authorizer.authenticate = AsyncMock()
        authorizer.create_reverse_authorization_config = Mock()
        return authorizer

    @pytest.fixture
    def http_listener(self, mock_http_server):
        """Create an HttpListener instance."""
        return HttpListener(http_server=mock_http_server)

    @pytest.fixture
    def http_listener_with_auth(self, mock_http_server, mock_authorizer):
        """Create an HttpListener instance with authorization."""
        return HttpListener(http_server=mock_http_server, authorizer=mock_authorizer)

    # ── Initialization Tests ─────────────────────────────────────────────────

    def test_init_basic(self, mock_http_server):
        """Test basic HttpListener initialization."""
        listener = HttpListener(http_server=mock_http_server)

        assert listener._http_server is mock_http_server
        assert listener._authorizer is None
        assert listener._public_url is None
        assert listener._router_registered is False
        assert listener._node is None

    def test_init_with_authorizer(self, mock_http_server, mock_authorizer):
        """Test HttpListener initialization with authorizer."""
        listener = HttpListener(http_server=mock_http_server, authorizer=mock_authorizer)

        assert listener._http_server is mock_http_server
        assert listener._authorizer is mock_authorizer

    # ── Node Event Listener Interface Tests ──────────────────────────────────

    @pytest.mark.asyncio
    async def test_on_node_initialized_first_time(self, http_listener, mock_node):
        """Test on_node_initialized when called for the first time."""
        with patch.object(http_listener, "create_router") as mock_create_router:
            mock_router = Mock()
            mock_create_router.return_value = mock_router

            await http_listener.on_node_initialized(mock_node)

            assert http_listener._public_url == mock_node.public_url
            assert http_listener._router_registered is True
            mock_create_router.assert_called_once()
            http_listener._http_server.include_router.assert_called_once_with(mock_router)

    @pytest.mark.asyncio
    async def test_on_node_initialized_already_registered(self, http_listener, mock_node):
        """Test on_node_initialized when router already registered."""
        http_listener._router_registered = True

        with patch.object(http_listener, "create_router") as mock_create_router:
            await http_listener.on_node_initialized(mock_node)

            mock_create_router.assert_not_called()
            http_listener._http_server.include_router.assert_not_called()

    @pytest.mark.asyncio
    async def test_on_node_initialized_no_public_url(self, http_listener):
        """Test on_node_initialized with node that has no public URL."""
        node = Mock()
        node.public_url = None

        with patch.object(http_listener, "create_router") as mock_create_router:
            mock_create_router.return_value = Mock()

            await http_listener.on_node_initialized(node)

            assert http_listener._public_url is None

    @pytest.mark.asyncio
    async def test_on_node_stopped_default_http_server(self, mock_http_server, mock_node):
        """Test on_node_stopped with DefaultHttpServer."""
        # Import DefaultHttpServer for instance checking
        from naylence.fame.connector.default_http_server import DefaultHttpServer

        # Mock DefaultHttpServer.release
        with patch.object(DefaultHttpServer, "release", new_callable=AsyncMock) as mock_release:
            # Make the server appear to be a DefaultHttpServer instance
            mock_http_server.__class__ = DefaultHttpServer
            mock_http_server.host = "localhost"
            mock_http_server.port = 8080

            listener = HttpListener(http_server=mock_http_server)
            listener._router_registered = True

            await listener.on_node_stopped(mock_node)

            assert listener._router_registered is False
            mock_release.assert_called_once_with(host="localhost", port=8080)

    @pytest.mark.asyncio
    async def test_on_node_stopped_regular_server(self, http_listener, mock_node):
        """Test on_node_stopped with regular HTTP server."""
        http_listener._router_registered = True

        await http_listener.on_node_stopped(mock_node)

        assert http_listener._router_registered is False

    @pytest.mark.asyncio
    async def test_on_node_started(self, http_listener, mock_node):
        """Test on_node_started (should be no-op)."""
        await http_listener.on_node_started(mock_node)
        # No assertions needed as it's a no-op

    # ── Transport Listener Interface Tests ────────────────────────────────────

    @pytest.mark.asyncio
    async def test_start(self, http_listener):
        """Test start method (should be no-op for HTTP)."""
        await http_listener.start()
        # No assertions needed as HTTP server lifecycle is managed externally

    @pytest.mark.asyncio
    async def test_stop(self, http_listener):
        """Test stop method."""
        await http_listener.stop()
        # No assertions needed as this is primarily cleanup

    def test_as_inbound_connector_no_base_url(self, http_listener):
        """Test as_inbound_connector when no base URL available."""
        http_listener._http_server.actual_base_url = None

        result = http_listener.as_inbound_connector()

        assert result is None

    def test_as_inbound_connector_basic(self, http_listener):
        """Test as_inbound_connector with basic configuration."""
        result = http_listener.as_inbound_connector()

        assert result is not None
        assert result["url"] == "http://localhost:8080/fame/v1/ingress/upstream"
        assert "auth" in result

    def test_as_inbound_connector_with_reverse_auth(self, http_listener, mock_node, mock_authorizer):
        """Test as_inbound_connector with reverse authorization."""
        # Set up node with security manager
        mock_security_manager = Mock()
        mock_security_manager.authorizer = mock_authorizer
        mock_node.security_manager = mock_security_manager
        http_listener._node = mock_node

        # Mock reverse auth config - create a proper NoAuth instance

        mock_auth_config = NoAuth()
        mock_authorizer.create_reverse_authorization_config.return_value = mock_auth_config

        result = http_listener.as_inbound_connector()

        assert result is not None
        mock_authorizer.create_reverse_authorization_config.assert_called_once_with(mock_node)

    def test_as_inbound_connector_reverse_auth_failure(self, http_listener, mock_node, mock_authorizer):
        """Test as_inbound_connector when reverse auth creation fails."""
        # Set up node with security manager
        mock_security_manager = Mock()
        mock_security_manager.authorizer = mock_authorizer
        mock_node.security_manager = mock_security_manager
        http_listener._node = mock_node

        # Mock reverse auth config to raise exception
        mock_authorizer.create_reverse_authorization_config.side_effect = Exception("Auth failed")

        result = http_listener.as_inbound_connector()

        assert result is not None
        # Should fall back to NoAuth

    def test_as_inbound_connector_no_reverse_auth_method(self, http_listener, mock_node):
        """Test as_inbound_connector when authorizer has no reverse auth method."""
        # Set up node with security manager but authorizer without reverse auth
        mock_security_manager = Mock()
        mock_authorizer = Mock()
        del mock_authorizer.create_reverse_authorization_config  # Remove the method
        mock_security_manager.authorizer = mock_authorizer
        mock_node.security_manager = mock_security_manager
        http_listener._node = mock_node

        result = http_listener.as_inbound_connector()

        assert result is not None
        # Should use NoAuth

    # ── Property Tests ────────────────────────────────────────────────────────

    def test_is_running(self, http_listener):
        """Test is_running property."""
        assert http_listener.is_running is True

        http_listener._http_server.is_running = False
        assert http_listener.is_running is False

    def test_base_url_with_public_url(self, http_listener):
        """Test base_url property when public URL is set."""
        http_listener._public_url = "https://external.example.com:9090"

        assert http_listener.base_url == "https://external.example.com:9090"

    def test_base_url_without_public_url(self, http_listener):
        """Test base_url property when public URL is not set."""
        http_listener._public_url = None

        assert http_listener.base_url == "http://localhost:8080"

    def test_ingress_prefix(self, http_listener):
        """Test ingress_prefix property."""
        assert http_listener.ingress_prefix == "/fame/v1/ingress"

    def test_upstream_endpoint(self, http_listener):
        """Test upstream_endpoint property."""
        assert http_listener.upstream_endpoint == "/fame/v1/ingress/upstream"

    def test_http_server(self, http_listener, mock_http_server):
        """Test http_server property."""
        assert http_listener.http_server is mock_http_server

    # ── Router Creation Tests ─────────────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_create_router_basic(self, http_listener, mock_node):
        """Test create_router creates proper FastAPI router."""
        # Set the node first since create_router no longer takes it as parameter
        http_listener._node = mock_node

        http_listener._node = mock_node
        router = await http_listener.create_router()

        assert http_listener._node is mock_node
        assert router.prefix == "/fame/v1/ingress"
        assert len(router.routes) == 3  # upstream, downstream, health

    # ── HTTP Endpoint Tests ───────────────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_upstream_endpoint_no_auth_no_connector(self, http_listener, mock_node):
        """Test upstream endpoint with no auth and no connector."""
        http_listener._node = mock_node
        router = await http_listener.create_router()

        # Create test client
        from fastapi import FastAPI

        app = FastAPI()
        app.include_router(router)
        client = TestClient(app)

        # Create a proper FameEnvelope for upstream
        test_frame = DataFrame(payload=b"test data")
        envelope = FameEnvelope(frame=test_frame)
        envelope_json = envelope.model_dump_json()

        # Test request should fail with 503 (no upstream connector)
        response = client.post(
            "/fame/v1/ingress/upstream", content=envelope_json, headers={"Content-Type": "application/json"}
        )

        assert response.status_code == 503
        assert "No upstream connector available" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_upstream_endpoint_with_connector(self, http_listener, mock_node):
        """Test upstream endpoint with valid connector."""
        # Set up upstream connector
        mock_connector = Mock(spec=HttpStatelessConnector)
        mock_connector.push_to_receive = AsyncMock()
        mock_node.upstream_connector = mock_connector

        http_listener._node = mock_node
        router = await http_listener.create_router()

        # Create test client
        from fastapi import FastAPI

        app = FastAPI()
        app.include_router(router)
        client = TestClient(app)

        # Create a proper FameEnvelope for upstream
        test_frame = DataFrame(payload=b"test data")
        envelope = FameEnvelope(frame=test_frame)
        envelope_json = envelope.model_dump_json()

        # Test successful request
        response = client.post(
            "/fame/v1/ingress/upstream", content=envelope_json, headers={"Content-Type": "application/json"}
        )

        assert response.status_code == 202
        assert response.json()["status"] == "message_received"
        # Verify the connector received a FameChannelMessage, not raw data
        mock_connector.push_to_receive.assert_called_once()
        call_args = mock_connector.push_to_receive.call_args[0][0]
        # Should be a FameChannelMessage
        assert hasattr(call_args, "envelope")
        assert hasattr(call_args, "context")

    @pytest.mark.asyncio
    async def test_upstream_endpoint_empty_body(self, http_listener, mock_node):
        """Test upstream endpoint with empty request body."""
        http_listener._node = mock_node
        router = await http_listener.create_router()

        # Create test client
        from fastapi import FastAPI

        app = FastAPI()
        app.include_router(router)
        client = TestClient(app)

        # Test request with empty body
        response = client.post("/fame/v1/ingress/upstream")

        assert response.status_code == 400
        assert "Empty request body" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_upstream_endpoint_rejects_raw_binary_data(self, http_listener, mock_node):
        """Test upstream endpoint properly rejects raw binary data."""
        http_listener._node = mock_node
        router = await http_listener.create_router()

        # Create test client
        from fastapi import FastAPI

        app = FastAPI()
        app.include_router(router)
        client = TestClient(app)

        # Test request with raw binary data (old behavior that should now be rejected)
        response = client.post(
            "/fame/v1/ingress/upstream",
            content=b"raw binary frame data",
            headers={"Content-Type": "application/octet-stream"},
        )

        assert response.status_code == 400
        assert "Invalid request body - expected FameEnvelope JSON" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_upstream_endpoint_with_auth_success(
        self, http_listener_with_auth, mock_node, mock_authorizer
    ):
        """Test upstream endpoint with successful authentication."""
        # Set up auth result
        auth_result = AuthorizationContext(system_id="test-system")
        mock_authorizer.authenticate.return_value = auth_result

        # Set up upstream connector
        mock_connector = Mock(spec=HttpStatelessConnector)
        mock_connector.push_to_receive = AsyncMock()
        mock_node.upstream_connector = mock_connector

        http_listener_with_auth._node = mock_node
        router = await http_listener_with_auth.create_router()

        # Create test client
        from fastapi import FastAPI

        app = FastAPI()
        app.include_router(router)
        client = TestClient(app)

        # Create a proper FameEnvelope for upstream
        test_frame = DataFrame(payload=b"test data")
        envelope = FameEnvelope(frame=test_frame)
        envelope_json = envelope.model_dump_json()

        # Test successful request with auth
        response = client.post(
            "/fame/v1/ingress/upstream",
            content=envelope_json,
            headers={"Authorization": "Bearer token123", "Content-Type": "application/json"},
        )

        assert response.status_code == 202
        mock_authorizer.authenticate.assert_called_once_with(mock_node, "Bearer token123")

        # Verify the connector received a FameChannelMessage with authorization context
        mock_connector.push_to_receive.assert_called_once()
        call_args = mock_connector.push_to_receive.call_args[0][0]

        # Should be a FameChannelMessage
        assert hasattr(call_args, "envelope")
        assert hasattr(call_args, "context")
        # Check envelope frame type and payload (accounting for JSON serialization changes)
        assert call_args.envelope.frame.type == test_frame.type
        # After JSON serialization/deserialization, bytes become string
        assert call_args.envelope.frame.payload == "test data"
        assert call_args.context is not None
        assert call_args.context.security is not None
        assert call_args.context.security.authorization == auth_result

    @pytest.mark.asyncio
    async def test_upstream_endpoint_auth_failure(
        self, http_listener_with_auth, mock_node, mock_authorizer
    ):
        """Test upstream endpoint with authentication failure."""
        # Set up auth to fail
        mock_authorizer.authenticate.return_value = None

        http_listener_with_auth._node = mock_node
        router = await http_listener_with_auth.create_router()

        # Create test client
        from fastapi import FastAPI

        app = FastAPI()
        app.include_router(router)
        client = TestClient(app)

        # Create a proper FameEnvelope for upstream
        test_frame = DataFrame(payload=b"test data")
        envelope = FameEnvelope(frame=test_frame)
        envelope_json = envelope.model_dump_json()

        # Test request with failed auth
        response = client.post(
            "/fame/v1/ingress/upstream",
            content=envelope_json,
            headers={"Authorization": "Bearer invalid", "Content-Type": "application/json"},
        )

        assert response.status_code == 401
        assert "Authentication failed" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_upstream_endpoint_auth_exception(
        self, http_listener_with_auth, mock_node, mock_authorizer
    ):
        """Test upstream endpoint with authentication exception."""
        # Set up auth to raise exception
        mock_authorizer.authenticate.side_effect = Exception("Auth error")

        http_listener_with_auth._node = mock_node
        router = await http_listener_with_auth.create_router()

        # Create test client
        from fastapi import FastAPI

        app = FastAPI()
        app.include_router(router)
        client = TestClient(app)

        # Create a proper FameEnvelope for upstream
        test_frame = DataFrame(payload=b"test data")
        envelope = FameEnvelope(frame=test_frame)
        envelope_json = envelope.model_dump_json()

        # Test request with auth exception
        response = client.post(
            "/fame/v1/ingress/upstream",
            content=envelope_json,
            headers={"Authorization": "Bearer token", "Content-Type": "application/json"},
        )

        assert response.status_code == 500
        assert "Authorization error: Auth error" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_upstream_endpoint_connector_queue_full(self, http_listener, mock_node):
        """Test upstream endpoint when connector queue is full."""
        # Set up upstream connector that raises QueueFull
        mock_connector = Mock(spec=HttpStatelessConnector)
        mock_connector.push_to_receive = AsyncMock(side_effect=asyncio.QueueFull())
        mock_node.upstream_connector = mock_connector

        http_listener._node = mock_node
        router = await http_listener.create_router()

        # Create test client
        from fastapi import FastAPI

        app = FastAPI()
        app.include_router(router)
        client = TestClient(app)

        # Create a proper FameEnvelope for upstream
        test_frame = DataFrame(payload=b"test data")
        envelope = FameEnvelope(frame=test_frame)
        envelope_json = envelope.model_dump_json()

        # Test request with queue full - upstream now handles QueueFull specifically
        response = client.post(
            "/fame/v1/ingress/upstream", content=envelope_json, headers={"Content-Type": "application/json"}
        )

        assert response.status_code == 429
        assert "receiver busy" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_downstream_endpoint_node_attach(self, http_listener, mock_node):
        """Test downstream endpoint with NodeAttach frame."""
        # Set up node attach handler
        mock_connector = Mock()
        mock_connector.push_to_receive = AsyncMock()

        with patch.object(
            http_listener, "_handle_node_attach_frame", return_value=mock_connector
        ) as mock_handler:
            http_listener._node = mock_node
            router = await http_listener.create_router()

            # Create test client
            from fastapi import FastAPI

            app = FastAPI()
            app.include_router(router)
            client = TestClient(app)

            # Create NodeAttach frame
            attach_frame = NodeAttachFrame(
                system_id="test-child", instance_id="test-instance", supported_inbound_connectors=[]
            )
            envelope = FameEnvelope(frame=attach_frame)

            # Test NodeAttach request
            response = client.post(
                "/fame/v1/ingress/downstream/test-child",
                content=envelope.model_dump_json(),
                headers={"Content-Type": "application/json"},
            )

            assert response.status_code == 202
            assert response.json()["status"] == "attach_in_progress"
            mock_handler.assert_called_once()

    @pytest.mark.asyncio
    async def test_downstream_endpoint_child_id_mismatch(self, http_listener, mock_node):
        """Test downstream endpoint with mismatched child ID."""
        http_listener._node = mock_node
        router = await http_listener.create_router()

        # Create test client
        from fastapi import FastAPI

        app = FastAPI()
        app.include_router(router)
        client = TestClient(app)

        # Create NodeAttach frame with different system_id
        attach_frame = NodeAttachFrame(
            system_id="different-child", instance_id="test-instance", supported_inbound_connectors=[]
        )
        envelope = FameEnvelope(frame=attach_frame)

        # Test request with mismatched ID
        response = client.post(
            "/fame/v1/ingress/downstream/test-child",
            content=envelope.model_dump_json(),
            headers={"Content-Type": "application/json"},
        )

        assert response.status_code == 400
        assert "Child ID mismatch" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_downstream_endpoint_attach_failure(self, http_listener, mock_node):
        """Test downstream endpoint when node attach fails."""
        # Set up node attach handler to fail
        with patch.object(
            http_listener, "_handle_node_attach_frame", side_effect=Exception("Attach failed")
        ):
            http_listener._node = mock_node
            router = await http_listener.create_router()

            # Create test client
            from fastapi import FastAPI

            app = FastAPI()
            app.include_router(router)
            client = TestClient(app)

            # Create NodeAttach frame
            attach_frame = NodeAttachFrame(
                system_id="test-child", instance_id="test-instance", supported_inbound_connectors=[]
            )
            envelope = FameEnvelope(frame=attach_frame)

            # Test request with attach failure
            response = client.post(
                "/fame/v1/ingress/downstream/test-child",
                content=envelope.model_dump_json(),
                headers={"Content-Type": "application/json"},
            )

            assert response.status_code == 400
            assert "Node attachment failed: Attach failed" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_downstream_endpoint_existing_connector(self, http_listener, mock_node):
        """Test downstream endpoint with existing connector."""
        # Set up existing connector
        mock_connector = Mock()
        mock_connector.push_to_receive = AsyncMock()

        with patch.object(http_listener, "_get_existing_connector", return_value=mock_connector):
            http_listener._node = mock_node
            router = await http_listener.create_router()

            # Create test client
            from fastapi import FastAPI

            app = FastAPI()
            app.include_router(router)
            client = TestClient(app)

            # Create a proper FameEnvelope with DataFrame (not NodeAttach)
            test_frame = DataFrame(payload=b"test data")
            envelope = FameEnvelope(frame=test_frame)
            envelope_json = envelope.model_dump_json()

            # Test regular frame (not NodeAttach)
            response = client.post(
                "/fame/v1/ingress/downstream/test-child",
                content=envelope_json,
                headers={"Content-Type": "application/json"},
            )

            assert response.status_code == 202
            assert response.json()["status"] == "message_received"
            # Verify the connector received a FameChannelMessage, not raw data
            mock_connector.push_to_receive.assert_called_once()
            call_args = mock_connector.push_to_receive.call_args[0][0]
            # Should be a FameChannelMessage
            assert hasattr(call_args, "envelope")
            assert hasattr(call_args, "context")

    @pytest.mark.asyncio
    async def test_downstream_endpoint_no_existing_connector(self, http_listener, mock_node):
        """Test downstream endpoint with no existing connector."""
        with patch.object(http_listener, "_get_existing_connector", return_value=None):
            http_listener._node = mock_node
            router = await http_listener.create_router()

            # Create test client
            from fastapi import FastAPI

            app = FastAPI()
            app.include_router(router)
            client = TestClient(app)

            # Create a proper FameEnvelope with DataFrame (not NodeAttach)
            test_frame = DataFrame(payload=b"test data")
            envelope = FameEnvelope(frame=test_frame)
            envelope_json = envelope.model_dump_json()

            # Test regular frame without existing connector
            response = client.post(
                "/fame/v1/ingress/downstream/test-child",
                content=envelope_json,
                headers={"Content-Type": "application/json"},
            )

            assert response.status_code == 400
            assert "No established connection - NodeAttach required" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_downstream_endpoint_empty_body(self, http_listener, mock_node):
        """Test downstream endpoint with empty body."""
        http_listener._node = mock_node
        router = await http_listener.create_router()

        # Create test client
        from fastapi import FastAPI

        app = FastAPI()
        app.include_router(router)
        client = TestClient(app)

        # Test request with empty body
        response = client.post("/fame/v1/ingress/downstream/test-child")

        assert response.status_code == 400
        assert "Empty request body" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_downstream_endpoint_rejects_raw_binary_data(self, http_listener, mock_node):
        """Test downstream endpoint properly rejects raw binary data."""
        http_listener._node = mock_node
        router = await http_listener.create_router()

        # Create test client
        from fastapi import FastAPI

        app = FastAPI()
        app.include_router(router)
        client = TestClient(app)

        # Test request with raw binary data (old behavior that should now be rejected)
        response = client.post(
            "/fame/v1/ingress/downstream/test-child",
            content=b"raw binary frame data",
            headers={"Content-Type": "application/octet-stream"},
        )

        assert response.status_code == 400
        assert "Invalid request body - expected FameEnvelope JSON" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_health_endpoint(self, http_listener, mock_node):
        """Test health check endpoint."""
        http_listener._node = mock_node
        router = await http_listener.create_router()

        # Create test client
        from fastapi import FastAPI

        app = FastAPI()
        app.include_router(router)
        client = TestClient(app)

        # Test health check
        response = client.get("/fame/v1/ingress/health")

        assert response.status_code == 200
        assert response.json()["status"] == "healthy"

    # ── Node Attach Frame Handling Tests ─────────────────────────────────────

    @pytest.mark.asyncio
    async def test_handle_node_attach_frame_success(self, http_listener, mock_node):
        """Test successful node attach frame handling."""
        # Create test frame and envelope
        attach_frame = NodeAttachFrame(
            system_id="test-child", instance_id="test-instance", supported_inbound_connectors=[]
        )
        envelope = FameEnvelope(frame=attach_frame)

        # Mock connector creation
        mock_connector = Mock()
        mock_node.create_origin_connector.return_value = mock_connector

        with patch("naylence.fame.connector.connector_selection_policy.ConnectorSelectionContext"):
            with patch(
                "naylence.fame.connector.connector_selection_policy.default_connector_selection_policy"
            ) as mock_policy:
                mock_selection_result = Mock()
                mock_selection_result.fallback_used = False
                mock_selection_result.selection_reason = "Best match"
                mock_selection_result.connector_config = Mock()
                mock_policy.select_connector.return_value = mock_selection_result

                result = await http_listener._handle_node_attach_frame(
                    child_id="test-child", attach_frame=attach_frame, envelope=envelope, node=mock_node
                )

                assert result is mock_connector
                mock_node.create_origin_connector.assert_called_once_with(
                    origin_type=DeliveryOriginType.DOWNSTREAM,
                    system_id="test-child",
                    connector_config=mock_selection_result.connector_config,
                    authorization=None,
                )

    @pytest.mark.asyncio
    async def test_handle_node_attach_frame_with_auth(self, http_listener, mock_node):
        """Test node attach frame handling with authorization."""
        # Create test frame and envelope
        attach_frame = NodeAttachFrame(
            system_id="test-child", instance_id="test-instance", supported_inbound_connectors=[]
        )
        envelope = FameEnvelope(frame=attach_frame)
        auth_context = AuthorizationContext(system_id="test-child")

        # Mock connector creation
        mock_connector = Mock()
        mock_node.create_origin_connector.return_value = mock_connector

        with patch("naylence.fame.connector.connector_selection_policy.ConnectorSelectionContext"):
            with patch(
                "naylence.fame.connector.connector_selection_policy.default_connector_selection_policy"
            ) as mock_policy:
                mock_selection_result = Mock()
                mock_selection_result.fallback_used = False
                mock_selection_result.selection_reason = "Best match"
                mock_selection_result.connector_config = Mock()
                mock_policy.select_connector.return_value = mock_selection_result

                result = await http_listener._handle_node_attach_frame(
                    child_id="test-child",
                    attach_frame=attach_frame,
                    envelope=envelope,
                    node=mock_node,
                    authorization=auth_context,
                )

                assert result is mock_connector
                mock_node.create_origin_connector.assert_called_once_with(
                    origin_type=DeliveryOriginType.DOWNSTREAM,
                    system_id="test-child",
                    connector_config=mock_selection_result.connector_config,
                    authorization=auth_context,
                )

    @pytest.mark.asyncio
    async def test_handle_node_attach_frame_fallback(self, http_listener, mock_node):
        """Test node attach frame handling with fallback connector."""
        # Create test frame and envelope
        attach_frame = NodeAttachFrame(
            system_id="test-child", instance_id="test-instance", supported_inbound_connectors=[]
        )
        envelope = FameEnvelope(frame=attach_frame)

        # Mock connector creation
        mock_connector = Mock()
        mock_node.create_origin_connector.return_value = mock_connector

        with patch("naylence.fame.connector.connector_selection_policy.ConnectorSelectionContext"):
            with patch(
                "naylence.fame.connector.connector_selection_policy.default_connector_selection_policy"
            ) as mock_policy:
                mock_selection_result = Mock()
                mock_selection_result.fallback_used = True
                mock_selection_result.selection_reason = "Fallback used"
                mock_selection_result.connector_config = Mock()
                mock_policy.select_connector.return_value = mock_selection_result

                result = await http_listener._handle_node_attach_frame(
                    child_id="test-child", attach_frame=attach_frame, envelope=envelope, node=mock_node
                )

                assert result is mock_connector

    # ── Connector Management Tests ───────────────────────────────────────────

    def test_get_existing_connector_routing_node(self, http_listener, mock_node):
        """Test _get_existing_connector with RoutingNodeLike."""
        mock_connector = Mock()
        mock_node._downstream_connector.return_value = mock_connector
        http_listener._node = mock_node

        result = http_listener._get_existing_connector("test-child")

        assert result is mock_connector
        mock_node._downstream_connector.assert_called_once_with("test-child")

    def test_get_existing_connector_no_connector(self, http_listener, mock_node):
        """Test _get_existing_connector when no connector exists."""
        mock_node._downstream_connector.return_value = None
        http_listener._node = mock_node

        result = http_listener._get_existing_connector("test-child")

        assert result is None

    def test_get_existing_connector_non_routing_node(self, http_listener):
        """Test _get_existing_connector with non-RoutingNodeLike."""
        non_routing_node = Mock()  # Not a RoutingNodeLike
        http_listener._node = non_routing_node

        result = http_listener._get_existing_connector("test-child")

        assert result is None

    def test_get_existing_connector_no_node(self, http_listener):
        """Test _get_existing_connector when no node is set."""
        result = http_listener._get_existing_connector("test-child")

        assert result is None

    # ── Test Helper Function Tests ───────────────────────────────────────────

    def test_get_connector_helper_function(self, http_listener, mock_node):
        """Test get_connector helper function."""
        mock_connector = Mock(spec=HttpStatelessConnector)
        mock_node._downstream_connector.return_value = mock_connector
        http_listener._node = mock_node

        # Set the global instance
        import naylence.fame.connector.http_listener as http_listener_module

        http_listener_module._last_http_listener_instance = http_listener

        result = get_connector("test-system")

        assert result is mock_connector

    def test_get_connector_helper_no_connector(self, http_listener, mock_node):
        """Test get_connector helper when no connector exists."""
        mock_node._downstream_connector.return_value = None
        http_listener._node = mock_node

        # Set the global instance
        import naylence.fame.connector.http_listener as http_listener_module

        http_listener_module._last_http_listener_instance = http_listener

        result = get_connector("test-system")

        assert result is None

    def test_get_connector_helper_wrong_type(self, http_listener, mock_node):
        """Test get_connector helper when connector is wrong type."""
        mock_connector = Mock()  # Not HttpStatelessConnector
        mock_node._downstream_connector.return_value = mock_connector
        http_listener._node = mock_node

        # Set the global instance
        import naylence.fame.connector.http_listener as http_listener_module

        http_listener_module._last_http_listener_instance = http_listener

        result = get_connector("test-system")

        assert result is None

    def test_get_connector_helper_no_instance(self):
        """Test get_connector helper when no instance exists."""
        # Clear the global instance
        import naylence.fame.connector.http_listener as http_listener_module

        http_listener_module._last_http_listener_instance = None

        result = get_connector("test-system")

        assert result is None

    # ── Error Handling and Edge Cases ───────────────────────────────────────

    @pytest.mark.asyncio
    async def test_downstream_endpoint_json_parse_error(self, http_listener, mock_node):
        """Test downstream endpoint with invalid JSON."""
        with patch.object(http_listener, "_get_existing_connector", return_value=None):
            http_listener._node = mock_node
            router = await http_listener.create_router()

            # Create test client
            from fastapi import FastAPI

            app = FastAPI()
            app.include_router(router)
            client = TestClient(app)

            # Test request with invalid JSON that can't be parsed as envelope
            response = client.post(
                "/fame/v1/ingress/downstream/test-child",
                content=b"invalid json data",
                headers={"Content-Type": "application/json"},
            )

            assert response.status_code == 400
            # assert "No established connection - NodeAttach required" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_upstream_endpoint_non_http_connector(self, http_listener, mock_node):
        """Test upstream endpoint with non-HTTP connector."""
        # Set up non-HTTP upstream connector
        mock_connector = Mock()  # Not HttpStatelessConnector
        mock_node.upstream_connector = mock_connector

        http_listener._node = mock_node
        router = await http_listener.create_router()

        # Create test client
        from fastapi import FastAPI

        app = FastAPI()
        app.include_router(router)
        client = TestClient(app)

        # Create a proper FameEnvelope for upstream
        test_frame = DataFrame(payload=b"test data")
        envelope = FameEnvelope(frame=test_frame)
        envelope_json = envelope.model_dump_json()

        # Test request should fail with 503
        response = client.post(
            "/fame/v1/ingress/upstream", content=envelope_json, headers={"Content-Type": "application/json"}
        )

        assert response.status_code == 503
        assert "Upstream connector is not a HttpStatelessConnector" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_downstream_endpoint_connector_queue_full(self, http_listener, mock_node):
        """Test downstream endpoint when connector queue is full."""
        # Set up existing connector that raises QueueFull
        mock_connector = Mock()
        mock_connector.push_to_receive = AsyncMock(side_effect=asyncio.QueueFull())

        with patch.object(http_listener, "_get_existing_connector", return_value=mock_connector):
            http_listener._node = mock_node
            router = await http_listener.create_router()

            # Create test client
            from fastapi import FastAPI

            app = FastAPI()
            app.include_router(router)
            client = TestClient(app)

            # Create a proper FameEnvelope with DataFrame (not NodeAttach)
            test_frame = DataFrame(payload=b"test data")
            envelope = FameEnvelope(frame=test_frame)
            envelope_json = envelope.model_dump_json()

            # Test request with queue full
            response = client.post(
                "/fame/v1/ingress/downstream/test-child",
                content=envelope_json,
                headers={"Content-Type": "application/json"},
            )

            assert response.status_code == 429
            assert "receiver busy" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_downstream_endpoint_attach_queue_full(self, http_listener, mock_node):
        """Test downstream endpoint when attach connector queue is full."""
        # Set up node attach handler to raise QueueFull
        with patch.object(http_listener, "_handle_node_attach_frame", side_effect=asyncio.QueueFull()):
            http_listener._node = mock_node
            router = await http_listener.create_router()

            # Create test client
            from fastapi import FastAPI

            app = FastAPI()
            app.include_router(router)
            client = TestClient(app)

            # Create NodeAttach frame
            attach_frame = NodeAttachFrame(
                system_id="test-child", instance_id="test-instance", supported_inbound_connectors=[]
            )
            envelope = FameEnvelope(frame=attach_frame)

            # Test request with queue full during attach
            response = client.post(
                "/fame/v1/ingress/downstream/test-child", content=envelope.model_dump_json()
            )

            assert response.status_code == 400
            assert "Node attachment failed" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_downstream_endpoint_specific_error_messages(self, http_listener, mock_node):
        """Test downstream endpoint error message mapping."""
        error_cases = [
            ("No suitable connector found", "No compatible connector configuration available"),
            ("ConnectError occurred", "Cannot establish outbound connection for attachment"),
            ("Invalid connector config", "Connector configuration error"),
            ("certificate validation failed", "Certificate validation failed"),
        ]

        for original_error, expected_message in error_cases:
            with patch.object(
                http_listener, "_handle_node_attach_frame", side_effect=Exception(original_error)
            ):
                http_listener._node = mock_node
                router = await http_listener.create_router()

                # Create test client
                from fastapi import FastAPI

                app = FastAPI()
                app.include_router(router)
                client = TestClient(app)

                # Create NodeAttach frame
                attach_frame = NodeAttachFrame(
                    system_id="test-child", instance_id="test-instance", supported_inbound_connectors=[]
                )
                envelope = FameEnvelope(frame=attach_frame)

                # Test request with specific error
                response = client.post(
                    "/fame/v1/ingress/downstream/test-child", content=envelope.model_dump_json()
                )

                assert response.status_code == 400
                assert expected_message in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_upstream_endpoint_general_exception(self, http_listener, mock_node):
        """Test upstream endpoint with general exception."""
        # Set up upstream connector that raises general exception
        mock_connector = Mock(spec=HttpStatelessConnector)
        mock_connector.push_to_receive = AsyncMock(side_effect=ValueError("Some error"))
        mock_node.upstream_connector = mock_connector

        http_listener._node = mock_node
        router = await http_listener.create_router()

        # Create test client
        from fastapi import FastAPI

        app = FastAPI()
        app.include_router(router)
        client = TestClient(app)

        # Create a proper FameEnvelope for upstream
        test_frame = DataFrame(payload=b"test data")
        envelope = FameEnvelope(frame=test_frame)
        envelope_json = envelope.model_dump_json()

        # Test request with general exception
        response = client.post(
            "/fame/v1/ingress/upstream", content=envelope_json, headers={"Content-Type": "application/json"}
        )

        assert response.status_code == 500
        assert "Internal server error: Some error" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_downstream_endpoint_general_exception(self, http_listener, mock_node):
        """Test downstream endpoint with general exception."""
        # Set up existing connector that raises general exception
        mock_connector = Mock()
        mock_connector.push_to_receive = AsyncMock(side_effect=ValueError("Some error"))

        with patch.object(http_listener, "_get_existing_connector", return_value=mock_connector):
            http_listener._node = mock_node
            router = await http_listener.create_router()

            # Create test client
            from fastapi import FastAPI

            app = FastAPI()
            app.include_router(router)
            client = TestClient(app)

            # Create a proper FameEnvelope with DataFrame (not NodeAttach)
            test_frame = DataFrame(payload=b"test data")
            envelope = FameEnvelope(frame=test_frame)
            envelope_json = envelope.model_dump_json()

            # Test request with general exception
            response = client.post(
                "/fame/v1/ingress/downstream/test-child",
                content=envelope_json,
                headers={"Content-Type": "application/json"},
            )

            assert response.status_code == 500
            assert "Internal server error: Some error" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_downstream_endpoint_auth_with_security_manager(self, http_listener, mock_node):
        """Test downstream endpoint using node's security manager for auth."""
        # Set up node security manager with authorizer
        mock_security_manager = Mock()
        mock_authorizer = Mock()
        mock_authorizer.authenticate = AsyncMock(return_value=AuthorizationContext(system_id="test"))
        mock_security_manager.authorizer = mock_authorizer
        mock_node.security_manager = mock_security_manager

        # Set up existing connector
        mock_connector = Mock()
        mock_connector.push_to_receive = AsyncMock()

        with patch.object(http_listener, "_get_existing_connector", return_value=mock_connector):
            http_listener._node = mock_node
            router = await http_listener.create_router()

            # Create test client
            from fastapi import FastAPI

            app = FastAPI()
            app.include_router(router)
            client = TestClient(app)

            # Create a proper FameEnvelope with DataFrame (not NodeAttach)
            test_frame = DataFrame(payload=b"test data")
            envelope = FameEnvelope(frame=test_frame)
            envelope_json = envelope.model_dump_json()

            # Test request with auth header
            response = client.post(
                "/fame/v1/ingress/downstream/test-child",
                content=envelope_json,
                headers={"Authorization": "Bearer token123", "Content-Type": "application/json"},
            )

            assert response.status_code == 202
            mock_authorizer.authenticate.assert_called_once_with(mock_node, "Bearer token123")

    @pytest.mark.asyncio
    async def test_upstream_endpoint_auth_with_security_manager(self, http_listener, mock_node):
        """Test upstream endpoint using node's security manager for auth."""
        # Set up node security manager with authorizer
        mock_security_manager = Mock()
        mock_authorizer = Mock()
        mock_authorizer.authenticate = AsyncMock(return_value=AuthorizationContext(system_id="test"))
        mock_security_manager.authorizer = mock_authorizer
        mock_node.security_manager = mock_security_manager

        # Set up upstream connector
        mock_connector = Mock(spec=HttpStatelessConnector)
        mock_connector.push_to_receive = AsyncMock()
        mock_node.upstream_connector = mock_connector

        http_listener._node = mock_node
        router = await http_listener.create_router()

        # Create test client
        from fastapi import FastAPI

        app = FastAPI()
        app.include_router(router)
        client = TestClient(app)

        # Create a proper FameEnvelope for upstream
        test_frame = DataFrame(payload=b"test data")
        envelope = FameEnvelope(frame=test_frame)
        envelope_json = envelope.model_dump_json()

        # Test request with auth header
        response = client.post(
            "/fame/v1/ingress/upstream",
            content=envelope_json,
            headers={"Authorization": "Bearer token123", "Content-Type": "application/json"},
        )

        assert response.status_code == 202
        mock_authorizer.authenticate.assert_called_once_with(mock_node, "Bearer token123")
