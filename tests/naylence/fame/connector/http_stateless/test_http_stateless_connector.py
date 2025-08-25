from __future__ import annotations

import asyncio
from unittest.mock import Mock, patch

import pytest

from naylence.fame.connector.http_stateless_connector import HttpStatelessConnector
from naylence.fame.errors.errors import FameTransportClose


class TestHttpStatelessConnector:
    """Test suite for HttpStatelessConnector."""

    @pytest.fixture
    def connector(self):
        """Create a test connector instance."""
        return HttpStatelessConnector(
            url="https://example.com/outbox",
            max_queue=10,
            auth_header="Bearer test-token",
        )

    @pytest.mark.asyncio
    async def test_connector_initialization(self):
        """Test that connector initializes correctly."""
        connector = HttpStatelessConnector(
            url="https://example.com/outbox",
            max_queue=100,
        )

        assert connector._url == "https://example.com/outbox"
        assert connector._recv_q.maxsize == 100
        assert connector._auth_header is None

    @pytest.mark.asyncio
    async def test_set_auth_header(self, connector):
        """Test setting authentication header."""
        connector.set_auth_header("Bearer new-token")
        assert connector._auth_header == "Bearer new-token"

    @pytest.mark.asyncio
    async def test_push_to_receive(self, connector):
        """Test pushing bytes to receive queue."""
        test_data = b"test envelope data"

        await connector.push_to_receive(test_data)

        # Verify data is in the queue
        assert connector._recv_q.qsize() == 1
        received = await connector._recv_q.get()
        assert received == test_data

    @pytest.mark.asyncio
    async def test_push_to_receive_queue_full(self):
        """Test push_to_receive raises exception when queue is full."""
        connector = HttpStatelessConnector(
            url="https://example.com/outbox",
            max_queue=1,
        )

        # Fill the queue
        await connector.push_to_receive(b"first")

        # Second push should raise QueueFull (testing synchronous put_nowait)
        with pytest.raises(asyncio.QueueFull):
            await connector.push_to_receive(
                b"second"
            )  # Removed await since push_to_receive uses put_nowait

    @pytest.mark.asyncio
    async def test_transport_receive(self, connector):
        """Test receiving bytes from transport."""
        test_data = b"test envelope"
        await connector.push_to_receive(test_data)

        received = await connector._transport_receive()
        assert received == test_data

    @pytest.mark.asyncio
    async def test_transport_send_bytes_success(self, connector):
        """Test successful HTTP send."""
        test_data = b"test envelope"

        with patch.object(connector._http, "post") as mock_post:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.text = "OK"
            mock_post.return_value = mock_response

            await connector._transport_send_bytes(test_data)

            mock_post.assert_called_once_with(
                "https://example.com/outbox",
                content=test_data,
                headers={
                    "Content-Type": "application/octet-stream",
                    "Authorization": "Bearer test-token",
                },
            )

    @pytest.mark.asyncio
    async def test_transport_send_bytes_http_error(self, connector):
        """Test HTTP send with error response."""
        test_data = b"test envelope"

        with patch.object(connector._http, "post") as mock_post:
            mock_response = Mock()
            mock_response.status_code = 400
            mock_response.text = "Bad Request"
            mock_post.return_value = mock_response

            with pytest.raises(FameTransportClose) as exc_info:
                await connector._transport_send_bytes(test_data)

            assert exc_info.value.code == 400
            assert "400 Bad Request" in str(exc_info.value.reason)

    @pytest.mark.asyncio
    async def test_transport_send_bytes_without_auth(self):
        """Test HTTP send without authentication header."""
        connector = HttpStatelessConnector(
            url="https://example.com/outbox",
            max_queue=10,
        )
        test_data = b"test envelope"

        with patch.object(connector._http, "post") as mock_post:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_post.return_value = mock_response

            await connector._transport_send_bytes(test_data)

            mock_post.assert_called_once_with(
                "https://example.com/outbox",
                content=test_data,
                headers={
                    "Content-Type": "application/octet-stream",
                },
            )

    @pytest.mark.asyncio
    async def test_transport_close(self, connector):
        """Test transport close cleanup."""
        with patch.object(connector._http, "aclose") as mock_close:
            await connector._transport_close(1000, "normal closure")
            mock_close.assert_called_once()

    @pytest.mark.asyncio
    async def test_queue_space_property(self, connector):
        """Test queue space property."""
        # Empty queue should have full space
        assert connector.queue_space == 10

        # Add one item
        await connector.push_to_receive(b"test")
        assert connector.queue_space == 9

    @pytest.mark.asyncio
    async def test_remaining_credits_property(self, connector):
        """Test remaining credits property."""
        # This tests the property exists and doesn't crash
        # The actual value depends on flow control implementation
        credits = connector.remaining_credits
        assert isinstance(credits, int)
        assert credits >= 0
