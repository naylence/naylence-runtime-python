from __future__ import annotations

import pytest

from naylence.fame.connector.http_stateless_connector import HttpStatelessConnector
from naylence.fame.connector.http_stateless_connector_factory import (
    HttpStatelessConnectorConfig,
    HttpStatelessConnectorFactory,
)


class TestHttpStatelessConnectorFactory:
    """Test suite for HttpStatelessConnectorFactory."""

    @pytest.fixture
    def factory(self):
        """Create a test factory instance."""
        return HttpStatelessConnectorFactory()

    @pytest.fixture
    def basic_config(self):
        """Create a basic connector configuration."""
        return HttpStatelessConnectorConfig(
            type="HttpStatelessConnector",
            url="https://example.com/outbox",
            params={"url": "https://example.com/outbox"},
        )

    @pytest.fixture
    def config_with_auth(self):
        """Create a connector configuration with authentication."""
        from naylence.fame.core.protocol.frames import Auth

        return HttpStatelessConnectorConfig(
            type="HttpStatelessConnector",
            url="https://example.com/outbox",
            params={"url": "https://example.com/outbox", "max_queue": 512},
            auth=Auth(scheme="bearer", token="test-token-123"),
        )

    @pytest.mark.asyncio
    async def test_create_basic_connector(self, factory, basic_config):
        """Test creating a basic connector without authentication."""
        connector = await factory.create(config=basic_config)

        assert isinstance(connector, HttpStatelessConnector)
        assert connector._url == "https://example.com/outbox"
        assert connector._recv_q.maxsize == 1024  # default
        assert connector._auth_header is None

    # @pytest.mark.asyncio
    # async def test_create_connector_with_auth(self, factory, config_with_auth):
    #     """Test creating a connector with authentication."""
    #     connector = await factory.create(config=config_with_auth)

    #     assert isinstance(connector, HttpStatelessConnector)
    #     assert connector._url == "https://example.com/outbox"
    #     assert connector._recv_q.maxsize == 512
    #     assert connector._auth_header == "Bearer test-token-123"

    @pytest.mark.asyncio
    async def test_create_with_websocket(self, factory):
        """Test creating connector with existing transport primitive."""
        existing_connector = HttpStatelessConnector(url="https://primitive.com/outbox")

        result = await factory.create(config=None, websocket=existing_connector)

        assert result is existing_connector

    @pytest.mark.asyncio
    async def test_create_without_config(self, factory):
        """Test that factory raises error without config."""
        with pytest.raises(ValueError, match="Config not set"):
            await factory.create(config=None)

    # @pytest.mark.asyncio
    # async def test_create_without_params(self, factory):
    #     """Test that factory raises error without params."""
    #     config = HttpStatelessConnectorConfig(
    #         type="HttpStatelessConnector",
    #         url="https://example.com/outbox",
    #         params=None,
    #     )

    #     with pytest.raises(ValueError, match="Invalid configuration: params not set"):
    #         await factory.create(config=config)

    # @pytest.mark.asyncio
    # async def test_create_without_url(self, factory):
    #     """Test that factory raises error without url in params."""
    #     config = HttpStatelessConnectorConfig(
    #         type="HttpStatelessConnector",
    #         url="https://example.com/outbox",
    #         params={"max_queue": 100},  # missing url
    #     )

    #     with pytest.raises(ValueError, match="url is required in config params"):
    #         await factory.create(config=config)

    def test_config_dataclass_defaults(self):
        """Test HttpStatelessConnectorConfig defaults."""
        config = HttpStatelessConnectorConfig(url="https://example.com/outbox")

        assert config.type == "HttpStatelessConnector"
        assert config.url == "https://example.com/outbox"
        assert config.max_queue == 1024
        assert config.kind == "http-stateless"

    def test_config_dataclass_custom_values(self):
        """Test HttpStatelessConnectorConfig with custom values."""
        config = HttpStatelessConnectorConfig(
            type="CustomType",
            url="https://custom.com/outbox",
            max_queue=2048,
            kind="custom-http",
        )

        assert config.type == "CustomType"
        assert config.url == "https://custom.com/outbox"
        assert config.max_queue == 2048
        assert config.kind == "custom-http"
