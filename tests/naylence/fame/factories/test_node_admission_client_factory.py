"""Test AdmissionClientFactory to ensure configs resolve to correct subtypes."""

import pytest

from naylence.fame.factory import create_resource
from naylence.fame.node.admission.admission_client_factory import AdmissionClientFactory
from naylence.fame.node.admission.direct_admission_client import (
    DirectAdmissionClient,
)
from naylence.fame.node.admission.direct_admission_client_factory import (
    DirectNodeAdmissionConfig,
)
from naylence.fame.node.admission.welcome_service_client import (
    WelcomeServiceClient,
)
from naylence.fame.node.admission.welcome_service_client_factory import (
    WelcomeServiceClientConfig,
)


class TestAdmissionClientFactory:
    """Test AdmissionClientFactory and its implementations."""

    @pytest.mark.asyncio
    async def test_welcome_service_client_factory(self):
        """Test WelcomeServiceClient factory creates correct instance."""
        config = WelcomeServiceClientConfig(
            url="https://example.com/admit", supported_transports=["websocket", "http"]
        )
        client = await create_resource(AdmissionClientFactory, config)

        assert isinstance(client, WelcomeServiceClient)
        assert client.__class__.__name__ == "WelcomeServiceClient"

    @pytest.mark.asyncio
    async def test_direct_admission_client_factory(self):
        """Test DirectAdmissionClient factory creates correct instance."""
        config = DirectNodeAdmissionConfig(
            connection_grants=[
                {
                    "type": "WebSocketConnectionGrant",
                    "purpose": "node.attach",
                    "url": "ws://localhost:8080/test",
                }
            ],
        )
        client = await create_resource(AdmissionClientFactory, config)

        assert isinstance(client, DirectAdmissionClient)
        assert client.__class__.__name__ == "DirectAdmissionClient"

    @pytest.mark.asyncio
    async def test_admission_client_factory_from_dict(self):
        """Test factory with dictionary configuration."""
        config = {
            "type": "WelcomeServiceClient",
            "url": "https://example.com/admit",
            "supported_transports": ["websocket"],
        }
        client = await create_resource(AdmissionClientFactory, config)

        assert isinstance(client, WelcomeServiceClient)

    @pytest.mark.asyncio
    async def test_direct_admission_client_factory_from_dict(self):
        """Test DirectAdmissionClient factory with dictionary configuration."""
        config = {
            "type": "DirectAdmissionClient",
            "connection_grants": [
                {
                    "type": "WebSocketConnectionGrant",
                    "purpose": "node.attach",
                    "url": "ws://localhost:8080/test",
                }
            ],
        }
        client = await create_resource(AdmissionClientFactory, config)

        assert isinstance(client, DirectAdmissionClient)

    @pytest.mark.asyncio
    async def test_admission_client_factory_invalid_type(self):
        """Test factory with invalid type raises error."""
        config = {"type": "InvalidAdmissionClient"}

        with pytest.raises(Exception):
            await create_resource(AdmissionClientFactory, config)
