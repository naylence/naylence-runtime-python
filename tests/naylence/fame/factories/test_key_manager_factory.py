"""Test KeyManagerFactory to ensure configs resolve to correct subtypes."""

import pytest

from naylence.fame.core import create_resource
from naylence.fame.security.keys.default_key_manager import DefaultKeyManager
from naylence.fame.security.keys.default_key_manager_factory import (
    DefaultKeyManagerConfig,
)
from naylence.fame.security.keys.key_manager_factory import KeyManagerFactory


class TestKeyManagerFactory:
    """Test KeyManagerFactory and its implementations."""

    @pytest.mark.asyncio
    async def test_default_key_manager_factory(self):
        """Test DefaultKeyManager factory creates correct instance."""
        config = DefaultKeyManagerConfig()

        # Need to provide crypto provider for key manager
        from naylence.fame.security.crypto.providers.crypto_provider import (
            get_crypto_provider,
        )

        crypto_provider = get_crypto_provider()

        manager = await create_resource(KeyManagerFactory, config, crypto=crypto_provider)

        assert isinstance(manager, DefaultKeyManager)
        assert manager.__class__.__name__ == "DefaultKeyManager"

    @pytest.mark.asyncio
    async def test_key_manager_factory_from_dict(self):
        """Test factory with dictionary configuration."""
        config = {"type": "DefaultKeyManager"}

        from naylence.fame.security.crypto.providers.crypto_provider import (
            get_crypto_provider,
        )

        crypto_provider = get_crypto_provider()

        manager = await create_resource(KeyManagerFactory, config, crypto=crypto_provider)

        assert isinstance(manager, DefaultKeyManager)

    @pytest.mark.asyncio
    async def test_key_manager_factory_with_node_context(self):
        """Test factory with node context configuration."""
        config = DefaultKeyManagerConfig(has_upstream=True, node_id="test-node-123")

        from naylence.fame.security.crypto.providers.crypto_provider import (
            get_crypto_provider,
        )

        crypto_provider = get_crypto_provider()

        manager = await create_resource(KeyManagerFactory, config, crypto=crypto_provider)

        assert isinstance(manager, DefaultKeyManager)

    @pytest.mark.asyncio
    async def test_key_manager_factory_invalid_type(self):
        """Test factory with invalid type raises error."""
        config = {"type": "InvalidKeyManager"}

        from naylence.fame.security.crypto.providers.crypto_provider import (
            get_crypto_provider,
        )

        crypto_provider = get_crypto_provider()

        with pytest.raises(Exception):
            await create_resource(KeyManagerFactory, config, crypto=crypto_provider)
