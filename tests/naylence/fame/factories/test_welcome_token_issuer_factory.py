"""Test TokenIssuerFactory to ensure configs resolve to correct subtypes."""

import pytest

from naylence.fame.factory import create_resource
from naylence.fame.security.auth.jwt_token_issuer import JWTTokenIssuer
from naylence.fame.security.auth.jwt_token_issuer_factory import JWTTokenIssuerConfig
from naylence.fame.security.auth.noop_token_issuer import NoopTokenIssuer
from naylence.fame.security.auth.token_issuer_factory import TokenIssuerFactory


class TestTokenIssuerFactory:
    """Test TokenIssuerFactory and its implementations."""

    @pytest.mark.asyncio
    async def test_noop_token_issuer_factory(self):
        """Test NoopTokenIssuer factory creates correct instance."""
        config = {"type": "NoopTokenIssuer"}
        issuer = await create_resource(TokenIssuerFactory, config)

        assert isinstance(issuer, NoopTokenIssuer)
        assert issuer.__class__.__name__ == "NoopTokenIssuer"

    @pytest.mark.asyncio
    async def test_jwt_token_issuer_factory(self):
        """Test JWTTokenIssuer factory creates correct instance."""
        config = JWTTokenIssuerConfig(kid="test-key-id", issuer="test-issuer", ttl_sec=3600)
        issuer = await create_resource(TokenIssuerFactory, config)

        assert isinstance(issuer, JWTTokenIssuer)
        assert issuer.__class__.__name__ == "JWTTokenIssuer"

    @pytest.mark.asyncio
    async def test_token_issuer_factory_from_dict(self):
        """Test factory with dictionary configuration."""
        config = {"type": "NoopTokenIssuer"}
        issuer = await create_resource(TokenIssuerFactory, config)

        assert isinstance(issuer, NoopTokenIssuer)

    @pytest.mark.asyncio
    async def test_jwt_token_issuer_factory_from_dict(self):
        """Test JWT factory with dictionary configuration."""
        config = {
            "type": "JWTTokenIssuer",
            "kid": "dict-key-id",
            "issuer": "dict-issuer",
            "ttl_sec": 1800,
        }
        issuer = await create_resource(TokenIssuerFactory, config)

        assert isinstance(issuer, JWTTokenIssuer)

    @pytest.mark.asyncio
    async def test_token_issuer_factory_invalid_type(self):
        """Test factory with invalid type raises error."""
        config = {"type": "InvalidTokenIssuer"}

        with pytest.raises(Exception):
            await create_resource(TokenIssuerFactory, config)
