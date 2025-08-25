"""Test NodeAttachAuthorizerFactory to ensure configs resolve to correct subtypes."""

import pytest

from naylence.fame.core import create_resource
from naylence.fame.security.auth.authorizer_factory import AuthorizerFactory
from naylence.fame.security.auth.default_authorizer import DefaultAuthorizer
from naylence.fame.security.auth.default_authorizer_factory import (
    DefaultAuthorizerConfig,
)
from naylence.fame.security.auth.jwks_jwt_token_verifier_factory import (
    JWKSVerifierConfig,
)
from naylence.fame.security.auth.noop_authorizer import NoopAuthorizer
from naylence.fame.security.auth.noop_authorizer_factory import NoopAuthorizerConfig
from naylence.fame.security.auth.noop_token_verifier_factory import (
    NoopTokenVerifierConfig,
)
from naylence.fame.security.auth.oauth2_authorizer import OAuth2Authorizer
from naylence.fame.security.auth.oauth2_authorizer_factory import (
    OAuth2AuthorizerConfig,
)
from naylence.fame.security.auth.shared_secret_authorizer import (
    SharedSecretAuthorizer,
)
from naylence.fame.security.auth.shared_secret_authorizer_factory import (
    SharedSecretAuthorizerConfig,
)
from naylence.fame.security.credential.credential_provider_factory import (
    StaticCredentialProviderConfig,
)


class TestNodeAttachAuthorizerFactory:
    """Test NodeAttachAuthorizerFactory and its implementations."""

    @pytest.mark.asyncio
    async def test_default_node_attach_authorizer_factory(self):
        """Test DefaultAuthorizer factory creates correct instance."""
        config = DefaultAuthorizerConfig(verifier=NoopTokenVerifierConfig())
        authorizer = await create_resource(AuthorizerFactory, config)

        assert isinstance(authorizer, DefaultAuthorizer)
        assert authorizer.__class__.__name__ == "DefaultAuthorizer"

    @pytest.mark.asyncio
    async def test_noop_node_attach_authorizer_factory(self):
        """Test NoopAuthorizer factory creates correct instance."""
        config = NoopAuthorizerConfig()
        authorizer = await create_resource(AuthorizerFactory, config)

        assert isinstance(authorizer, NoopAuthorizer)
        assert authorizer.__class__.__name__ == "NoopAuthorizer"

    @pytest.mark.asyncio
    async def test_shared_secret_node_attach_authorizer_factory(self):
        """Test SharedSecretAuthorizer factory creates correct instance."""
        config = SharedSecretAuthorizerConfig(
            secret=StaticCredentialProviderConfig(credential_value="test-secret")
        )
        authorizer = await create_resource(AuthorizerFactory, config)

        assert isinstance(authorizer, SharedSecretAuthorizer)
        assert authorizer.__class__.__name__ == "SharedSecretAuthorizer"

    @pytest.mark.asyncio
    async def test_oauth2_node_attach_authorizer_factory(self):
        """Test OAuth2Authorizer factory creates correct instance."""
        config = OAuth2AuthorizerConfig(
            issuer="test-issuer",
            verifier_config=JWKSVerifierConfig(
                issuer="test-issuer",
                jwks_url="https://example.com/.well-known/jwks.json",
                allowed_algorithms=["RS256"],
                audience="test-audience",
            ),
            required_scopes=["node.connect"],
        )
        authorizer = await create_resource(AuthorizerFactory, config)

        assert isinstance(authorizer, OAuth2Authorizer)
        assert authorizer.__class__.__name__ == "OAuth2Authorizer"

    @pytest.mark.asyncio
    async def test_node_attach_authorizer_factory_from_dict(self):
        """Test factory with dictionary configuration."""
        config = {"type": "NoopAuthorizer"}
        authorizer = await create_resource(AuthorizerFactory, config)

        assert isinstance(authorizer, NoopAuthorizer)

    @pytest.mark.asyncio
    async def test_shared_secret_authorizer_factory_from_dict(self):
        """Test SharedSecret factory with dictionary configuration."""
        config = {
            "type": "SharedSecretAuthorizer",
            "secret": {
                "type": "StaticCredentialProvider",
                "credential_value": "dict-secret",
            },
        }
        authorizer = await create_resource(AuthorizerFactory, config)

        assert isinstance(authorizer, SharedSecretAuthorizer)

    @pytest.mark.asyncio
    async def test_node_attach_authorizer_factory_invalid_type(self):
        """Test factory with invalid type raises error."""
        config = {"type": "InvalidNodeAttachAuthorizer"}

        with pytest.raises(Exception):
            await create_resource(AuthorizerFactory, config)
