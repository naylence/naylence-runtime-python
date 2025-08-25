"""
Test SecurityManagerFactory integration.
"""

import pytest

from naylence.fame.security.default_security_manager_factory import (
    DefaultSecurityManagerConfig,
    DefaultSecurityManagerFactory,
)


@pytest.mark.asyncio
async def test_default_security_manager_factory():
    """Test DefaultSecurityManagerFactory creates correct instance."""
    factory = DefaultSecurityManagerFactory()
    config = DefaultSecurityManagerConfig()

    security_manager = await factory.create(config)

    assert security_manager is not None
    assert hasattr(security_manager, "policy")
    assert hasattr(security_manager, "envelope_signer")
    assert hasattr(security_manager, "envelope_verifier")
    assert hasattr(security_manager, "encryption")
    assert hasattr(security_manager, "authorizer")


@pytest.mark.asyncio
async def test_security_manager_factory_with_kwargs():
    """Test that factories accept runtime kwargs."""
    factory = DefaultSecurityManagerFactory()
    config = DefaultSecurityManagerConfig()

    # Test with authorizer kwarg (as used by sentinel)
    from naylence.fame.security.auth.default_authorizer import DefaultAuthorizer
    from naylence.fame.security.auth.noop_token_verifier import NoopTokenVerifier

    token_verifier = NoopTokenVerifier()
    authorizer = DefaultAuthorizer(token_verifier=token_verifier)

    security_manager = await factory.create(config, authorizer=authorizer)

    assert security_manager is not None
    assert security_manager.authorizer is authorizer


if __name__ == "__main__":
    pytest.main([__file__])
