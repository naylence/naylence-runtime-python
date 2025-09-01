#!/usr/bin/env python3
"""
Test script to verify polymorphic Auth deserialization works correctly.
Note: This test is deprecated as the auth system was refactored to use injection strategies.
"""

# DEPRECATED: This test was for the old Auth system which was replaced
# with the new AuthInjectionStrategy system. Keeping for reference but disabled.

# import asyncio
# from naylence.fame.core import create_resource
# from naylence.fame.security.auth.auth_injection_strategy_factory import AuthInjectionStrategyFactory
# from naylence.fame.connector.connector_config import (
#     BearerTokenHeaderAuth,
#     WebSocketSubprotocolAuth,
#     QueryParamAuth,
#     NoAuth
# )


# async def test_polymorphic_auth_deserialization():
# """Test that polymorphic auth deserialization works through factory system."""

# print("🧪 Testing polymorphic Auth deserialization...")

# Test BearerTokenHeaderAuth
# config = {
#     "type": "BearerTokenHeaderAuth",
#     "token": "test-token",
#     "param": "X-Custom-Auth"
# }
# auth = await create_resource(AuthInjectionStrategyFactory, config)
# assert isinstance(auth, BearerTokenHeaderAuth)
# assert auth.token == "test-token"
# assert auth.header_name == "X-Custom-Auth"
# print("✅ BearerTokenHeaderAuth polymorphic deserialization works")

# Test WebSocketSubprotocolAuth
# config = {
#     "type": "WebSocketSubprotocolAuth",
#     "token": "ws-token",
#     "param": "custom-bearer"
# }
# auth = await create_resource(AuthInjectionStrategyFactory, config)
# assert isinstance(auth, WebSocketSubprotocolAuth)
# assert auth.token == "ws-token"
# assert auth.subprotocol_prefix == "custom-bearer"
# print("✅ WebSocketSubprotocolAuth polymorphic deserialization works")

# Test QueryParamAuth
# config = {
#     "type": "QueryParamAuth",
#     "token": "query-token",
#     "param": "access_token"
# }
# auth = await create_resource(AuthInjectionStrategyFactory, config)
# assert isinstance(auth, QueryParamAuth)
# assert auth.token == "query-token"
# assert auth.param_name == "access_token"
# print("✅ QueryParamAuth polymorphic deserialization works")

# Test NoAuth
# config = {
#     "type": "NoAuth"
# }
# auth = await create_resource(AuthInjectionStrategyFactory, config)
# assert isinstance(auth, NoAuth)
# print("✅ NoAuth polymorphic deserialization works")

# print("🎉 All polymorphic Auth deserialization tests passed!")


# async def test_legacy_format_mapping():
# """Test that legacy format mapping works in connector factories."""

# print("\n🧪 Testing legacy format mapping...")

# from naylence.fame.connector.websocket_connector_factory import (
#     WebSocketConnectorFactory,
#     WebSocketConnectorConfig,
# )

# Test legacy subprotocol auth
# config = WebSocketConnectorConfig(
#     params={"url": "ws://example.com"},
#     auth={
#         "style": "subprotocol",
#         "token": "legacy-token",
#         "param": "legacy-bearer"
#     }
# )

# factory = WebSocketConnectorFactory()
# We can't easily test this without a real WebSocket connection,
# but we can verify the auth config is created properly

# print("✅ Legacy format mapping structure validated")

# print("🎉 All legacy format mapping tests passed!")


# DEPRECATED: This test file is disabled as the auth system was refactored.
# The old Auth system was replaced with AuthInjectionStrategy.

# if __name__ == "__main__":
# print("DEPRECATED: This test is disabled - auth system was refactored")
# pass
# asyncio.run(test_polymorphic_auth_deserialization())
# asyncio.run(test_legacy_format_mapping())
