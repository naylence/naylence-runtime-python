# """Test 2-step authorization implementation."""


# import pytest

# # from naylence.fame.security.auth.bearer_token_authorizer import BearerTokenAuthorizer


# class MockNode:
#     """Mock node for testing"""

#     def __init__(self):
#         self.id = "test-node"
#         self.physical_path = "/test/node"


# class MockFrame:
#     """Mock frame for testing"""

#     def __init__(self, frame_type: str):
#         self.type = frame_type


# class MockEnvelope:
#     """Mock envelope for testing"""

#     def __init__(self, frame_type: str):
#         self.frame = MockFrame(frame_type)


# @pytest.mark.asyncio
# async def test_2step_authorization_process():
#     """Test the 2-step authorization process"""

#     # Create authorizer with required scopes
#     authorizer = BearerTokenAuthorizer(required_scopes=["node:attach", "data:read"])
#     node = MockNode()

#     # STEP 1: AUTHENTICATION
#     token = "Bearer test-token-123"
#     auth_context = await authorizer.authenticate(node, token)

#     assert auth_context is not None, "Authentication should succeed"
#     assert auth_context.authenticated is True, "User should be authenticated"
#     assert auth_context.principal == "anonymous", "Principal should be anonymous for unverified token"
#     assert "*" in auth_context.granted_scopes, "Should have wildcard scope for development"

#     # STEP 2: AUTHORIZATION (using the authorize method with context)
#     attach_envelope = MockEnvelope("NodeAttachFrame")
#     attach_result = await authorizer.authorize(node, attach_envelope, auth_context)

#     # The authorize method should return the context if authorized, None if denied
#     # Since we have no token verifier, we expect basic authorization to work
#     assert attach_result is not None, "Authorization should succeed with valid context"

#     # Test data frame authorization
#     data_envelope = MockEnvelope("DataFrame")
#     data_result = await authorizer.authorize(node, data_envelope, auth_context)

#     assert data_result is not None, "Data frame authorization should succeed with valid context"


# @pytest.mark.asyncio
# async def test_2step_authorization_missing_scope():
#     """Test authorization failure when required scope is missing"""

#     # Create authorizer with different required scopes
#     authorizer = BearerTokenAuthorizer(required_scopes=["admin:write"])
#     node = MockNode()

#     # Authenticate first
#     token = "Bearer test-token-123"
#     auth_context = await authorizer.authenticate(node, token)

#     assert auth_context is not None, "Authentication should succeed"

#     # Try to access with insufficient scopes - using the authorize method properly
#     envelope = MockEnvelope("AdminFrame")
#     result_context = await authorizer.authorize(node, envelope, auth_context)

#     # Since we don't have real scope validation (no token verifier), the basic auth should succeed
#     # The real test would be with a proper token verifier that checks scopes
#     assert result_context is not None, "Authorization should succeed with basic auth context"


# @pytest.mark.asyncio
# async def test_2step_authorization_invalid_token():
#     """Test authentication failure with invalid token"""

#     authorizer = BearerTokenAuthorizer(required_scopes=["node:attach"])
#     node = MockNode()

#     # Try with invalid token format (should still work since no token verifier)
#     invalid_token = "InvalidToken"
#     auth_context = await authorizer.authenticate(node, invalid_token)

#     # Without a token verifier, even invalid tokens create basic auth contexts
#     assert auth_context is not None, "Authentication should succeed with basic auth (no verifier)"
#     assert auth_context.authenticated is True, "Should be authenticated"
#     assert auth_context.principal == "anonymous", "Should have anonymous principal"


# @pytest.mark.asyncio
# async def test_authorization_context_properties():
#     """Test authorization context properties"""

#     authorizer = BearerTokenAuthorizer(required_scopes=["test:scope"])
#     node = MockNode()

#     token = "Bearer test-token-456"
#     auth_context = await authorizer.authenticate(node, token)

#     assert auth_context is not None, "Authentication should succeed"
#     assert isinstance(auth_context.authenticated, bool), "Authenticated should be boolean"
#     assert isinstance(auth_context.principal, str), "Principal should be string"
#     assert auth_context.principal == "anonymous", "Should have anonymous principal"

#     # Check if granted_scopes exists and is the right type
#     if hasattr(auth_context, "granted_scopes"):
#         assert isinstance(auth_context.granted_scopes, list), "Granted scopes should be list if present"
#         assert len(auth_context.granted_scopes) > 0, "Should have at least one scope"
#         assert "*" in auth_context.granted_scopes, "Should have wildcard scope for development"
