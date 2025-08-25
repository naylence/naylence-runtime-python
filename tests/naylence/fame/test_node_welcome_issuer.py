import pytest

from naylence.fame.core import NodeAttachFrame, create_fame_envelope
from naylence.fame.node.node_context import FameNodeAuthorizationContext
from naylence.fame.security.auth.default_authorizer import DefaultAuthorizer
from naylence.fame.security.auth.jwt_token_issuer import JWTTokenIssuer
from naylence.fame.security.auth.token_issuer import TokenIssuer
from naylence.fame.security.crypto.providers.default_crypto_provider import DefaultCryptoProvider


class MockNodeLike:
    """Mock NodeLike object for testing"""

    def __init__(self, node_id: str = "test-node", physical_path: str = "/test/system/path"):
        self._id = node_id
        self._physical_path = physical_path

    @property
    def id(self) -> str:
        return self._id

    @property
    def physical_path(self) -> str:
        return self._physical_path


# ——— defaults for both token and request ———
DEFAULT_SYSTEM_ID = "agent-xyz"
DEFAULT_PARENT_PATH = "/root/router-abc"
DEFAULT_INSTANCE_ID = "instance-1"
DEFAULT_CAPABILITIES = ["cap1", "cap2"]
DEFAULT_ASSIGNED_PATH = "/root/router-abc/agent-xyz"
DEFAULT_LOGICAL_PATHS = ["foo.agents"]

TOKEN_ARGS = {
    "system_id": DEFAULT_SYSTEM_ID,
    "parent_path": DEFAULT_PARENT_PATH,
    "instance_id": DEFAULT_INSTANCE_ID,
    "accepted_capabilities": DEFAULT_CAPABILITIES,
    "assigned_path": DEFAULT_ASSIGNED_PATH,
    "accepted_logicals": DEFAULT_LOGICAL_PATHS,
}

REQUEST_BASE = {
    "system_id": DEFAULT_SYSTEM_ID,
    "instance_id": DEFAULT_INSTANCE_ID,
    "capabilities": DEFAULT_CAPABILITIES,
    "assigned_path": DEFAULT_ASSIGNED_PATH,
    "accepted_logicals": DEFAULT_LOGICAL_PATHS,
}


@pytest.fixture
def crypto_provider():
    return DefaultCryptoProvider()


@pytest.fixture
def issuer(crypto_provider):
    return JWTTokenIssuer(
        kid="dev",
        signing_key_pem=crypto_provider.signing_private_pem,
        issuer=crypto_provider.issuer,
        ttl_sec=600,
    )


@pytest.fixture
def authorizer(crypto_provider):
    return DefaultAuthorizer(crypto_provider.get_token_verifier())


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "auth_target, request_overrides, expected",
    [
        # happy path
        (DEFAULT_PARENT_PATH, {}, True),
        # wrong system_id on the Frame
        (DEFAULT_PARENT_PATH, {"system_id": "no-match"}, False),
        # wrong target_system_id passed to authorize()
        ("no-match", {}, False),
        # wrong instance_id
        (DEFAULT_PARENT_PATH, {"instance_id": "no-match"}, False),
        # wrong assigned_path
        (DEFAULT_PARENT_PATH, {"assigned_path": "/mismatch"}, False),
        # wrong capabilities
        (DEFAULT_PARENT_PATH, {"capabilities": ["unexpected-cap"]}, False),
        # wrong logicals
        (DEFAULT_PARENT_PATH, {"accepted_logicals": ["wrong.path"]}, False),
    ],
    ids=[
        "valid",
        "mismatch_system_id",
        "mismatch_target_system_id",
        "mismatch_instance_id",
        "mismatch_assigned_path",
        "mismatch_capabilities",
        "mismatch_logicals",
    ],
)
async def test_node_attach_authorization(
    issuer: TokenIssuer,
    authorizer: DefaultAuthorizer,
    auth_target: str,
    request_overrides: dict,
    expected: bool,
):
    # 1) issue a token with the *default* good values converted to claims format
    claims = {
        "sub": TOKEN_ARGS["system_id"],
        "aud": TOKEN_ARGS["parent_path"],
        "instance_id": TOKEN_ARGS["instance_id"],
        "assigned_path": TOKEN_ARGS["assigned_path"],
        "accepted_capabilities": TOKEN_ARGS["accepted_capabilities"],
        "accepted_logicals": TOKEN_ARGS["accepted_logicals"],
    }
    token = issuer.issue(claims)

    # 2) build the Frame by merging in any per-scenario tweaks (no longer includes attach_token)
    frame_kwargs = {**REQUEST_BASE, **request_overrides}
    request = NodeAttachFrame(**frame_kwargs)

    # 3) create a mock node with the target system ID
    target_node = MockNodeLike(node_id=auth_target, physical_path=auth_target)

    # 4) create auth context from token (simulating wire-level authentication)
    # For DefaultAuthorizer, we need to verify the token and create auth context
    # Always verify against the original parent_path the token was issued for
    raw_claims = await authorizer._token_verifier.verify(
        token,
        expected_audience=DEFAULT_PARENT_PATH,  # Use the parent_path the token was issued for
    )
    auth_context = FameNodeAuthorizationContext.model_validate(raw_claims, by_alias=True)
    # Mark as authenticated since this simulates successful wire-level authentication
    auth_context.authenticated = True

    # 5) do the one authorize() call and check True/False
    # Create proper delivery context with the authorization context
    from naylence.fame.node.node_context import create_node_delivery_context

    delivery_context = create_node_delivery_context(authorization=auth_context)

    # Wrap the request frame in an envelope for the authorize method
    envelope = create_fame_envelope(frame=request)

    try:
        result = await authorizer.authorize(
            target_node,
            envelope,
            delivery_context,
        )
    except ValueError:
        # Authorization failures are thrown as ValueError exceptions
        # Convert them to failed authorization (False)
        result = None

    # pytest will show you both expected and actual on failure.
    assert bool(result) == expected
