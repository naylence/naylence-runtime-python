from unittest.mock import patch

import pytest

from naylence.fame.security.auth.jwt_token_verifier import JWTTokenVerifier


class TestJWTScopeValidation:
    """Test JWT token verifier scope validation."""

    @pytest.fixture
    def verifier_with_scopes(self):
        """Create a JWT verifier that requires specific scopes."""
        # Using a dummy key for testing
        public_key = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0vx7agoebGcQSuuPiLJX
ZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tS
oc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt
7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0
zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0f
M4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDK
gwIDAQAB
-----END PUBLIC KEY-----"""

        return JWTTokenVerifier(
            key=public_key,
            issuer="test-issuer",
            required_scopes=["node.connect", "node.read"],
        )

    @pytest.mark.asyncio
    async def test_valid_scopes_in_scope_claim(self, verifier_with_scopes):
        """Test that tokens with required scopes in 'scope' claim are accepted."""
        # Mock the JWT decode to return claims with required scopes
        mock_claims = {
            "sub": "test-subject",
            "aud": "test-audience",
            "iss": "test-issuer",
            "exp": 9999999999,  # Far future
            "nbf": 0,  # Past
            "scope": "node.connect node.read node.write",  # Space-separated
        }

        with patch("jwt.decode", return_value=mock_claims):
            claims = await verifier_with_scopes.verify("dummy-token")
            assert claims["scope"] == "node.connect node.read node.write"

    @pytest.mark.asyncio
    async def test_valid_scopes_in_scp_claim(self, verifier_with_scopes):
        """Test that tokens with required scopes in 'scp' claim are accepted."""
        mock_claims = {
            "sub": "test-subject",
            "aud": "test-audience",
            "iss": "test-issuer",
            "exp": 9999999999,
            "nbf": 0,
            "scp": ["node.connect", "node.read", "node.write"],  # Array format
        }

        with patch("jwt.decode", return_value=mock_claims):
            claims = await verifier_with_scopes.verify("dummy-token")
            assert claims["scp"] == ["node.connect", "node.read", "node.write"]

    @pytest.mark.asyncio
    async def test_missing_required_scopes(self, verifier_with_scopes):
        """Test that tokens missing required scopes are rejected."""
        mock_claims = {
            "sub": "test-subject",
            "aud": "test-audience",
            "iss": "test-issuer",
            "exp": 9999999999,
            "nbf": 0,
            "scope": "node.write",  # Missing required scopes
        }

        with patch("jwt.decode", return_value=mock_claims):
            with pytest.raises(ValueError, match="Token missing required scopes"):
                await verifier_with_scopes.verify("dummy-token")

    @pytest.mark.asyncio
    async def test_no_scope_claims(self, verifier_with_scopes):
        """Test that tokens without any scope claims are rejected."""
        mock_claims = {
            "sub": "test-subject",
            "aud": "test-audience",
            "iss": "test-issuer",
            "exp": 9999999999,
            "nbf": 0,
            # No scope or scp claim
        }

        with patch("jwt.decode", return_value=mock_claims):
            with pytest.raises(ValueError, match="Token missing required scopes"):
                await verifier_with_scopes.verify("dummy-token")

    @pytest.mark.asyncio
    async def test_no_required_scopes_configured(self):
        """Test that verifier without required scopes accepts any token."""
        public_key = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0vx7agoebGcQSuuPiLJX
ZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tS
oc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt
7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0
zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0f
M4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDK
gwIDAQAB
-----END PUBLIC KEY-----"""

        verifier = JWTTokenVerifier(
            key=public_key,
            issuer="test-issuer",
            # No required_scopes
        )

        mock_claims = {
            "sub": "test-subject",
            "aud": "test-audience",
            "iss": "test-issuer",
            "exp": 9999999999,
            "nbf": 0,
            # No scope claims, but that's OK since no scopes required
        }

        with patch("jwt.decode", return_value=mock_claims):
            claims = await verifier.verify("dummy-token")
            assert claims["sub"] == "test-subject"
