from unittest.mock import AsyncMock, patch

import base64
import json
import pytest

from naylence.fame.security.auth.oauth2_client_credentials_token_provider import (
    OAuth2ClientCredentialsTokenProvider,
)
from naylence.fame.security.auth.token import Token
from naylence.fame.security.credential import StaticCredentialProvider


def create_jwt(payload: dict) -> str:
    """Create a minimal JWT token for testing."""
    header = {"alg": "HS256", "typ": "JWT"}

    def encode_segment(data: dict) -> str:
        json_bytes = json.dumps(data).encode("utf-8")
        b64 = base64.urlsafe_b64encode(json_bytes).decode("utf-8")
        return b64.rstrip("=")

    return f"{encode_segment(header)}.{encode_segment(payload)}.signature"


class TestOAuth2ClientCredentialsTokenProvider:
    """Test OAuth2 client credentials token provider."""

    @pytest.fixture
    def client_id_provider(self):
        """Create a credential provider with OAuth2 client ID."""
        return StaticCredentialProvider("test-client-id")

    @pytest.fixture
    def client_secret_provider(self):
        """Create a credential provider with OAuth2 client secret."""
        return StaticCredentialProvider("test-client-secret")

    @pytest.fixture
    def token_provider(self, client_id_provider, client_secret_provider):
        """Create an OAuth2 token provider."""
        return OAuth2ClientCredentialsTokenProvider(
            token_url="https://auth.example.com/oauth/token",
            client_id_provider=client_id_provider,
            client_secret_provider=client_secret_provider,
            scopes=["node.connect"],
        )

    @pytest.mark.asyncio
    async def test_successful_token_request(self, token_provider):
        """Test successful OAuth2 token request."""
        mock_response_data = {
            "access_token": "test-access-token",
            "token_type": "Bearer",
            "expires_in": 3600,
        }

        with patch("aiohttp.ClientSession.post") as mock_post:
            # Mock the response
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value=mock_response_data)
            mock_post.return_value.__aenter__.return_value = mock_response

            token = await token_provider.get_token()

            assert isinstance(token, Token)
            assert token.value == "test-access-token"
            assert token.expires_at is not None

            # Verify the request was made correctly
            mock_post.assert_called_once()
            call_args = mock_post.call_args
            assert call_args[0][0] == "https://auth.example.com/oauth/token"
            assert call_args[1]["data"]["grant_type"] == "client_credentials"
            assert call_args[1]["data"]["client_id"] == "test-client-id"
            assert call_args[1]["data"]["client_secret"] == "test-client-secret"
            assert call_args[1]["data"]["scope"] == "node.connect"

    @pytest.mark.asyncio
    async def test_token_caching(self, token_provider):
        """Test that tokens are cached and reused."""
        mock_response_data = {
            "access_token": "cached-token",
            "token_type": "Bearer",
            "expires_in": 3600,
        }

        with patch("aiohttp.ClientSession.post") as mock_post:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value=mock_response_data)
            mock_post.return_value.__aenter__.return_value = mock_response

            # First call should make HTTP request
            token1 = await token_provider.get_token()
            assert isinstance(token1, Token)
            assert token1.value == "cached-token"
            assert mock_post.call_count == 1

            # Second call should use cached token
            token2 = await token_provider.get_token()
            assert isinstance(token2, Token)
            assert token2.value == "cached-token"
            assert mock_post.call_count == 1  # Still only 1 call

    @pytest.mark.asyncio
    async def test_token_error_response(self, token_provider):
        """Test handling of OAuth2 error responses."""
        with patch("aiohttp.ClientSession.post") as mock_post:
            mock_response = AsyncMock()
            mock_response.status = 400
            mock_response.text = AsyncMock(return_value="invalid_client")
            mock_post.return_value.__aenter__.return_value = mock_response

            with pytest.raises(ValueError, match="OAuth2 token request failed"):
                await token_provider.get_token()

    @pytest.mark.asyncio
    async def test_missing_client_secret(self):
        """Test error when client secret is not available."""
        client_id_provider = StaticCredentialProvider("test-client-id")
        empty_secret_provider = StaticCredentialProvider("")  # Empty credential

        token_provider = OAuth2ClientCredentialsTokenProvider(
            token_url="https://auth.example.com/oauth/token",
            client_id_provider=client_id_provider,
            client_secret_provider=empty_secret_provider,
        )

        with pytest.raises(ValueError, match="Client secret not available"):
            await token_provider.get_token()

    @pytest.mark.asyncio
    async def test_multiple_scopes(self, client_id_provider, client_secret_provider):
        """Test requesting multiple OAuth2 scopes."""
        token_provider = OAuth2ClientCredentialsTokenProvider(
            token_url="https://auth.example.com/oauth/token",
            client_id_provider=client_id_provider,
            client_secret_provider=client_secret_provider,
            scopes=["node.connect", "node.read", "node.write"],
        )

        mock_response_data = {
            "access_token": "multi-scope-token",
            "expires_in": 3600,
        }

        with patch("aiohttp.ClientSession.post") as mock_post:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value=mock_response_data)
            mock_post.return_value.__aenter__.return_value = mock_response

            await token_provider.get_token()

            # Verify scopes were sent correctly
            call_args = mock_post.call_args
            assert call_args[1]["data"]["scope"] == "node.connect node.read node.write"


class TestOAuth2ClientCredentialsTokenProviderIdentity:
    """Test get_identity method for OAuth2 client credentials token provider."""

    @pytest.fixture
    def client_id_provider(self):
        """Create a credential provider with OAuth2 client ID."""
        return StaticCredentialProvider("test-client-id")

    @pytest.fixture
    def client_secret_provider(self):
        """Create a credential provider with OAuth2 client secret."""
        return StaticCredentialProvider("test-client-secret")

    @pytest.fixture
    def token_provider(self, client_id_provider, client_secret_provider):
        """Create an OAuth2 token provider."""
        return OAuth2ClientCredentialsTokenProvider(
            token_url="https://auth.example.com/oauth/token",
            client_id_provider=client_id_provider,
            client_secret_provider=client_secret_provider,
            scopes=["node.connect"],
        )

    @pytest.mark.asyncio
    async def test_extracts_subject_from_valid_jwt(self, token_provider):
        """Test extraction of subject from valid JWT token."""
        jwt_token = create_jwt({"sub": "user-123", "aud": "test-audience"})
        mock_response_data = {
            "access_token": jwt_token,
            "token_type": "Bearer",
            "expires_in": 3600,
        }

        with patch("aiohttp.ClientSession.post") as mock_post:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value=mock_response_data)
            mock_post.return_value.__aenter__.return_value = mock_response

            identity = await token_provider.get_identity()

            assert identity is not None
            assert identity.subject == "user-123"
            assert identity.claims["sub"] == "user-123"
            assert identity.claims["aud"] == "test-audience"

    @pytest.mark.asyncio
    async def test_returns_none_for_non_jwt_token(self, token_provider):
        """Test that non-JWT tokens return None."""
        mock_response_data = {
            "access_token": "opaque-token-value",
            "token_type": "Bearer",
            "expires_in": 3600,
        }

        with patch("aiohttp.ClientSession.post") as mock_post:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value=mock_response_data)
            mock_post.return_value.__aenter__.return_value = mock_response

            identity = await token_provider.get_identity()

            assert identity is None

    @pytest.mark.asyncio
    async def test_returns_none_when_jwt_has_no_sub_claim(self, token_provider):
        """Test that JWTs without sub claim return None."""
        jwt_token = create_jwt({"aud": "test-audience", "iss": "issuer"})
        mock_response_data = {
            "access_token": jwt_token,
            "token_type": "Bearer",
            "expires_in": 3600,
        }

        with patch("aiohttp.ClientSession.post") as mock_post:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value=mock_response_data)
            mock_post.return_value.__aenter__.return_value = mock_response

            identity = await token_provider.get_identity()

            assert identity is None

    @pytest.mark.asyncio
    async def test_returns_none_for_malformed_jwt(self, token_provider):
        """Test that malformed JWTs return None."""
        mock_response_data = {
            "access_token": "header.invalid-base64.signature",
            "token_type": "Bearer",
            "expires_in": 3600,
        }

        with patch("aiohttp.ClientSession.post") as mock_post:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value=mock_response_data)
            mock_post.return_value.__aenter__.return_value = mock_response

            identity = await token_provider.get_identity()

            assert identity is None
