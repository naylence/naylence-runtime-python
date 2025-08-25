from __future__ import annotations

from pydantic import ConfigDict, Field
from pydantic.alias_generators import to_camel

from naylence.fame.factory import ResourceConfig
from naylence.fame.security.auth.token_provider_factory import TokenProviderConfig


class ConnectorAuth(ResourceConfig):
    """Base class for connector authentication configurations."""

    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        extra="allow",
        arbitrary_types_allowed=True,  # Allow TokenProvider protocol
    )


class BearerTokenHeaderAuth(ConnectorAuth):
    """Bearer token authentication via HTTP Authorization header."""

    type: str = "BearerTokenHeaderAuth"
    token_provider: TokenProviderConfig = Field(description="Token provider for dynamic token acquisition")
    header_name: str = Field(default="Authorization", description="HTTP header name", alias="param")

    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        extra="allow",
        arbitrary_types_allowed=True,  # Allow TokenProvider protocol
    )

    def model_dump(self, **kwargs) -> dict:
        """Override to provide backward-compatible format."""
        super().model_dump(**kwargs)
        return {
            "scheme": "bearer",
            "token": "[DYNAMIC]",  # Placeholder - token is retrieved by auth strategy
            "style": "header",
            "param": self.header_name,
        }


class WebSocketSubprotocolAuth(ConnectorAuth):
    """Bearer token authentication via WebSocket subprotocol."""

    type: str = "WebSocketSubprotocolAuth"
    token_provider: TokenProviderConfig = Field(description="Token provider for dynamic token acquisition")
    subprotocol_prefix: str = Field(default="bearer", description="Subprotocol prefix", alias="param")

    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        extra="allow",
        arbitrary_types_allowed=True,  # Allow TokenProvider protocol
    )

    # def model_dump(self, **kwargs) -> dict:
    #     """Override to provide backward-compatible format."""
    #     super().model_dump(**kwargs)
    #     return {
    #         "scheme": "bearer",
    #         "token": "[DYNAMIC]",  # Placeholder - token is retrieved by auth strategy
    #         "style": "subprotocol",
    #         "param": self.subprotocol_prefix,
    #     }


class QueryParamAuth(ConnectorAuth):
    """Authentication via URL query parameter."""

    type: str = "QueryParamAuth"
    token_provider: TokenProviderConfig = Field(description="Token provider for dynamic token acquisition")
    param_name: str = Field(default="token", description="Query parameter name", alias="param")

    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        extra="allow",
        arbitrary_types_allowed=True,  # Allow TokenProvider protocol
    )

    def model_dump(self, **kwargs) -> dict:
        """Override to provide backward-compatible format."""
        super().model_dump(**kwargs)
        return {
            "scheme": "bearer",
            "token": "[DYNAMIC]",  # Placeholder - token is retrieved by auth strategy
            "style": "query",
            "param": self.param_name,
        }


class NoAuth(ConnectorAuth):
    """No authentication configuration."""

    type: str = "NoAuth"

    def model_dump(self, **kwargs) -> dict:
        """Override to provide backward-compatible format."""
        return {}
