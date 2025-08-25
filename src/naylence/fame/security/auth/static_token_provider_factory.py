"""
Factory for StaticTokenProvider.
"""

from datetime import datetime
from typing import Any, Optional

from pydantic import ConfigDict, Field, field_serializer
from pydantic.alias_generators import to_camel

from naylence.fame.security.auth.static_token_provider import StaticTokenProvider
from naylence.fame.security.auth.token_provider import TokenProvider
from naylence.fame.security.auth.token_provider_factory import (
    TokenProviderConfig,
    TokenProviderFactory,
)


class StaticTokenProviderConfig(TokenProviderConfig):
    """Configuration for StaticTokenProvider."""

    type: str = "StaticTokenProvider"
    token: str = Field(description="The static token value")
    expires_at: Optional[datetime] = Field(default=None, description="Optional expiration time")

    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        extra="allow",
        arbitrary_types_allowed=True,  # Allow TokenProvider protocol
    )

    @field_serializer("expires_at")
    def serialize_dt(self, dt: datetime, _info):
        return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")


class StaticTokenProviderFactory(TokenProviderFactory):
    async def create(
        self,
        config: Optional[StaticTokenProviderConfig | dict[str, Any]] = None,
        **kwargs: Any,
    ) -> TokenProvider:
        if isinstance(config, dict):
            config = StaticTokenProviderConfig(**config)

        if not config:
            raise ValueError("StaticTokenProvider requires configuration")

        return StaticTokenProvider(token=config.token, expires_at=config.expires_at)
