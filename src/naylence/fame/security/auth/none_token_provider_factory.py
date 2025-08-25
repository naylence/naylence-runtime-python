from __future__ import annotations

from typing import Any, Optional

from naylence.fame.security.auth.token_provider import TokenProvider
from naylence.fame.security.auth.token_provider_factory import (
    TokenProviderConfig,
    TokenProviderFactory,
)


class NoneTokenProviderConfig(TokenProviderConfig):
    type: str = "NoneTokenProvider"


class NoneTokenProviderFactory(TokenProviderFactory):
    async def create(
        self,
        config: Optional[NoneTokenProviderConfig | dict[str, Any]] = None,
        **kwargs: Any,
    ) -> TokenProvider:
        from naylence.fame.security.auth.none_token_provider import NoneTokenProvider

        return NoneTokenProvider()
