from typing import Any, Optional

from naylence.fame.security.auth.noop_token_issuer import NoopTokenIssuer
from naylence.fame.security.auth.token_issuer import TokenIssuer
from naylence.fame.security.auth.token_issuer_factory import (
    TokenIssuerConfig,
    TokenIssuerFactory,
)


class NoopTokenIssuerConfig(TokenIssuerConfig):
    type: str = "NoopTokenIssuer"


class NoopTokenIssuerFactory(TokenIssuerFactory):
    async def create(
        self,
        config: Optional[NoopTokenIssuerConfig | dict[str, Any]] = None,
        **kwargs: Any,
    ) -> TokenIssuer:
        return NoopTokenIssuer()
