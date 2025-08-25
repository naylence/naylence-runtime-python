from typing import Any, Optional

from naylence.fame.security.auth.token_verifier import TokenVerifier
from naylence.fame.security.auth.token_verifier_factory import (
    TokenVerifierConfig,
    TokenVerifierFactory,
)


class NoopTokenVerifierConfig(TokenVerifierConfig):
    type: str = "NoopTokenVerifier"


class NoopTokenVerifierFactory(TokenVerifierFactory):
    async def create(
        self,
        config: Optional[TokenVerifierConfig | dict[str, Any]] = None,
        **kwargs: Any,
    ) -> TokenVerifier:
        from naylence.fame.security.auth.noop_token_verifier import NoopTokenVerifier

        return NoopTokenVerifier()
