from __future__ import annotations

from typing import Any, Dict, Optional, Union

from naylence.fame.security.keys.attachment_key_validator import AttachmentKeyValidator
from naylence.fame.security.keys.attachment_key_validator_factory import (
    AttachmentKeyValidatorConfig,
    AttachmentKeyValidatorFactory,
)


class NoopKeyValidatorConfig(AttachmentKeyValidatorConfig):
    """Configuration for no-op attachment key validator."""

    type: str = "NoopKeyValidator"


class NoopKeyValidatorFactory(AttachmentKeyValidatorFactory[NoopKeyValidatorConfig]):
    """Factory for creating certificate-based attachment key validators."""

    type = "AttachmentCertValidator"
    is_default: bool = True
    priority: int = 0

    async def create(
        self, config: Optional[Union[NoopKeyValidatorConfig, Dict[str, Any]]] = None, **kwargs
    ) -> AttachmentKeyValidator:
        from naylence.fame.security.keys.noop_key_validator import NoopKeyValidator

        return NoopKeyValidator()
