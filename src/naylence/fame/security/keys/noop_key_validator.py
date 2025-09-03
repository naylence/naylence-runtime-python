from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from naylence.fame.security.keys.attachment_key_validator import (
    AttachmentKeyValidator,
    KeyInfo,
)
from naylence.fame.util.logging import getLogger

logger = getLogger(__name__)


class NoopKeyValidator(AttachmentKeyValidator):
    def __init__(
        self,
    ):
        logger.debug("noop_key_validator_initialized")

    async def validate_key(self, key: Dict[str, Any]) -> KeyInfo:
        return KeyInfo()

    async def validate_child_attachment_logicals(
        self,
        child_keys: Optional[List[Dict[str, Any]]],
        authorized_logicals: Optional[List[str]],
        child_id: str,
    ) -> Tuple[bool, str]:
        return True, "Noop validator always authorizes logicals"
