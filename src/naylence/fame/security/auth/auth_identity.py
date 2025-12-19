"""
Authentication identity model.

This module provides the AuthIdentity model that represents an authenticated
identity extracted from tokens or other authentication sources.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel


class AuthIdentity(BaseModel):
    """
    Represents an authenticated identity.

    This model encapsulates identity information typically extracted from
    authentication tokens (JWT subject, claims, etc.).
    """

    subject: Optional[str] = Field(
        default=None,
        description="The subject identifier (typically 'sub' claim from JWT)",
    )
    claims: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional claims from the authentication source",
    )

    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        extra="allow",
    )
