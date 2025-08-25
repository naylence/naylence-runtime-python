from __future__ import annotations

from typing import Optional

from pydantic import ConfigDict, Field
from pydantic.alias_generators import to_camel

from naylence.fame.core.util.resource_config import ResourceConfig


class TransportListenerConfig(ResourceConfig):
    """Base configuration for transport listeners."""

    host: str = "0.0.0.0"
    port: int = 0  # Let OS choose port

    # Optional authorizer configuration for this listener
    authorizer: Optional[dict] = Field(
        default=None,
        description="Authorizer configuration for this listener. If not provided, "
        "falls back to the node's security manager authorizer.",
    )

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True, extra="ignore")
