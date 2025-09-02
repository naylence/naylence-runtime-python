from typing import Optional

from pydantic import Field

from naylence.fame.factory import ResourceConfig


class SecurityManagerConfig(ResourceConfig):
    """Security configuration for a node."""

    type: str = "SecurityManager"


class SecurityProfile(SecurityManagerConfig):
    """Security configuration for a node."""

    type: str = "SecurityProfile"
    profile: Optional[str] = Field(default=None, description="Security profile name")
