from __future__ import annotations

from pydantic import ConfigDict

from naylence.fame.core import ResourceConfig


class WelcomeServiceConfig(ResourceConfig):
    model_config = ConfigDict(extra="allow")
    type: str = "WelcomeService"
