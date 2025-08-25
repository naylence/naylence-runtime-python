from pydantic import ConfigDict
from pydantic.alias_generators import to_camel

from naylence.fame.factory import ResourceConfig


class HttpServerConfig(ResourceConfig):
    """Base configuration for HTTP servers."""

    type: str = "DefaultHttpServer"
    host: str = "0.0.0.0"
    port: int = 0  # Let OS choose port

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True, extra="ignore")
