from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel

# Some well-known grant purposes
GRANT_PURPOSE_NODE_ATTACH = "node.attach"


class Grant(BaseModel):
    """
    Base class for connection grants.

    A connection grant represents a permission to establish a connection
    with specific configuration parameters. It's returned by the NodeWelcomeFrame
    and used to create connectors for establishing connections.
    """

    type: str = Field(description="Type of grant")
    purpose: str = Field(description="Purpose of the grant (e.g., 'node.attach')")

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True, extra="ignore")
