from typing import Any, Optional

from pydantic import BaseModel, Field


class PeerConfig(BaseModel):
    direct_url: Optional[str] = Field(default=None)
    admission: Optional[Any] = Field(default=None, description="Admission client config")
