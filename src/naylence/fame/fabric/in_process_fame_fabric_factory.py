from typing import Any, Optional

from naylence.fame.core import (
    FameConfig,
    FameFabric,
    FameFabricConfig,
    FameFabricFactory,
)
from naylence.fame.fabric.in_process_fame_fabric import InProcessFameFabric


class InProcessFameFabricFactory(FameFabricFactory):
    is_default: bool = True

    async def create(
        self,
        config: Optional[FameFabricConfig | dict[str, Any]] = None,
        root_config: FameConfig | None = None,
        **kwargs: Any,
    ) -> FameFabric:
        return InProcessFameFabric(config=root_config)
