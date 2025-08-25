from functools import wraps
from types import MappingProxyType
from typing import Callable, Mapping, ParamSpec, TypeVar, overload

from naylence.fame.core import FameFabric, FameServiceProxy

P = ParamSpec("P")
R = TypeVar("R")


# --------------------------------------------------------------------------- #
#  Public decorator – usable as @rpc or @rpc(...)
# --------------------------------------------------------------------------- #
@overload  # ❶ @rpc       -> Decorated fn
def operation(  # noqa: D401
    __fn: Callable[P, R],
    /,
) -> Callable[P, R]: ...  # pragma: no cover


@overload  # ❷ @rpc(...)
def operation(  # noqa: D401
    *,
    name: str | None = None,
    streaming: bool = False,
) -> Callable[[Callable[P, R]], Callable[P, R]]: ...  # pragma: no cover


def operation(  # noqa: D401
    __fn: Callable[P, R] | None = None,
    /,
    *,
    name: str | None = None,
    streaming: bool = False,
):
    """
    Decorate an async method so the SDK exposes it as JSON-RPC.

    Can be used **both** as::

        @rpc
        async def ping(self): ...

    or::

        @rpc(name="fib.stream", streaming=True)
        async def fib(self, n): ...
    """

    def _decorator(fn: Callable[P, R]) -> Callable[P, R]:
        fn._rpc_name = name or fn.__name__  # type: ignore[attr-defined]
        fn._rpc_streaming = streaming  # type: ignore[attr-defined]
        return wraps(fn)(fn)

    # Bare form @rpc
    if __fn is not None and callable(__fn):
        return _decorator(__fn)

    # Called form @rpc(...)
    return _decorator


class RpcMixin:
    """
    Adds wiring for @rpc-decorated methods.

    After subclass creation, `cls._rpc_registry` contains:

        {
            "wire.method": (attr_name: str, streaming: bool),
            ...
        }

    Registry is immutable (MappingProxyType) and cumulative across inheritance.
    """

    _rpc_registry: Mapping[str, tuple[str, bool]] = MappingProxyType({})

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)

        # Start with a copy of parent registry so inheritance works
        registry: dict[str, tuple[str, bool]] = dict(getattr(cls, "_rpc_registry", {}))  # type: ignore[attr-defined]

        # Scan the new subclass' namespace
        for attr, obj in cls.__dict__.items():
            if hasattr(obj, "_rpc_name"):  # set by @rpc
                registry[obj._rpc_name] = (attr, obj._rpc_streaming)  # type: ignore[attr-defined]

        # Freeze to prevent accidental mutation
        cls._rpc_registry = MappingProxyType(registry)


class RpcProxy(FameServiceProxy):
    def __getattr__(self, name: str):
        if name.startswith("_"):
            return super().__getattribute__(name)

        async def _call(*args, **kwargs):
            stream = kwargs.pop("_stream", False)

            # FameServiceProxy’s original packing rule
            if len(args) == 1 and not kwargs and isinstance(args[0], dict):
                params = args[0]
            else:
                params = {"args": args, "kwargs": kwargs}

            if stream:
                # ⬇️  await here so caller gets the AsyncIterator, not a coroutine
                fabric = self._fabric or FameFabric.current()
                if self._address:
                    return await fabric.invoke_stream(self._address, name, params, timeout_ms=self._timeout)
                return await fabric.invoke_by_capability_stream(
                    self._capabilities, name, params, timeout_ms=self._timeout
                )
            if self._address:
                return await self._invoke(self._address, name, params)
            return await self._invoke_by_capability(self._capabilities, name, params)

        return _call
