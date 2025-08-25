from contextvars import Token

from starlette.types import ASGIApp, Receive, Scope, Send

from fastapi import FastAPI
from naylence.fame.core import FameFabric
from naylence.fame.core.fame_fabric import _FABRIC_STACK
from naylence.fame.node.node import _NODE_STACK, get_node

# --------------------------------------------------------------------------- #
# Helpers                                                                     #
# --------------------------------------------------------------------------- #


def init_app_state(app: FastAPI) -> None:
    """
    Call once (e.g. in the FastAPI lifespan) to attach the current
    FameFabric and node to `app.state` so the middleware can re-bind them.
    """
    app.state.fabric = FameFabric.current()
    app.state.node = get_node()


def _push_fame_context(app_state) -> tuple[Token, Token]:
    """Push fabric / node onto their task-local stacks and return tokens."""
    tok_fabric: Token = _FABRIC_STACK.set([*(_FABRIC_STACK.get()), app_state.fabric])
    tok_node: Token = _NODE_STACK.set([*(_NODE_STACK.get() or []), app_state.node])
    return tok_fabric, tok_node


def _pop_fame_context(tok_fabric: Token, tok_node: Token) -> None:
    """Restore previous stack values to avoid bleed-through between requests."""
    _NODE_STACK.reset(tok_node)
    _FABRIC_STACK.reset(tok_fabric)


# --------------------------------------------------------------------------- #
# Middleware                                                                  #
# --------------------------------------------------------------------------- #


class FameContextMiddleware:
    """
    ASGI middleware that re-binds Fame's task-local stacks for **every**
    incoming scope (HTTP or WebSocket), so `FameFabric.current()` and
    `get_node()` transparently work inside FastAPI routes & WS handlers.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        # Only bind for scopes where we actually need Fame context.
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        # Grab the app instance Starlette stuffs into the scope.
        app_state = scope["app"].state

        tok_fabric, tok_node = _push_fame_context(app_state)
        try:
            await self.app(scope, receive, send)
        finally:
            _pop_fame_context(tok_fabric, tok_node)
