from __future__ import annotations


class FameTransportClose(BaseException):
    """Raise inside a Fame handler to abort the socket with a WS close frame."""

    def __init__(self, code: int, reason: str = ""):
        super().__init__(reason)
        self.code = code
        self.reason = reason


class FameConnectError(BaseException):
    """Raise inside a Fame handler to abort the socket with a WS close frame."""


class FameMessageTooLarge(BaseException):
    """Raise if the message exceed the max allowed size."""


class FameProtocolError(Exception):
    """
    Raised when an incoming or outgoing frame violates the Fame wire protocol.
    Carries an associated WebSocket close code and human-readable reason.
    """

    def __init__(self, code: int = 1002, reason: str = "protocol error"):
        super().__init__(reason)
        self.code = code
        self.reason = reason


class BackPressureFull(FameProtocolError):
    """
    Raised when a connector's send-queue is at capacity
    and enqueueing times out.
    """

    pass


class NotAuthorized(FameTransportClose):
    """Use for 4403 Forbidden attach errors."""

    def __init__(self, reason: str = "attach-unauthorized"):
        super().__init__(4403, reason)
