from __future__ import annotations

from collections import namedtuple
from contextlib import contextmanager
from contextvars import ContextVar, Token
from typing import Optional

from structlog.contextvars import bind_contextvars, clear_contextvars

from naylence.fame.core import FameEnvelope

EnvelopeSnapshot = namedtuple("EnvelopeSnapshot", ["id", "sid", "trace_id", "flow_id", "to", "reply_to"])

current_envelope: ContextVar[Optional[EnvelopeSnapshot]] = ContextVar("current_envelope", default=None)


def current_trace_id():
    env = current_envelope.get()
    return env.trace_id if env else None


def current_envelope_id():
    env = current_envelope.get()
    return env.id if env else None


@contextmanager
def envelope_context(env: FameEnvelope):
    snapshot = EnvelopeSnapshot(env.id, env.sid, env.trace_id, env.flow_id, env.to, env.reply_to)

    # set our own ContextVar
    token: Token = current_envelope.set(snapshot)

    # _also_ bind into structlog’s contextvars
    bind_contextvars()
    try:
        yield
    finally:
        # restore the old snapshot
        try:
            current_envelope.reset(token)
        except ValueError:
            # we're in a different context than the one that did the set()
            # swallow it so shutdown loops don’t trigger unraisable warnings
            pass
        # clear structlog’s contextvars for next request
        clear_contextvars()
