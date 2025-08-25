"""
Ensure DefaultMCPService’s background janitor really evicts idle sessions.

We shrink IDLE_TIMEOUT to 50 ms on the concrete *instance*, register a
pre-staled `_MCPSessionEntry`, wait a short moment, and assert the entry was
removed by the janitor.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable

import pytest
from pydantic import AnyUrl

from naylence.fame.core import FameEnvelope
from naylence.fame.mcp.default_mcp_host_service import (
    DefaultMCPHostService,
    _MCPSessionEntry,
)

# --------------------------------------------------------------------------- #
# Helpers                                                                     #
# --------------------------------------------------------------------------- #


async def _fake_sender(envelope: FameEnvelope) -> None:
    """Stub Fame fabric sender; the test never inspects envelopes."""
    return None


async def _dummy_handler(_uri: AnyUrl, _notification: Any) -> Awaitable[None]:  # type: ignore[override]
    """No-op notification handler for the dummy session entry."""
    return None  # type: ignore


# --------------------------------------------------------------------------- #
# The test                                                                    #
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_evict_idle_background(monkeypatch):
    # 1.  Instantiate the service (spawns the background janitor immediately)
    svc = DefaultMCPHostService(_fake_sender)

    # 2.  Tighten the idle timeout **on this instance only**
    monkeypatch.setattr(svc, "IDLE_TIMEOUT", timedelta(seconds=0.05), raising=False)

    # 3.  Register an entry whose last-used timestamp is already stale
    entry = _MCPSessionEntry(
        endpoint="dummy://",
        message_handler=_dummy_handler,  # type: ignore
        auth=None,  # type: ignore[arg-type]  – auth not used here
    )
    entry.last_used = datetime.now(timezone.utc) - timedelta(seconds=1)
    svc._sessions["old"] = entry

    assert "old" in svc._sessions  # sanity

    # 4.  Give the janitor one full cycle (half of IDLE_TIMEOUT = 25 ms)
    await asyncio.sleep(0.15)  # generous 3× margin for CI jitter

    # 5.  Entry should have been evicted & closed
    assert "old" not in svc._sessions

    # 6.  Clean up so the task doesn’t linger after the test module
    await svc.close()
