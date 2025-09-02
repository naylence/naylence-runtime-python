from datetime import datetime, timedelta, timezone

import pytest

from naylence.fame.node.admission.direct_admission_client import DirectAdmissionClient


@pytest.mark.asyncio
async def test_ttl_logic_with_specific_ttl():
    """Test that client TTL is used when specified."""
    now = datetime.now(timezone.utc)
    client_ttl_sec = 3600  # Client TTL is 1 hour

    connection_grants = [{"type": "WebSocketConnectionGrant", "purpose": "node.attach", "url": "ws://test.com"}]

    client = DirectAdmissionClient(
        connection_grants=connection_grants,
        ttl_sec=client_ttl_sec,
    )

    envelope = await client.hello("system1", "instance1")

    # Should use client TTL (1 hour)
    # Allow for small time difference in test execution
    expected_expires_at = now + timedelta(seconds=client_ttl_sec)
    assert abs((envelope.frame.expires_at - expected_expires_at).total_seconds()) < 1


@pytest.mark.asyncio
async def test_ttl_logic_with_different_ttl():
    """Test that different client TTL values are used correctly."""
    now = datetime.now(timezone.utc)
    client_ttl_sec = 7200  # Client TTL is 2 hours

    connection_grants = [{"type": "WebSocketConnectionGrant", "purpose": "node.attach", "url": "ws://test.com"}]

    client = DirectAdmissionClient(
        connection_grants=connection_grants,
        ttl_sec=client_ttl_sec,
    )

    envelope = await client.hello("system1", "instance1")

    # Should use client TTL (2 hours)
    # Allow for small time difference in test execution
    expected_expires_at = now + timedelta(seconds=client_ttl_sec)
    assert abs((envelope.frame.expires_at - expected_expires_at).total_seconds()) < 1


@pytest.mark.asyncio
async def test_ttl_logic_zero_ttl():
    """Test that zero TTL falls back to default 24 hours."""
    now = datetime.now(timezone.utc)

    connection_grants = [{"type": "WebSocketConnectionGrant", "purpose": "node.attach", "url": "ws://test.com"}]

    client = DirectAdmissionClient(
        connection_grants=connection_grants,
        ttl_sec=0,  # Zero TTL
    )

    envelope = await client.hello("system1", "instance1")

    # Should use default 24h since ttl_sec is 0 (falsy)
    expected_expires_at = now + timedelta(hours=24)
    assert abs((envelope.frame.expires_at - expected_expires_at).total_seconds()) < 1


@pytest.mark.asyncio
async def test_ttl_logic_default_fallback():
    """Test that default 24h is used when no TTL is specified."""
    now = datetime.now(timezone.utc)

    connection_grants = [{"type": "WebSocketConnectionGrant", "purpose": "node.attach", "url": "ws://test.com"}]

    client = DirectAdmissionClient(
        connection_grants=connection_grants,
        # ttl_sec defaults to 0
    )

    envelope = await client.hello("system1", "instance1")

    # Should use default 24h
    expected_expires_at = now + timedelta(hours=24)
    assert abs((envelope.frame.expires_at - expected_expires_at).total_seconds()) < 1
