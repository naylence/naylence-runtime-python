"""
Tests for RootSessionManager expiry functionality.
"""

import asyncio
from datetime import datetime, timedelta, timezone
from typing import List, Optional
from unittest.mock import Mock

import pytest

from naylence.fame.core import (
    FameEnvelope,
    FameEnvelopeWith,
    NodeWelcomeFrame,
)
from naylence.fame.errors.errors import FameConnectError
from naylence.fame.node.root_session_manager import RootSessionManager


class MockNode:
    """Mock NodeLike object for testing."""

    def __init__(self, node_id: str = "test-root"):
        self._id = node_id
        self._sid = "test-sid"
        self._physical_path = f"/{node_id}"
        self._accepted_logicals = set()
        self.envelope_factory = Mock()
        self.default_binding_path = "default"
        self.has_parent = False
        self.security_manager = Mock()

    @property
    def id(self) -> str:
        return self._id

    @property
    def sid(self) -> str:
        return self._sid

    @property
    def physical_path(self) -> str:
        return self._physical_path

    @property
    def accepted_logicals(self) -> set:
        return self._accepted_logicals

    async def _dispatch_event(self, event_name: str, *args):
        """Mock event dispatch."""
        pass


class MockAdmissionClient:
    """Mock AdmissionClient for testing."""

    def __init__(self, should_succeed: bool = True, expires_in_seconds: Optional[int] = None):
        self.should_succeed = should_succeed
        self.expires_in_seconds = expires_in_seconds
        self.hello_calls = []

    def has_upstream(self) -> bool:
        return True

    async def close(self) -> None:
        pass

    async def hello(
        self,
        system_id: str,
        instance_id: str,
        requested_logicals: Optional[List[str]] = None,
    ) -> FameEnvelopeWith[NodeWelcomeFrame]:
        self.hello_calls.append((system_id, instance_id, requested_logicals))

        if not self.should_succeed:
            raise FameConnectError("Admission failed")

        # Calculate expiry time if specified
        expires_at = None
        if self.expires_in_seconds is not None:
            expires_at = datetime.now(timezone.utc) + timedelta(seconds=self.expires_in_seconds)

        # Return a mock welcome envelope
        welcome_frame = NodeWelcomeFrame(
            system_id=system_id,
            instance_id=instance_id,
            assigned_path=f"/{system_id}",
            accepted_logicals=requested_logicals or [],
            connection_grants=[],
            expires_at=expires_at,
        )
        envelope = FameEnvelope(frame=welcome_frame)
        return envelope  # type: ignore


@pytest.mark.asyncio
async def test_root_session_manager_with_expiry():
    """Test admission with expiry time tracking."""
    node = MockNode("root-test")
    admission_client = MockAdmissionClient(should_succeed=True, expires_in_seconds=300)  # 5 minutes

    welcome_frames = []

    async def on_welcome(frame: NodeWelcomeFrame):
        welcome_frames.append(frame)

    manager = RootSessionManager(
        node=node,  # type: ignore
        admission_client=admission_client,  # type: ignore
        requested_logicals=["test.local"],
        on_welcome=on_welcome,
        enable_continuous_refresh=False,  # Disable for this test
    )

    # Test perform_admission directly to avoid continuous refresh
    welcome_frame = await manager.perform_admission()

    # Verify expiry tracking
    assert manager.current_welcome_frame is not None
    assert manager.admission_expires_at is not None
    assert manager.admission_expires_at == welcome_frame.expires_at

    # Verify expiry is approximately 5 minutes from now
    now = datetime.now(timezone.utc)
    time_diff = (manager.admission_expires_at - now).total_seconds()
    assert 295 <= time_diff <= 305  # Allow some tolerance


@pytest.mark.asyncio
async def test_root_session_manager_continuous_refresh():
    """Test continuous refresh with short expiry."""
    node = MockNode("root-test")
    # Set very short expiry (2 seconds) and short refresh safety (0.5 seconds)
    admission_client = MockAdmissionClient(should_succeed=True, expires_in_seconds=2)

    welcome_frames = []

    async def on_welcome(frame: NodeWelcomeFrame):
        welcome_frames.append(frame)

    manager = RootSessionManager(
        node=node,  # type: ignore
        admission_client=admission_client,  # type: ignore
        requested_logicals=["test.local"],
        on_welcome=on_welcome,
        enable_continuous_refresh=True,
    )

    # Override the refresh safety to be very short for testing
    manager.JWT_REFRESH_SAFETY = 0.5

    # Start without waiting for ready to avoid blocking
    await manager.start(wait_until_ready=False)

    # Wait for first admission
    await manager.await_ready(timeout=2.0)
    assert manager.is_ready
    assert len(welcome_frames) >= 1

    # Wait a bit longer to see if refresh is triggered
    await asyncio.sleep(2.5)  # Should trigger refresh before 2-second expiry

    # Verify at least one refresh occurred
    assert len(admission_client.hello_calls) >= 2, "Expected at least 2 admissions (initial + refresh)"

    await manager.stop()


@pytest.mark.asyncio
async def test_root_session_manager_no_expiry():
    """Test admission without expiry time."""
    node = MockNode("root-test")
    admission_client = MockAdmissionClient(should_succeed=True, expires_in_seconds=None)

    welcome_frames = []

    async def on_welcome(frame: NodeWelcomeFrame):
        welcome_frames.append(frame)

    manager = RootSessionManager(
        node=node,  # type: ignore
        admission_client=admission_client,  # type: ignore
        requested_logicals=["test.local"],
        on_welcome=on_welcome,
        enable_continuous_refresh=True,
    )

    # Test start and wait for ready
    await manager.start(wait_until_ready=True)

    # Verify admission was called
    assert len(admission_client.hello_calls) == 1

    # Verify no expiry tracking
    assert manager.current_welcome_frame is not None
    assert manager.admission_expires_at is None

    # Verify manager is ready
    assert manager.is_ready

    await manager.stop()


@pytest.mark.asyncio
async def test_root_session_manager_factory_with_expiry():
    """Test factory method with expiry functionality."""
    node = MockNode("root-sentinel")
    admission_client = MockAdmissionClient(expires_in_seconds=600)  # 10 minutes

    manager = RootSessionManager.create_for_root_sentinel(
        node=node,  # type: ignore
        admission_client=admission_client,  # type: ignore
        requested_logicals=["example.com"],
        enable_continuous_refresh=True,
    )

    # Verify the manager was created with continuous refresh enabled
    assert manager._enable_continuous_refresh is True

    # Test that it can perform admission
    welcome_frame = await manager.perform_admission()
    assert welcome_frame.system_id == "root-sentinel"
    assert welcome_frame.accepted_logicals == ["example.com"]
    assert welcome_frame.expires_at is not None

    # Verify expiry tracking
    assert manager.admission_expires_at is not None


@pytest.mark.asyncio
async def test_root_session_manager_one_shot_admission():
    """Test one-shot admission without continuous refresh."""
    node = MockNode("root-test")
    admission_client = MockAdmissionClient(should_succeed=True, expires_in_seconds=300)

    welcome_frames = []

    async def on_welcome(frame: NodeWelcomeFrame):
        welcome_frames.append(frame)

    manager = RootSessionManager(
        node=node,  # type: ignore
        admission_client=admission_client,  # type: ignore
        requested_logicals=["test.local"],
        on_welcome=on_welcome,
        enable_continuous_refresh=False,  # One-shot mode
    )

    # Test start and wait for ready
    await manager.start(wait_until_ready=True)

    # Verify admission was called only once
    assert len(admission_client.hello_calls) == 1

    # Wait a bit to ensure no refresh happens
    await asyncio.sleep(0.5)
    assert len(admission_client.hello_calls) == 1

    # Verify manager is ready
    assert manager.is_ready
    assert manager.admission_expires_at is not None

    await manager.stop()
