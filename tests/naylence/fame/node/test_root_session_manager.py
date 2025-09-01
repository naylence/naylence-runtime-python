"""
Tests for RootSessionManager.
These tests cover the admission logic for root sentinels.
"""

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

    def __init__(self, should_succeed: bool = True):
        self.should_succeed = should_succeed
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

        # Return a mock welcome envelope
        welcome_frame = NodeWelcomeFrame(
            system_id=system_id,
            instance_id=instance_id,
            assigned_path=f"/{system_id}",
            accepted_logicals=requested_logicals or [],
            connection_grants=[],
        )
        envelope = FameEnvelope(frame=welcome_frame)
        return envelope  # type: ignore


@pytest.mark.asyncio
async def test_root_session_manager_successful_admission():
    """Test successful admission flow."""
    node = MockNode("root-test")
    admission_client = MockAdmissionClient(should_succeed=True)

    welcome_frames = []

    async def on_welcome(frame: NodeWelcomeFrame):
        welcome_frames.append(frame)

    manager = RootSessionManager(
        node=node,  # type: ignore
        admission_client=admission_client,  # type: ignore
        requested_logicals=["test.local"],
        on_welcome=on_welcome,
    )

    # Test start and wait for ready
    await manager.start(wait_until_ready=True)

    # Verify admission was called
    assert len(admission_client.hello_calls) == 1
    system_id, instance_id, logicals = admission_client.hello_calls[0]
    assert system_id == "root-test"
    assert logicals == ["test.local"]

    # Verify welcome callback was called
    assert len(welcome_frames) == 1
    assert welcome_frames[0].system_id == "root-test"

    # Verify manager is ready
    assert manager.is_ready

    await manager.stop()


@pytest.mark.asyncio
async def test_root_session_manager_admission_failure():
    """Test admission failure handling."""
    node = MockNode("root-test")
    admission_client = MockAdmissionClient(should_succeed=False)

    failed_exceptions = []

    async def on_admission_failed(exc: BaseException):
        failed_exceptions.append(exc)

    async def on_welcome(frame: NodeWelcomeFrame):
        pass  # Should not be called

    manager = RootSessionManager(
        node=node,  # type: ignore
        admission_client=admission_client,  # type: ignore
        requested_logicals=["test.local"],
        on_welcome=on_welcome,
        on_admission_failed=on_admission_failed,
    )

    # Test that start raises an exception after max retries
    with pytest.raises(FameConnectError):
        await manager.start(wait_until_ready=True)

    # Verify multiple attempts were made
    assert len(admission_client.hello_calls) == manager.RETRY_MAX_ATTEMPTS

    # Verify failure callback was called once at the end
    assert len(failed_exceptions) == 1

    await manager.stop()


@pytest.mark.asyncio
async def test_root_session_manager_perform_admission():
    """Test one-shot admission."""
    node = MockNode("root-test")
    admission_client = MockAdmissionClient(should_succeed=True)

    async def on_welcome(frame: NodeWelcomeFrame):
        pass

    manager = RootSessionManager(
        node=node,  # type: ignore
        admission_client=admission_client,  # type: ignore
        requested_logicals=["test.local"],
        on_welcome=on_welcome,
    )

    # Test direct admission call
    welcome_frame = await manager.perform_admission()

    assert welcome_frame.system_id == "root-test"
    assert welcome_frame.assigned_path == "/root-test"
    assert welcome_frame.accepted_logicals == ["test.local"]

    # Verify admission was called once
    assert len(admission_client.hello_calls) == 1


@pytest.mark.asyncio
async def test_root_session_manager_start_without_wait():
    """Test starting without waiting for ready."""
    node = MockNode("root-test")
    admission_client = MockAdmissionClient(should_succeed=True)

    async def on_welcome(frame: NodeWelcomeFrame):
        pass

    manager = RootSessionManager(
        node=node,  # type: ignore
        admission_client=admission_client,  # type: ignore
        requested_logicals=["test.local"],
        on_welcome=on_welcome,
    )

    # Start without waiting
    await manager.start(wait_until_ready=False)

    # Should not be ready immediately
    assert not manager.is_ready

    # Wait for ready explicitly
    await manager.await_ready(timeout=1.0)

    # Now should be ready
    assert manager.is_ready

    await manager.stop()
