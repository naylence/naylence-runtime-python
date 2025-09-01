"""Test the factory method for RootSessionManager."""

from typing import List, Optional
from unittest.mock import Mock

import pytest

from naylence.fame.core import FameEnvelope, NodeWelcomeFrame
from naylence.fame.node.root_session_manager import RootSessionManager


class MockNode:
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
        pass


class MockAdmissionClient:
    def __init__(self):
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
    ):
        self.hello_calls.append((system_id, instance_id, requested_logicals))

        welcome_frame = NodeWelcomeFrame(
            system_id=system_id,
            instance_id=instance_id,
            assigned_path=f"/{system_id}",
            accepted_logicals=requested_logicals or [],
            connection_grants=[{"purpose": "certificate_sign", "endpoint": "https://ca.example.com"}],
        )
        envelope = FameEnvelope(frame=welcome_frame)
        return envelope


@pytest.mark.asyncio
async def test_create_for_root_sentinel():
    """Test the factory method creates a properly configured manager."""
    node = MockNode("root-sentinel")
    admission_client = MockAdmissionClient()

    manager = RootSessionManager.create_for_root_sentinel(
        node=node,  # type: ignore
        admission_client=admission_client,  # type: ignore
        requested_logicals=["example.com"],
    )

    # Verify the manager was created
    assert manager is not None
    assert manager._node == node
    assert manager._admission_client == admission_client
    assert manager._requested_logicals == ["example.com"]

    # Test that it can perform admission
    welcome_frame = await manager.perform_admission()
    assert welcome_frame.system_id == "root-sentinel"
    assert welcome_frame.accepted_logicals == ["example.com"]

    # Verify the default handlers work
    await manager._on_welcome(welcome_frame)  # Should not raise

    from naylence.fame.errors.errors import FameConnectError

    if manager._on_admission_failed:
        await manager._on_admission_failed(FameConnectError("test"))  # Should not raise


if __name__ == "__main__":
    import asyncio

    asyncio.run(test_create_for_root_sentinel())
