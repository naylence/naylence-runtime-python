import pytest


@pytest.fixture(scope="session")
def setup_security_environment():
    # Setup code for security environment
    pass


@pytest.fixture(scope="function")
def security_component():
    # Setup code for individual security component
    pass


@pytest.fixture(scope="session")
def setup_node_environment():
    # Setup code for node environment
    pass


@pytest.fixture(scope="function")
def node_component():
    # Setup code for individual node component
    pass


@pytest.fixture(scope="function")
async def default_storage_provider():
    """Provide a default in-memory storage provider for tests."""
    from naylence.fame.storage.in_memory_storage_provider import InMemoryStorageProvider

    return InMemoryStorageProvider()
