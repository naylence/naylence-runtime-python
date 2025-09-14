"""
RPC Integration Test Configuration
"""

from pathlib import Path

import pytest


@pytest.fixture(scope="package")
def docker_compose_file():
    """Path to the docker-compose file for RPC tests."""
    return str(Path(__file__).parent / "docker-compose.yml")


@pytest.fixture(scope="package")
def docker_compose_project_name():
    """Project name for Docker Compose to avoid conflicts."""
    return "naylence-rpc-test"


@pytest.fixture(scope="package")
def docker_services(docker_compose_file, docker_compose_project_name):
    """Create package-scoped docker services for RPC tests."""
    from pytest_docker.plugin import DockerComposeExecutor, Services

    executor = DockerComposeExecutor("docker compose", [docker_compose_file], docker_compose_project_name)
    services = Services(executor)

    # Start the services
    try:
        executor.execute("up -d --build")
        yield services
    finally:
        # Cleanup: stop and remove containers
        try:
            executor.execute("down -v --remove-orphans")
        except Exception:
            pass  # Ignore cleanup errors


@pytest.fixture(scope="package")
def rpc_docker_service(docker_service_factory, docker_ip, docker_services):
    """Start the RPC sentinel service using docker-compose."""
    # Create the service fixture using the factory
    service_fixture = docker_service_factory(
        service_name="sentinel", port=8000, project_name="naylence-rpc-test", timeout=60.0
    )

    # Run the fixture and yield the result
    yield from service_fixture(docker_ip, docker_services)


@pytest.fixture(scope="function")
def rpc_client_config(generic_client_config):
    """Provide configuration for RPC client tests."""
    config = generic_client_config.copy()

    # Add RPC-specific connection grants
    config["node"]["admission"]["connection_grants"] = [
        {
            "type": "WebSocketConnectionGrant",
            "purpose": "node.attach",
            "url": "ws://localhost:28000/fame/v1/attach/ws/downstream",  # Will be updated by test
            "auth": {
                "type": "NoAuth",
            },
        }
    ]

    # Add "at-most-once" delivery policy to avoid ACK requirements
    config["node"]["delivery"] = {"type": "DeliveryProfile", "profile": "at-most-once"}

    return config
