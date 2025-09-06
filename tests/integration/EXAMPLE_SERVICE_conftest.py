"""
EXAMPLE: How to create a new Docker service integration test
"""

from pathlib import Path

import pytest
import requests


@pytest.fixture(scope="session")
def docker_compose_file():
    """Path to the docker-compose file for this service tests."""
    return str(Path(__file__).parent / "docker-compose.yml")


@pytest.fixture(scope="session")
def docker_compose_project_name():
    """Project name for Docker Compose to avoid conflicts."""
    return "naylence-myservice-test"


def _is_my_service_ready(service_url: str) -> bool:
    """Custom health check for your service."""
    try:
        response = requests.get(f"{service_url}/health", timeout=3)
        return response.status_code == 200
    except requests.exceptions.RequestException:
        return False


@pytest.fixture(scope="session")
def my_service(docker_service_factory, docker_ip, docker_services):
    """Start your service using the generic Docker service factory."""

    # Create the service fixture using the factory
    service_fixture = docker_service_factory(
        service_name="my-service",  # Name in docker-compose.yml
        port=9000,  # Port your service listens on
        project_name="naylence-myservice-test",
        health_check=_is_my_service_ready,  # Optional: custom health check
        timeout=60.0,  # Optional: timeout in seconds
    )

    # Run the fixture and yield the result
    yield from service_fixture(docker_ip, docker_services)


@pytest.fixture(scope="function")
def my_service_client_config(generic_client_config):
    """Provide configuration for your service client tests."""
    config = generic_client_config.copy()

    # Add service-specific connection grants
    config["node"]["admission"]["connection_grants"] = [
        {
            "type": "HttpConnectionGrant",
            "purpose": "api.access",
            "url": "http://localhost:9000/api",  # Will be updated by test
            "auth": {
                "type": "NoAuth",
            },
        }
    ]

    return config


# USAGE IN YOUR TEST:
#
# def test_my_service_integration(my_service, my_service_client_config):
#     # my_service provides:
#     # {
#     #     "url": "http://docker_ip:random_port",
#     #     "port": random_port,
#     #     "service_name": "my-service",
#     #     "docker_ip": docker_ip
#     # }
#
#     service_url = my_service["url"]
#
#     # Update client config with actual service URL
#     my_service_client_config["node"]["admission"]["connection_grants"][0]["url"] = f"{service_url}/api"
#
#     # Your test logic here...
#     response = requests.get(f"{service_url}/health")
#     assert response.status_code == 200
