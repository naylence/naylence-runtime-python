"""Telemetry integration test configuration and fixtures."""

from pathlib import Path
from typing import Generator

import pytest
import requests


@pytest.fixture(scope="package")
def docker_compose_file():
    """Path to the docker-compose file for telemetry tests."""
    return str(Path(__file__).parent / "docker-compose.yml")


@pytest.fixture(scope="package")
def docker_compose_project_name():
    """Project name for Docker Compose to avoid conflicts."""
    return "naylence-telemetry-test"


@pytest.fixture(scope="package")
def docker_services(docker_compose_file, docker_compose_project_name):
    """Create package-scoped docker services for telemetry tests."""
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


def _is_otel_collector_ready(service_url: str) -> bool:
    """Check if OpenTelemetry Collector is ready."""
    try:
        # Extract the port from the URL and try HTTP endpoint
        if ":" in service_url:
            host, port = service_url.split("http://")[-1].split(":")
            http_port = int(port) + 1  # HTTP port is typically GRPC port + 1
            response = requests.get(f"http://{host}:{http_port}/v1/traces", timeout=2)
            return response.status_code in [200, 405]  # 405 is expected for GET on traces endpoint
        return False
    except (requests.exceptions.RequestException, ValueError):
        return False


@pytest.fixture(scope="package")
def otel_collector_service(docker_service_factory, docker_ip, docker_services):
    """Start OpenTelemetry Collector service."""
    service_fixture = docker_service_factory(
        service_name="otel-collector",
        port=4317,  # Internal GRPC port (maps to external 14317)
        project_name="naylence-telemetry-test",
        health_check=_is_otel_collector_ready,
        timeout=60.0,
    )

    yield from service_fixture(docker_ip, docker_services)


@pytest.fixture(scope="package")
def telemetry_sentinel_service(
    docker_service_factory, docker_ip, docker_services, integration_docker_image
):
    """Start Telemetry Sentinel service with OpenTelemetry integration."""
    # integration_docker_image ensures source code changes trigger rebuilds
    service_fixture = docker_service_factory(
        service_name="telemetry-sentinel", port=8000, project_name="naylence-telemetry-test", timeout=60.0
    )

    yield from service_fixture(docker_ip, docker_services)


@pytest.fixture(scope="package")
def telemetry_services(
    otel_collector_service, telemetry_sentinel_service, docker_services, docker_ip
) -> Generator[dict, None, None]:
    """Provide connection details for all telemetry services."""

    # Get additional service ports if needed
    otel_grpc_port = otel_collector_service["port"]  # This is the external mapped port (14317)
    otel_http_port = docker_services.port_for("otel-collector", 4318)  # This will be 14318

    # Telemetry sentinel service details
    sentinel_port = telemetry_sentinel_service["port"]
    sentinel_url = telemetry_sentinel_service["url"]

    # Build service URLs
    otel_grpc_url = f"{docker_ip}:{otel_grpc_port}"
    otel_http_url = f"{docker_ip}:{otel_http_port}"

    yield {
        "otel_collector_grpc": otel_grpc_url,
        "otel_collector_http": otel_http_url,
        "sentinel_url": sentinel_url,
        "sentinel_port": sentinel_port,
    }


def _is_jaeger_ready(jaeger_url: str) -> bool:
    """Check if Jaeger is ready."""
    try:
        response = requests.get(f"{jaeger_url}/api/services", timeout=2)
        return response.status_code == 200
    except requests.exceptions.RequestException:
        return False


def _is_jaeger_api_ready(jaeger_api_url: str) -> bool:
    """Check if Jaeger API is ready for testing."""
    try:
        # Check if the API endpoint is accessible
        response = requests.get(f"{jaeger_api_url}/api/services", timeout=2)
        return response.status_code == 200
    except requests.exceptions.RequestException:
        return False


def _is_prometheus_ready(prometheus_url: str) -> bool:
    """Check if Prometheus is ready."""
    try:
        response = requests.get(f"{prometheus_url}/-/ready", timeout=2)
        return response.status_code == 200
    except requests.exceptions.RequestException:
        return False


@pytest.fixture
def otel_exporter_config(telemetry_services):
    """OpenTelemetry exporter configuration for tests."""
    return {
        "endpoint": telemetry_services["otel_collector_grpc"],
        "insecure": True,
    }


@pytest.fixture(scope="function")
def telemetry_client_config(generic_client_config):
    """Provide configuration for telemetry client tests."""
    config = generic_client_config.copy()

    # Add telemetry-specific connection grants
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

    # Add telemetry configuration to the client
    config["node"]["telemetry"] = {
        "type": "OpenTelemetryTraceEmitter",
        "service_name": "fame-telemetry-test-client",
        "endpoint": "http://localhost:4317",
    }

    return config
