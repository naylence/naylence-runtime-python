"""
Multi-Service Integration Test Configuration
Demonstrates how to orchestrate multiple services with docker-compose for complex scenarios.
"""

from pathlib import Path
from typing import Generator

import pytest
import requests


@pytest.fixture(scope="session")
def docker_compose_file():
    """Path to the docker-compose file for multi-service tests."""
    return str(Path(__file__).parent / "docker-compose.yml")


@pytest.fixture(scope="session")
def docker_compose_project_name():
    """Project name for Docker Compose to avoid conflicts."""
    return "naylence-multi-service-test"


@pytest.fixture(scope="session")
def multi_service_cluster(docker_ip, docker_services) -> Generator[dict, None, None]:
    """Start multi-service cluster and wait for all services to be ready."""

    # Get service ports
    sentinel_port = docker_services.port_for("sentinel", 8000)
    service_node_port = docker_services.port_for("service-node", 8001)
    metrics_port = docker_services.port_for("metrics-collector", 9090)
    tracing_port = docker_services.port_for("jaeger", 16686)

    # Build service URLs
    sentinel_url = f"http://{docker_ip}:{sentinel_port}"
    service_node_url = f"http://{docker_ip}:{service_node_port}"
    metrics_url = f"http://{docker_ip}:{metrics_port}"
    tracing_url = f"http://{docker_ip}:{tracing_port}"

    # Wait for all services to be ready with proper dependency order
    print("🏗️ Starting multi-service cluster...")

    # 1. Wait for sentinel first (core infrastructure)
    print("⏳ Waiting for sentinel...")
    docker_services.wait_until_responsive(
        timeout=60.0, pause=2.0, check=lambda: _is_service_ready(sentinel_url)
    )
    print("✅ Sentinel ready")

    # 2. Wait for service node (depends on sentinel)
    print("⏳ Waiting for service node...")
    docker_services.wait_until_responsive(
        timeout=60.0, pause=2.0, check=lambda: _is_service_ready(service_node_url)
    )
    print("✅ Service node ready")

    # 3. Wait for metrics collector
    print("⏳ Waiting for metrics collector...")
    docker_services.wait_until_responsive(
        timeout=30.0, pause=1.0, check=lambda: _is_metrics_ready(metrics_url)
    )
    print("✅ Metrics collector ready")

    # 4. Wait for tracing system
    print("⏳ Waiting for tracing system...")
    docker_services.wait_until_responsive(
        timeout=30.0, pause=1.0, check=lambda: _is_tracing_ready(tracing_url)
    )
    print("✅ Tracing system ready")

    print("🎉 Multi-service cluster fully operational!")

    yield {
        "sentinel": sentinel_url,
        "service_node": service_node_url,
        "metrics": metrics_url,
        "tracing": tracing_url,
        "cluster_ready": True,
    }


def _is_service_ready(service_url: str) -> bool:
    """Check if a Fame service is ready."""
    try:
        response = requests.get(f"{service_url}/health", timeout=3)
        return response.status_code == 200
    except requests.exceptions.RequestException:
        return False


def _is_metrics_ready(metrics_url: str) -> bool:
    """Check if metrics collector is ready."""
    try:
        response = requests.get(f"{metrics_url}/-/ready", timeout=2)
        return response.status_code == 200
    except requests.exceptions.RequestException:
        return False


def _is_tracing_ready(tracing_url: str) -> bool:
    """Check if tracing system is ready."""
    try:
        response = requests.get(f"{tracing_url}/api/services", timeout=2)
        return response.status_code == 200
    except requests.exceptions.RequestException:
        return False


@pytest.fixture
def cluster_client_config(multi_service_cluster):
    """Configuration for connecting to the multi-service cluster."""
    sentinel_url = multi_service_cluster["sentinel"]

    return {
        "node": {
            "type": "Node",
            "id": "test-client",
            "admission": {
                "type": "DirectAdmissionClient",
                "connection_grants": [
                    {
                        "type": "WebSocketConnectionGrant",
                        "purpose": "node.attach",
                        "url": f"{sentinel_url.replace('http', 'ws')}/fame/v1/attach/ws/downstream",
                        "auth": {"type": "NoAuth"},
                    }
                ],
            },
        },
    }


@pytest.fixture
def service_discovery(multi_service_cluster):
    """Provide service discovery information for tests."""
    return {
        "calculator": "calculator@/service-node",
        "data_processor": "processor@/service-node",
        "notification": "notifications@/service-node",
        # Add more services as needed
    }
