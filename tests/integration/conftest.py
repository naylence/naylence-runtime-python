import hashlib
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Callable, Optional

import docker
import docker.errors
import pytest
import requests


def _calculate_source_hash(project_root: Path) -> str:
    """Calculate a hash of the source code to detect changes."""
    hasher = hashlib.sha256()

    # Key files/directories that should trigger rebuilds
    key_paths = ["src/naylence", "pyproject.toml", "poetry.lock", "tests/integration/docker/Dockerfile"]

    for key_path in key_paths:
        path = project_root / key_path
        if path.is_file():
            # Hash file content
            with open(path, "rb") as f:
                hasher.update(f.read())
        elif path.is_dir():
            # Hash all Python files in directory
            for py_file in path.rglob("*.py"):
                if py_file.is_file():
                    try:
                        with open(py_file, "rb") as f:
                            hasher.update(f.read())
                    except OSError:
                        # Skip files we can't read
                        continue

    return hasher.hexdigest()[:12]  # Short hash for image tag


@pytest.fixture(scope="session")
def integration_docker_image():
    """Build Docker image with automatic rebuilding when source code changes."""
    client = docker.from_env()

    # Get paths
    project_root = Path(__file__).parent.parent.parent
    dockerfile_path = Path(__file__).parent / "docker" / "Dockerfile"

    # Check for force rebuild environment variable
    force_rebuild = os.getenv("PYTEST_DOCKER_REBUILD", "").lower() in ("true", "1", "yes")

    if force_rebuild:
        print("🔄 Force rebuilding Docker image (PYTEST_DOCKER_REBUILD=true)")
        image_name = f"naylence-runtime-integration:force-{int(time.time())}"
        source_hash = None
    else:
        # Calculate source hash for versioning
        source_hash = _calculate_source_hash(project_root)
        image_name = f"naylence-runtime-integration:{source_hash}"

        # Check if image with this hash already exists
        try:
            existing_image = client.images.get(image_name)
            print(f"✅ Using existing Docker image: {existing_image}")
            return image_name
        except docker.errors.ImageNotFound:
            pass

        # Clean up old integration images to save space (keep only last 3)
    try:
        integration_images = []
        integration_images.extend(
            (image, tag)
            for image in client.images.list()
            for tag in image.tags
            if tag.startswith("naylence-runtime-integration:")
        )

        # Sort by creation time and keep only the 3 most recent
        integration_images.sort(key=lambda x: x[0].attrs.get("Created", ""), reverse=True)
        for image_obj, tag in integration_images[3:]:  # Remove all but latest 3
            if tag != image_name:  # Don't remove the one we're about to build
                try:
                    client.images.remove(tag, force=True)
                    print(f"🗑️ Removed old image: {tag}")
                except Exception:
                    pass  # Ignore errors removing old images
    except Exception:
        pass  # Ignore errors during cleanup

    # Build the image
    print(f"🐳 Building Docker image: {image_name}")
    if source_hash:
        print(f"📦 Source hash: {source_hash}")

    try:
        # Build image using Docker client
        image, logs = client.images.build(
            path=str(project_root),
            dockerfile=str(dockerfile_path.relative_to(project_root)),
            tag=image_name,
            rm=True,
            forcerm=True,
            nocache=force_rebuild,  # No cache when force rebuilding
            pull=False,  # Don't pull base image every time
        )

        # Print build logs
        for log in logs:
            if isinstance(log, dict) and "stream" in log:
                stream_content = log["stream"]
                if isinstance(stream_content, str):
                    print(stream_content.strip())

        print(f"✅ Successfully built Docker image: {image_name}")
        return image_name

    except Exception as e:
        print(f"❌ Failed to build Docker image: {e}")
        raise


@pytest.fixture(scope="session")
def docker_network():
    """Create a shared Docker network for integration tests."""
    client = docker.from_env()
    network_name = "naylence-integration-test"

    # Check if network already exists
    try:
        existing_network = client.networks.get(network_name)
        print(f"✅ Using existing Docker network: {network_name}")
        return existing_network
    except docker.errors.NotFound:
        pass

    # Create the network
    print(f"🌐 Creating Docker network: {network_name}")
    network = client.networks.create(network_name, driver="bridge")

    yield network

    # Cleanup: Remove the network after tests
    try:
        network.remove()
        print(f"🗑️ Removed Docker network: {network_name}")
    except Exception as e:
        print(f"⚠️ Failed to remove network {network_name}: {e}")


def _stream_docker_compose_logs(service_name: str, compose_file_dir: Path, prefix: str = "🐳"):
    """Stream docker-compose logs in real-time to stdout."""
    try:
        cmd = ["docker", "compose", "logs", "-f", service_name]

        process = subprocess.Popen(
            cmd,
            cwd=compose_file_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

        for line in iter(process.stdout.readline, ""):  # type: ignore
            if line.strip():
                print(f"{prefix} {line.strip()}", flush=True)

    except Exception as e:
        print(f"⚠️ Log streaming stopped: {e}", flush=True)


def _default_http_health_check(url: str) -> bool:
    """Default HTTP health check - 200 or 404 means server is running."""
    try:
        response = requests.get(f"{url}/", timeout=3)
        return response.status_code in [200, 404]
    except requests.exceptions.RequestException:
        return False


@pytest.fixture(scope="session")
def docker_service_factory():
    """Factory to create Docker service fixtures with common patterns."""

    def create_service_fixture(
        service_name: str,
        port: int,
        project_name: str,
        compose_file_path: Optional[str] = None,
        health_check: Optional[Callable[[str], bool]] = None,
        timeout: float = 60.0,
    ):
        """
        Create a Docker service fixture for integration testing.

        Args:
            service_name: Name of the service in docker-compose.yml
            port: Port the service listens on
            project_name: Docker Compose project name
            compose_file_path: Path to docker-compose.yml (defaults to docker-compose.yml in same dir)
            health_check: Function to check if service is ready (defaults to HTTP check)
            timeout: Timeout in seconds to wait for service to be ready
        """

        def service_fixture(docker_ip, docker_services):
            # Set up compose file path
            if compose_file_path:
                compose_dir = Path(compose_file_path).parent
            else:
                # Assume docker-compose.yml is in the same directory as the test file
                import inspect

                frame = inspect.currentframe()
                while frame:
                    if (
                        "conftest.py" in frame.f_code.co_filename
                        and "integration" in frame.f_code.co_filename
                    ):
                        if "rpc" in frame.f_code.co_filename or "sentinel" in frame.f_code.co_filename:
                            compose_dir = Path(frame.f_code.co_filename).parent
                            break
                    frame = frame.f_back
                else:
                    compose_dir = Path.cwd()

            # Check for debug flags
            show_docker_logs = os.getenv("PYTEST_DOCKER_LOGS", "").lower() in ("true", "1", "yes")
            verbose = "-v" in sys.argv or "--verbose" in sys.argv

            print(f"🚀 Starting {service_name} via docker-compose...")

            # Start log streaming if requested
            log_thread = None
            if show_docker_logs or verbose:
                print("📋 Streaming Docker container logs...")
                log_thread = threading.Thread(
                    target=_stream_docker_compose_logs, args=(service_name, compose_dir), daemon=True
                )
                log_thread.start()

            # Get the service port
            service_port = docker_services.port_for(service_name, port)
            service_url = f"http://{docker_ip}:{service_port}"

            print(f"⏳ Waiting for {service_name} to be ready...")

            # Use provided health check or default
            check_func = health_check or _default_http_health_check

            # Wait for the service to be ready
            docker_services.wait_until_responsive(
                timeout=timeout, pause=2.0, check=lambda: check_func(service_url)
            )

            print(f"✅ {service_name} is ready!")

            yield {
                "url": service_url,
                "port": service_port,
                "service_name": service_name,
                "docker_ip": docker_ip,
            }

            print(f"🗑️ Stopping {service_name} container...")

        return service_fixture

    return create_service_fixture


@pytest.fixture(scope="session")
def docker_compose_file():
    """Path to the docker-compose file - can be overridden by specific tests."""
    # Default fallback - look for docker-compose.yml in the test directory
    import inspect

    frame = inspect.currentframe()
    while frame:
        filename = frame.f_code.co_filename
        if "test_" in filename or "conftest.py" in filename:
            test_dir = Path(filename).parent
            compose_file = test_dir / "docker-compose.yml"
            if compose_file.exists():
                return str(compose_file)
        frame = frame.f_back

    # Ultimate fallback
    return str(Path.cwd() / "docker-compose.yml")


@pytest.fixture(scope="session")
def docker_compose_project_name():
    """Default project name for Docker Compose - can be overridden."""
    return "naylence-integration-test"


@pytest.fixture(scope="function")
def generic_client_config():
    """Provide a generic configuration template for Fame clients."""
    return {
        "node": {
            "type": "Node",
            "id": "test-client",
            "admission": {
                "type": "DirectAdmissionClient",
                "connection_grants": [],  # To be populated by specific tests
            },
        },
    }


@pytest.fixture(scope="session")
def setup_security_environment():
    # Setup code for security environment
    pass


@pytest.fixture(scope="function")
def security_component():
    # Code to create and return a security component instance
    pass


@pytest.fixture(scope="function")
def node_component():
    # Code to create and return a node component instance
    pass


@pytest.fixture(scope="function")
def cleanup_security_environment():
    yield
    # Teardown code for security environment
    pass
