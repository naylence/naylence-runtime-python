# RPC Integration Tests

This directory contains clean, working integration tests for Fame RPC functionality.

## Test Files

### Core Tests
- `test_local_rpc.py` - Local RPC testing using in-process Fame fabric
- `test_client_to_docker_sentinel.py` - Client-to-Docker sentinel RPC integration test

### Docker Infrastructure
- `docker-compose.yml` - Docker Compose setup using shared integration image
- `sentinel_with_calculator.py` - Sentinel service with Calculator RPC service

### Shared Integration Image
- Uses `naylence-runtime-integration:latest` built from `tests/integration/Dockerfile.test`
- Build once with: `./tests/integration/build-shared-image.sh`
- Shared across all integration tests for efficiency

### Configuration
- `config/sentinel-config.yml` - Sentinel configuration for Docker deployment

## Running Tests

### Local RPC Test
```bash
python test_local_rpc.py
```

### Docker Integration Test
```bash
# Build shared integration image (once)
./tests/integration/build-shared-image.sh

# Start Docker sentinel
docker-compose up -d

# Run client test
python test_client_to_docker_sentinel.py

# Clean up
docker-compose down
```

## Architecture

The tests demonstrate:
- **Local RPC**: Direct in-process Fame fabric communication
- **Docker RPC**: Client-to-Docker sentinel communication via WebSocket
- **Service Discovery**: Proper Fame address resolution (`service@/domain`)
- **Error Handling**: RPC error propagation and handling
- **Telemetry**: OpenTelemetry trace integration

## Key Components

- **FameRPCService**: Base class for RPC services using `handle_rpc_request` pattern
- **RpcProxy**: Client-side proxy for making RPC calls
- **DirectAdmissionClient**: WebSocket-based client connection to sentinel
- **Calculator Service**: Example RPC service with add, multiply, divide operations

## Proven Patterns

### Client Configuration
```python
CLIENT_CONFIG = {
    "node": {
        "type": "Node",
        "id": "test-client",
        "admission": {
            "type": "DirectAdmissionClient", 
            "connection_grants": [
                {
                    "type": "WebSocketConnectionGrant",
                    "purpose": "node.attach",
                    "url": "ws://localhost:8000/fame/v1/attach/ws/downstream",
                    "auth": {"type": "NoAuth"},
                }
            ],
        },
    },
}
```

### RPC Service Implementation
```python
class CalculatorService(FameRPCService):
    async def handle_rpc_request(self, method: str, params: dict) -> any:
        kwargs = params.get("kwargs", {})
        if method == "add":
            return kwargs.get("a", 0) + kwargs.get("b", 0)
        # ... other methods
```
