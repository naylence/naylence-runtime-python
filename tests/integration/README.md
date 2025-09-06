# Integration Tests

This directory contains integration tests for the Naylence Fame runtime, organized with shared Docker infrastructure for efficiency.

## Shared Docker Infrastructure

### Build Once, Use Everywhere
All integration tests use a shared Docker image to avoid rebuilding the same environment multiple times:

```bash
# Build the shared integration image (run once)
./tests/integration/build-shared-image.sh
```

This creates `naylence-runtime-integration:latest` that all integration tests can use.

### Shared Resources
- `Dockerfile.test` - Universal Dockerfile for all integration tests
- `docker-compose.shared.yml` - Defines the shared image build and network
- `build-shared-image.sh` - Script to build the shared image
- `naylence-integration` network - Shared Docker network for inter-test communication

## Integration Test Categories

### RPC Integration Tests (`sentinel/rpc/`)
Tests RPC functionality between local clients and Docker-based sentinels:
- Local RPC testing
- Client-to-Docker RPC communication
- Error handling and telemetry integration

### Telemetry Integration Tests (`telemetry/`)
Tests OpenTelemetry integration with external observability infrastructure:
- Trace emission and correlation
- Metrics collection
- External collector integration

## Usage Pattern

1. **Build shared image once:**
   ```bash
   ./tests/integration/build-shared-image.sh
   ```

2. **Use shared image in your docker-compose.yml:**
   ```yaml
   services:
     your-service:
       image: naylence-runtime-integration:latest
       # ... your specific configuration
   
   networks:
     default:
       external: true
       name: naylence-integration
   ```

3. **Run your integration tests:**
   ```bash
   docker-compose up -d
   python your_test.py
   docker-compose down
   ```

## Benefits

- **Faster Testing**: Build image once, use across all tests
- **Consistency**: All tests use the same base environment
- **Resource Efficiency**: Reduced Docker build times and disk usage
- **Easy Maintenance**: Single Dockerfile to maintain for all integration tests
