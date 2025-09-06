# Telemetry Integration Tests

This directory contains Docker Compose-based integration tests for the telemetry functionality in Naylence Runtime.

## Overview

The integration tests spin up real telemetry infrastructure including:

- **OpenTelemetry Collector**: Receives and processes telemetry data
- **Jaeger**: Distributed tracing backend for trace visualization
- **Prometheus**: Metrics collection and storage

## Test Structure

```
tests/integration/telemetry/
├── conftest.py                 # Pytest fixtures and test configuration
├── docker-compose.yml          # Service definitions for test infrastructure
├── otel-collector-config.yml   # OpenTelemetry Collector configuration
├── prometheus.yml              # Prometheus configuration
├── test_otel_integration.py    # Main integration tests
├── run_tests.sh               # Test runner script
└── README.md                  # This file
```

## Running Tests

### Prerequisites

1. **Docker & Docker Compose**: Must be installed and running
2. **Python Environment**: Activate your virtual environment
3. **Dependencies**: Install with `poetry install --with dev,observability`

### Quick Start

```bash
# From the project root
./tests/integration/telemetry/run_tests.sh
```

### Manual Execution

```bash
# Change to telemetry test directory
cd tests/integration/telemetry

# Start services manually (optional - tests handle this)
docker compose up -d

# Run tests
python -m pytest test_otel_integration.py -v

# Clean up
docker compose down --volumes
```

## Test Cases

### 1. Trace Emission to Jaeger (`test_trace_emission_to_jaeger`)
- Creates spans with envelope trace IDs
- Verifies traces appear in Jaeger
- Validates trace ID correlation

### 2. Envelope Trace ID Correlation (`test_envelope_trace_id_correlation`)
- Tests different envelope trace ID formats (short, exact, long)
- Validates deterministic conversion to OpenTelemetry trace IDs
- Ensures consistent trace correlation

### 3. Span Attributes Propagation (`test_span_attributes_propagation`)
- Verifies envelope attributes are properly set on spans
- Tests custom attribute addition
- Validates attribute visibility in Jaeger

## Service Endpoints

When services are running, you can access:

- **Jaeger UI**: http://localhost:16686
- **Prometheus**: http://localhost:9090
- **OpenTelemetry Collector**: 
  - gRPC: localhost:4317
  - HTTP: localhost:4318

## Configuration

### OpenTelemetry Collector
- Receives OTLP traces and metrics
- Exports to Jaeger and Prometheus
- Logs all data for debugging

### Jaeger
- Stores and visualizes distributed traces
- Provides REST API for test verification
- Accepts traces from OTel Collector

### Prometheus
- Collects metrics from OTel Collector
- Provides metrics storage and querying
- Web UI for metrics exploration

## Troubleshooting

### Services Not Starting
```bash
# Check service logs
docker compose logs

# Restart specific service
docker compose restart jaeger
```

### Port Conflicts
If you get port binding errors, ensure no other services are using:
- 4317, 4318 (OpenTelemetry)
- 16686 (Jaeger UI)
- 9090 (Prometheus)

### Test Failures
1. Check that all services are healthy
2. Verify trace data propagation (may take 1-2 seconds)
3. Review test logs for specific error details

## CI/CD Integration

These tests are designed to run in CI environments:

```yaml
# Example GitHub Actions step
- name: Run Telemetry Integration Tests
  run: |
    ./tests/integration/telemetry/run_tests.sh
```

## Extending Tests

To add new integration tests:

1. Add test methods to `test_otel_integration.py`
2. Use the `telemetry_services` fixture for service endpoints
3. Use the `otel_exporter_config` fixture for OTel configuration
4. Follow the existing pattern for trace verification via Jaeger API

## Architecture

```
[Test Code] -> [OTel SDK] -> [OTel Collector] -> [Jaeger/Prometheus]
                                ^
                                |
                            [Test Verification]
```

The tests create real telemetry data through the OpenTelemetry SDK, which flows through the complete telemetry pipeline, allowing for end-to-end validation of trace correlation and data propagation.
