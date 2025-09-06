#!/bin/bash

# Integration Test Runner for Telemetry
# This script runs the telemetry integration tests with Docker Compose

set -e

echo "🚀 Starting Telemetry Integration Tests"

# Get the absolute path to the script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

# Change to the project root directory
cd "$PROJECT_ROOT"

# Ensure we're in a virtual environment
if [[ -z "$VIRTUAL_ENV" ]]; then
    echo "⚠️  No virtual environment detected. Please activate your virtual environment first."
    echo "   Run: source .venv/bin/activate"
    exit 1
fi

# Change to telemetry test directory
cd "$SCRIPT_DIR"

# Run the integration tests
echo "🧪 Running telemetry integration tests..."
python -m pytest test_otel_integration.py -v --tb=short

echo "✅ Telemetry integration tests completed!"
