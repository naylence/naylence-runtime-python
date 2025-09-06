#!/usr/bin/env python3
"""
Telemetry Sentinel serving script for telemetry integration tests.
Serves a Sentinel with OpenTelemetry integration for testing telemetry flow.
"""

import asyncio
import os
from typing import List, Optional

from naylence.fame.core import FameFabric, FameRPCService
from naylence.fame.service.rpc import RpcMixin, operation
from naylence.fame.util.logging import enable_logging

enable_logging(log_level="trace")


class TelemetryTestService(RpcMixin, FameRPCService):
    """Service for testing telemetry functionality."""

    @property
    def capabilities(self) -> Optional[List[str]]:
        """Declare capabilities for this service."""
        return ["telemetry", "testing"]

    @operation
    async def process_data(self, data: dict, trace_context: Optional[dict] = None) -> dict:
        """Process data and generate telemetry events."""
        print(f"📊 TelemetryTestService.process_data({data})")

        # Simulate some processing work that should be traced
        result = {
            "input": data,
            "processed": True,
            "result_count": len(data) if isinstance(data, dict) else 1,
            "trace_context": trace_context,
        }

        print(f"✅ TelemetryTestService.process_data result: {result}")
        return result

    @operation
    async def trigger_nested_operations(self, operation_count: int = 3) -> dict:
        """Trigger nested operations to test span hierarchies."""
        print(f"🔄 TelemetryTestService.trigger_nested_operations(count={operation_count})")

        results = []
        for i in range(operation_count):
            # Simulate nested work
            sub_result = await self._nested_operation(f"operation_{i}")
            results.append(sub_result)

            # Small delay to make spans more visible
            await asyncio.sleep(0.1)

        result = {"nested_operations": results, "total_count": operation_count, "completed": True}

        print(f"✅ TelemetryTestService.trigger_nested_operations result: {result}")
        return result

    async def _nested_operation(self, operation_name: str) -> dict:
        """Helper method for nested operations."""
        print(f"  🔧 Nested operation: {operation_name}")

        # Simulate some work
        await asyncio.sleep(0.05)

        return {"operation": operation_name, "timestamp": asyncio.get_event_loop().time(), "success": True}

    @operation
    async def generate_error(self, error_type: str = "generic") -> dict:
        """Generate an error for testing error telemetry."""
        print(f"💥 TelemetryTestService.generate_error(type={error_type})")

        if error_type == "value_error":
            raise ValueError(f"Test error of type: {error_type}")
        elif error_type == "runtime_error":
            raise RuntimeError(f"Test runtime error: {error_type}")
        else:
            raise Exception(f"Generic test error: {error_type}")


async def main():
    """Start sentinel with telemetry test service."""
    print("🚀 Starting Telemetry Test Sentinel...")

    # Get OpenTelemetry collector endpoint from environment
    otel_endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://otel-collector:4317")
    print(f"📡 OpenTelemetry endpoint: {otel_endpoint}")

    # Sentinel configuration with telemetry enabled
    SENTINEL_CONFIG = {
        "node": {
            "type": "Sentinel",
            "id": "telemetry-test-sentinel",
            "public_url": "http://localhost:8000",
            "listeners": [
                {
                    "type": "HttpListener",
                    "port": 8000,
                },
                {
                    "type": "WebSocketListener",
                    "port": 8000,
                },
            ],
            "requested_logicals": ["fame.fabric"],
            "security": {
                "type": "SecurityProfile",
                "profile": "open",
            },
            "admission": {
                "type": "AdmissionProfile",
                "profile": "none",
            },
            "storage": {
                "type": "StorageProfile",
                "profile": "memory",
            },
            "telemetry": {
                "type": "OpenTelemetryTraceEmitter",
                "service_name": "fame-telemetry-test-sentinel",
                "endpoint": otel_endpoint,
            },
        },
    }

    # Create telemetry-enabled fabric
    async with FameFabric.get_or_create(root_config=SENTINEL_CONFIG, log_level="trace") as fabric:
        print("✅ Telemetry Test Sentinel fabric started")

        # Serve the telemetry test service
        telemetry_service = TelemetryTestService()
        service_address = await fabric.serve(telemetry_service, "telemetry-test")
        print(f"📊 Telemetry Test service available at: {service_address}")

        print("🎯 Telemetry Test Sentinel ready")
        print("   - HTTP endpoint: http://localhost:8000")
        print("   - WebSocket endpoint: ws://localhost:8000")
        print("   - Telemetry service: telemetry-test@fame.fabric")
        print(f"   - OpenTelemetry exporter: {otel_endpoint}")

        # Keep running until interrupted
        try:
            while True:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            print("\n🛑 Shutting down telemetry sentinel...")

    print("✅ Telemetry Test Sentinel stopped")


if __name__ == "__main__":
    asyncio.run(main())
