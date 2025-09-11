#!/usr/bin/env python3
"""
Custom Sentinel serving script for RPC integration tests.
Serves a Sentinel with Calculator service using proper FameFabric.get_or_create() pattern.
"""

import asyncio
from typing import List, Optional

from naylence.fame.core import FameFabric, FameRPCService
from naylence.fame.service.rpc import RpcMixin, operation
from naylence.fame.util.logging import enable_logging

enable_logging(log_level="trace")


class CalculatorService(RpcMixin, FameRPCService):
    """Simple calculator service for RPC testing using @operation decorators."""

    @property
    def capabilities(self) -> Optional[List[str]]:
        """Declare capabilities for this service."""
        return ["calculator", "math"]

    @operation
    async def add(self, a: float, b: float) -> float:
        """Add two numbers."""
        result = a + b
        print(f"🧮 Calculator.add({a}, {b}) = {result}")
        return result

    @operation
    async def multiply(self, a: float, b: float) -> float:
        """Multiply two numbers."""
        result = a * b
        print(f"🧮 Calculator.multiply({a}, {b}) = {result}")
        return result

    @operation
    async def divide(self, a: float, b: float) -> float:
        """Divide two numbers."""
        if b == 0:
            print(f"🧮 Calculator.divide({a}, {b}) = ERROR: Division by zero")
            raise ValueError("Division by zero")
        result = a / b
        print(f"🧮 Calculator.divide({a}, {b}) = {result}")
        return result

    @operation(name="fib_stream", streaming=True)
    async def fib(self, n: int):
        a, b = 0, 1
        for _ in range(n):
            yield a
            a, b = b, a + b


async def main():
    """Start sentinel with calculator service using proper FameFabric pattern."""
    print("🚀 Starting Sentinel with Calculator service...")

    # Use the dev_mode SENTINEL_CONFIG pattern
    SENTINEL_CONFIG = {
        "node": {
            "type": "Sentinel",
            "id": "test-sentinel",
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
            "delivery": {
                "type": "DeliveryProfile",
                "profile": "at-most-once",
            },
        },
    }

    # Use the correct FameFabric.get_or_create() pattern
    async with FameFabric.get_or_create(root_config=SENTINEL_CONFIG, log_level="trace") as fabric:
        print("✅ Sentinel fabric started")

        # Serve the calculator service
        calculator = CalculatorService()
        calc_address = await fabric.serve(calculator, "calculator")
        print(f"📊 Calculator service available at: {calc_address}")

        print("🎯 Sentinel ready for RPC calls")
        print("   - HTTP endpoint: http://localhost:8000")
        print("   - WebSocket endpoint: ws://localhost:8000")
        print("   - Calculator service: calculator@fame.fabric")

        # Keep running until interrupted
        try:
            while True:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            print("\n🛑 Shutting down sentinel...")

    print("✅ Sentinel stopped")


if __name__ == "__main__":
    asyncio.run(main())
