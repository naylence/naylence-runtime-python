"""
Local RPC test - test Calculator service without Docker to verify basic RPC functionality.
Tests the pattern: async with FameFabric.get_or_create() -> bind service -> get proxy -> invoke proxy
"""

from typing import List, Optional

import pytest

from naylence.fame.core import FameFabric, FameRPCService
from naylence.fame.service import RpcProxy
from naylence.fame.service.rpc import RpcMixin, operation


class CalculatorService(RpcMixin, FameRPCService):
    """Simple calculator service for RPC testing using @operation decorators."""

    @property
    def capabilities(self) -> Optional[List[str]]:
        """Declare capabilities for this service."""
        return ["calculator", "math"]

    # Use the RpcMixin implementation without override
    # The generic implementation is inherited from RpcMixin

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


@pytest.mark.asyncio
async def test_local_rpc():
    """Test RPC service locally using FameFabric.get_or_create() pattern."""
    print("🚀 Starting local RPC test...")

    try:
        # Use FameFabric.get_or_create() pattern
        async with FameFabric.get_or_create() as fabric:
            print("✅ Local fabric created")

            # Bind service
            calculator_service = CalculatorService()
            calc_address = await fabric.serve(calculator_service, "calculator")
            print(f"📊 Calculator service bound at: {calc_address}")

            # Get proxy
            calculator_proxy = RpcProxy(address=calc_address)
            print(f"🔗 RPC proxy created for: {calc_address}")

            # Invoke proxy - test add operation
            print("\n🧮 Testing Calculator RPC operations...")

            result = await calculator_proxy.add(a=5.0, b=3.0)
            print(f"✅ Calculator.add(5.0, 3.0) = {result}")
            assert result == 8.0, f"Expected 8.0, got {result}"

            # Test multiply operation
            result = await calculator_proxy.multiply(a=4.0, b=7.0)
            print(f"✅ Calculator.multiply(4.0, 7.0) = {result}")
            assert result == 28.0, f"Expected 28.0, got {result}"

            # Test divide operation
            result = await calculator_proxy.divide(a=15.0, b=3.0)
            print(f"✅ Calculator.divide(15.0, 3.0) = {result}")
            assert result == 5.0, f"Expected 5.0, got {result}"

            # Test error handling
            try:
                await calculator_proxy.divide(a=10.0, b=0.0)
                assert False, "Expected Exception for division by zero"
            except Exception as e:
                if "Division by zero" in str(e):
                    print(f"✅ Division by zero properly handled: {e}")
                else:
                    print(f"❌ Unexpected error: {e}")
                    raise

            async for v in await calculator_proxy.fib_stream(_stream=True, n=10):
                print(v, end=" ")
            print()

            print("\n🎉 All local RPC tests passed!")

    except Exception as e:
        print(f"❌ Error during local RPC test: {e}")
        import traceback

        traceback.print_exc()
        return False

    return True


# if __name__ == "__main__":
#     success = asyncio.run(main())
#     sys.exit(0 if success else 1)
