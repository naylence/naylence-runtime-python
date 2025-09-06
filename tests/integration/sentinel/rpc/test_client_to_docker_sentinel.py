"""
RPC Integration Tests - Client to Docker Sentinel
Tests RPC calls from local client to Docker sentinel using proper DirectAdmissionClient.
"""

import pytest

from naylence.fame.core import FameAddress, FameFabric
from naylence.fame.service import RpcProxy


@pytest.mark.asyncio
async def test_client_to_docker_rpc_integration(rpc_docker_service, rpc_client_config):
    """Test RPC calls from local client to Docker sentinel via docker-compose."""
    print("🚀 Starting client test - connecting to Docker sentinel...")

    # Update client config with the actual sentinel URL from docker-compose
    sentinel_url = rpc_docker_service["url"]
    websocket_url = sentinel_url.replace("http://", "ws://") + "/fame/v1/attach/ws/downstream"

    # Update the connection grant URL to use the actual service URL
    rpc_client_config["node"]["admission"]["connection_grants"][0]["url"] = websocket_url

    try:
        # Create client fabric using the provided config
        async with FameFabric.create(root_config=rpc_client_config):
            print("✅ Client fabric created and connected to Docker sentinel")

            # Create RPC proxy for calculator service
            calculator = RpcProxy(address=FameAddress("calculator@/test-sentinel"))

            print("🧮 Testing Calculator RPC operations...")

            # Test add operation
            result = await calculator.add(a=5.0, b=3.0)
            print(f"✅ Calculator.add(5.0, 3.0) = {result}")
            assert result == 8.0, f"Expected 8.0, got {result}"

            # Test multiply operation
            result = await calculator.multiply(a=4.0, b=7.0)
            print(f"✅ Calculator.multiply(4.0, 7.0) = {result}")
            assert result == 28.0, f"Expected 28.0, got {result}"

            # Test divide operation
            result = await calculator.divide(a=15.0, b=3.0)
            print(f"✅ Calculator.divide(15.0, 3.0) = {result}")
            assert result == 5.0, f"Expected 5.0, got {result}"

            # Test error handling
            with pytest.raises(Exception) as exc_info:
                await calculator.divide(a=10.0, b=0.0)

            assert "Division by zero" in str(exc_info.value)
            print(f"✅ Calculator properly handles division by zero: {exc_info.value}")

            fib_numbers = []
            async for v in await calculator.fib_stream(_stream=True, n=10):
                print(v, end=" ")
                fib_numbers.append(v)
            assert fib_numbers == [0, 1, 1, 2, 3, 5, 8, 13, 21, 34], (
                f"Expected Fibonacci sequence, got {fib_numbers}"
            )
            print()

            print("🎉 All Calculator RPC tests passed!")

    except Exception as e:
        print(f"❌ Error during client test: {e}")
        raise

    print("✅ Client test completed successfully")


# if __name__ == "__main__":
#     # Allow script to be run directly for development/debugging
#     async def main():
#         """Test connecting to Docker sentinel and calling Calculator service."""
#         print("🚀 Starting client test - connecting to Docker sentinel...")

#         # Client configuration with DirectAdmissionClient to connect to Docker sentinel
#         CLIENT_CONFIG = {
#             "node": {
#                 "type": "Node",
#                 "id": "test-client",
#                 "admission": {
#                     "type": "DirectAdmissionClient",
#                     "connection_grants": [
#                         {
#                             "type": "WebSocketConnectionGrant",
#                             "purpose": "node.attach",
#                             "url": "ws://localhost:8000/fame/v1/attach/ws/downstream",
#                             "auth": {
#                                 "type": "NoAuth",
#                             },
#                         }
#                     ],
#                 },
#             },
#         }

#         try:
#             # Create client fabric using FameFabric.create()
#             async with FameFabric.create(root_config=CLIENT_CONFIG) as fabric:
#                 print("✅ Client fabric created and connected to Docker sentinel")

#                 # Create RPC proxy for calculator service
#                 calculator = RpcProxy(address=FameAddress("calculator@/test-sentinel"))

#                 print("🧮 Testing Calculator RPC operations...")

#                 # Test add operation
#                 result = await calculator.add(a=5.0, b=3.0)
#                 print(f"✅ Calculator.add(5.0, 3.0) = {result}")
#                 assert result == 8.0, f"Expected 8.0, got {result}"

#                 # Test multiply operation
#                 result = await calculator.multiply(a=4.0, b=7.0)
#                 print(f"✅ Calculator.multiply(4.0, 7.0) = {result}")
#                 assert result == 28.0, f"Expected 28.0, got {result}"

#                 # Test divide operation
#                 result = await calculator.divide(a=15.0, b=3.0)
#                 print(f"✅ Calculator.divide(15.0, 3.0) = {result}")
#                 assert result == 5.0, f"Expected 5.0, got {result}"

#                 # Test error handling
#                 try:
#                     await calculator.divide(a=10.0, b=0.0)
#                     assert False, "Expected Exception for division by zero"
#                 except Exception as e:
#                     if "Division by zero" in str(e):
#                         print(f"✅ Calculator properly handles division by zero: {e}")
#                     else:
#                         print(f"❌ Unexpected error: {e}")
#                         raise

#                 print("🎉 All Calculator RPC tests passed!")

#         except Exception as e:
#             print(f"❌ Error during client test: {e}")
#             import traceback
#             traceback.print_exc()
#             sys.exit(1)

#         print("✅ Client test completed successfully")

#     asyncio.run(main())
