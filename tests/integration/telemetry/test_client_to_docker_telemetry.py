"""
Telemetry Integration Tests - Client to Docker Sentinel
Tests telemetry functionality from local client to Docker telemetry sentinel
using proper FameFabric pattern.
"""

import asyncio
import time
from typing import Any

import pytest
from opentelemetry import trace

from naylence.fame.core import FameAddress, FameFabric
from naylence.fame.service import RpcProxy


@pytest.mark.asyncio
async def test_telemetry_service_to_service_integration(telemetry_services, telemetry_client_config):
    """Test telemetry functionality from client to telemetry sentinel via docker-compose."""
    print("🚀 Starting telemetry client test - connecting to Docker telemetry sentinel...")

    # Update client config with actual service URLs from docker-compose
    sentinel_url = telemetry_services["sentinel_url"]
    websocket_url = sentinel_url.replace("http://", "ws://") + "/fame/v1/attach/ws/downstream"
    otel_grpc_url = f"http://{telemetry_services['otel_collector_grpc']}"

    # Update the connection grant URL to use the actual service URL
    telemetry_client_config["node"]["admission"]["connection_grants"][0]["url"] = websocket_url

    # Update the telemetry exporter endpoint (config is flattened)
    telemetry_client_config["node"]["telemetry"]["endpoint"] = otel_grpc_url

    try:
        # Create client fabric with telemetry enabled
        async with FameFabric.create(root_config=telemetry_client_config):
            print("✅ Telemetry client fabric created and connected to Docker sentinel")

            # Create RPC proxy for telemetry test service
            telemetry_service = RpcProxy(address=FameAddress("telemetry-test@/telemetry-test-sentinel"))

            print("📊 Testing Telemetry service operations...")

            # Test basic data processing with telemetry
            test_data = {"operation": "test_process", "value": 42, "timestamp": time.time()}
            result: Any = await telemetry_service.process_data(data=test_data)
            print(f"✅ TelemetryService.process_data({test_data}) = {result}")
            assert result["processed"] is True
            assert result["input"] == test_data
            assert result["result_count"] == len(test_data)

            # Test nested operations to generate span hierarchies
            operation_count = 3
            result = await telemetry_service.trigger_nested_operations(operation_count=operation_count)
            print(f"✅ TelemetryService.trigger_nested_operations(count={operation_count}) = {result}")
            assert result["completed"] is True
            assert result["total_count"] == operation_count
            assert len(result["nested_operations"]) == operation_count

            # Test error handling with telemetry
            with pytest.raises(Exception) as exc_info:
                await telemetry_service.generate_error(error_type="value_error")

            assert "Test error of type: value_error" in str(exc_info.value)
            print(f"✅ TelemetryService properly handles errors with telemetry: {exc_info.value}")

            print("🎉 All Telemetry service tests passed!")

            # Give telemetry time to flush
            print("⏳ Waiting for telemetry data to flush...")
            await asyncio.sleep(2)

    except Exception as e:
        print(f"❌ Error during telemetry client test: {e}")
        raise

    print("✅ Telemetry client test completed successfully")


@pytest.mark.asyncio
async def test_telemetry_trace_correlation(telemetry_services, telemetry_client_config):
    """Test trace correlation between client and service."""
    print("🔗 Testing telemetry trace correlation...")

    # Update client config with actual service URLs
    sentinel_url = telemetry_services["sentinel_url"]
    websocket_url = sentinel_url.replace("http://", "ws://") + "/fame/v1/attach/ws/downstream"
    otel_grpc_url = f"http://{telemetry_services['otel_collector_grpc']}"

    telemetry_client_config["node"]["admission"]["connection_grants"][0]["url"] = websocket_url
    telemetry_client_config["node"]["telemetry"]["endpoint"] = otel_grpc_url

    try:
        async with FameFabric.create(root_config=telemetry_client_config):
            print("✅ Telemetry client fabric created for trace correlation test")

            telemetry_service = RpcProxy(address=FameAddress("telemetry-test@/telemetry-test-sentinel"))

            # Create a custom tracer to generate parent spans
            tracer = trace.get_tracer(__name__)

            # Test multiple operations with different trace contexts
            test_scenarios = [
                {"scenario": "basic_operation", "data": {"test": "scenario_1"}},
                {"scenario": "complex_operation", "data": {"test": "scenario_2", "nested": {"value": 123}}},
                {"scenario": "error_operation", "data": {"test": "scenario_3"}},
            ]

            for scenario in test_scenarios:
                with tracer.start_as_current_span(f"client_operation_{scenario['scenario']}") as span:
                    span.set_attribute("test.scenario", scenario["scenario"])
                    span.set_attribute("test.client", "fame-telemetry-test-client")

                    try:
                        if scenario["scenario"] == "error_operation":
                            # This should generate error telemetry
                            with pytest.raises(Exception):
                                await telemetry_service.generate_error(error_type="runtime_error")
                            print(f"✅ Error scenario handled: {scenario['scenario']}")
                        else:
                            # Normal operations
                            result: Any = await telemetry_service.process_data(
                                data=scenario["data"], trace_context={"scenario": scenario["scenario"]}
                            )
                            print(
                                f"✅ Trace correlation test - {scenario['scenario']}: {result['processed']}"
                            )

                    except Exception as e:
                        if scenario["scenario"] != "error_operation":
                            print(f"❌ Unexpected error in scenario {scenario['scenario']}: {e}")
                            raise
                        # Expected error for error_operation scenario
                        span.set_attribute("test.expected_error", True)

                    # Small delay between scenarios
                    await asyncio.sleep(0.5)

            print("🎉 All trace correlation tests passed!")

            # Give telemetry extra time to process correlation data
            print("⏳ Waiting for trace correlation data to flush...")
            await asyncio.sleep(3)

    except Exception as e:
        print(f"❌ Error during trace correlation test: {e}")
        raise

    print("✅ Trace correlation test completed successfully")


@pytest.mark.asyncio
async def test_telemetry_performance_and_overhead(telemetry_services, telemetry_client_config):
    """Test telemetry performance impact and overhead."""
    print("⚡ Testing telemetry performance and overhead...")

    # Update client config
    sentinel_url = telemetry_services["sentinel_url"]
    websocket_url = sentinel_url.replace("http://", "ws://") + "/fame/v1/attach/ws/downstream"
    otel_grpc_url = f"http://{telemetry_services['otel_collector_grpc']}"

    telemetry_client_config["node"]["admission"]["connection_grants"][0]["url"] = websocket_url
    telemetry_client_config["node"]["telemetry"]["endpoint"] = otel_grpc_url

    try:
        async with FameFabric.create(root_config=telemetry_client_config):
            print("✅ Telemetry client fabric created for performance test")

            telemetry_service = RpcProxy(address=FameAddress("telemetry-test@/telemetry-test-sentinel"))

            # Performance test: multiple rapid operations
            operation_count = 10
            start_time = time.time()

            results = []
            for i in range(operation_count):
                result = await telemetry_service.process_data(
                    data={"operation_id": i, "batch": "performance_test"}
                )
                results.append(result)

                # No delay - test rapid fire operations

            end_time = time.time()
            total_duration = end_time - start_time
            avg_duration = total_duration / operation_count

            print("✅ Performance test completed:")
            print(f"   - Operations: {operation_count}")
            print(f"   - Total time: {total_duration:.3f}s")
            print(f"   - Avg per operation: {avg_duration:.3f}s")
            print(f"   - Operations/sec: {operation_count / total_duration:.2f}")

            # Verify all operations completed successfully
            assert len(results) == operation_count
            for i, result in enumerate(results):
                assert result["processed"] is True
                assert result["input"]["operation_id"] == i

            print("🎉 Performance test passed!")

            # Allow telemetry to flush
            await asyncio.sleep(2)

    except Exception as e:
        print(f"❌ Error during performance test: {e}")
        raise

    print("✅ Performance test completed successfully")
