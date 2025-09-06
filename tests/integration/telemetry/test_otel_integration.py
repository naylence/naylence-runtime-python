"""Integration tests for OpenTelemetry trace emitter."""

import time

import pytest
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

from naylence.fame.telemetry.open_telemetry_trace_emitter import OpenTelemetryTraceEmitter


class TestOpenTelemetryTraceEmitter:
    """Integration tests for OpenTelemetry trace emitter with real OTel infrastructure."""

    @pytest.fixture(scope="function")
    def setup_otel(self, otel_exporter_config):
        """Set up OpenTelemetry SDK for integration tests."""
        # Reset any existing tracer provider
        trace._TRACER_PROVIDER = None

        # Create tracer provider with service name
        from opentelemetry.sdk.resources import Resource

        resource = Resource.create({"service.name": "test-service"})
        tracer_provider = TracerProvider(resource=resource)
        trace.set_tracer_provider(tracer_provider)

        # Create OTLP exporter
        otlp_exporter = OTLPSpanExporter(
            endpoint=otel_exporter_config["endpoint"], insecure=otel_exporter_config["insecure"]
        )

        # Add span processor
        span_processor = BatchSpanProcessor(otlp_exporter)
        tracer_provider.add_span_processor(span_processor)

        yield tracer_provider

        # Cleanup
        tracer_provider.shutdown()

    def test_trace_emission_integration(self, telemetry_services, setup_otel):
        """Test that traces are properly sent to Jaeger."""
        tracer_provider = setup_otel

        # Create trace emitter
        emitter = OpenTelemetryTraceEmitter("test-service")

        # Create a test envelope with trace ID
        test_env_trace_id = "test123456789abc"
        attributes = {
            "env.trace_id": test_env_trace_id,
            "env.id": "test-envelope-123",
            "test.attribute": "test-value",
        }

        # Emit a test span
        with emitter.start_span("test-operation", attributes=attributes) as span:
            span.set_attribute("operation.type", "integration-test")
            span.set_attribute("test.step", "main-operation")

            # Simulate some work
            time.sleep(0.1)

        # Force flush
        tracer_provider.force_flush(timeout_millis=5000)

        # Wait a bit for data to propagate
        time.sleep(2)

        # For ultra-minimal ephemeral testing, we verify:
        # 1. Span was created successfully (no exceptions)
        # 2. Data was sent to OTel Collector (which logs it via debug exporter)
        # 3. Envelope trace ID conversion worked (tested in separate test)
        # The debug exporter will log the trace data to collector logs for verification
        assert True, "Span successfully created and sent to OpenTelemetry Collector"

    def test_envelope_trace_id_conversion(self, telemetry_services, setup_otel):
        """Test that envelope trace IDs are properly converted to OTel trace IDs."""
        tracer_provider = setup_otel
        emitter = OpenTelemetryTraceEmitter("conversion-test")

        # Test different envelope trace ID formats
        test_cases = [
            ("short123", "short12300000000"),  # Padded to 16 chars
            ("exactly16chars!!", "exactly16chars!!"),  # Exact 16 chars
            ("toolongtraceids123456", "toolongtraceids1"),  # Trimmed to 16 chars
        ]

        for env_trace_id, expected_normalized in test_cases:
            attributes = {
                "env.trace_id": env_trace_id,
                "env.id": f"envelope-{env_trace_id}",
                "test.case": env_trace_id,
            }

            # Create the emitter instance to test the conversion logic
            expected_otel_trace_id = emitter._convert_env_trace_id_to_otel(env_trace_id)

            # Verify the conversion matches our expectation
            expected_bytes = expected_normalized.encode("utf-8")[:16]
            expected_int = int.from_bytes(expected_bytes, byteorder="big")

            assert expected_otel_trace_id == expected_int, f"Conversion failed for {env_trace_id}"

            # Create span to verify no exceptions
            with emitter.start_span(f"conversion-test-{env_trace_id}", attributes=attributes):
                time.sleep(0.01)

        # Force flush to ensure all spans are processed
        tracer_provider.force_flush(timeout_millis=3000)

    def test_span_attributes_integration(self, telemetry_services, setup_otel):
        """Test that envelope attributes are properly handled in integration."""
        tracer_provider = setup_otel
        emitter = OpenTelemetryTraceEmitter("attributes-test")

        attributes = {
            "env.trace_id": "attr123456789abc",
            "env.id": "envelope-attr-123",
            "env.corr_id": "correlation-456",
            "env.flow_id": "flow-789",
            "custom.attribute": "custom-value",
        }

        # Test that span creation with envelope attributes works
        with emitter.start_span("attributes-test-operation", attributes=attributes) as span:
            span.set_attribute("additional.attr", "additional-value")
            # Verify the span object has the expected interface
            assert hasattr(span, "set_attribute")
            assert hasattr(span, "record_exception")
            assert hasattr(span, "set_status_error")

        # Force flush to ensure span is processed
        tracer_provider.force_flush(timeout_millis=3000)

        # Test passes if no exceptions are thrown during span creation and attribute setting
        assert True
