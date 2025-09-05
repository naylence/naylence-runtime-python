"""
Tests for telemetry factory implementations.
"""

from naylence.fame.telemetry.noop_trace_emitter import NoopTraceEmitter
from naylence.fame.telemetry.noop_trace_emitter_factory import (
    NoopTraceEmitterConfig,
    NoopTraceEmitterFactory,
)
from naylence.fame.telemetry.open_telemetry_trace_emitter import OpenTelemetryTraceEmitter
from naylence.fame.telemetry.open_telemetry_trace_emitter_factory import (
    OpenTelemetryTraceEmitterConfig,
    OpenTelemetryTraceEmitterFactory,
)
from naylence.fame.telemetry.trace_emitter_factory import TraceEmitterFactory


class TestNoopTraceEmitterFactory:
    """Test cases for NoopTraceEmitterFactory."""

    async def test_create_noop_trace_emitter(self):
        """Test creating a NoopTraceEmitter instance."""
        factory = NoopTraceEmitterFactory()
        config = NoopTraceEmitterConfig()

        emitter = await factory.create(config)

        assert isinstance(emitter, NoopTraceEmitter)

    async def test_create_via_base_factory(self):
        """Test creating a NoopTraceEmitter via the base factory."""
        config = NoopTraceEmitterConfig()

        emitter = await TraceEmitterFactory.create_trace_emitter(config)

        assert isinstance(emitter, NoopTraceEmitter)

    async def test_span_functionality(self):
        """Test basic span functionality with NoopTraceEmitter."""
        config = NoopTraceEmitterConfig()
        emitter = await TraceEmitterFactory.create_trace_emitter(config)

        with emitter.start_span("test-span") as span:
            span.set_attribute("key", "value")
            span.record_exception(ValueError("test"))
            span.set_status_error("test error")

        # No assertions needed - noop implementation should handle all calls gracefully


class TestOpenTelemetryTraceEmitterFactory:
    """Test cases for OpenTelemetryTraceEmitterFactory."""

    async def test_create_opentelemetry_trace_emitter(self):
        """Test creating an OpenTelemetryTraceEmitter instance."""
        factory = OpenTelemetryTraceEmitterFactory()
        config = OpenTelemetryTraceEmitterConfig(service_name="test-service")

        emitter = await factory.create(config)

        assert isinstance(emitter, OpenTelemetryTraceEmitter)

    async def test_create_via_base_factory(self):
        """Test creating an OpenTelemetryTraceEmitter via the base factory."""
        config = OpenTelemetryTraceEmitterConfig(service_name="test-service")

        emitter = await TraceEmitterFactory.create_trace_emitter(config)

        assert isinstance(emitter, OpenTelemetryTraceEmitter)

    async def test_create_with_dict_config(self):
        """Test creating with dictionary configuration."""
        config = {"type": "OpenTelemetryTraceEmitter", "service_name": "dict-service"}

        emitter = await TraceEmitterFactory.create_trace_emitter(config)

        assert isinstance(emitter, OpenTelemetryTraceEmitter)

    async def test_create_with_default_config(self):
        """Test creating with default configuration."""
        factory = OpenTelemetryTraceEmitterFactory()

        emitter = await factory.create()

        assert isinstance(emitter, OpenTelemetryTraceEmitter)

    async def test_span_functionality(self):
        """Test basic span functionality with OpenTelemetryTraceEmitter."""
        config = OpenTelemetryTraceEmitterConfig(service_name="test-service")
        emitter = await TraceEmitterFactory.create_trace_emitter(config)

        with emitter.start_span("test-span", attributes={"initial": "value"}) as span:
            span.set_attribute("key", "value")
            span.record_exception(ValueError("test"))
            span.set_status_error("test error")

        # Basic functionality test - no specific assertions needed for OpenTelemetry internals


class TestTraceEmitterConfig:
    """Test cases for configuration classes."""

    def test_noop_config_defaults(self):
        """Test NoopTraceEmitterConfig defaults."""
        config = NoopTraceEmitterConfig()

        assert config.type == "NoopTraceEmitter"

    def test_opentelemetry_config_defaults(self):
        """Test OpenTelemetryTraceEmitterConfig defaults."""
        config = OpenTelemetryTraceEmitterConfig()

        assert config.type == "OpenTelemetryTraceEmitter"
        assert config.service_name == "naylence-service"

    def test_opentelemetry_config_custom_service_name(self):
        """Test OpenTelemetryTraceEmitterConfig with custom service name."""
        config = OpenTelemetryTraceEmitterConfig(service_name="custom-service")

        assert config.service_name == "custom-service"
