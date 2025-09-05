from sys import exc_info
from typing import Optional

from naylence.fame.util import logging

logger = logging.getLogger(__name__)


def setup_otel(
    *,
    service_name: str,
    endpoint: Optional[str] = None,
    environment: Optional[str] = None,
    sampler: str = "parentbased_always_on",
    headers: Optional[dict[str, str]] = None,
) -> None:
    try:
        from opentelemetry import trace
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
        from opentelemetry.sdk.trace.sampling import ALWAYS_OFF, ALWAYS_ON, ParentBased, TraceIdRatioBased

        provider = trace.get_tracer_provider()
        if not isinstance(provider, TracerProvider):
            # Build a provider only once
            res = Resource.create(
                {
                    "service.name": service_name,
                    "service.instance.id": __import__("uuid").uuid4().hex,
                    "deployment.environment": environment or "dev",
                }
            )
            provider = TracerProvider(resource=res)

            # Sampler
            sampler = sampler.lower()
            base = (
                ALWAYS_OFF
                if sampler == "always_off"
                else TraceIdRatioBased(float(sampler.split("ratio:")[1]))
                if sampler.startswith("ratio:")
                else ALWAYS_ON
            )
            provider.sampler = ParentBased(base)

            # Exporter
            if endpoint:
                from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

                exporter = OTLPSpanExporter(endpoint=endpoint, headers=headers)
            else:
                exporter = ConsoleSpanExporter()

            provider.add_span_processor(BatchSpanProcessor(exporter))
            trace.set_tracer_provider(provider)
    except ImportError:
        # OTel not installed → quietly do nothing
        logger.error("open_telemetry_not_available", error=exc_info)
        return
