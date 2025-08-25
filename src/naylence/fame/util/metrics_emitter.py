from __future__ import annotations

from typing import Mapping, Optional, Protocol


class MetricsEmitter(Protocol):
    """
    Protocol for emitting metrics such as counters, gauges, and histograms.
    Implementations should be thread-safe and non-blocking.
    """

    def counter(self, name: str, value: float, tags: Optional[Mapping[str, str]] = None) -> None: ...

    def gauge(self, name: str, value: float, tags: Optional[Mapping[str, str]] = None) -> None: ...

    def histogram(self, name: str, value: float, tags: Optional[Mapping[str, str]] = None) -> None: ...


class NoOpMetricsEmitter:
    """
    A no-op implementation of MetricsEmitter that discards all metrics.
    """

    def counter(self, name: str, value: float, tags: Optional[Mapping[str, str]] = None) -> None:
        return

    def gauge(self, name: str, value: float, tags: Optional[Mapping[str, str]] = None) -> None:
        return

    def histogram(self, name: str, value: float, tags: Optional[Mapping[str, str]] = None) -> None:
        return


# Example Prometheus-based implementation (optional)
# Uncomment and install prometheus_client to use
#
# from prometheus_client import Counter, Gauge, Histogram
#
# _counters: dict[str, Counter] = {}
# _gauges: dict[str, Gauge] = {}
# _histograms: dict[str, Histogram] = {}
#
# class PrometheusMetricsEmitter:
#    def counter(self, name: str, value: float, tags: Mapping[str, str] = None) -> None:
#        c = _counters.get(name)
#        if c is None:
#            c = Counter(name, f"Counter metric {name}", list(tags.keys()) if tags else [])
#            _counters[name] = c
#        if tags:
#            c = c.labels(**tags)
#        c.inc(value)
#
#    def gauge(self, name: str, value: float, tags: Mapping[str, str] = None) -> None:
#        g = _gauges.get(name)
#        if g is None:
#            g = Gauge(name, f"Gauge metric {name}", list(tags.keys()) if tags else [])
#            _gauges[name] = g
#        if tags:
#            g = g.labels(**tags)
#        g.set(value)
#
#    def histogram(self, name: str, value: float, tags: Mapping[str, str] = None) -> None:
#        h = _histograms.get(name)
#        if h is None:
#            h = Histogram(name, f"Histogram metric {name}", list(tags.keys()) if tags else [])
#            _histograms[name] = h
#        if tags:
#            h = h.labels(**tags)
#        h.observe(value)
