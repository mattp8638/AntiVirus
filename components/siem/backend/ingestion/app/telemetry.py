"""Telemetry normalisation helpers for MVP-4."""
from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Iterable, List, Optional
import re

from .models import TelemetrySample


@dataclass(frozen=True)
class MetricRule:
    pattern: re.Pattern[str]
    unit: str
    description: str
    min_value: Optional[float] = None
    max_value: Optional[float] = None
    integer_only: bool = False


METRIC_RULES: List[MetricRule] = [
    MetricRule(
        pattern=re.compile(r"^cpu\.total\.percent$"),
        unit="percent",
        description="Total CPU usage across all cores",
        min_value=0.0,
        max_value=100.0,
    ),
    MetricRule(
        pattern=re.compile(r"^cpu\.core\.\d+\.percent$"),
        unit="percent",
        description="Per-core CPU usage percentage",
        min_value=0.0,
        max_value=100.0,
    ),
    MetricRule(
        pattern=re.compile(r"^cpu\.load\.(1m|5m|15m)$"),
        unit="load",
        description="System load average",
        min_value=0.0,
    ),
    MetricRule(
        pattern=re.compile(r"^cpu\.context_switches\.per_sec$"),
        unit="count_per_sec",
        description="Context switches per second",
        min_value=0.0,
    ),
    MetricRule(
        pattern=re.compile(r"^memory\.(total|used|available)\.bytes$"),
        unit="bytes",
        description="Memory usage in bytes",
        min_value=0.0,
        integer_only=True,
    ),
    MetricRule(
        pattern=re.compile(r"^memory\.swap\.used\.bytes$"),
        unit="bytes",
        description="Swap usage in bytes",
        min_value=0.0,
        integer_only=True,
    ),
    MetricRule(
        pattern=re.compile(r"^disk\.[a-zA-Z0-9_.-]+\.(total|used|free)\.bytes$"),
        unit="bytes",
        description="Disk usage in bytes",
        min_value=0.0,
        integer_only=True,
    ),
    MetricRule(
        pattern=re.compile(r"^disk\.[a-zA-Z0-9_.-]+\.percent$"),
        unit="percent",
        description="Disk usage percentage",
        min_value=0.0,
        max_value=100.0,
    ),
    MetricRule(
        pattern=re.compile(r"^disk\.[a-zA-Z0-9_.-]+\.io_wait\.percent$"),
        unit="percent",
        description="Disk IO wait percentage",
        min_value=0.0,
        max_value=100.0,
    ),
    MetricRule(
        pattern=re.compile(r"^network\.bytes\.(sent|received)$"),
        unit="bytes",
        description="Network throughput in bytes",
        min_value=0.0,
        integer_only=True,
    ),
    MetricRule(
        pattern=re.compile(r"^network\.packets\.(sent|received)$"),
        unit="count",
        description="Network packets per interval",
        min_value=0.0,
        integer_only=True,
    ),
    MetricRule(
        pattern=re.compile(r"^network\.errors\.(dropped|retransmit)$"),
        unit="count",
        description="Network error counters",
        min_value=0.0,
        integer_only=True,
    ),
    MetricRule(
        pattern=re.compile(r"^system\.uptime\.seconds$"),
        unit="seconds",
        description="System uptime in seconds",
        min_value=0.0,
        integer_only=True,
    ),
    MetricRule(
        pattern=re.compile(r"^system\.boot\.unix_seconds$"),
        unit="unix_seconds",
        description="System boot time as Unix epoch seconds",
        min_value=0.0,
        integer_only=True,
    ),
    MetricRule(
        pattern=re.compile(r"^system\.clock\.skew\.seconds$"),
        unit="seconds",
        description="Clock skew between agent and ingestion service",
    ),
    MetricRule(
        pattern=re.compile(r"^agent\.process\.healthy$"),
        unit="bool",
        description="Agent process health flag",
        min_value=0.0,
        max_value=1.0,
        integer_only=True,
    ),
]


class TelemetryValidationError(ValueError):
    """Raised when telemetry fails schema or unit validation."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _match_rule(metric_name: str) -> MetricRule:
    for rule in METRIC_RULES:
        if rule.pattern.match(metric_name):
            return rule
    raise TelemetryValidationError("unknown_metric")


def normalise_samples(samples: Iterable[TelemetrySample]) -> List[TelemetrySample]:
    normalised: List[TelemetrySample] = []
    for sample in samples:
        rule = _match_rule(sample.name)
        unit = sample.unit or rule.unit
        if unit != rule.unit:
            raise TelemetryValidationError("unit_mismatch")
        value = float(sample.value)
        if not math.isfinite(value):
            raise TelemetryValidationError("value_not_finite")
        if rule.integer_only:
            if value % 1 != 0:
                raise TelemetryValidationError("value_not_integer")
            value = float(int(value))
        if rule.min_value is not None and value < rule.min_value:
            raise TelemetryValidationError("value_below_min")
        if rule.max_value is not None and value > rule.max_value:
            raise TelemetryValidationError("value_above_max")
        normalised.append(
            TelemetrySample(
                name=sample.name,
                unit=unit,
                value=value,
                observed_at=sample.observed_at,
            )
        )
    return normalised


def metric_description(metric_name: str) -> str:
    return _match_rule(metric_name).description


def metric_unit(metric_name: str) -> str:
    return _match_rule(metric_name).unit
