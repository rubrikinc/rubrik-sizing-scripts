"""Shared utilities for all Rubrik Discovery collectors."""

from __future__ import annotations

import logging
import re
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import gaps

logger = logging.getLogger(__name__)


def enum_text(value: Any) -> Optional[str]:
    """Plain text of an SDK enum member or string; None stays None.

    ``str()`` of an Azure SDK enum member gives ``Kind.STORAGE_V2``, not the API value
    ``StorageV2``, so collectors must read ``.value`` instead.
    """
    if value is None:
        return None
    return str(getattr(value, "value", value))


def decimal_gb(num_bytes: Optional[float]) -> Optional[float]:
    """Decimal GB (10**9 bytes), 3 decimals, as PowerShell reports it. None-safe."""
    return None if num_bytes is None else round(num_bytes / 1e9, 3)


def decimal_tb(num_bytes: Optional[float]) -> Optional[float]:
    """Decimal TB (10**12 bytes), 4 decimals, as PowerShell reports it. None-safe."""
    return None if num_bytes is None else round(num_bytes / 1e12, 4)


def metric_timespan(start: datetime, end: datetime) -> str:
    """The ``timespan`` of an Azure Monitor metrics query: two UTC instants ending in ``Z``.

    ``datetime.isoformat()`` of an aware datetime gives ``2026-10-14T07:43:08.151577+00:00``. Azure
    Monitor answers that with ``BadRequest: Detected invalid time interval input``, so every metrics
    query of a run failed and storage capacity came out blank.
    """

    def instant(moment: datetime) -> str:
        return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    return f"{instant(start)}/{instant(end)}"


_warned: set = set()
_warned_lock = threading.Lock()


def warn_once(message: str, *args: Any) -> None:
    """Log a warning the first time this cause is seen in the run, however often it recurs.

    Two messages are the same cause when they differ only in digits, so a failure repeated for 249
    accounts is one line on the screen. Failures are still counted where they happen.
    """
    text = message % args if args else message
    # Counted for the subscription it names even when it is not shown again (see gaps.py): the same
    # cause in a second subscription is still a gap in that subscription.
    gaps.note(text)
    key = re.sub(r"\d+", "#", text)[:120]
    with _warned_lock:
        if key in _warned:
            return
        _warned.add(key)
    logger.warning(message, *args, extra={gaps.ALREADY_COUNTED: True})


def latest_maximum(
    monitor: Any, resource_id: str, metric_name: str, namespace: Optional[str] = None
) -> Optional[float]:
    """Latest non-null hourly Maximum of a metric over the last day, or None.

    PowerShell reads ``(Get-AzMetric -AggregationType Maximum ...).Data.Maximum | Select -Last 1``.
    Best-effort: a failed or empty query returns None and never raises.
    """
    if not resource_id:
        return None
    end = datetime.now(timezone.utc)
    timespan = metric_timespan(end - timedelta(days=1), end)
    try:
        result = monitor.metrics.list(
            resource_uri=resource_id,
            timespan=timespan,
            interval="PT1H",
            metricnames=metric_name,
            aggregation="Maximum",
            metricnamespace=namespace,
        )
        for metric in result.value:
            for series in metric.timeseries:
                for point in reversed(series.data):
                    value = getattr(point, "maximum", None)
                    if value is not None:
                        return value
    except Exception as exc:
        logger.debug("%s unavailable for %s: %s", metric_name, resource_id[:60], exc)
        warn_once(
            "Azure Monitor metric query failed (the same failure is not repeated): %s: %s",
            type(exc).__name__,
            " ".join(str(exc).split())[:240],
        )
    return None


@dataclass
class TagSummary:
    """Summary of tag coverage across a set of Azure resources."""

    key_coverage: dict[str, float] = field(default_factory=dict)
    """Percentage of resources that have each tag key (0.0–100.0)."""

    common_values: dict[str, dict[str, int]] = field(default_factory=dict)
    """Top values per tag key: {key: {value: count}}."""

    untagged_count: int = 0
    """Number of resources with no tags at all."""

    untagged_pct: float = 0.0
    """Percentage of resources with no tags (0.0–100.0)."""

    missing_keys: list[str] = field(default_factory=list)
    """Tag keys with < 50% coverage — governance signal."""


def build_tag_summary(resources_tags: list[Optional[dict[str, str]]]) -> TagSummary:
    """Build a TagSummary from a list of resource tag dicts.

    Args:
        resources_tags: One dict per resource (use None or ``{}`` for untagged).

    Returns:
        Populated TagSummary dataclass.
    """
    total = len(resources_tags)
    if total == 0:
        return TagSummary()

    untagged_count = sum(1 for t in resources_tags if not t)

    key_counts: dict[str, int] = {}
    value_dist: dict[str, dict[str, int]] = {}

    for tags in resources_tags:
        if not tags:
            continue
        for k, v in tags.items():
            key_counts[k] = key_counts.get(k, 0) + 1
            inner = value_dist.setdefault(k, {})
            inner[v] = inner.get(v, 0) + 1

    key_coverage = {k: round(count / total * 100, 1) for k, count in key_counts.items()}

    # Keep only the top 5 values per key for compactness.
    common_values = {
        k: dict(sorted(vals.items(), key=lambda x: x[1], reverse=True)[:5])
        for k, vals in value_dist.items()
    }

    missing_keys = [k for k, pct in key_coverage.items() if pct < 50.0]

    return TagSummary(
        key_coverage=key_coverage,
        common_values=common_values,
        untagged_count=untagged_count,
        untagged_pct=round(untagged_count / total * 100, 1),
        missing_keys=missing_keys,
    )


def parse_resource_group(resource_id: str) -> str:
    """Extract the resource group name from an ARM resource ID.

    Args:
        resource_id: Full ARM resource ID string.

    Returns:
        Resource group name, or empty string if not parseable.
    """
    parts = resource_id.split("/")
    lower_parts = resource_id.lower().split("/")
    try:
        idx = lower_parts.index("resourcegroups")
        return parts[idx + 1]
    except (ValueError, IndexError):
        return ""


def parse_resource_name(resource_id: str) -> Optional[str]:
    """Extract the resource name (final path segment) from an ARM resource ID.

    Args:
        resource_id: Full ARM resource ID string.

    Returns:
        Resource name, or None if the ID is empty/unparseable.
    """
    if not resource_id:
        return None
    name = resource_id.rstrip("/").split("/")[-1]
    return name or None
