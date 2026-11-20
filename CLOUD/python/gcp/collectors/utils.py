"""Shared utilities for all Rubrik Discovery GCP collectors."""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass, field
from typing import Optional

# 429 only as a number of its own, never inside a project ID, a number or a path.
_RATE_LIMITED = re.compile(
    r"resource_exhausted|quota exceeded|rate_limit_exceeded|too many requests|"
    r"(?<![\w/-])429(?![\w-])"
)

# ── Graceful stop ─────────────────────────────────────────────────────────────
#
# The first Ctrl-C (or SIGTERM) during the scan sets this flag instead of ending the process.
# Collectors that loop over many calls check it and return what they have, so the results zip is
# still written, marked partial. ``main`` installs the signal handlers; collectors only read it.

_STOP = threading.Event()


class ScanStopped(Exception):
    """A project that was not scanned (or only partly) because the run was asked to stop."""


def request_stop() -> None:
    _STOP.set()


def stop_requested() -> bool:
    return _STOP.is_set()


def reset_stop() -> None:
    _STOP.clear()


def brief_error(exc: Exception) -> str:
    """One-line summary of an exception for collector warnings.

    Google API / gRPC errors stringify to a multi-line dump that embeds the
    full protobuf error detail (``[reason: ... metadata {...} links {...}]``),
    which floods the customer-facing console and makes a gracefully-skipped
    collector look like a crash. Keep only the human-readable first line, and
    drop the trailing protobuf detail list.
    """
    msg = str(exc).split("\n", 1)[0]  # first line only
    msg = msg.split(" [", 1)[0]  # drop the trailing protobuf detail list
    return msg.strip() or exc.__class__.__name__


def classify_error(exc: Exception) -> str:
    """Bucket a collector exception into a coarse reason category.

    Used to tell a genuinely-empty project apart from one we couldn't read.
    Returns one of: ``API_DISABLED``, ``BILLING_DISABLED``, ``PERMISSION_DENIED``,
    ``RATE_LIMITED``, ``SDK_MISSING``, ``OTHER``.
    """
    if isinstance(exc, (ImportError, ModuleNotFoundError)):
        return "SDK_MISSING"
    text = str(exc).lower()
    # A project with billing off refuses Compute, Spanner and Backup and DR reads. Like a disabled
    # API it holds nothing we can size, and the fix (link a billing account) is a different one.
    if (
        "billing must be enabled" in text
        or "requires billing to be enabled" in text
        or "absent billing account" in text
        or "billing_disabled" in text
        or "billing account for the project is not found" in text
    ):
        return "BILLING_DISABLED"
    if (
        "service_disabled" in text
        or "has not been used in project" in text
        or "it is disabled" in text
    ):
        return "API_DISABLED"
    if (
        "permission_denied" in text
        or "denied by cloud iam" in text
        or "missing required iam permission" in text
        or ("permission" in text and "denied" in text)
    ):
        return "PERMISSION_DENIED"
    # A throttled call that ran out of retries.  The data exists but was not read, so the run must
    # not present it as empty.  A retry that timed out names the last error in its message.
    if _RATE_LIMITED.search(text):
        return "RATE_LIMITED"
    if "cannot import name" in text or "no module named" in text:
        return "SDK_MISSING"
    return "OTHER"


def collection_error(collector: str, exc: Exception) -> dict:
    """Build a structured collector-failure record (``project_id`` stamped later).

    Collectors append these to ``self.errors`` so a partial scan surfaces in the
    output instead of silently showing zeros.
    """
    return {
        "collector": collector,
        "category": classify_error(exc),
        "message": brief_error(exc),
    }


@dataclass
class LabelSummary:
    """Summary of label coverage across a set of GCP resources."""

    key_coverage: dict[str, float] = field(default_factory=dict)
    """Percentage of resources that have each label key (0.0–100.0)."""

    common_values: dict[str, dict[str, int]] = field(default_factory=dict)
    """Top values per label key: {key: {value: count}}."""

    unlabelled_count: int = 0
    """Number of resources with no labels at all."""

    unlabelled_pct: float = 0.0
    """Percentage of resources with no labels (0.0–100.0)."""

    missing_keys: list[str] = field(default_factory=list)
    """Label keys with < 50% coverage — governance signal."""


def build_label_summary(
    resources_labels: list[Optional[dict[str, str]]],
) -> LabelSummary:
    """Build a LabelSummary from a list of resource label dicts.

    Args:
        resources_labels: One dict per resource (use None or ``{}`` for unlabelled).

    Returns:
        Populated LabelSummary dataclass.
    """
    total = len(resources_labels)
    if total == 0:
        return LabelSummary()

    unlabelled_count = sum(1 for labels in resources_labels if not labels)

    key_counts: dict[str, int] = {}
    value_dist: dict[str, dict[str, int]] = {}

    for labels in resources_labels:
        if not labels:
            continue
        for k, v in labels.items():
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

    return LabelSummary(
        key_coverage=key_coverage,
        common_values=common_values,
        unlabelled_count=unlabelled_count,
        unlabelled_pct=round(unlabelled_count / total * 100, 1),
        missing_keys=missing_keys,
    )


def parse_project_from_resource_name(resource_name: str) -> str:
    """Extract the project ID from a GCP resource name.

    Handles both full names (``//service.googleapis.com/projects/<id>/...``)
    and relative names (``projects/<id>/...``).

    Args:
        resource_name: GCP resource name string.

    Returns:
        Project ID, or empty string if not parseable.
    """
    if not resource_name:
        return ""
    # Strip the service prefix: //service.googleapis.com/
    name = resource_name
    if name.startswith("//"):
        slash = name.find("/", 2)
        if slash >= 0:
            name = name[slash + 1 :]

    parts = name.split("/")
    try:
        idx = parts.index("projects")
        return parts[idx + 1]
    except (ValueError, IndexError):
        return ""


def parse_leaf_name(resource_name: str) -> str:
    """Extract the leaf resource name (final path segment) from a GCP resource name.

    Args:
        resource_name: GCP resource name string.

    Returns:
        Leaf name, or empty string if unparseable.
    """
    if not resource_name:
        return ""
    return resource_name.rstrip("/").split("/")[-1]
