"""Operator-controlled disk exclusion for sizing.

Disks are flagged, never removed: raw totals stay intact and the SE decides
what to do with the flag.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterable, Mapping

# GCP label keys allow only [a-z0-9_-], so the AWS tag key (with colons) is not
# a legal label; the AWS-style key is still honored if it shows up elsewhere.
EXCLUDE_LABEL = "rubrik_sizing_exclude"
_EXCLUDE_KEYS = (EXCLUDE_LABEL, "rubrik:sizing:exclude")
_TRUTHY = frozenset({"true", "yes", "y", "1", "exclude"})

REASON_LABEL = f"label {EXCLUDE_LABEL}"
REASON_PATTERN = "name matches exclusion pattern"

logger = logging.getLogger(__name__)


class VolumeExclusionEngine:
    """Decides whether a disk is excluded from sizing by label or name regex."""

    def __init__(self, name_patterns: Iterable[str] | None = None) -> None:
        self._patterns: list[re.Pattern[str]] = []
        for raw in name_patterns or ():
            try:
                self._patterns.append(re.compile(raw))
            except re.error as exc:
                logger.warning("Ignoring invalid volume exclusion pattern %r: %s", raw, exc)

    def evaluate(
        self, name: str, instance_name: str, labels: Mapping[str, str] | None
    ) -> str | None:
        """Return an audit reason string if the disk is excluded, else None."""
        for key in _EXCLUDE_KEYS:
            value = (labels or {}).get(key)
            if value is not None and str(value).strip().lower() in _TRUTHY:
                return f"label {key}"
        for text in (name, instance_name):
            if not text:
                continue
            for pattern in self._patterns:
                if pattern.search(text):
                    return f"{REASON_PATTERN} {pattern.pattern!r}"
        return None
