"""Operator-controlled volume exclusion for sizing.

Volumes are flagged, never removed: raw totals stay intact and the SE decides
what to do with the flag, matching the existing archival-heuristic behavior.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterable, Mapping

EXCLUDE_TAG = "rubrik:sizing:exclude"
_TRUTHY = frozenset({"true", "yes", "y", "1", "exclude"})

REASON_TAG = f"tag {EXCLUDE_TAG}"
REASON_PATTERN = "name matches exclusion pattern"


class VolumeExclusionEngine:
    """Decides whether a volume is excluded from sizing by tag or name regex."""

    def __init__(self, name_patterns: Iterable[str] | None = None) -> None:
        self._patterns: list[re.Pattern[str]] = []
        for raw in name_patterns or ():
            try:
                self._patterns.append(re.compile(raw))
            except re.error as exc:
                logging.warning("Ignoring invalid volume exclusion pattern %r: %s", raw, exc)

    def evaluate(
        self, name: str, instance_name: str, tags: Mapping[str, str] | None
    ) -> str | None:
        """Return an audit reason string if the volume is excluded, else None."""
        value = (tags or {}).get(EXCLUDE_TAG)
        if value is not None and str(value).strip().lower() in _TRUTHY:
            return REASON_TAG
        for text in (name, instance_name):
            if not text:
                continue
            for pattern in self._patterns:
                if pattern.search(text):
                    return f"{REASON_PATTERN} {pattern.pattern!r}"
        return None
