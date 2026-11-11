"""Operator-controlled volume exclusion for sizing.

Disks are flagged, never removed: raw totals stay intact and the SE decides
what to do with the flag. Standalone copy of the AWS engine (the CLIs ship
independently); keep the tag key, truthy set, and reason strings in sync.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterable, Mapping

logger = logging.getLogger(__name__)

EXCLUDE_TAG = "rubrik:sizing:exclude"
_TRUTHY = frozenset({"true", "yes", "y", "1", "exclude"})

REASON_TAG = f"tag {EXCLUDE_TAG}"
REASON_PATTERN = "name matches exclusion pattern"


class VolumeExclusionEngine:
    """Decides whether a disk is excluded from sizing by tag or name regex."""

    def __init__(self, name_patterns: Iterable[str] | None = None) -> None:
        self._patterns: list[re.Pattern[str]] = []
        for raw in name_patterns or ():
            try:
                self._patterns.append(re.compile(raw))
            except re.error as exc:
                logger.warning("Ignoring invalid volume exclusion pattern %r: %s", raw, exc)

    def evaluate(
        self, name: str, instance_name: str, tags: Mapping[str, str] | None
    ) -> str | None:
        """Return an audit reason string if the disk is excluded, else None."""
        if _tag_excludes(tags):
            return REASON_TAG
        for text in (name, instance_name):
            if not text:
                continue
            for pattern in self._patterns:
                if pattern.search(text):
                    return f"{REASON_PATTERN} {pattern.pattern!r}"
        return None


def _tag_excludes(tags: Mapping[str, str] | None) -> bool:
    # Azure tag names are case-insensitive, unlike AWS, so match the key that way.
    for key, value in (tags or {}).items():
        if (
            str(key).strip().lower() == EXCLUDE_TAG
            and value is not None
            and str(value).strip().lower() in _TRUTHY
        ):
            return True
    return False
