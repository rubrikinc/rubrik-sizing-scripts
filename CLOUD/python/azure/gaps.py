"""Which subscriptions had something go wrong during their scan.

The Azure collectors do not keep an error list: a failure is logged as a warning and the collector
carries on with what it has, so a subscription can finish with a VM listing, a vault or a cost query
missing. Every such warning begins with ``[<subscription id>]``, and every warning in the scan
collectors is a failure that left something out (a listing that failed, an item that was skipped, a
query that was denied), so counting them per subscription says which subscriptions have gaps without
editing the collectors.

``GapRecorder`` is a logging handler that does the counting. It runs only while a scan is in progress.
``utils.warn_once`` shows a repeated cause once on the screen; it calls :func:`note` first, so the
repeat in a second subscription is still counted there.
"""

from __future__ import annotations

import logging
import re
import threading
from typing import Optional

# "[<subscription id>] message": the id is a GUID, but only its shape is relied on, so a message from a
# collector that names it differently is simply not attributed.
_SUBSCRIPTION = re.compile(r"^\[([^\]\s]+)\]")

# Set on the record warn_once logs after it has already counted the message, so the handler does not
# count it a second time.
ALREADY_COUNTED = "gap_already_counted"

_current: Optional["GapRecorder"] = None
_current_lock = threading.Lock()


class GapRecorder(logging.Handler):
    """Counts the warnings and errors of each subscription, and keeps a few as examples."""

    def __init__(self, subscriptions: list[str], examples: int = 3) -> None:
        super().__init__(level=logging.WARNING)
        self._known = set(subscriptions)
        self._examples = examples
        self._lock = threading.Lock()
        self._counts: dict[str, int] = {}
        self._messages: dict[str, list[str]] = {}

    # ── recording ──────────────────────────────────────────────────────────────

    def emit(self, record: logging.LogRecord) -> None:
        try:
            if record.levelno >= logging.WARNING and not getattr(record, ALREADY_COUNTED, False):
                self.add(record.getMessage())
        except Exception:  # noqa: BLE001 - counting gaps must never stop a scan
            self.handleError(record)

    def add(self, message: str) -> None:
        """Count a warning or error message against the subscription it names, if any."""
        found = _SUBSCRIPTION.match(message)
        if not found or found.group(1) not in self._known:
            return
        sub = found.group(1)
        with self._lock:
            self._counts[sub] = self._counts.get(sub, 0) + 1
            kept = self._messages.setdefault(sub, [])
            if len(kept) < self._examples and message not in kept:
                kept.append(message)

    # ── reading ────────────────────────────────────────────────────────────────

    def count(self, sub_id: str) -> int:
        with self._lock:
            return self._counts.get(sub_id, 0)

    def examples(self, sub_id: str) -> list[str]:
        with self._lock:
            return list(self._messages.get(sub_id, []))

    def has_gaps(self, sub_id: str) -> bool:
        return self.count(sub_id) > 0

    def gaps(self) -> dict[str, int]:
        """Every subscription with at least one gap, and how many."""
        with self._lock:
            return dict(self._counts)

    # ── lifecycle ──────────────────────────────────────────────────────────────

    def install(self) -> "GapRecorder":
        """Start counting: attach to the root logger and become the recorder note() reports to."""
        global _current
        logging.getLogger().addHandler(self)
        with _current_lock:
            _current = self
        return self

    def uninstall(self) -> None:
        global _current
        logging.getLogger().removeHandler(self)
        with _current_lock:
            if _current is self:
                _current = None


def note(message: str) -> None:
    """Report a failure message to the running recorder, whether or not it will be shown.

    ``warn_once`` calls this before it decides whether to log, so a cause already shown for one
    subscription is still counted for the next.
    """
    with _current_lock:
        recorder = _current
    if recorder is not None:
        recorder.add(message)
