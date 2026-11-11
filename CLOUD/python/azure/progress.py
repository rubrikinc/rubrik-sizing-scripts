"""Live progress of the long collection steps, shown on the spinner.

Collectors report how far they are with ``count``; the screen reads ``describe`` on every
refresh of the spinner, so a 30-minute step shows ``120/257 accounts`` instead of looking stuck.
Nothing here prints, so it is safe to call from worker threads.
"""

from __future__ import annotations

import threading
from typing import Callable, Optional

from rich.text import Text

_lock = threading.Lock()
# subscription id -> [step name, done, total, unit]
_steps: dict = {}


def step(sub_id: str, name: str) -> None:
    """The step a subscription is in now (``storage``, ``databases``…), with no count yet."""
    with _lock:
        _steps[sub_id] = [name, None, None, ""]


def count(sub_id: str, done: int, total: int, unit: str) -> None:
    """How many of the step's items are done, for example 120 of 257 accounts."""
    with _lock:
        entry = _steps.setdefault(sub_id, ["", None, None, ""])
        entry[1:] = [done, total, unit]


def finish(sub_id: str) -> None:
    """The subscription is done; it no longer appears in the progress."""
    with _lock:
        _steps.pop(sub_id, None)


def counter(sub_id: str) -> str:
    """``120/257 accounts``, or empty while the step has not counted anything."""
    with _lock:
        entry = list(_steps.get(sub_id) or [])
    if not entry or not entry[2]:
        return ""
    return f"{entry[1]}/{entry[2]} {entry[3]}".strip()


def describe(sub_id: str) -> str:
    """``storage 120/257 accounts``, the step alone, or empty."""
    with _lock:
        entry = list(_steps.get(sub_id) or [])
    if not entry:
        return ""
    return " ".join(part for part in (entry[0], counter(sub_id)) if part)


def running() -> list:
    """The subscriptions in progress, in the order they started."""
    with _lock:
        return list(_steps)


class Live:
    """A spinner text worked out again on every refresh."""

    def __init__(self, render: Callable[[], str]) -> None:
        self._render = render

    def __rich__(self) -> Text:
        return Text.from_markup(self._render())


def every(items: list, sub_id: Optional[str], unit: str):
    """Yield the items and count them for ``sub_id`` as they go."""
    total = len(items)
    for index, item in enumerate(items):
        if sub_id:
            count(sub_id, index, total, unit)
        yield item
    if sub_id:
        count(sub_id, total, total, unit)
