"""Shared retry/backoff for transient GCP API errors.

At org scale (hundreds–thousands of projects, many collectors running in
parallel) the limiting factor is no longer correctness but transient quota and
availability errors: ``429 RESOURCE_EXHAUSTED`` from per-project API quotas,
``503 SERVICE_UNAVAILABLE`` blips, ``500``/``504`` server errors.  None of these
should fail a project — they should back off and retry.

This module centralises that policy so every collector retries the same way.
It is importable without any Google SDK installed (the SDK import is deferred),
so the unit tests that mock collectors at the client boundary keep working: a
mocked call never raises a retryable error, so ``retry_call`` returns on the
first attempt with no sleeping.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from typing import Callable, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")

# Backoff envelope.  ``timeout`` is the total wall-clock budget across all
# attempts for a single call — generous because a throttled org-wide run would
# rather wait than drop a project's data.
_INITIAL_BACKOFF_S = 1.0
_MAX_BACKOFF_S = 60.0
_BACKOFF_MULTIPLIER = 2.0
_TOTAL_TIMEOUT_S = 600.0


def _is_retryable(exc: Exception) -> bool:
    """Return True for transient errors worth retrying.

    Quota (429), service-unavailable (503), internal (500), deadline (504) and
    aborted-concurrency (409) are transient.  Permission/not-found/invalid are
    not — they will never succeed on retry and are handled by each collector's
    graceful-degradation ``except``.
    """
    try:
        from google.api_core import exceptions as gexc
    except Exception:  # SDK not installed — nothing is retryable
        return False

    return isinstance(
        exc,
        (
            gexc.TooManyRequests,  # 429
            gexc.ResourceExhausted,  # 429 quota exceeded
            gexc.ServiceUnavailable,  # 503
            gexc.InternalServerError,  # 500
            gexc.GatewayTimeout,  # 504
            gexc.DeadlineExceeded,  # 504-ish
            gexc.Aborted,  # 409 concurrency
        ),
    )


class RateLimiter:
    """Sliding-window limiter shared by every thread that calls one quota-limited API.

    ``acquire`` returns at once while fewer than ``max_calls`` calls were made in the last
    ``period`` seconds, and sleeps until the oldest call leaves the window otherwise.  It paces
    first attempts only: a retry already backs off exponentially in ``retry_call``.
    """

    def __init__(
        self,
        max_calls: int,
        period: float = 60.0,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._max_calls = max_calls
        self._period = period
        self._clock = clock
        self._sleep = sleep
        self._calls: deque[float] = deque()
        self._lock = threading.Lock()

    def acquire(self) -> None:
        while True:
            with self._lock:
                now = self._clock()
                while self._calls and now - self._calls[0] >= self._period:
                    self._calls.popleft()
                if len(self._calls) < self._max_calls:
                    self._calls.append(now)
                    return
                wait = self._period - (now - self._calls[0])
            # Sleep outside the lock so other threads can check the window meanwhile.
            self._sleep(max(wait, 0.0))


def retry_call(
    func: Callable[[], T],
    *,
    description: str = "",
    timeout: float = _TOTAL_TIMEOUT_S,
) -> T:
    """Run ``func`` with exponential backoff on transient GCP errors.

    Args:
        func: A zero-arg callable that performs (and fully materialises) the API
            call.  Materialising matters for paginated iterators — the network
            calls must happen *inside* ``func`` for the retry to cover them, so
            pass e.g. ``lambda: list(client.list_assets(...))``.  When a listing
            is quota-limited, retry one page per call instead: a retry re-runs
            all of ``func``, so wrapping the whole listing restarts it from page
            one on every 429.
        description: Short human label used in the backoff log line.
        timeout: Total wall-clock budget in seconds across all attempts.

    Returns:
        Whatever ``func`` returns.

    Raises:
        The last exception if it is non-retryable, or if the retry budget is
        exhausted.  Callers keep their existing try/except for graceful
        degradation — this only absorbs the *transient* failures.
    """
    try:
        from google.api_core import retry as g_retry
    except Exception:
        # No SDK (e.g. a pure-logic test path): run once, undecorated.
        return func()

    def _on_error(exc: Exception) -> None:
        logger.warning(
            "Transient GCP error%s, backing off and retrying: %s",
            f" during {description}" if description else "",
            exc,
        )

    policy = g_retry.Retry(
        predicate=_is_retryable,
        initial=_INITIAL_BACKOFF_S,
        maximum=_MAX_BACKOFF_S,
        multiplier=_BACKOFF_MULTIPLIER,
        timeout=timeout,
        on_error=_on_error,
    )
    return policy(func)()
