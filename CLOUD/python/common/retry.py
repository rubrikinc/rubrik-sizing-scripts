"""Shared retry with exponential backoff for transient cloud API errors.

No cloud SDK is imported at module load. Each provider supplies a predicate
that decides whether an exception is transient.
"""

from __future__ import annotations

import logging
import random
import time
from typing import Callable, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")

INITIAL_BACKOFF_S = 1.0
MAX_BACKOFF_S = 60.0
BACKOFF_MULTIPLIER = 2.0
TOTAL_TIMEOUT_S = 600.0

_AWS_THROTTLE_CODES = frozenset(
    {
        "Throttling",
        "ThrottlingException",
        "ThrottledException",
        "RequestLimitExceeded",
        "RequestThrottled",
        "RequestThrottledException",
        "TooManyRequestsException",
        "ProvisionedThroughputExceededException",
        "TransactionInProgressException",
        "SlowDown",
        "PriorRequestNotComplete",
        "EC2ThrottledException",
        "ServiceUnavailable",
        "InternalError",
    }
)
_TRANSIENT_HTTP = frozenset({429, 500, 502, 503, 504})


def retry_call(
    func: Callable[[], T],
    *,
    is_retryable: Callable[[BaseException], bool],
    description: str = "",
    initial: float = INITIAL_BACKOFF_S,
    maximum: float = MAX_BACKOFF_S,
    multiplier: float = BACKOFF_MULTIPLIER,
    timeout: float = TOTAL_TIMEOUT_S,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> T:
    """Run ``func``, retrying while ``is_retryable`` says the error is transient.

    ``func`` must perform and fully materialise the API call, for example
    ``lambda: list(client.list_assets(...))``. Non-retryable errors raise
    immediately. Once ``timeout`` seconds have elapsed the last error is raised.
    Sleeps use full jitter, bounded by the current backoff, and are at least the error's
    Retry-After value (capped at ``maximum``) when it carries one.
    """
    start = clock()
    delay = initial
    attempt = 0
    while True:
        attempt += 1
        try:
            return func()
        except Exception as exc:
            if not is_retryable(exc):
                raise
            elapsed = clock() - start
            wait = random.uniform(0, delay)
            retry_after = retry_after_seconds(exc)
            if retry_after is not None:
                wait = max(wait, min(retry_after, maximum))
            if elapsed + wait > timeout:
                raise
            logger.warning(
                "Transient error%s (attempt %d), retrying in %.1fs: %s",
                f" during {description}" if description else "",
                attempt,
                wait,
                exc,
            )
            sleep(wait)
            delay = min(delay * multiplier, maximum)


def _status_code(exc: BaseException) -> int | None:
    for attr in ("status_code", "code"):
        value = getattr(exc, attr, None)
        if isinstance(value, int):
            return value
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        code = response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        if isinstance(code, int):
            return code
    code = getattr(response, "status_code", None)
    return code if isinstance(code, int) else None


def google_is_retryable(exc: BaseException) -> bool:
    """429, 500, 503, 504 and aborted-concurrency Google API errors."""
    try:
        from google.api_core import exceptions as gexc
    except Exception:
        return False
    return isinstance(
        exc,
        (
            gexc.TooManyRequests,
            gexc.ResourceExhausted,
            gexc.ServiceUnavailable,
            gexc.InternalServerError,
            gexc.GatewayTimeout,
            gexc.DeadlineExceeded,
            gexc.Aborted,
        ),
    )


def aws_is_retryable(exc: BaseException) -> bool:
    """botocore ClientError throttle codes, or HTTP 429/503 responses."""
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        code = response.get("Error", {}).get("Code")
        if code in _AWS_THROTTLE_CODES:
            return True
    return _status_code(exc) in {429, 503}


def azure_is_retryable(exc: BaseException) -> bool:
    """Azure SDK errors carrying HTTP 429 or 503."""
    return _status_code(exc) in {429, 503}


def retry_after_seconds(exc: BaseException) -> float | None:
    """Value of a Retry-After header on the error's response, if any."""
    response = getattr(exc, "response", None)
    headers = getattr(response, "headers", None)
    if not headers:
        return None
    try:
        return float(headers.get("Retry-After"))
    except (TypeError, ValueError):
        return None
