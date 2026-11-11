import logging
import threading

from botocore.config import Config

# Applied to every boto3 client so a slow/unreachable region endpoint
# (e.g. opt-in regions like me-south-1) fails fast instead of hanging.
BOTO_CFG = Config(connect_timeout=15, read_timeout=30, retries={"max_attempts": 1})

# S3 and CloudWatch clients retry throttling with client-side rate limiting. Each attempt
# can take up to the connect timeout, so a call to an unreachable endpoint can take about
# max_attempts * connect_timeout; unreachable regions are normally skipped earlier by the
# fail-fast availability-zone probe in main.py. botocore marks adaptive mode experimental.
BOTO_ADAPTIVE_CFG = Config(
    connect_timeout=15, read_timeout=30, retries={"max_attempts": 4, "mode": "adaptive"}
)

# Reading backup plans is 1 + N x (2 + M) sequential calls per region (plans, then each plan's
# details and selections), and the Backup API throttles at low rates. Standard retry mode rides
# out throttling; the timeouts match BOTO_CFG so an unreachable region cannot stall for 10
# retries at botocore's 60 s default.
BOTO_BACKUP_CFG = Config(
    connect_timeout=15, read_timeout=30, retries={"max_attempts": 10, "mode": "standard"}
)

_THROTTLE_MARKERS = ("Throttl", "RequestLimitExceeded", "TooManyRequests", "SlowDown")
_DENIED_MARKERS = ("AccessDenied", "UnauthorizedOperation", "not authorized")


def classify_metric_error(exc: Exception) -> str:
    """'throttled', 'access denied' or 'error', from the AWS error code or message."""
    response = getattr(exc, "response", None)
    code = response.get("Error", {}).get("Code", "") if isinstance(response, dict) else ""
    text = f"{code} {exc}"
    if any(m in text for m in _THROTTLE_MARKERS):
        return "throttled"
    if any(m in text for m in _DENIED_MARKERS):
        return "access denied"
    return "error"


def is_scp_denial(exc: Exception) -> bool:
    """Return True when an exception is an SCP explicit-deny (not a real error)."""
    msg = str(exc)
    return "service_control_policy" in msg or (
        "AccessDeniedException" in msg and "explicit deny" in msg
    )


def record_metric_failures(
    tracker: "DenialTracker | None",
    region: str,
    what: str,
    errors: list[Exception],
    service: str = "cloudwatch",
) -> None:
    """Record failures of one kind for one region as a single scan error.

    The message counts failures by class so a mix of throttling and access-denied errors is
    visible, and keeps the first error as an example.
    """
    if not errors:
        return
    counts: dict[str, int] = {}
    for exc in errors:
        kind = classify_metric_error(exc)
        counts[kind] = counts.get(kind, 0) + 1
    summary = ", ".join(f"{n} {kind}" for kind, n in sorted(counts.items()))
    message = f"{what} failed {len(errors)} time(s) ({summary}); first: {errors[0]}"
    logging.warning("%s in %s", message, region)
    if tracker is not None:
        tracker.record_permission_error(service, region, Exception(message))


class DenialTracker:
    """Thread-safe accumulator for access errors during a parallel region scan.

    Tracks two distinct failure modes:
    - SCP explicit-deny: org policy blocked the call entirely (record / denied_services)
    - IAM permission error: role lacks the permission (record_permission_error / permission_errors)

    Both are persisted in the output JSON so silent scan gaps are visible to the SE.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._denied: set[str] = set()
        self._errors: list[dict] = []

    def record(self, service: str) -> None:
        with self._lock:
            self._denied.add(service)

    def denied_services(self) -> frozenset[str]:
        with self._lock:
            return frozenset(self._denied)

    def record_permission_error(self, service: str, region: str, error: Exception) -> None:
        """Record a non-SCP AccessDenied or other permission gap for a service+region."""
        with self._lock:
            self._errors.append({"service": service, "region": region, "error": str(error)[:300]})

    def permission_errors(self) -> list[dict]:
        with self._lock:
            return list(self._errors)

    def __bool__(self) -> bool:
        with self._lock:
            return bool(self._denied)
