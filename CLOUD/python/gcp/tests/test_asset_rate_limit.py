"""The Cloud Asset rate-limit handling: the shared limiter, the RATE_LIMITED category, and how a
failed listing is shown and stored (as unknown, never as zero).

All Google SDK calls are mocked; no test waits in real time.
"""

from __future__ import annotations

import json
import threading
from unittest.mock import MagicMock, patch

import main
import preflight
import pytest
from collectors.asset import AssetInventory
from collectors.retry import RateLimiter, retry_call
from collectors.utils import classify_error
from google.api_core import exceptions as gexc
from preflight_core import ERROR
from rich.console import Console
from streaming_writer import slice_from_result

# ── RateLimiter ─────────────────────────────────────────────────────────────────


class _FakeTime:
    """A clock and a sleep that advances it, so the limiter's waits cost no real time."""

    def __init__(self) -> None:
        self.now = 1000.0
        self.slept: list[float] = []

    def clock(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.now += seconds


def _limiter(max_calls: int, period: float = 60.0) -> tuple[RateLimiter, _FakeTime]:
    fake = _FakeTime()
    return RateLimiter(max_calls, period, clock=fake.clock, sleep=fake.sleep), fake


def test_the_limiter_lets_calls_through_while_under_the_limit():
    limiter, fake = _limiter(3)
    for _ in range(3):
        limiter.acquire()
    assert fake.slept == []


def test_the_limiter_waits_for_the_oldest_call_to_leave_the_window():
    limiter, fake = _limiter(2, period=60.0)
    limiter.acquire()
    fake.now += 10
    limiter.acquire()
    limiter.acquire()  # third call: must wait until the first is 60s old, i.e. 50s from now

    assert fake.slept == [pytest.approx(50.0)]


def test_the_limiter_never_lets_more_than_the_limit_into_one_window():
    limiter, fake = _limiter(5, period=60.0)
    stamps = []
    for _ in range(23):
        limiter.acquire()
        stamps.append(fake.now)

    for i, start in enumerate(stamps):
        in_window = [s for s in stamps[i:] if s - start < 60.0]
        assert len(in_window) <= 5


def test_the_limiter_is_shared_safely_between_threads():
    """Eight workers acquiring at once still stay under the limit (real threads, fake time)."""
    limiter, fake = _limiter(10, period=60.0)
    lock = threading.Lock()
    stamps: list[float] = []

    def worker():
        for _ in range(10):
            limiter.acquire()
            with lock:
                stamps.append(fake.now)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(stamps) == 80
    for start in stamps:
        assert len([s for s in stamps if start <= s < start + 60.0]) <= 10


# ── retry_call budget ───────────────────────────────────────────────────────────


def test_retry_call_gives_up_when_the_per_call_budget_is_spent():
    calls = {"n": 0}

    def always_throttled():
        calls["n"] += 1
        raise gexc.TooManyRequests("429 Quota exceeded")

    ticks = iter(range(0, 10_000, 40))
    with patch("google.api_core.retry.retry_unary.time") as fake_time, patch(
        "time.sleep", return_value=None
    ):
        fake_time.monotonic.side_effect = lambda: next(ticks)
        with pytest.raises(Exception):  # noqa: B017 - api_core raises its own RetryError
            retry_call(always_throttled, description="t", timeout=100.0)

    assert 1 <= calls["n"] < 20


# ── RATE_LIMITED classification ─────────────────────────────────────────────────


@pytest.mark.parametrize(
    "message",
    [
        "Timeout of 120.0s exceeded, last exception: 429 Quota exceeded for quota metric "
        "'ListAssets Requests' and limit 'ListAssets Requests per minute'",
        "429 Quota exceeded for quota metric 'Read requests'",
        "RESOURCE_EXHAUSTED: too fast",
        "rate_limit_exceeded",
        "429 Too Many Requests",
    ],
)
def test_a_throttled_error_is_rate_limited(message):
    assert classify_error(Exception(message)) == "RATE_LIMITED"


@pytest.mark.parametrize(
    "message",
    [
        "403 Cloud Asset API has not been used in project p before or it is disabled",
        "403 Request denied by Cloud IAM",
        "connection reset by peer",
        "404 resource projects/p-4290-x not found",
    ],
)
def test_other_errors_are_not_rate_limited(message):
    assert classify_error(Exception(message)) != "RATE_LIMITED"


def test_a_disabled_api_that_also_mentions_a_quota_stays_api_disabled():
    text = "403 API has not been used in project p before or it is disabled. Quota exceeded"
    assert classify_error(Exception(text)) == "API_DISABLED"


def test_the_access_check_reports_a_rate_limited_call_as_could_not_check():
    status, code = preflight.classify(Exception("429 Quota exceeded for quota metric 'x'"))
    assert (status, code) == (ERROR, "TooManyRequests")


# ── A failed listing is unknown, not zero ───────────────────────────────────────


def _console(monkeypatch) -> Console:
    console = Console(record=True, width=140)
    monkeypatch.setattr(main, "console", console)
    return console


def test_a_rate_limited_project_line_is_not_a_zero_count(monkeypatch):
    console = _console(monkeypatch)
    failed = AssetInventory("p", failed=True, failure_category="RATE_LIMITED")

    main._print_project_line("p", {"asset": failed}, 9, 12)

    text = console.export_text()
    assert "asset listing rate limited" in text
    assert "0 assets" not in text
    assert "✓" not in text


def test_an_unreadable_listing_line_says_could_not_be_read(monkeypatch):
    console = _console(monkeypatch)
    failed = AssetInventory("p", failed=True, failure_category="API_DISABLED")

    main._print_project_line("p", {"asset": failed}, 1, 2)

    assert "asset listing could not be read" in console.export_text()


def test_a_listing_that_worked_still_prints_its_count(monkeypatch):
    console = _console(monkeypatch)
    ok = AssetInventory("p", total_assets=31, assets_by_type={"t/A": 31})

    main._print_project_line("p", {"asset": ok}, 1, 2)

    text = console.export_text()
    assert "31" in text and "assets" in text and "✓" in text


def test_a_genuinely_empty_project_is_still_a_zero_count(monkeypatch):
    console = _console(monkeypatch)

    main._print_project_line("p", {"asset": AssetInventory("p")}, 1, 2)

    text = console.export_text()  # clears the recording, so read it once
    assert "0 assets" in text and "✓" in text


def test_the_streamed_slice_leaves_out_counts_of_a_failed_listing():
    failed = AssetInventory("p", failed=True, failure_category="RATE_LIMITED")
    ok = AssetInventory("q", total_assets=4, assets_by_type={"t/A": 4})

    assert slice_from_result("p", {"asset": failed})["asset_counts"] is None
    assert slice_from_result("q", {"asset": ok})["asset_counts"] == {"total": 4, "t/A": 4}
    assert slice_from_result("r", {"asset": AssetInventory("r")})["asset_counts"] == {"total": 0}


def test_the_failure_reaches_collection_errors_in_the_summary():
    """The reason is recorded per project, so the run summary counts it as incomplete."""
    failed = AssetInventory("p", failed=True, failure_category="RATE_LIMITED")
    errors = [{"collector": "asset", "category": "RATE_LIMITED", "message": "429 Quota exceeded"}]

    summary = main._summarise_project("p", {"asset": failed, "errors": errors})

    assert summary["incomplete"] is True


def test_collect_project_records_the_asset_failure_with_its_category(mock_credentials):
    failing = MagicMock()
    failing.collect.return_value = AssetInventory("p", failed=True, failure_category="RATE_LIMITED")
    failing.errors = [
        {"collector": "asset", "category": "RATE_LIMITED", "message": "429 Quota exceeded"}
    ]
    with patch("collectors.asset.AssetCollector", return_value=failing):
        result = main._collect_project("p", mock_credentials, None, selected={"asset"})

    assert result["asset"].failed is True
    assert [(e["collector"], e["category"]) for e in result["errors"]] == [
        ("asset", "RATE_LIMITED")
    ]
    # And it serialises: a failed listing must not break the JSON.
    json.dumps(slice_from_result("p", result), default=str)
