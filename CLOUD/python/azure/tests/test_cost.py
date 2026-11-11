"""Tests for collectors/cost.py — Azure SDK is fully mocked."""

from __future__ import annotations

from types import SimpleNamespace as NS
from unittest.mock import MagicMock, patch

import pytest
from azure.core.exceptions import HttpResponseError
from collectors.cost import (
    DEFAULT_BACKUP_SERVICE_NAMES,
    CostCollector,
    CostSummary,
    MonthlyServiceSpend,
    _col_idx,
    _parse_month,
    _six_month_window,
    classify_service,
)

from tests.fixtures import MOCK_COST_ROWS, SUB_ID, mock_cost_query_effect


def _make_collector(query_result=None, raise_error=None) -> CostCollector:
    """Return a CostCollector with a mocked CostManagementClient."""
    mock_client = MagicMock()

    if raise_error is not None:
        mock_client.query.usage.side_effect = raise_error
    elif query_result is not None:
        mock_client.query.usage.return_value = query_result
    else:
        mock_client.query.usage.side_effect = mock_cost_query_effect

    with (
        patch("collectors.cost.CostManagementClient", return_value=mock_client),
        patch("collectors.cost.QueryDefinition", MagicMock()),
        patch("collectors.cost.QueryTimePeriod", MagicMock()),
        patch("collectors.cost.QueryDataset", MagicMock()),
        patch("collectors.cost.QueryAggregation", MagicMock()),
        patch("collectors.cost.QueryGrouping", MagicMock()),
        patch("collectors.cost.QueryColumnType", NS(DIMENSION="Dimension")),
    ):
        collector = CostCollector(SUB_ID, MagicMock())
        collector._client = mock_client

    return collector


def _mock_result(rows, col_names=None):
    """Build a mock API result object."""
    names = col_names or ["Cost", "ServiceName", "BillingMonth", "Currency"]
    return NS(
        columns=[NS(name=n) for n in names],
        rows=rows,
    )


def test_collect_returns_cost_summary():
    collector = _make_collector()
    result = collector.collect()
    assert isinstance(result, CostSummary)
    assert result.subscription_id == SUB_ID


def test_collect_parses_fixture_rows():
    collector = _make_collector()
    result = collector.collect()

    assert result.total_6mo_spend > 0
    assert len(result.months_collected) == 6
    assert len(result.monthly_spend_by_service) == 36  # 6 services × 6 months
    assert len(result.top_services) <= 10


def test_collect_top_service_is_virtual_machines():
    collector = _make_collector()
    result = collector.collect()

    assert result.top_services[0]["service"] == "Virtual Machines"


def test_collect_months_sorted():
    collector = _make_collector()
    result = collector.collect()

    assert result.months_collected == sorted(result.months_collected)
    assert result.months_collected[0] == "2025-11"
    assert result.months_collected[-1] == "2026-04"


def test_collect_completed_months_count_excludes_current():
    """Only full months strictly before the current calendar month count."""
    collector = _make_collector()
    result = collector.collect()
    # Any month strictly before the current UTC month should be counted.
    from datetime import datetime, timezone

    current = datetime.now(timezone.utc).strftime("%Y-%m")
    expected = sum(1 for m in result.months_collected if m < current)
    assert result.completed_months_count == expected
    # Fixture has 6 months; at least the earliest should be completed.
    assert result.completed_months_count >= 1
    assert result.completed_months_count <= len(result.months_collected)


def test_collect_total_spend_sum():
    # Sum all Cost values in MOCK_COST_ROWS
    expected = round(sum(r[0] for r in MOCK_COST_ROWS), 2)
    collector = _make_collector()
    result = collector.collect()
    assert result.total_6mo_spend == expected


def test_collect_monthly_spend_entries_have_correct_fields():
    collector = _make_collector()
    result = collector.collect()

    entry = result.monthly_spend_by_service[0]
    assert isinstance(entry, MonthlyServiceSpend)
    assert entry.month.startswith("20")  # YYYY-MM
    assert entry.cost_usd > 0
    assert entry.currency == "USD"
    assert entry.service


def test_collect_returns_empty_on_http_error():
    collector = _make_collector(raise_error=HttpResponseError(message="403 Forbidden"))
    result = collector.collect()

    assert result.total_6mo_spend == 0.0
    assert result.months_collected == []
    assert "unavailable" in result.data_note.lower() or "check" in result.data_note.lower()


def test_collect_returns_empty_on_generic_exception():
    collector = _make_collector(raise_error=RuntimeError("unexpected"))
    result = collector.collect()

    assert result.total_6mo_spend == 0.0
    assert isinstance(result, CostSummary)


def test_collect_skips_zero_cost_rows():
    rows = [
        [0.0, "Virtual Machines", "20260101000000", "USD"],
        [500.00, "Azure Storage", "20260101000000", "USD"],
    ]
    collector = _make_collector(query_result=_mock_result(rows))
    result = collector.collect()

    # Zero-cost row should be filtered; only 1 service row
    assert len(result.monthly_spend_by_service) == 1
    assert result.monthly_spend_by_service[0].service == "Azure Storage"


def test_collect_handles_empty_result():
    collector = _make_collector(query_result=_mock_result([]))
    result = collector.collect()

    assert result.total_6mo_spend == 0.0
    assert result.months_collected == []


def test_collect_handles_none_result():
    collector = _make_collector(query_result=NS(columns=[], rows=None))
    result = collector.collect()
    assert result.total_6mo_spend == 0.0


def test_collect_top_services_capped_at_ten():
    # 12 distinct services
    rows = [[float(i * 100), f"Service-{i:02d}", "20260101000000", "USD"] for i in range(1, 13)]
    collector = _make_collector(query_result=_mock_result(rows))
    result = collector.collect()

    assert len(result.top_services) == 10


def test_collect_top_services_sorted_descending():
    rows = [
        [100.0, "Cheap", "20260101000000", "USD"],
        [500.0, "Expensive", "20260101000000", "USD"],
        [250.0, "Mid-range", "20260101000000", "USD"],
    ]
    collector = _make_collector(query_result=_mock_result(rows))
    result = collector.collect()

    costs = [s["total_cost_usd"] for s in result.top_services]
    assert costs == sorted(costs, reverse=True)
    assert result.top_services[0]["service"] == "Expensive"


def test_collect_handles_reordered_columns():
    # API returns columns in a different order
    rows = [["USD", "20260101000000", "Virtual Machines", 1234.56]]
    alt_result = NS(
        columns=[
            NS(name="Currency"),
            NS(name="BillingMonth"),
            NS(name="ServiceName"),
            NS(name="Cost"),
        ],
        rows=rows,
    )
    collector = _make_collector(query_result=alt_result)
    result = collector.collect()

    assert result.total_6mo_spend == 1234.56
    assert result.top_services[0]["service"] == "Virtual Machines"


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("20240101000000", "2024-01"),  # 14-digit string
        ("20240601000000", "2024-06"),
        ("202401", "2024-01"),  # 6-digit string
        ("2024-01-01", "2024-01"),  # ISO date
        ("2024-01-01T00:00:00", "2024-01"),  # ISO datetime
        (None, "Unknown"),
    ],
)
def test_parse_month(raw, expected):
    from datetime import datetime, timezone

    if raw == "datetime_obj":
        raw = datetime(2024, 3, 1, tzinfo=timezone.utc)
        expected = "2024-03"
    assert _parse_month(raw) == expected


def test_parse_month_datetime_object():
    from datetime import datetime, timezone

    dt = datetime(2025, 11, 1, tzinfo=timezone.utc)
    assert _parse_month(dt) == "2025-11"


def test_six_month_window_span():
    from datetime import datetime, timezone

    now = datetime(2026, 4, 12, tzinfo=timezone.utc)
    start, end = _six_month_window(now)
    assert start.year == 2025
    assert start.month == 11
    assert start.day == 1
    assert end == now


def test_six_month_window_year_boundary():
    from datetime import datetime, timezone

    now = datetime(2026, 2, 15, tzinfo=timezone.utc)
    start, end = _six_month_window(now)
    assert start.year == 2025
    assert start.month == 9


def test_col_idx_found():
    assert _col_idx(["Cost", "ServiceName", "BillingMonth"], "ServiceName", 99) == 1


def test_col_idx_not_found_returns_default():
    assert _col_idx(["A", "B"], "Missing", 5) == 5


# ---------------------------------------------------------------------------
# Backup-vs-other classification
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name,expected",
    [
        ("Recovery Services", "backup"),
        ("recovery services", "backup"),
        ("RECOVERY SERVICES", "backup"),
        ("Azure Backup", "backup"),
        ("Azure Site Recovery", "backup"),
        ("Site Recovery", "backup"),
        ("Backup", "backup"),
        ("Virtual Machines", "other"),
        ("Azure Storage", "other"),
        ("Azure SQL Database", "other"),
        ("Azure Monitor", "other"),
        ("", "other"),
    ],
)
def test_classify_service_default_list(name, expected):
    assert classify_service(name) == expected


def test_classify_service_custom_list_overrides_default():
    custom = frozenset({"azure snapshots"})
    # "Recovery Services" is no longer backup with this list
    assert classify_service("Recovery Services", custom) == "other"
    # "Azure Snapshots" now classifies as backup
    assert classify_service("Azure Snapshots", custom) == "backup"


def test_default_backup_service_names_nonempty():
    assert "recovery services" in DEFAULT_BACKUP_SERVICE_NAMES
    assert "azure backup" in DEFAULT_BACKUP_SERVICE_NAMES


def test_collect_splits_backup_and_other_totals():
    collector = _make_collector()
    result = collector.collect()
    assert result.backup_6mo_spend > 0
    assert result.other_6mo_spend > 0
    assert round(result.backup_6mo_spend + result.other_6mo_spend, 2) == result.total_6mo_spend


def test_collect_top_services_include_category():
    collector = _make_collector()
    result = collector.collect()
    assert all("category" in s for s in result.top_services)
    # "Recovery Services" should be tagged backup
    rs = next((s for s in result.top_services if s["service"] == "Recovery Services"), None)
    assert rs is not None
    assert rs["category"] == "backup"


def test_collect_top_backup_services_is_backup_only():
    collector = _make_collector()
    result = collector.collect()
    assert all(classify_service(s["service"]) == "backup" for s in result.top_backup_services)
    # Recovery Services is in the fixture
    assert any(s["service"] == "Recovery Services" for s in result.top_backup_services)


def test_monthly_spend_by_service_has_category_field():
    collector = _make_collector()
    result = collector.collect()
    rs_entries = [e for e in result.monthly_spend_by_service if e.service == "Recovery Services"]
    assert rs_entries
    assert all(e.category == "backup" for e in rs_entries)
    vm_entries = [e for e in result.monthly_spend_by_service if e.service == "Virtual Machines"]
    assert all(e.category == "other" for e in vm_entries)


def test_collect_zero_backup_when_no_backup_services():
    # Only VM spend, no Recovery Services
    from tests.test_cost import _mock_result

    rows = [
        [1000.0, "Virtual Machines", "20260101000000", "USD"],
        [500.0, "Azure Storage", "20260101000000", "USD"],
    ]
    collector = _make_collector(query_result=_mock_result(rows))
    result = collector.collect()
    assert result.backup_6mo_spend == 0.0
    assert result.other_6mo_spend == result.total_6mo_spend
    assert result.top_backup_services == []


def test_collect_custom_backup_services_reclassifies():
    """Passing a custom list to the collector retags services at collection time."""
    from tests.test_cost import _mock_result

    rows = [
        [1000.0, "Virtual Machines", "20260101000000", "USD"],
        [500.0, "Azure Snapshots", "20260101000000", "USD"],
    ]
    # Default list — "Azure Snapshots" isn't on it
    default_coll = _make_collector(query_result=_mock_result(rows))
    default_result = default_coll.collect()
    assert default_result.backup_6mo_spend == 0.0

    # Custom list includes "snapshot" → now matches
    custom_coll = _make_collector(query_result=_mock_result(rows))
    custom_coll._backup_services = frozenset({"snapshot"})
    custom_result = custom_coll.collect()
    assert custom_result.backup_6mo_spend == 500.0
    assert custom_result.other_6mo_spend == 1000.0


# ---------------------------------------------------------------------------
# backup_only scope — only relevant (backup) cost data is pulled
# ---------------------------------------------------------------------------


def _make_backup_only_collector(rows, service_names=None, dims_error=None):
    """A backup_only CostCollector with mocked usage + dimensions endpoints.

    ``service_names`` seeds the ServiceName dimension enumeration; pass None to
    omit the dimension entirely.  ``dims_error`` makes dimensions.list raise.
    """
    mock_client = MagicMock()
    mock_client.query.usage.return_value = _mock_result(rows)

    if dims_error is not None:
        mock_client.dimensions.list.side_effect = dims_error
    else:
        dims = []
        if service_names is not None:
            dims.append(NS(category="ServiceName", data=list(service_names)))
            dims.append(NS(category="ResourceLocation", data=["eastus"]))  # noise
        mock_client.dimensions.list.return_value = iter(dims)

    with (
        patch("collectors.cost.CostManagementClient", return_value=mock_client),
        patch("collectors.cost.QueryColumnType", NS(DIMENSION="Dimension")),
    ):
        collector = CostCollector(SUB_ID, MagicMock(), backup_only=True)
        collector._client = mock_client
    return collector


def test_backup_only_drops_non_backup_rows_client_side():
    """Even if the server returns non-backup rows, they're dropped client-side."""
    rows = [
        [1000.0, "Virtual Machines", "20260101000000", "USD"],
        [300.0, "Recovery Services", "20260101000000", "USD"],
        [200.0, "Azure Backup", "20260101000000", "USD"],
    ]
    collector = _make_backup_only_collector(rows, dims_error=RuntimeError("no dims"))
    result = collector.collect()

    assert result.other_6mo_spend == 0.0
    assert result.total_6mo_spend == 500.0
    assert result.backup_6mo_spend == 500.0
    assert {s["service"] for s in result.top_services} == {"Recovery Services", "Azure Backup"}
    assert "Virtual Machines" not in {s["service"] for s in result.top_services}


def test_backup_only_builds_server_side_in_filter():
    """Discovered ServiceName values are classified into an IN filter."""
    rows = [[300.0, "Recovery Services", "20260101000000", "USD"]]
    collector = _make_backup_only_collector(
        rows,
        service_names=["Virtual Machines", "Recovery Services", "Azure Backup", "Azure Storage"],
    )
    collector.collect()

    # Inspect the filter passed to the usage query.
    _, kwargs = collector._client.query.usage.call_args
    query_def = kwargs.get("query_definition")
    if query_def is None:
        # positional: usage(scope, query_def)
        query_def = collector._client.query.usage.call_args[0][1]
    cost_filter = query_def.dataset.filter
    assert cost_filter is not None
    assert cost_filter.dimensions.name == "ServiceName"
    assert cost_filter.dimensions.operator == "In"
    assert set(cost_filter.dimensions.values_property) == {"Recovery Services", "Azure Backup"}


def test_backup_only_no_filter_when_dimension_unavailable():
    """Dimension enumeration failure → no server filter, client filter still applies."""
    rows = [
        [1000.0, "Virtual Machines", "20260101000000", "USD"],
        [300.0, "Recovery Services", "20260101000000", "USD"],
    ]
    collector = _make_backup_only_collector(rows, dims_error=RuntimeError("403"))
    result = collector.collect()

    query_def = collector._client.query.usage.call_args[0][1]
    assert query_def.dataset.filter is None  # no server-side filter built
    # Client-side filter still produced backup-only output.
    assert result.total_6mo_spend == 300.0
    assert result.other_6mo_spend == 0.0


def test_backup_only_no_backup_services_returns_clean_empty():
    """Enumeration finds no backup service → skip the query, clean empty result.

    This is the real-world lab case: a subscription with VM/storage/SQL spend
    but no Recovery Services / Azure Backup.  We must NOT send an empty
    ``IN ()`` filter (Azure 400s on it).
    """
    rows = [[1000.0, "Virtual Machines", "20260101000000", "USD"]]
    collector = _make_backup_only_collector(
        rows,
        service_names=["Virtual Machines", "Azure Storage", "SQL Database"],
    )
    result = collector.collect()

    collector._client.query.usage.assert_not_called()  # query skipped entirely
    assert result.total_6mo_spend == 0.0
    assert "no backup-attributable spend" in result.data_note.lower()


def test_backup_only_data_note_mentions_scope():
    rows = [[300.0, "Recovery Services", "20260101000000", "USD"]]
    collector = _make_backup_only_collector(rows, service_names=["Recovery Services"])
    result = collector.collect()
    assert "backup-attributable" in result.data_note.lower()


def test_default_is_not_backup_only():
    """Default collector pulls all services and never touches the dimensions API."""
    collector = _make_collector()
    result = collector.collect()
    assert result.other_6mo_spend > 0  # non-backup spend retained
    collector._client.dimensions.list.assert_not_called()


# ---------------------------------------------------------------------------
# 429 throttling + retry behaviour
# ---------------------------------------------------------------------------


def _http_error(status_code: int, message: str = "err", retry_after=None):
    """Build an HttpResponseError that looks like an Azure SDK one."""
    exc = HttpResponseError(message=message)
    exc.status_code = status_code
    if retry_after is not None:
        exc.response = NS(headers={"Retry-After": str(retry_after)})
    return exc


def test_429_retried_then_succeeds(monkeypatch):
    """A single 429 should be retried; on the second call we succeed cleanly."""
    from tests.test_cost import _mock_result

    ok_result = _mock_result(
        [
            [100.0, "Virtual Machines", "20260101000000", "USD"],
        ]
    )

    calls = {"n": 0}

    def _side_effect(scope, query):
        calls["n"] += 1
        if calls["n"] == 1:
            raise _http_error(429, "Too many requests")
        return ok_result

    # No real sleeping.
    monkeypatch.setattr("collectors.cost.time.sleep", lambda s: None)

    collector = _make_collector()
    collector._client.query.usage.side_effect = _side_effect
    result = collector.collect()

    assert calls["n"] == 2
    assert result.total_6mo_spend == 100.0
    assert "unavailable" not in result.data_note  # normal-success data_note


def test_429_exhausts_retries_produces_throttled_note(monkeypatch):
    """Sustained 429s fall back to the throttled data_note — not permission."""
    calls = {"n": 0}

    def _side_effect(scope, query):
        calls["n"] += 1
        raise _http_error(429, "Too many requests")

    monkeypatch.setattr("collectors.cost.time.sleep", lambda s: None)
    collector = _make_collector()
    collector._client.query.usage.side_effect = _side_effect
    result = collector.collect()

    # All 4 attempts (1 initial + 3 retries) should have fired.
    assert calls["n"] == 4
    assert result.total_6mo_spend == 0.0
    assert "rate limit" in result.data_note.lower()
    assert "try re-running" in result.data_note.lower()
    # The throttled note explicitly contrasts with permission issues.
    assert "429" in result.data_note
    assert "Cost Management Reader" not in result.data_note


def test_429_honours_retry_after_header(monkeypatch):
    """Retry-After header should override the static backoff schedule."""
    slept = []
    monkeypatch.setattr("collectors.cost.time.sleep", slept.append)

    from tests.test_cost import _mock_result

    calls = {"n": 0}

    def _side_effect(scope, query):
        calls["n"] += 1
        if calls["n"] == 1:
            raise _http_error(429, "throttled", retry_after=7)
        return _mock_result([[1.0, "x", "20260101000000", "USD"]])

    collector = _make_collector()
    collector._client.query.usage.side_effect = _side_effect
    collector.collect()

    assert slept == [7.0]  # used the Retry-After value, not a backoff default


def test_403_produces_permission_note_without_retry(monkeypatch):
    """A 403 is a real permission issue — no retry, clear message."""
    calls = {"n": 0}

    def _side_effect(scope, query):
        calls["n"] += 1
        raise _http_error(403, "Forbidden")

    monkeypatch.setattr("collectors.cost.time.sleep", lambda s: None)
    collector = _make_collector()
    collector._client.query.usage.side_effect = _side_effect
    result = collector.collect()

    assert calls["n"] == 1
    assert "Cost Management Reader" in result.data_note


def test_5xx_retried_then_gives_server_error_note(monkeypatch):
    """Transient 5xx should retry; sustained 5xx produces server_error note."""
    calls = {"n": 0}

    def _side_effect(scope, query):
        calls["n"] += 1
        raise _http_error(503, "Service unavailable")

    monkeypatch.setattr("collectors.cost.time.sleep", lambda s: None)
    collector = _make_collector()
    collector._client.query.usage.side_effect = _side_effect
    result = collector.collect()

    assert calls["n"] == 4
    assert "server error" in result.data_note.lower()


def test_404_produces_not_registered_note(monkeypatch):
    """404 suggests the Cost Management provider isn't registered."""
    calls = {"n": 0}

    def _side_effect(scope, query):
        calls["n"] += 1
        raise _http_error(404, "Not found")

    monkeypatch.setattr("collectors.cost.time.sleep", lambda s: None)
    collector = _make_collector()
    collector._client.query.usage.side_effect = _side_effect
    result = collector.collect()

    assert calls["n"] == 1
    assert "provider" in result.data_note.lower()
    assert "az provider register" in result.data_note.lower()


def test_retry_after_seconds_missing_returns_none():
    from collectors.cost import _retry_after_seconds

    exc = HttpResponseError(message="no headers")
    assert _retry_after_seconds(exc) is None


def test_retry_after_seconds_parses_numeric_header():
    from collectors.cost import _retry_after_seconds

    exc = HttpResponseError(message="x")
    exc.response = NS(headers={"Retry-After": "42"})
    assert _retry_after_seconds(exc) == 42.0


def test_retry_after_seconds_case_insensitive_key():
    from collectors.cost import _retry_after_seconds

    exc = HttpResponseError(message="x")
    exc.response = NS(headers={"retry-after": "3"})
    assert _retry_after_seconds(exc) == 3.0
