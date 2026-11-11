"""Azure Cost Management collector for Rubrik Discovery.

Queries 6 months of ActualCost spend grouped by ServiceName and billing month.
Never accesses archived data, cold storage tiers, or per-resource metrics.

Each spend row is tagged ``backup`` or ``other`` via ``classify_service()`` so
the report can show backup-related services (Recovery Services, Azure Backup,
Site Recovery) separately from the rest.  Extend via the ``backup_services``
constructor argument on ``CostCollector`` if needed.

Resilience: the Cost Management API aggressively throttles (429).  We retry
on 429 / 5xx with exponential backoff, honour the ``Retry-After`` header
when present, and distinguish throttling from permission failures so the
customer-facing warning message reflects the actual cause.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from azure.core.exceptions import HttpResponseError
from azure.identity import DefaultAzureCredential
from azure.mgmt.costmanagement import CostManagementClient
from azure.mgmt.costmanagement.models import (
    QueryAggregation,
    QueryColumnType,
    QueryComparisonExpression,
    QueryDataset,
    QueryDefinition,
    QueryFilter,
    QueryGrouping,
    QueryTimePeriod,
)
from cloud import DEFAULT_CLOUD, CloudEnvironment

logger = logging.getLogger(__name__)


#: Backoff schedule (seconds) for retries on 429 / 5xx.  Used as a fallback
#: when the response has no ``Retry-After`` header.  Total worst-case wait
#: across three retries is ~50 s — enough to clear most Cost Management
#: throttling windows without making the customer run feel hung.
_RETRY_BACKOFFS: tuple[float, ...] = (5.0, 15.0, 30.0)

#: Internal reason codes returned from ``_query_costs`` so the collect()
#: caller can build a human-readable ``data_note`` appropriate to the
#: actual failure mode.
_REASON_THROTTLED = "throttled"
_REASON_PERMISSION = "permission"
_REASON_NOT_REGISTERED = "not_registered"
_REASON_SERVER_ERROR = "server_error"
_REASON_NO_BACKUP = "no_backup"
_REASON_UNKNOWN = "unknown"

_REASON_NOTES: dict[str, str] = {
    _REASON_THROTTLED: (
        "Cost data unavailable — Azure Cost Management throttled this "
        "request (HTTP 429). This is a rate limit, not a permissions "
        "issue; try re-running in a few minutes."
    ),
    _REASON_PERMISSION: (
        "Cost data unavailable — check that the identity has Cost "
        "Management Reader on this subscription."
    ),
    _REASON_NOT_REGISTERED: (
        "Cost data unavailable — the Microsoft.CostManagement resource "
        "provider may not be registered on this subscription "
        "(run: az provider register --namespace Microsoft.CostManagement)."
    ),
    _REASON_SERVER_ERROR: (
        "Cost data unavailable — Azure Cost Management returned server "
        "errors. Typically transient; try re-running in a few minutes."
    ),
    _REASON_NO_BACKUP: (
        "No backup-attributable spend (Recovery Services / Azure Backup / "
        "Site Recovery) found in the last 6 months — the customer is not "
        "paying for native Azure backup on this subscription."
    ),
    _REASON_UNKNOWN: ("Cost data unavailable — see the warnings above for details."),
}


#: Azure ``ServiceName`` values that are unambiguously backup-attributable.
#: Case-insensitive matching; substring matches count (so "Azure Backup" also
#: catches "Azure Backup Services" if Microsoft ever renames things).
#: Callers can extend this via the ``backup_services`` constructor argument
#: if a customer has unusual billing labels.
DEFAULT_BACKUP_SERVICE_NAMES: frozenset[str] = frozenset(
    {
        "recovery services",  # vault compute + base charges
        "azure backup",  # newer label for protected-instance charges
        "backup",  # bare name sometimes appears
        "azure site recovery",  # DR, typically paired with backup
        "site recovery",
    }
)


def classify_service(
    service_name: str,
    backup_services: frozenset[str] = DEFAULT_BACKUP_SERVICE_NAMES,
) -> str:
    """Return ``"backup"`` if *service_name* matches any backup label, else ``"other"``.

    Matching is case-insensitive and uses substring containment — so
    ``"Recovery Services"`` in the billing data matches the
    ``"recovery services"`` entry in the default set.
    """
    if not service_name:
        return "other"
    name_lc = service_name.lower()
    for marker in backup_services:
        if marker in name_lc:
            return "backup"
    return "other"


@dataclass
class MonthlyServiceSpend:
    """Azure spend for one service in one calendar month."""

    month: str  # YYYY-MM
    service: str
    cost_usd: float
    currency: str = "USD"
    category: str = "other"  # "backup" | "other" — from classify_service()


@dataclass
class BackupCostMonth:
    """One month of Backup spend, as ``Get-AzureSizingInfo.ps1`` writes it to azure_backup_costs."""

    billing_month: (
        str  # ISO 8601 start of the month as the API returned it, e.g. 2026-09-01T00:00:00
    )
    pre_tax_cost_usd: float
    cost_usd: float


@dataclass
class CostSummary:
    """6-month cost summary for a single Azure subscription."""

    subscription_id: str

    monthly_spend_by_service: list[MonthlyServiceSpend] = field(default_factory=list)
    """One entry per (month, service) pair with non-zero spend."""

    total_6mo_spend: float = 0.0
    """Sum of all service spend across the 6-month window."""

    backup_6mo_spend: float = 0.0
    """Subset of ``total_6mo_spend`` attributed to backup-related services."""

    other_6mo_spend: float = 0.0
    """Everything that isn't backup-attributable — workloads, storage, DB, etc."""

    top_services: list[dict] = field(default_factory=list)
    """Up to 10 services sorted by total spend: [{service, total_cost_usd, category}]."""

    top_backup_services: list[dict] = field(default_factory=list)
    """Backup-only services sorted by total spend: [{service, total_cost_usd}]."""

    currency: str = "USD"
    months_collected: list[str] = field(default_factory=list)
    """Sorted YYYY-MM strings for months that had data."""

    current_month_partial: bool = False
    data_note: str = ""

    completed_months_count: int = 0
    """Number of fully-completed months in ``months_collected`` (i.e. months
    before the current calendar month).  Used by the risk model to annualise
    spend without under-counting the partial current month."""

    backup_cost_months: list[BackupCostMonth] = field(default_factory=list)
    """Spend of the ``Backup`` service per month over the last 11 months plus the current one
    (PowerShell's azure_backup_costs); empty when that query is unavailable."""


class CostCollector:
    """Collects 6-month Azure spend via the Cost Management API.

    Credentials are always injected — never instantiated inside this class.
    """

    def __init__(
        self,
        subscription_id: str,
        credential: DefaultAzureCredential,
        backup_services: Optional[frozenset[str]] = None,
        cloud: CloudEnvironment = DEFAULT_CLOUD,
        backup_only: bool = False,
    ) -> None:
        """
        Args:
            subscription_id: Azure subscription ID to query.
            credential: Validated credential injected from ``auth.get_credential()``.
            backup_services: Override the default set of backup-attributable
                service names.  Case-insensitive substring matches.  Pass
                ``None`` (default) to use ``DEFAULT_BACKUP_SERVICE_NAMES``.
            cloud: Target Azure cloud (public vs. sovereign); drives ARM endpoint + token scope.
            backup_only: When True, only *relevant* (backup-attributable) spend
                is pulled — Azure is asked to return just those services via a
                server-side ``ServiceName IN (...)`` filter, and any non-backup
                rows that slip through are dropped client-side.  The customer's
                full bill breakdown is never retrieved.  When False (default) the
                full 6-month all-services breakdown is pulled and tagged
                backup/other.
        """
        self._sub_id = subscription_id
        self._client = CostManagementClient(credential, **cloud.client_kwargs())
        self._scope = f"/subscriptions/{subscription_id}"
        self._backup_services = (
            backup_services if backup_services is not None else DEFAULT_BACKUP_SERVICE_NAMES
        )
        self._backup_only = backup_only
        self._main_reason: Optional[str] = None

    def collect(self) -> CostSummary:
        """Query 6 months of spend grouped by service and billing month.

        Returns an empty (but valid) CostSummary — never raises — when the
        Cost Management API is unavailable or the subscription lacks permissions.

        Returns:
            Populated CostSummary dataclass.
        """
        logger.debug("[%s] Starting cost collection", self._sub_id)

        now = datetime.now(timezone.utc)
        start_date, end_date = _six_month_window(now)

        scope_note = (
            " Scope: backup-attributable services only (Recovery Services / "
            "Azure Backup / Site Recovery)."
            if self._backup_only
            else ""
        )
        summary = CostSummary(
            subscription_id=self._sub_id,
            current_month_partial=True,
            data_note=(
                f"Data from {start_date.strftime('%Y-%m-%d')} to "
                f"{end_date.strftime('%Y-%m-%d')}. "
                f"Current month figures are partial.{scope_note}"
            ),
        )

        rows, col_names, reason = self._query_costs(start_date, end_date)
        self._main_reason = reason
        if rows is None:
            summary.data_note = _REASON_NOTES.get(
                reason or _REASON_UNKNOWN,
                _REASON_NOTES[_REASON_UNKNOWN],
            )
            return summary

        self._populate_summary(summary, rows, col_names or [])

        logger.debug(
            "[%s] Cost complete: %.2f %s over %d months, %d service rows",
            self._sub_id,
            summary.total_6mo_spend,
            summary.currency,
            len(summary.months_collected),
            len(summary.monthly_spend_by_service),
        )
        return summary

    def collect_backup_months(self, now: Optional[datetime] = None) -> list[BackupCostMonth]:
        """The monthly ``Backup`` service spend PowerShell writes to azure_backup_costs.

        Call after ``collect()``: when that query failed because of throttling, a missing
        permission, an unregistered provider or a server error, this one would fail the same way,
        so it returns ``[]`` without repeating the retries.

        Same query as the script: type ``Usage``, monthly, from 11 months ago to now, filtered
        to ``ServiceName`` ``Backup``, summing ``PreTaxCostUSD`` and ``CostUSD``. Columns are
        found by name; PowerShell reads them by position. Returns ``[]`` if the query fails.
        """
        if self._main_reason in (
            _REASON_THROTTLED,
            _REASON_PERMISSION,
            _REASON_NOT_REGISTERED,
            _REASON_SERVER_ERROR,
        ):
            return []
        now = now or datetime.now(timezone.utc)
        query_def = QueryDefinition(
            type="Usage",
            timeframe="Custom",
            time_period=QueryTimePeriod(from_property=_add_months(now, -11), to=now),
            dataset=QueryDataset(
                granularity="Monthly",
                aggregation={
                    "totalCostUSD": QueryAggregation(name="CostUSD", function="Sum"),
                    "totalPreTaxCostUSD": QueryAggregation(name="PreTaxCostUSD", function="Sum"),
                },
                filter=QueryFilter(
                    dimensions=QueryComparisonExpression(
                        name="ServiceName", operator="In", values_property=["Backup"]
                    )
                ),
            ),
        )
        rows, col_names, reason = self._execute_query(query_def)
        if rows is None:
            logger.info("[%s] Backup cost months unavailable (%s)", self._sub_id, reason)
            return []
        names = col_names or []
        pre_tax_idx = _col_idx(names, "PreTaxCostUSD", 0)
        cost_idx = _col_idx(names, "CostUSD", 1)
        month_idx = _col_idx(names, "BillingMonth", 2)
        months: list[BackupCostMonth] = []
        for row in rows:
            try:
                months.append(
                    BackupCostMonth(
                        billing_month=_month_start(row[month_idx]),
                        pre_tax_cost_usd=float(row[pre_tax_idx]),
                        cost_usd=float(row[cost_idx]),
                    )
                )
            except (IndexError, TypeError, ValueError) as exc:
                logger.debug("[%s] Skipping backup cost row %r: %s", self._sub_id, row, exc)
        return months

    def _resolve_backup_scope(self) -> tuple[str, Optional[QueryFilter]]:
        """Decide how to scope a backup-only cost pull.

        The Cost Management query filter only supports exact-match ``In`` (no
        substring / contains), while our backup classification is substring
        based.  To bridge the two we enumerate the actual ``ServiceName``
        dimension values for this subscription, classify each through
        ``classify_service()``, and build an ``In`` filter from the exact names
        that match.

        Returns ``(mode, filter)`` where ``mode`` is one of:

        - ``"filter"`` — at least one backup service exists; ``filter`` is a
          server-side ``ServiceName IN (...)`` so Azure returns only those rows.
        - ``"no_backup"`` — enumeration succeeded but no service classifies as
          backup; there is genuinely nothing relevant to pull, so the caller
          should skip the query entirely (sending an empty ``In ()`` is a 400).
        - ``"fallback"`` — the dimension values couldn't be enumerated; the
          caller should issue an unfiltered query and rely on the client-side
          backup filter in ``_populate_summary``.
        """
        names = self._list_service_names()
        if not names:
            # None (lookup error) or empty (API returned no values) — can't
            # build a reliable filter; let the client-side filter handle it.
            return "fallback", None

        backup_names = sorted(
            {n for n in names if classify_service(n, self._backup_services) == "backup"}
        )
        if not backup_names:
            logger.info(
                "[%s] No backup-attributable services in 6-month billing "
                "(%d services seen); skipping cost query",
                self._sub_id,
                len(names),
            )
            return "no_backup", None

        logger.debug(
            "[%s] Backup cost scope — %d service(s): %s",
            self._sub_id,
            len(backup_names),
            ", ".join(backup_names),
        )
        return "filter", QueryFilter(
            dimensions=QueryComparisonExpression(
                name="ServiceName",
                operator="In",
                values_property=backup_names,
            )
        )

    def _list_service_names(self) -> Optional[list[str]]:
        """Enumerate distinct ``ServiceName`` dimension values for this scope.

        ``expand="data"`` is required — without it the dimensions API returns
        the dimension definitions with empty ``data``.  Best-effort: returns
        ``None`` (not an empty list) on any failure so the caller can
        distinguish "couldn't look up" from "looked up, found none".
        """
        try:
            names: list[str] = []
            for dim in self._client.dimensions.list(self._scope, expand="data"):
                if getattr(dim, "category", None) == "ServiceName" and getattr(dim, "data", None):
                    names.extend(dim.data)
            return names
        except Exception as exc:  # noqa: BLE001 — graceful degradation, traced below
            logger.info(
                "[%s] ServiceName dimension unavailable (%s); "
                "falling back to client-side backup filter",
                self._sub_id,
                exc,
            )
            return None

    def _query_costs(
        self,
        start: datetime,
        end: datetime,
    ) -> tuple[Optional[list], Optional[list[str]], Optional[str]]:
        """Execute the Cost Management query with retry on throttling.

        Returns:
            ``(rows, column_names, None)`` on success.
            ``(None, None, reason)`` on failure, where ``reason`` is one of
            the ``_REASON_*`` codes so ``collect()`` can build a
            user-friendly note.
        """
        # When scoped to backup only, ask Azure to return just the relevant
        # services so we never pull the customer's full bill over the wire.
        # Best-effort: if the ServiceName values can't be enumerated, we fall
        # back to an unfiltered query and drop non-backup rows client-side in
        # _populate_summary — the output stays backup-only either way.
        cost_filter = None
        if self._backup_only:
            mode, cost_filter = self._resolve_backup_scope()
            if mode == "no_backup":
                # Nothing relevant to pull — return a clean empty result rather
                # than issuing an invalid empty-IN query.
                return None, None, _REASON_NO_BACKUP

        query_def = QueryDefinition(
            type="ActualCost",
            timeframe="Custom",
            time_period=QueryTimePeriod(from_property=start, to=end),
            dataset=QueryDataset(
                granularity="Monthly",
                aggregation={"totalCost": QueryAggregation(name="Cost", function="Sum")},
                grouping=[
                    QueryGrouping(
                        type=QueryColumnType.DIMENSION,
                        name="ServiceName",
                    )
                ],
                filter=cost_filter,
            ),
        )

        return self._execute_query(query_def)

    def _execute_query(
        self, query_def: QueryDefinition
    ) -> tuple[Optional[list], Optional[list[str]], Optional[str]]:
        """Run a Cost Management query, retrying throttling and transient server errors.

        Returns ``(rows, column_names, None)`` on success and ``(None, None, reason)`` on
        failure, with ``reason`` one of the ``_REASON_*`` codes.
        """
        max_attempts = len(_RETRY_BACKOFFS) + 1
        for attempt in range(max_attempts):
            try:
                result = self._client.query.usage(self._scope, query_def)
                if not result:
                    return [], [], None
                col_names = [c.name for c in (result.columns or [])]
                return (result.rows or []), col_names, None

            except HttpResponseError as exc:
                status = getattr(exc, "status_code", None)
                msg = getattr(exc, "message", str(exc))

                # Throttling — honour Retry-After when present, else back off.
                if status == 429:
                    if attempt < max_attempts - 1:
                        wait = _retry_after_seconds(exc) or _RETRY_BACKOFFS[attempt]
                        logger.info(
                            "[%s] Cost Management throttled (429); "
                            "retrying in %.0fs (attempt %d/%d)",
                            self._sub_id,
                            wait,
                            attempt + 1,
                            max_attempts,
                        )
                        time.sleep(wait)
                        continue
                    logger.warning(
                        "[%s] Cost Management still throttled after %d attempts",
                        self._sub_id,
                        max_attempts,
                    )
                    return None, None, _REASON_THROTTLED

                # Transient server errors — retry with backoff.
                if status is not None and 500 <= status < 600:
                    if attempt < max_attempts - 1:
                        wait = _RETRY_BACKOFFS[attempt]
                        logger.info(
                            "[%s] Cost Management %d; retrying in %.0fs (attempt %d/%d)",
                            self._sub_id,
                            status,
                            wait,
                            attempt + 1,
                            max_attempts,
                        )
                        time.sleep(wait)
                        continue
                    logger.warning(
                        "[%s] Cost Management %d after %d attempts: %s",
                        self._sub_id,
                        status,
                        max_attempts,
                        msg,
                    )
                    return None, None, _REASON_SERVER_ERROR

                # 4xx (other than 429) — do not retry.
                if status in (401, 403):
                    logger.warning(
                        "[%s] Cost Management %d (permission denied): %s",
                        self._sub_id,
                        status,
                        msg,
                    )
                    return None, None, _REASON_PERMISSION

                if status == 404:
                    logger.warning(
                        "[%s] Cost Management 404 (provider not registered?): %s",
                        self._sub_id,
                        msg,
                    )
                    return None, None, _REASON_NOT_REGISTERED

                logger.warning(
                    "[%s] Cost Management query failed (HTTP %s): %s",
                    self._sub_id,
                    status,
                    msg,
                )
                return None, None, _REASON_UNKNOWN

            except Exception as exc:
                logger.warning("[%s] Cost query error: %s", self._sub_id, exc)
                return None, None, _REASON_UNKNOWN

        # Shouldn't reach here — the loop returns on every path — but fall
        # through defensively.
        return None, None, _REASON_UNKNOWN

    def _populate_summary(
        self,
        summary: CostSummary,
        rows: list,
        col_names: list[str],
    ) -> None:
        """Parse raw Cost Management rows into summary fields.

        The API returns rows in column order declared by ``result.columns``.
        Typical order with our query: ``[Cost, ServiceName, BillingMonth, Currency]``.
        We resolve by name first, fall back to that positional default.
        """
        cost_idx = _col_idx(col_names, "Cost", 0)
        service_idx = _col_idx(col_names, "ServiceName", 1)
        month_idx = _col_idx(col_names, "BillingMonth", 2)
        currency_idx = _col_idx(col_names, "Currency", 3)

        service_totals: dict[str, float] = {}
        service_categories: dict[str, str] = {}
        months_seen: set[str] = set()
        backup_total = 0.0
        other_total = 0.0

        for row in rows:
            try:
                cost_val = float(row[cost_idx]) if row[cost_idx] is not None else 0.0
                if cost_val == 0.0:
                    continue

                service = (
                    str(row[service_idx])
                    if len(row) > service_idx and row[service_idx]
                    else "Other"
                )
                month = _parse_month(row[month_idx] if len(row) > month_idx else None)
                currency = (
                    str(row[currency_idx])
                    if len(row) > currency_idx and row[currency_idx]
                    else "USD"
                )

                category = classify_service(service, self._backup_services)

                # Backup-only scope: drop any non-backup row that the
                # server-side filter didn't already exclude (e.g. when the
                # ServiceName dimension couldn't be enumerated).
                if self._backup_only and category != "backup":
                    continue

                summary.monthly_spend_by_service.append(
                    MonthlyServiceSpend(
                        month=month,
                        service=service,
                        cost_usd=round(cost_val, 2),
                        currency=currency,
                        category=category,
                    )
                )
                summary.currency = currency  # all rows should agree
                service_totals[service] = service_totals.get(service, 0.0) + cost_val
                service_categories[service] = category
                months_seen.add(month)

                if category == "backup":
                    backup_total += cost_val
                else:
                    other_total += cost_val

            except Exception as exc:
                logger.warning("[%s] Skipping cost row %r: %s", self._sub_id, row, exc)

        summary.total_6mo_spend = round(sum(service_totals.values()), 2)
        summary.backup_6mo_spend = round(backup_total, 2)
        summary.other_6mo_spend = round(other_total, 2)
        summary.months_collected = sorted(months_seen)
        summary.top_services = [
            {
                "service": svc,
                "total_cost_usd": round(total, 2),
                "category": service_categories.get(svc, "other"),
            }
            for svc, total in sorted(service_totals.items(), key=lambda x: -x[1])[:10]
        ]
        summary.top_backup_services = [
            {"service": svc, "total_cost_usd": round(total, 2)}
            for svc, total in sorted(service_totals.items(), key=lambda x: -x[1])
            if service_categories.get(svc) == "backup"
        ][:10]

        # Count months strictly before the current calendar month as "completed".
        current_month = datetime.now(timezone.utc).strftime("%Y-%m")
        summary.completed_months_count = sum(
            1 for m in summary.months_collected if m != "Unknown" and m < current_month
        )


def _retry_after_seconds(exc: HttpResponseError) -> Optional[float]:
    """Extract a ``Retry-After`` header value from a 429 response, if present.

    Azure Cost Management 429s usually include a ``Retry-After`` header set
    to the number of seconds the caller should wait.  When absent, the
    caller falls back to the module's static backoff schedule.
    """
    try:
        response = getattr(exc, "response", None)
        if response is None:
            return None
        headers = getattr(response, "headers", None) or {}
        if not hasattr(headers, "get"):
            return None
        # Header names can vary in case depending on the underlying HTTP
        # library — try the common variants.
        for key in ("Retry-After", "retry-after", "RETRY-AFTER"):
            val = headers.get(key)
            if val:
                return float(val)
    except (ValueError, TypeError, AttributeError):
        return None
    return None


def _six_month_window(now: datetime) -> tuple[datetime, datetime]:
    """Return ``(start, end)`` covering the past 6 months including the current partial month.

    Example: if today is 2026-04-12, returns (2025-11-01 UTC, now).
    """
    y, m = now.year, now.month
    start_m = m - 5
    start_y = y
    if start_m <= 0:
        start_m += 12
        start_y -= 1
    start = datetime(start_y, start_m, 1, tzinfo=timezone.utc)
    return start, now


def _add_months(moment: datetime, months: int) -> datetime:
    """``DateTime.AddMonths``: same day of month, clamped to the target month's last day."""
    index = moment.year * 12 + (moment.month - 1) + months
    year, month = divmod(index, 12)
    month += 1
    for day in range(moment.day, 0, -1):
        try:
            return moment.replace(year=year, month=month, day=day)
        except ValueError:
            continue
    return moment


def _month_start(raw: object) -> str:
    """A billing month as ISO 8601 text: ``2026-09-01T00:00:00``.

    The API returns an ISO string, a ``datetime``, or digits (``20260901000000``, ``20260901``).
    """
    if isinstance(raw, datetime):
        return raw.replace(tzinfo=None).isoformat(timespec="seconds")
    text = str(raw).strip()
    if len(text) >= 8 and text[:8].isdigit():
        text = f"{text[:4]}-{text[4:6]}-{text[6:8]}"
    return datetime.fromisoformat(text).replace(tzinfo=None).isoformat(timespec="seconds")


def _col_idx(col_names: list[str], name: str, default: int) -> int:
    """Return the index of *name* in *col_names*, or *default* if absent."""
    try:
        return col_names.index(name)
    except ValueError:
        return default


def _parse_month(raw: object) -> str:
    """Convert a Cost Management billing-month value to a ``YYYY-MM`` string.

    The API can return the month as a ``datetime``, a 14-digit integer string
    (``"20240101000000"``), a 6-digit string (``"202401"``), or an ISO date
    string (``"2024-01-01T00:00:00"``).
    """
    if raw is None:
        return "Unknown"
    if isinstance(raw, datetime):
        return raw.strftime("%Y-%m")
    s = str(raw).strip()
    # 14-digit or 8-digit numeric: 20240101000000 or 20240101
    if len(s) >= 8 and s[:8].isdigit():
        return f"{s[:4]}-{s[4:6]}"
    # 6-digit numeric: 202401
    if len(s) == 6 and s.isdigit():
        return f"{s[:4]}-{s[4:6]}"
    # ISO datetime: 2024-01-01T...
    if len(s) >= 7 and s[4] == "-":
        return s[:7]
    return s[:7] if len(s) >= 7 else s
