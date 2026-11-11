"""AWS total-spend collector — pulls 12 months of Cost Explorer data grouped by service."""

from __future__ import annotations

import fnmatch
import logging
import re
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from models.discovery import BackupCostMonth, ServiceCostEntry, SnapshotStorageCost

from collectors import DenialTracker, record_metric_failures

log = logging.getLogger(__name__)


def fetch_service_costs(session, account_id: str, account_alias: str) -> list[ServiceCostEntry]:
    """Return 12 months of amortized cost broken down by AWS service.

    Uses AmortizedCost so Reserved Instance / Savings Plan upfront fees are
    spread across the reservation period rather than charged in month 0.
    Cost Explorer data has a 24-48 h lag; the current partial month is included
    but will be lower than a full month.
    """
    client = session.client("ce", region_name="us-east-1")

    now = datetime.now(timezone.utc)
    start = now.replace(year=now.year - 1).strftime("%Y-%m-%d")
    end = now.strftime("%Y-%m-%d")

    entries: list[ServiceCostEntry] = []
    try:
        paginator_token = None
        while True:
            kwargs: dict = dict(
                TimePeriod={"Start": start, "End": end},
                Granularity="MONTHLY",
                Metrics=["AmortizedCost", "UnblendedCost"],
                GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}],
            )
            if paginator_token:
                kwargs["NextPageToken"] = paginator_token

            resp = client.get_cost_and_usage(**kwargs)

            for period in resp.get("ResultsByTime", []):
                ps = period["TimePeriod"]["Start"]
                pe = period["TimePeriod"]["End"]
                for group in period.get("Groups", []):
                    service = group["Keys"][0]
                    metrics = group.get("Metrics", {})
                    amortized = float(metrics.get("AmortizedCost", {}).get("Amount", 0))
                    if amortized == 0:
                        continue
                    entries.append(
                        ServiceCostEntry(
                            account_id=account_id,
                            account_alias=account_alias,
                            period_start=ps,
                            period_end=pe,
                            service=service,
                            amortized_cost=round(amortized, 4),
                            unblended_cost=round(
                                float(metrics.get("UnblendedCost", {}).get("Amount", 0)), 4
                            ),
                        )
                    )

            paginator_token = resp.get("NextPageToken")
            if not paginator_token:
                break

    except Exception as exc:
        log.warning("Could not fetch total AWS service costs: %s", exc)

    return entries


CE_METRICS = (
    "AmortizedCost",
    "BlendedCost",
    "NetAmortizedCost",
    "NetUnblendedCost",
    "NormalizedUsageAmount",
    "UnblendedCost",
    "UsageQuantity",
)

# Snapshot/backup USAGE_TYPEs: substring match on the region-prefix-stripped type, minus the
# types other services or the "AWS Backup" service query already count.
SNAPSHOT_KEYWORDS = (
    "Snapshot",
    "BackupUsage",
    "BackupStorage",
    "ChargedBackup",
    "BackupArchive",
    "Backup-Usage",
    "Backup-Storage",
    "ContinuousBackup",
)
MANAGED_EXCLUSIONS = (
    "*EFS-Backup*",
    "*FSx-OpenZFS*",
    "*S3-Backup*",
    "*DynamoDB-Backup-Advanced*",
    "*EKS-Backup*",
    "*Timestream-Backup*",
    "*AWSBackup-*",
)

# PowerShell's -replace is case-insensitive, so the prefix strip also removes e.g. "Backup-".
_REGION_PREFIX = re.compile(r"^[A-Z0-9]+-", re.IGNORECASE)
_BACKUP_OR_SNAPSHOT = re.compile(r"Backup|Snapshot", re.IGNORECASE)
_FIRST_CHUNK = 200
_FALLBACK_CHUNK = 100


def ce_time_period(now: Optional[datetime] = None) -> dict[str, str]:
    """The first of the month twelve months ago, up to today (the current month so far)."""
    now = now or datetime.now()
    month = now.month
    year = now.year - 1
    return {"Start": f"{year:04d}-{month:02d}-01", "End": now.strftime("%Y-%m-%d")}


def is_snapshot_usage_type(usage_type: str) -> bool:
    """Whether a region-prefix-stripped USAGE_TYPE is snapshot or backup storage."""
    lowered = usage_type.lower()
    if any(fnmatch.fnmatchcase(lowered, pattern.lower()) for pattern in MANAGED_EXCLUSIONS):
        return False
    return any(keyword.lower() in lowered for keyword in SNAPSHOT_KEYWORDS)


def _error_code(exc: Exception) -> str:
    return str(getattr(exc, "response", {}).get("Error", {}).get("Code", ""))


def _record_ce_failure(tracker: "DenialTracker | None", what: str, exc: Exception) -> None:
    code, text = _error_code(exc), str(exc)
    if "DataUnavailable" in code or "DataUnavailable" in text:
        message = f"{what}: Cost Explorer has no data (is it enabled for this account?)"
    elif "AccessDenied" in code or "AccessDenied" in text or "not authorized" in text:
        message = f"{what}: access denied (needs ce:GetCostAndUsage)"
    else:
        record_metric_failures(tracker, "global", what, [exc], service="cost")
        return
    logging.warning("%s", message)
    if tracker is not None:
        tracker.record_permission_error("cost", "global", Exception(message))


def _paged(call: Callable[..., dict], key: str, **kwargs: Any) -> list[dict]:
    """Follow ``NextPageToken``, so a long window or many groups is never cut off."""
    items: list[dict] = []
    token = None
    while True:
        page = call(**kwargs, **({"NextPageToken": token} if token else {}))
        items.extend(page.get(key, []))
        token = page.get("NextPageToken")
        if not token:
            return items


def _amount(metrics: dict, name: str) -> float:
    try:
        return float((metrics.get(name) or {}).get("Amount") or 0)
    except (TypeError, ValueError):
        return 0.0


def fetch_backup_cost_months(
    session,
    account_id: str,
    account_alias: str,
    tracker: "DenialTracker | None" = None,
    now: Optional[datetime] = None,
) -> list[BackupCostMonth]:
    """Monthly "AWS Backup" service cost, all seven metrics (``Get-AWSBackupCosts``)."""
    client = session.client("ce", region_name="us-east-1")
    try:
        periods = _paged(
            client.get_cost_and_usage,
            "ResultsByTime",
            TimePeriod=ce_time_period(now),
            Granularity="MONTHLY",
            Metrics=list(CE_METRICS),
            Filter={"Dimensions": {"Key": "SERVICE", "Values": ["AWS Backup"]}},
        )
    except Exception as exc:
        _record_ce_failure(tracker, "AWS Backup cost", exc)
        return []
    return [
        BackupCostMonth(
            account_id=account_id,
            account_alias=account_alias,
            period_start=p["TimePeriod"]["Start"],
            period_end=p["TimePeriod"]["End"],
            amounts={m: _amount(p.get("Total") or {}, m) for m in CE_METRICS},
        )
        for p in periods
    ]


def _snapshot_usage_types(client, window: dict[str, str]) -> list[str]:
    values = _paged(
        client.get_dimension_values,
        "DimensionValues",
        TimePeriod=window,
        Dimension="USAGE_TYPE",
    )
    matched: list[str] = []
    unclassified = 0
    for entry in values:
        usage_type = entry.get("Value")
        if not usage_type:
            continue
        bare = _REGION_PREFIX.sub("", usage_type)
        if is_snapshot_usage_type(bare):
            matched.append(usage_type)
        elif _BACKUP_OR_SNAPSHOT.search(bare):
            unclassified += 1
    if unclassified:
        logging.warning(
            "%d USAGE_TYPE line item(s) were not recognized and are left out of the snapshot "
            "cost totals; AWS may have added a service since this tool's keyword list",
            unclassified,
        )
    return matched


def fetch_snapshot_storage_costs(
    session,
    account_id: str,
    account_alias: str,
    tracker: "DenialTracker | None" = None,
    now: Optional[datetime] = None,
) -> list[SnapshotStorageCost]:
    """Monthly cost and usage of each snapshot/backup USAGE_TYPE (``Get-AWSSnapshotStorageCosts``).

    Usage types are discovered from Cost Explorer, filtered by keyword, and queried 200 at a
    time grouped by service and usage type (100 at a time if Cost Explorer rejects the size).
    """
    client = session.client("ce", region_name="us-east-1")
    window = ce_time_period(now)
    try:
        matched = _snapshot_usage_types(client, window)
        periods: list[dict] = []
        chunk, index = _FIRST_CHUNK, 0
        while index < len(matched):
            names = matched[index : index + chunk]
            try:
                periods.extend(
                    _paged(
                        client.get_cost_and_usage,
                        "ResultsByTime",
                        TimePeriod=window,
                        Granularity="MONTHLY",
                        Metrics=list(CE_METRICS),
                        GroupBy=[
                            {"Type": "DIMENSION", "Key": "SERVICE"},
                            {"Type": "DIMENSION", "Key": "USAGE_TYPE"},
                        ],
                        Filter={"Dimensions": {"Key": "USAGE_TYPE", "Values": names}},
                    )
                )
            except Exception as exc:
                if chunk > _FALLBACK_CHUNK and "ValidationException" in (
                    _error_code(exc) + str(exc)
                ):
                    chunk = _FALLBACK_CHUNK
                    continue
                raise
            index += len(names)
    except Exception as exc:
        _record_ce_failure(tracker, "Snapshot storage cost", exc)
        return []

    rows: list[SnapshotStorageCost] = []
    for period in periods:
        for group in period.get("Groups", []):
            keys = group.get("Keys") or ["", ""]
            metrics = group.get("Metrics") or {}
            rows.append(
                SnapshotStorageCost(
                    account_id=account_id,
                    account_alias=account_alias,
                    period_start=period["TimePeriod"]["Start"],
                    period_end=period["TimePeriod"]["End"],
                    service=keys[0],
                    usage_type=keys[1] if len(keys) > 1 else "",
                    usage_unit=str((metrics.get("UsageQuantity") or {}).get("Unit") or ""),
                    amounts={m: _amount(metrics, m) for m in CE_METRICS},
                )
            )
    return rows
