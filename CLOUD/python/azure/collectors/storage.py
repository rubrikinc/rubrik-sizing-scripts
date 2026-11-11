"""Azure Storage collector for Rubrik Discovery.

Collects per-subscription storage account inventory including redundancy
tier, blob soft-delete posture, versioning, and best-effort used capacity
via the Monitor metrics API.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional

from azure.core.exceptions import HttpResponseError, ResourceNotFoundError
from azure.identity import DefaultAzureCredential
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.storage import StorageManagementClient
import progress
from cloud import DEFAULT_CLOUD, CloudEnvironment

from collectors.utils import (
    TagSummary,
    build_tag_summary,
    decimal_gb,
    decimal_tb,
    enum_text,
    metric_timespan,
    parse_resource_group,
    warn_once,
)

logger = logging.getLogger(__name__)

# Capacity and object counts are the latest hourly Maximum of the last day, as the PowerShell
# script reads them (Get-AzMetric -AggregationType Maximum -StartTime now-1d, then the last data
# point). A daily (P1D) point is the fallback: it is the day's largest value, which overstates an
# account that shrank during the day.
_METRIC_AGGREGATION = "Maximum"
_METRIC_WINDOW = timedelta(days=1)
_INTERVALS = ("PT1H", "P1D")

#: Storage SKU name → human-readable redundancy label.
_SKU_REDUNDANCY: dict[str, str] = {
    "Standard_LRS": "LRS",
    "Standard_GRS": "GRS",
    "Standard_RAGRS": "RA-GRS",
    "Standard_ZRS": "ZRS",
    "Standard_GZRS": "GZRS",
    "Standard_RAGZRS": "RA-GZRS",
    "Premium_LRS": "Premium LRS",
    "Premium_ZRS": "Premium ZRS",
}


@dataclass
class FileShareInfo:
    """One Azure Files share, as PowerShell's ``Get-AzRmStorageShare -GetShareUsage`` reports it."""

    name: str
    quota_gib: Optional[int] = None
    usage_bytes: Optional[int] = None  # None when usage was not read or the call failed


# Premium SKUs that only hold Azure Files on a FileStorage account.
_PREMIUM_FILE_SKUS = frozenset({"Premium_LRS", "Premium_ZRS"})


def supports_azure_files(kind: str, sku: str) -> bool:
    """PowerShell's ``Get-AzureFileSAs``: which accounts it queries for file shares."""
    if kind in ("StorageV2", "Storage"):
        return sku not in _PREMIUM_FILE_SKUS
    return kind == "FileStorage" and sku in _PREMIUM_FILE_SKUS


@dataclass
class StorageAccountInfo:
    """Information about a single Azure Storage Account."""

    name: str
    resource_id: str
    resource_group: str
    subscription_id: str
    location: str
    kind: str  # StorageV2 / BlobStorage / FileStorage / BlockBlobStorage
    sku: str  # Raw SKU name, e.g. Standard_LRS
    redundancy: str  # Normalised: LRS / GRS / ZRS / RA-GRS / …
    access_tier: Optional[str]  # Hot / Cool / None (non-blob kinds)
    tags: dict[str, str]

    # Blob service data-protection properties
    blob_soft_delete_enabled: bool
    blob_soft_delete_days: Optional[int]
    container_soft_delete_enabled: bool
    container_soft_delete_days: Optional[int]
    versioning_enabled: bool
    blob_inventory_enabled: bool

    # Best-effort capacity (None = metrics unavailable or access denied)
    capacity_bytes: Optional[float]
    capacity_gb: Optional[float]
    # capacity_tb: straight unit conversion of capacity_gb (same /1024 divisor as
    # ComputeInventory.total_disk_tb) — not a new precision level, just a TB sibling.
    capacity_tb: Optional[float] = None
    # Decimal units (GB = 1e9 bytes, TB = 1e12) alongside the binary fields above.
    capacity_gb_decimal: Optional[float] = None
    capacity_tb_decimal: Optional[float] = None

    # Best-effort object/file counts via Monitor metrics (None = unavailable).
    # blob_count → cloud-native Blob sizing (object count); file_count + file_share_count →
    # Azure Files (NCD) sizing. Kept DISTINCT because Blob and Files are separate sizing
    # workloads (Blob = cloud-native getCnpPrices, Files = NAS CloudDirect).
    blob_count: Optional[int] = None
    file_count: Optional[int] = None
    file_share_count: Optional[int] = None

    # Per-service figures PowerShell writes next to the account total. Each is None when the
    # Monitor metric is unavailable, and hns_enabled is None when the API does not report it.
    hns_enabled: Optional[bool] = None
    blob_capacity_bytes: Optional[float] = None
    file_capacity_bytes: Optional[float] = None
    blob_container_count: Optional[int] = None

    # The account's Azure Files shares (empty for accounts that do not support Azure Files).
    file_shares: list[FileShareInfo] = field(default_factory=list)


@dataclass
class StorageInventory:
    """Storage inventory for a single subscription."""

    subscription_id: str
    accounts: list[StorageAccountInfo] = field(default_factory=list)

    # Roll-ups
    total_accounts: int = 0
    total_capacity_gb: Optional[float] = None  # None if metrics unavailable for all
    total_capacity_bytes: Optional[float] = None  # Σ capacity_bytes; None if unavailable for all
    total_capacity_tb: Optional[float] = None  # straight /1024 conversion of total_capacity_gb
    total_capacity_gb_decimal: Optional[float] = None
    total_capacity_tb_decimal: Optional[float] = None
    redundancy_breakdown: dict[str, int] = field(default_factory=dict)
    kind_breakdown: dict[str, int] = field(default_factory=dict)
    soft_delete_enabled_count: int = 0
    soft_delete_coverage_pct: float = 0.0
    versioning_enabled_count: int = 0
    versioning_coverage_pct: float = 0.0
    capacity_available: bool = False  # True if at least one account returned metrics
    # True if the capacity pass was requested (i.e. not opted out via --no-capacity).
    # Lets the SE distinguish "capacity unavailable / access denied" (requested + not
    # available) from "capacity not collected" (opted out) — both leave totals None.
    capacity_requested: bool = True
    # Σ object/file counts across accounts (None if no account returned that metric).
    total_blob_count: Optional[int] = None
    total_file_count: Optional[int] = None
    total_file_share_count: Optional[int] = None

    tag_summary: Optional[TagSummary] = None


class StorageCollector:
    """Collects Azure Storage Account inventory for a subscription.

    Credentials are always injected — never instantiated inside this class.
    """

    def __init__(
        self,
        subscription_id: str,
        credential: DefaultAzureCredential,
        regions: Optional[list[str]] = None,
        cloud: CloudEnvironment = DEFAULT_CLOUD,
        collect_capacity: bool = True,
        collect_file_shares: bool = True,
    ) -> None:
        """
        Args:
            subscription_id: Azure subscription ID to collect from.
            credential: Validated credential injected from ``auth.get_credential()``.
            regions: Normalised region names to include, or None for all.
            cloud: Target Azure cloud (public vs. sovereign); drives ARM endpoint + token scope.
            collect_capacity: When False, skip the Azure Monitor used-capacity metrics
                entirely (accounts are still inventoried). Lets the operator opt out of the
                slow/permission-sensitive capacity pass without dropping storage discovery.
            collect_file_shares: When False, do not list Azure Files shares (PowerShell's
                ``-SkipAzureFiles``); accounts are still inventoried.
        """
        self._sub_id = subscription_id
        self._collect_capacity = collect_capacity
        self._collect_file_shares = collect_file_shares
        self._metric_failures: list[str] = []
        self._regions: Optional[frozenset[str]] = frozenset(regions) if regions else None
        self._storage = StorageManagementClient(
            credential, subscription_id, **cloud.client_kwargs()
        )
        self._monitor = MonitorManagementClient(
            credential, subscription_id, **cloud.client_kwargs()
        )

    def collect(self) -> StorageInventory:
        """Run the full storage collection pass for this subscription.

        Returns:
            Populated StorageInventory dataclass.
        """
        logger.debug("[%s] Starting storage collection", self._sub_id)

        accounts = self._list_accounts()
        inventory = StorageInventory(
            subscription_id=self._sub_id,
            accounts=accounts,
            capacity_requested=self._collect_capacity,
        )
        self._compute_rollups(inventory)
        inventory.tag_summary = build_tag_summary([a.tags for a in accounts])

        # Capacity is best-effort via the Monitor metrics API and failures are only
        # logged at DEBUG. If NOT ONE account returned capacity, the report/Explorer
        # will silently show blank storage capacity — surface that loudly so the SE
        # knows to fix it rather than mistaking it for an empty environment.
        if self._collect_capacity and accounts and not inventory.capacity_available:
            logger.warning(
                "[%s] Used-capacity unavailable for ALL %d storage account(s): every Azure "
                "Monitor metrics query failed, so storage capacity will be blank in the report "
                "and Explorer. Most common cause (%s)",
                self._sub_id,
                len(accounts),
                self._top_metric_failure(),
            )

        logger.debug(
            "[%s] Storage complete: %d accounts, %.1f GB total capacity",
            self._sub_id,
            inventory.total_accounts,
            inventory.total_capacity_gb or 0.0,
        )
        return inventory

    def _note_metric_failure(self, exc: BaseException) -> None:
        """Keep why a metrics query failed. The first of each cause is warned about at once; the
        per-account detail stays at DEBUG, which is why this used to need ``--verbose``."""
        cause = f"{type(exc).__name__}: {' '.join(str(exc).split())[:240]}"
        self._metric_failures.append(cause)
        warn_once(
            "[%s] Azure Monitor metrics query failed (the same failure is not repeated): %s",
            self._sub_id,
            cause,
        )

    def _top_metric_failure(self) -> str:
        """The most common reason metrics queries failed, with how many of them it was."""
        if not self._metric_failures:
            return "no error was returned; the metric had no data points in the last day"
        counts: dict = {}
        for cause in self._metric_failures:
            counts.setdefault(re.sub(r"\d+", "#", cause), [0, cause])[0] += 1
        count, example = max(counts.values(), key=lambda item: item[0])
        return f"{count} of {len(self._metric_failures)} failed queries: {example}"

    def probe_monitor_access(self) -> str:
        """Pre-flight: can this identity read Azure Monitor storage metrics?

        Issues at most one cheap call each against the Storage and Monitor APIs
        (list one storage account, then one ``UsedCapacity`` query against it) so
        the operator learns *before* the full scan whether capacity will be blank.
        Monitor metrics read is granted at subscription scope, so a single
        resource probe is representative.

        Returns one of:
          ``"ok"``           — Monitor returned a response (access works).
          ``"denied"``       — Monitor read denied (401/403) — capacity will be blank.
          ``"no_accounts"``  — no in-scope storage accounts to probe.
          ``"error"``        — some other failure (throttling, transient); inconclusive.
          ``"skipped"``      — capacity collection opted out, nothing to probe.
        """
        if not self._collect_capacity:
            return "skipped"

        try:
            probe_id: Optional[str] = None
            for acct in self._storage.storage_accounts.list():
                location = (acct.location or "").lower()
                if self._regions and location not in self._regions:
                    continue
                if acct.id:
                    probe_id = acct.id
                    break
        except Exception as exc:
            logger.debug("[%s] Monitor pre-flight: account list failed: %s", self._sub_id, exc)
            return "error"

        if not probe_id:
            return "no_accounts"

        end_time = datetime.now(timezone.utc)
        timespan = metric_timespan(end_time - timedelta(hours=72), end_time)
        try:
            self._monitor.metrics.list(
                resource_uri=probe_id,
                timespan=timespan,
                interval="PT1H",
                metricnames="UsedCapacity",
                aggregation="Average",
                metricnamespace="Microsoft.Storage/storageAccounts",
            )
            return "ok"
        except HttpResponseError as exc:
            if exc.status_code in (401, 403):
                return "denied"
            logger.debug("[%s] Monitor pre-flight: query error: %s", self._sub_id, exc)
            return "error"
        except Exception as exc:
            logger.debug("[%s] Monitor pre-flight: unexpected error: %s", self._sub_id, exc)
            return "error"

    def _list_accounts(self) -> list[StorageAccountInfo]:
        """List all storage accounts in the subscription."""
        accounts: list[StorageAccountInfo] = []

        try:
            # Listed first so the spinner can count: each account takes several metric queries.
            in_scope = [
                acct
                for acct in self._storage.storage_accounts.list()
                if not self._regions or (acct.location or "").lower() in self._regions
            ]
            for acct in progress.every(in_scope, self._sub_id, "accounts"):
                try:
                    location = (acct.location or "").lower()
                    rg = parse_resource_group(acct.id or "")
                    sku = enum_text(acct.sku.name) if acct.sku else "Unknown"
                    redundancy = _SKU_REDUNDANCY.get(sku, sku)

                    blob_props = self._get_blob_properties(acct.name or "", rg)
                    capacity_bytes, capacity_gb = self._get_capacity(acct.id or "")
                    counts = self._get_object_counts(acct.id or "")
                    service_metrics = self._get_service_metrics(acct.id or "")
                    kind = enum_text(acct.kind) or "Unknown"
                    file_shares = (
                        self._list_file_shares(acct.name or "", rg)
                        if self._collect_file_shares and supports_azure_files(kind, sku)
                        else []
                    )
                    inventory_enabled = self._get_blob_inventory_enabled(acct.name or "", rg)

                    accounts.append(
                        StorageAccountInfo(
                            name=acct.name or "",
                            resource_id=acct.id or "",
                            resource_group=rg,
                            subscription_id=self._sub_id,
                            location=location,
                            kind=enum_text(acct.kind) or "Unknown",
                            sku=sku,
                            redundancy=redundancy,
                            access_tier=enum_text(acct.access_tier) or None,
                            tags=dict(acct.tags) if acct.tags else {},
                            blob_soft_delete_enabled=blob_props["blob_soft_delete_enabled"],
                            blob_soft_delete_days=blob_props["blob_soft_delete_days"],
                            container_soft_delete_enabled=blob_props[
                                "container_soft_delete_enabled"
                            ],
                            container_soft_delete_days=blob_props["container_soft_delete_days"],
                            versioning_enabled=blob_props["versioning_enabled"],
                            blob_inventory_enabled=inventory_enabled,
                            capacity_bytes=capacity_bytes,
                            capacity_gb=capacity_gb,
                            capacity_tb=(
                                round(capacity_gb / 1024, 3) if capacity_gb is not None else None
                            ),
                            capacity_gb_decimal=decimal_gb(capacity_bytes),
                            capacity_tb_decimal=decimal_tb(capacity_bytes),
                            blob_count=counts["blob_count"],
                            file_count=counts["file_count"],
                            file_share_count=counts["file_share_count"],
                            hns_enabled=getattr(acct, "is_hns_enabled", None),
                            blob_capacity_bytes=service_metrics["blob_capacity_bytes"],
                            file_capacity_bytes=service_metrics["file_capacity_bytes"],
                            blob_container_count=service_metrics["blob_container_count"],
                            file_shares=file_shares,
                        )
                    )
                except Exception as exc:
                    logger.warning(
                        "[%s] Skipping storage account %s: %s",
                        self._sub_id,
                        getattr(acct, "name", "?"),
                        exc,
                    )
        except HttpResponseError as exc:
            logger.warning("[%s] Failed to list storage accounts: %s", self._sub_id, exc)

        return accounts

    def _get_blob_properties(self, account_name: str, resource_group: str) -> dict:
        """Fetch blob service properties (soft delete, versioning).

        Returns a safe dict with all fields defaulting to False/None on error.
        """
        defaults: dict = {
            "blob_soft_delete_enabled": False,
            "blob_soft_delete_days": None,
            "container_soft_delete_enabled": False,
            "container_soft_delete_days": None,
            "versioning_enabled": False,
        }
        try:
            props = self._storage.blob_services.get_service_properties(resource_group, account_name)
            drp = getattr(props, "delete_retention_policy", None)
            cdrp = getattr(props, "container_delete_retention_policy", None)

            defaults["blob_soft_delete_enabled"] = bool(getattr(drp, "enabled", False))
            defaults["blob_soft_delete_days"] = (
                int(drp.days) if drp and getattr(drp, "days", None) is not None else None
            )
            defaults["container_soft_delete_enabled"] = bool(getattr(cdrp, "enabled", False))
            defaults["container_soft_delete_days"] = (
                int(cdrp.days) if cdrp and getattr(cdrp, "days", None) is not None else None
            )
            defaults["versioning_enabled"] = bool(getattr(props, "is_versioning_enabled", False))
        except (HttpResponseError, ResourceNotFoundError) as exc:
            # Premium / FileStorage accounts may not support blob service props.
            logger.debug(
                "[%s] Blob service properties unavailable for %s: %s",
                self._sub_id,
                account_name,
                exc,
            )
        except Exception as exc:
            logger.warning(
                "[%s] Unexpected error fetching blob props for %s: %s",
                self._sub_id,
                account_name,
                exc,
            )
        return defaults

    def _get_blob_inventory_enabled(self, account_name: str, resource_group: str) -> bool:
        """Return True if a blob inventory policy is configured for this account."""
        try:
            policy = self._storage.blob_inventory_policies.get(resource_group, account_name)
            return bool(getattr(getattr(policy, "properties", None), "policy", None))
        except ResourceNotFoundError:
            return False
        except Exception as exc:
            logger.debug(
                "[%s] Blob inventory check failed for %s: %s",
                self._sub_id,
                account_name,
                exc,
            )
            return False

    def _get_capacity(self, resource_id: str) -> tuple[Optional[float], Optional[float]]:
        """Fetch used capacity in bytes and GB via the Monitor metrics API.

        Best-effort — returns (None, None) on any error rather than crashing.

        Strategy 1: UsedCapacity at the account level: the latest hourly point, else the latest
        daily one (``_INTERVALS``).

        Strategy 2: If UsedCapacity returns no data, sum the per-service metrics
        (BlobCapacity, FileCapacity, TableCapacity, QueueCapacity) which are
        always emitted even when the account-level rollup is unavailable.
        """
        if not self._collect_capacity or not resource_id:
            return None, None

        end_time = datetime.now(timezone.utc)
        start_time = end_time - _METRIC_WINDOW
        timespan = metric_timespan(start_time, end_time)

        def _query(uri: str, namespace: str, metric_name: str, interval: str) -> Optional[float]:
            try:
                result = self._monitor.metrics.list(
                    resource_uri=uri,
                    timespan=timespan,
                    interval=interval,
                    metricnames=metric_name,
                    aggregation=_METRIC_AGGREGATION,
                    metricnamespace=namespace,
                )
                for m in result.value:
                    for ts in m.timeseries:
                        for point in reversed(ts.data):
                            value = getattr(point, "maximum", None)
                            if value is not None:
                                return value
            except HttpResponseError as exc:
                self._note_metric_failure(exc)
                logger.debug(
                    "[%s] %s(%s) unavailable for %s: %s",
                    self._sub_id,
                    metric_name,
                    interval,
                    uri[:60],
                    exc,
                )
            except Exception as exc:
                self._note_metric_failure(exc)
                logger.debug(
                    "[%s] Unexpected error fetching %s(%s) for %s: %s",
                    self._sub_id,
                    metric_name,
                    interval,
                    uri[:60],
                    exc,
                )
            return None

        # Strategy 1: account-level UsedCapacity.
        for interval in _INTERVALS:
            used = _query(
                resource_id,
                "Microsoft.Storage/storageAccounts",
                "UsedCapacity",
                interval,
            )
            if used is not None:
                return used, round(used / (1024**3), 3)

        # Strategy 2: sum per-service metrics — always emitted by Azure, more
        # reliable than the account-level rollup in some regions / account types.
        service_sources = [
            (
                f"{resource_id}/blobServices/default",
                "Microsoft.Storage/storageAccounts/blobServices",
                "BlobCapacity",
            ),
            (
                f"{resource_id}/fileServices/default",
                "Microsoft.Storage/storageAccounts/fileServices",
                "FileCapacity",
            ),
            (
                f"{resource_id}/tableServices/default",
                "Microsoft.Storage/storageAccounts/tableServices",
                "TableCapacity",
            ),
            (
                f"{resource_id}/queueServices/default",
                "Microsoft.Storage/storageAccounts/queueServices",
                "QueueCapacity",
            ),
        ]
        total_bytes: float = 0.0
        found_any = False
        for svc_uri, namespace, metric_name in service_sources:
            svc_bytes: Optional[float] = None
            for interval in _INTERVALS:
                svc_bytes = _query(svc_uri, namespace, metric_name, interval)
                if svc_bytes is not None:
                    break
            if svc_bytes is not None:
                total_bytes += svc_bytes
                found_any = True

        if found_any:
            return total_bytes, round(total_bytes / (1024**3), 3)

        return None, None

    def _get_object_counts(self, resource_id: str) -> dict[str, Optional[int]]:
        """Fetch blob/file object counts via the Monitor metrics API. Best-effort —
        each value is None on any error rather than crashing the run.

        - BlobCount        (blobServices) → number of blobs  → cloud-native Blob sizing
        - FileCount        (fileServices) → number of files  → Azure Files (NCD) sizing
        - FileShareCount   (fileServices) → number of shares → Azure Files (NCD) sizing

        These are point-in-time counts; we read the most recent Maximum over the last day,
        matching the capacity query, and round to a whole number.
        """
        out: dict[str, Optional[int]] = {
            "blob_count": None,
            "file_count": None,
            "file_share_count": None,
        }
        # Object counts ride the same Monitor-metrics pass as used-capacity, so
        # the collect_capacity toggle gates both: skip it → no Monitor calls.
        if not self._collect_capacity or not resource_id:
            return out

        end_time = datetime.now(timezone.utc)
        start_time = end_time - _METRIC_WINDOW
        timespan = metric_timespan(start_time, end_time)

        def _query(uri: str, namespace: str, metric_name: str) -> Optional[int]:
            for interval in _INTERVALS:
                try:
                    result = self._monitor.metrics.list(
                        resource_uri=uri,
                        timespan=timespan,
                        interval=interval,
                        metricnames=metric_name,
                        aggregation=_METRIC_AGGREGATION,
                        metricnamespace=namespace,
                    )
                    for m in result.value:
                        for ts in m.timeseries:
                            for point in reversed(ts.data):
                                value = getattr(point, "maximum", None)
                                if value is not None:
                                    return int(round(value))
                except HttpResponseError as exc:
                    self._note_metric_failure(exc)
                    logger.debug(
                        "[%s] %s(%s) unavailable for %s: %s",
                        self._sub_id,
                        metric_name,
                        interval,
                        uri[:60],
                        exc,
                    )
                except Exception as exc:
                    self._note_metric_failure(exc)
                    logger.debug(
                        "[%s] Unexpected error fetching %s(%s) for %s: %s",
                        self._sub_id,
                        metric_name,
                        interval,
                        uri[:60],
                        exc,
                    )
            return None

        blob_ns = "Microsoft.Storage/storageAccounts/blobServices"
        file_ns = "Microsoft.Storage/storageAccounts/fileServices"
        out["blob_count"] = _query(f"{resource_id}/blobServices/default", blob_ns, "BlobCount")
        out["file_count"] = _query(f"{resource_id}/fileServices/default", file_ns, "FileCount")
        out["file_share_count"] = _query(
            f"{resource_id}/fileServices/default", file_ns, "FileShareCount"
        )
        return out

    def _list_file_shares(self, account_name: str, resource_group: str) -> list[FileShareInfo]:
        """List an account's file shares and read each share's usage.

        Usage is the ``stats`` expansion of a per-share get, as in PowerShell, and is skipped
        when capacity collection is off. A share whose usage cannot be read keeps its quota.
        """
        shares: list[FileShareInfo] = []
        try:
            for item in self._storage.file_shares.list(resource_group, account_name):
                name = getattr(item, "name", "") or ""
                quota = getattr(item, "share_quota", None)
                usage = None
                if self._collect_capacity:
                    try:
                        detail = self._storage.file_shares.get(
                            resource_group, account_name, name, expand="stats"
                        )
                        quota = getattr(detail, "share_quota", quota)
                        usage = getattr(detail, "share_usage_bytes", None)
                    except Exception as exc:
                        logger.debug(
                            "[%s] Usage unavailable for share %s/%s: %s",
                            self._sub_id,
                            account_name,
                            name,
                            exc,
                        )
                shares.append(
                    FileShareInfo(
                        name=name,
                        quota_gib=int(quota) if quota is not None else None,
                        usage_bytes=int(usage) if usage is not None else None,
                    )
                )
        except Exception as exc:
            logger.debug(
                "[%s] Could not list file shares of %s: %s", self._sub_id, account_name, exc
            )
        return shares

    def _get_service_metrics(self, resource_id: str) -> dict[str, Optional[float]]:
        """Fetch BlobCapacity, FileCapacity and ContainerCount (the latest Maximum).

        PowerShell reports these beside the account-level UsedCapacity. Each value is None
        when the metric is unavailable or capacity collection is switched off.
        """
        out: dict[str, Optional[float]] = {
            "blob_capacity_bytes": None,
            "file_capacity_bytes": None,
            "blob_container_count": None,
        }
        if not self._collect_capacity or not resource_id:
            return out

        end_time = datetime.now(timezone.utc)
        start_time = end_time - _METRIC_WINDOW
        timespan = metric_timespan(start_time, end_time)

        def _query(uri: str, namespace: str, metric_name: str) -> Optional[float]:
            for interval in _INTERVALS:
                try:
                    result = self._monitor.metrics.list(
                        resource_uri=uri,
                        timespan=timespan,
                        interval=interval,
                        metricnames=metric_name,
                        aggregation=_METRIC_AGGREGATION,
                        metricnamespace=namespace,
                    )
                    for m in result.value:
                        for ts in m.timeseries:
                            for point in reversed(ts.data):
                                value = getattr(point, "maximum", None)
                                if value is not None:
                                    return value
                except Exception as exc:
                    self._note_metric_failure(exc)
                    logger.debug(
                        "[%s] %s(%s) unavailable for %s: %s",
                        self._sub_id,
                        metric_name,
                        interval,
                        uri[:60],
                        exc,
                    )
            return None

        blob_ns = "Microsoft.Storage/storageAccounts/blobServices"
        file_ns = "Microsoft.Storage/storageAccounts/fileServices"
        blob_uri = f"{resource_id}/blobServices/default"
        out["blob_capacity_bytes"] = _query(blob_uri, blob_ns, "BlobCapacity")
        out["file_capacity_bytes"] = _query(
            f"{resource_id}/fileServices/default", file_ns, "FileCapacity"
        )
        containers = _query(blob_uri, blob_ns, "ContainerCount")
        out["blob_container_count"] = None if containers is None else int(round(containers))
        return out

    def _compute_rollups(self, inventory: StorageInventory) -> None:
        """Compute aggregate fields on the inventory object in-place."""
        inventory.total_accounts = len(inventory.accounts)

        total_capacity_gb: Optional[float] = None
        total_capacity_bytes: Optional[float] = None
        # None until at least one account reports that metric; then a running sum.
        blob_sum: Optional[int] = None
        file_sum: Optional[int] = None
        share_sum: Optional[int] = None

        for acct in inventory.accounts:
            # Redundancy breakdown
            r = acct.redundancy
            inventory.redundancy_breakdown[r] = inventory.redundancy_breakdown.get(r, 0) + 1
            # Kind breakdown
            k = acct.kind
            inventory.kind_breakdown[k] = inventory.kind_breakdown.get(k, 0) + 1

            # Soft delete coverage
            if acct.blob_soft_delete_enabled:
                inventory.soft_delete_enabled_count += 1

            # Versioning coverage
            if acct.versioning_enabled:
                inventory.versioning_enabled_count += 1

            # Capacity
            if acct.capacity_gb is not None:
                total_capacity_gb = (total_capacity_gb or 0.0) + acct.capacity_gb
                inventory.capacity_available = True
            if acct.capacity_bytes is not None:
                total_capacity_bytes = (total_capacity_bytes or 0.0) + acct.capacity_bytes

            # Object/file counts (Blob vs Files kept separate)
            if acct.blob_count is not None:
                blob_sum = (blob_sum or 0) + acct.blob_count
            if acct.file_count is not None:
                file_sum = (file_sum or 0) + acct.file_count
            if acct.file_share_count is not None:
                share_sum = (share_sum or 0) + acct.file_share_count

        inventory.total_capacity_gb = (
            round(total_capacity_gb, 3) if total_capacity_gb is not None else None
        )
        inventory.total_capacity_bytes = (
            round(total_capacity_bytes, 3) if total_capacity_bytes is not None else None
        )
        inventory.total_capacity_tb = (
            round(inventory.total_capacity_gb / 1024, 3)
            if inventory.total_capacity_gb is not None
            else None
        )
        inventory.total_capacity_gb_decimal = decimal_gb(total_capacity_bytes)
        inventory.total_capacity_tb_decimal = decimal_tb(total_capacity_bytes)
        inventory.total_blob_count = blob_sum
        inventory.total_file_count = file_sum
        inventory.total_file_share_count = share_sum

        if inventory.total_accounts > 0:
            inventory.soft_delete_coverage_pct = round(
                inventory.soft_delete_enabled_count / inventory.total_accounts * 100, 1
            )
            inventory.versioning_coverage_pct = round(
                inventory.versioning_enabled_count / inventory.total_accounts * 100, 1
            )
