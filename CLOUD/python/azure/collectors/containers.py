"""Blob containers and the size and count of their blobs per access tier (PowerShell's
-GetContainerDetails).

Every blob of every container is listed with ``azure-storage-blob``, signed in with Entra ID, so the
sign-in needs a data role such as Storage Blob Data Reader. PowerShell lists them with the storage
account's key, which needs ``listKeys``; the blobs and the sums are the same.

The sums follow ``Get-AzureStorageAndFilesInventory``: Hot, Cool and Archive by the blob's access
tier (compared without regard to case, as ``-eq`` does), any other tier as unknown, and snapshots
left out. When one container's blobs cannot be listed, PowerShell keeps the previous container's
blobs in ``$azConBlobs`` and writes them again; here that container gets a row with empty values and
the reason, instead.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

from cloud import DEFAULT_CLOUD, CloudEnvironment
from collectors.key_vault import error_reason

try:
    from azure.storage.blob import BlobServiceClient

    HAS_SDK = True
except ImportError:  # pragma: no cover - the package is in requirements.txt
    BlobServiceClient = None  # type: ignore[assignment,misc]
    HAS_SDK = False

logger = logging.getLogger(__name__)

TIERS = ("hot", "cool", "archive")
# A missing data role refuses every container. After refusals in this many storage accounts, with
# nothing read yet, the subscription's remaining containers are listed but their blobs not tried.
STOP_AFTER_REFUSED_ACCOUNTS = 5
_ROLE_MISSING = "AuthorizationPermissionMismatch"
# Accounts with no blob service: PowerShell's container listing fails there and writes no rows.
_NO_BLOB_KINDS = frozenset({"filestorage"})


@dataclass
class ContainerStats:
    """One container: bytes and blob counts per tier. Every number is None when the listing failed."""

    name: str
    storage_account: str
    hot_bytes: Optional[int] = 0
    hot_count: Optional[int] = 0
    cool_bytes: Optional[int] = 0
    cool_count: Optional[int] = 0
    archive_bytes: Optional[int] = 0
    archive_count: Optional[int] = 0
    unknown_bytes: Optional[int] = 0
    unknown_count: Optional[int] = 0
    all_bytes: Optional[int] = 0
    all_count: Optional[int] = 0
    error: Optional[str] = None


@dataclass
class ContainerInventory:
    """The blob containers of one subscription's storage accounts."""

    subscription_id: str
    containers: list[ContainerStats] = field(default_factory=list)
    # storage account -> why its containers could not be listed
    account_errors: dict[str, str] = field(default_factory=dict)
    total_containers: int = 0


def _tier(blob: Any) -> str:
    tier = getattr(blob, "blob_tier", None)
    return str(getattr(tier, "value", tier) or "").lower()


def tally(name: str, account: str, blobs: Iterable[Any]) -> ContainerStats:
    """The sums PowerShell computes over ``Get-AzStorageBlob`` for one container."""
    stats = ContainerStats(name=name, storage_account=account)
    for blob in blobs:
        if getattr(blob, "snapshot", None):
            continue
        size = int(getattr(blob, "size", 0) or 0)
        tier = _tier(blob)
        bucket = tier if tier in TIERS else "unknown"
        setattr(stats, f"{bucket}_bytes", getattr(stats, f"{bucket}_bytes") + size)
        setattr(stats, f"{bucket}_count", getattr(stats, f"{bucket}_count") + 1)
        stats.all_bytes += size
        stats.all_count += 1
    return stats


def _failed(name: str, account: str, reason: str) -> ContainerStats:
    stats = ContainerStats(name=name, storage_account=account, error=reason)
    for attr in ("hot", "cool", "archive", "unknown", "all"):
        setattr(stats, f"{attr}_bytes", None)
        setattr(stats, f"{attr}_count", None)
    return stats


class ContainerCollector:
    """Lists the blob containers of the given storage accounts and sums their blobs."""

    def __init__(
        self,
        subscription_id: str,
        credential: Any,
        accounts: list[Any],
        cloud: CloudEnvironment = DEFAULT_CLOUD,
    ) -> None:
        self._sub_id = subscription_id
        self._credential = credential
        self._accounts = accounts
        self._cloud = cloud
        self._read_any = False
        self._refused_accounts: set = set()
        self._skip_reason: Optional[str] = None

    def collect(self) -> ContainerInventory:
        inventory = ContainerInventory(subscription_id=self._sub_id)
        for account in self._accounts:
            name = getattr(account, "name", "") or ""
            if (getattr(account, "kind", "") or "").lower() in _NO_BLOB_KINDS:
                continue
            if not HAS_SDK:
                inventory.account_errors[name] = "azure-storage-blob is not installed"
                continue
            self._account(inventory, name)
        inventory.total_containers = len(inventory.containers)
        if inventory.account_errors:
            reasons = ", ".join(sorted(set(inventory.account_errors.values())))
            logger.warning(
                "[%s] Blob containers of %d storage account(s) could not be listed (%s): %s",
                self._sub_id,
                len(inventory.account_errors),
                reasons,
                ", ".join(sorted(inventory.account_errors)),
            )
        return inventory

    def _account(self, inventory: ContainerInventory, account: str) -> None:
        url = f"https://{account}.blob.{self._cloud.storage_suffix}"
        try:
            service = BlobServiceClient(account_url=url, credential=self._credential)
            containers = list(service.list_containers())
        except Exception as exc:  # noqa: BLE001 - one account must not stop the others
            inventory.account_errors[account] = error_reason(exc)
            return
        for container in containers:
            name = getattr(container, "name", "") or ""
            if self._skip_reason:
                inventory.containers.append(_failed(name, account, self._skip_reason))
                continue
            try:
                blobs = service.get_container_client(name).list_blobs()
                inventory.containers.append(tally(name, account, blobs))
                self._read_any = True
            except Exception as exc:  # noqa: BLE001
                reason = error_reason(exc)
                inventory.containers.append(_failed(name, account, reason))
                if self._stop_after(account, reason):
                    continue
                logger.warning(
                    "[%s] Blobs of container %s in storage account %s could not be listed (%s); "
                    "its row is left empty",
                    self._sub_id,
                    name,
                    account,
                    reason,
                )

    def _stop_after(self, account: str, reason: str) -> bool:
        """Count a refusal; True once enough accounts refused that the rest are not tried."""
        if reason != _ROLE_MISSING or self._read_any:
            return False
        self._refused_accounts.add(account)
        if len(self._refused_accounts) < STOP_AFTER_REFUSED_ACCOUNTS:
            return False
        refused = len(self._refused_accounts)
        self._skip_reason = f"{_ROLE_MISSING}; not tried after {refused} refused accounts"
        logger.warning(
            "[%s] Blobs of containers in %d storage accounts could not be listed (%s) and none "
            "could be read; the subscription's other containers are listed with empty rows, "
            "not read",
            self._sub_id,
            refused,
            _ROLE_MISSING,
        )
        return True
