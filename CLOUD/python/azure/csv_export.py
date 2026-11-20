"""PowerShell-compatible CSV export of the Azure discovery results.

Writes files that ``Get-AzureSizingInfo.ps1`` writes, with the same names, column names and
column order. This module covers the VM and managed disk, storage account, file share, backup vault, backup cost,
AKS, Cosmos DB, SQL database and managed instance files, and the summary built from them.

Rows are built from the discovery JSON, so the same code serves a live run and a saved result.
Quoting follows ``Export-Csv``: every value is quoted except a null, which is an empty,
unquoted field (a file's quoted-empty columns write an empty string as ``""``), and a file with
no rows is empty (no header), as PowerShell writes it. Files use
``\\n`` line ends, UTF-8 and no BOM.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Optional

from anonymize import Anonymizer, file_rank

FILE_TIMESTAMP_FORMAT = "%Y-%m-%d_%H%M"

_GIB = 1073741824


def _format(value: Any) -> str:
    if isinstance(value, bool):
        return "True" if value else "False"
    if isinstance(value, float):
        return _format_float(value)
    return str(value)


def _format_float(value: float) -> str:
    """A double as .NET writes it: positional below 1e17, scientific from there."""
    text = repr(value)
    if "e" not in text:
        return text[:-2] if text.endswith(".0") else text
    mantissa, exponent = text.split("e")
    if 0 < int(exponent) < 17:
        digits = mantissa.replace("-", "").replace(".", "")
        sign = "-" if value < 0 else ""
        return sign + digits + "0" * (int(exponent) + 1 - len(digits))
    return text.replace("e", "E")


def render(
    columns: list[str],
    rows: list[dict[str, Any]],
    quoted_empty: frozenset[str] = frozenset(),
    quote_empty_tags: bool = False,
) -> str:
    """CSV text for ``rows`` under ``columns``; a missing key is a null. No rows gives ``""``.

    An empty string is a bare empty field, except in ``quoted_empty`` columns where it is ``""``;
    with ``quote_empty_tags`` the ``Tag:`` columns are such columns too.
    """
    if not rows:
        return ""

    def quote(text: str) -> str:
        return '"' + text.replace('"', '""') + '"'

    lines = [",".join(quote(c) for c in columns)]
    for row in rows:
        cells = []
        for column in columns:
            value = row.get(column)
            keeps_empty = column in quoted_empty or (quote_empty_tags and column.startswith("Tag:"))
            if value is None or (value == "" and not keeps_empty):
                cells.append("")
            else:
                cells.append(quote(_format(value)))
        lines.append(",".join(cells))
    return "\n".join(lines) + "\n"


# ── PowerShell helpers, re-implemented ────────────────────────────────────────


def _ps_round(value: float, digits: int) -> float:
    """``[math]::round($value, $digits)``.

    .NET scales by 10**digits, rounds half to even and scales back, so it is not Python's
    ``round(value, digits)``: 12.345 gives 12.34 here (12.35 in Python) because 12.345 * 100
    is exactly 1234.5.
    """
    if abs(value) < 1e16:
        power = 10.0**digits
        return round(value * power) / power
    return value


def _units_from_gib(gib: float, prefix: str = "Size", gb_precision: int = 3) -> dict[str, Any]:
    """ConvertTo-SizeUnits -InputUnit GiB (GiB, TiB and TB use 4 decimals)."""
    return {
        f"{prefix}GiB": _ps_round(gib, 4),
        f"{prefix}TiB": _ps_round(gib / 1024, 4),
        f"{prefix}GB": _ps_round(gib * 1.073741824, gb_precision),
        f"{prefix}TB": _ps_round(gib * 0.001073741824, 4),
    }


def _units_from_bytes(num_bytes: Optional[float], prefix: str) -> dict[str, Any]:
    """ConvertTo-SizeUnits -InputUnit Bytes -GiBPrecision 0 -GBPrecision 3, without the Bytes column.

    A null value is 0, as the ``[double]`` parameter makes it in PowerShell.
    """
    value = float(num_bytes or 0)
    gib = value / _GIB
    gb = value / 1000000000
    return {
        f"{prefix}GiB": _ps_round(gib, 0),
        f"{prefix}TiB": _ps_round(gib / 1024, 4),
        f"{prefix}GB": _ps_round(gb, 3),
        f"{prefix}TB": _ps_round(gb / 1000, 4),
    }


def _units_from_bytes_4(num_bytes: float, prefix: str) -> dict[str, Any]:
    """ConvertTo-SizeUnits -InputUnit Bytes with the default precision: 4 decimals throughout."""
    gib = num_bytes / _GIB
    gb = num_bytes / 1000000000
    return {
        f"{prefix}GiB": _ps_round(gib, 4),
        f"{prefix}TiB": _ps_round(gib / 1024, 4),
        f"{prefix}GB": _ps_round(gb, 4),
        f"{prefix}TB": _ps_round(gb / 1000, 4),
    }


def _size_columns(prefix: str, num_bytes: Optional[float]) -> dict[str, Any]:
    """The Bytes column plus ConvertTo-SizeUnits -InputUnit Bytes -GiBPrecision 0 -GBPrecision 3.

    A null value stays null in the Bytes column; the unit columns treat it as 0, as the
    ``[double]`` parameter does in PowerShell.
    """
    return {f"{prefix}Bytes": num_bytes, **_units_from_bytes(num_bytes, prefix)}


def unique_tag_names(result: dict) -> list[str]:
    """Tag names across all subscriptions, as ``Sort-Object -Unique`` leaves them.

    The sort ignores case and the first spelling of a name is kept. PowerShell sorts with the
    current culture, so names with punctuation can order differently there.
    """
    seen: dict[str, str] = {}
    for names in (result.get("tag_names") or {}).values():
        for name in names:
            if name:
                seen.setdefault(name.casefold(), name)
    return [seen[key] for key in sorted(seen)]


def _tag_cells(
    tags: Optional[dict[str, str]], names: list[str], case_sensitive: bool = False
) -> dict[str, Any]:
    """One ``Tag: <name>`` cell per name; a missing or empty value is ``-``.

    The SQL models carry tags in a ``Dictionary<string,string>``, so their lookup is case
    sensitive; the VM and storage lookup here ignores case.
    """
    fold = (lambda k: k) if case_sensitive else (lambda k: k.casefold())
    lookup = {fold(k): v for k, v in (tags or {}).items()}
    return {f"Tag: {name}": lookup.get(fold(name)) or "-" for name in names}


@dataclass
class _Context:
    tenant: Optional[str]
    tenant_id: str
    subscription_names: dict[str, str]
    tag_names: list[str]
    vm_policies: dict[tuple[str, str, str], list[str]]
    files_protection: list[tuple[str, str, Optional[str], Optional[str]]] = field(
        default_factory=list
    )
    # (subscription id, storage account) and (subscription id, server resource id), both lower case,
    # with the policy name of each Blob and PostgreSQL backup instance of a Backup Vault.
    blob_protection: list[tuple[str, str, Optional[str]]] = field(default_factory=list)
    postgres_protection: list[tuple[str, str, Optional[str]]] = field(default_factory=list)

    def subscription(self, subscription_id: str) -> str:
        return self.subscription_names.get(subscription_id) or subscription_id

    @property
    def tenant_key(self) -> str:
        """The SQL files fall back to the tenant id when the tenant has no name."""
        return self.tenant or self.tenant_id


def _vm_policies(result: dict) -> dict[tuple[str, str, str], list[str]]:
    """Backup policy names per VM, keyed by subscription, VM name and vault region.

    PowerShell keys the join the same way: the vault is in the region of every VM it protects.
    A SQL in VM item joins on the name of the server it runs on (``ServerName``), after the VM
    items of the same vault, as the script goes through a vault's VM policies and then its SQL
    policies. The cell lists each policy once: PowerShell appends the name once per database, so a
    server with four databases on one policy gets that name four times there.
    """
    policies: dict[tuple[str, str, str], list[str]] = {}
    for posture in result.get("backup_posture") or []:
        subscription = (posture.get("subscription_id") or "").lower()
        regions = {
            (v.get("name") or "").lower(): (v.get("location") or "").lower()
            for v in posture.get("vaults") or []
        }
        items = posture.get("protected_items") or []
        vault_order = list(dict.fromkeys((i.get("vault_name") or "").lower() for i in items))
        for vault in vault_order:
            in_vault = [i for i in items if (i.get("vault_name") or "").lower() == vault]
            vm_items = [
                (i, _resource_name(i.get("source_resource_id")))
                for i in in_vault
                if i.get("workload_type") == "VM"
            ]
            sql_items = [
                (i, (i.get("rest_properties") or {}).get("serverName"))
                for i in in_vault
                if _vault_kind(i) == "VM_SQL"
            ]
            for item, host in [*vm_items, *sql_items]:
                policy = item.get("policy_name")
                if not policy or not host:
                    continue
                policies.setdefault((subscription, host.lower(), regions.get(vault, "")), []).append(
                    policy
                )
    return policies


def _resource_name(resource_id: Optional[str]) -> str:
    return (resource_id or "").rstrip("/").rsplit("/", 1)[-1]


_STORAGE_ACCOUNT_IN_ID = re.compile(r"/storageAccounts/([^/]+)", re.IGNORECASE)


def _files_protection(result: dict) -> list[tuple[str, str, Optional[str], Optional[str]]]:
    """(subscription id, storage account, share, policy) for each Azure Files item of a Recovery
    Services vault, as ``Get-AzureFilesBackupItemTarget`` reads it.

    The account comes from the protected resource's id and the share from its friendly name, else the
    last ``;`` part of the item's name. An item whose account cannot be worked out is left out.
    """
    found = []
    for posture in result.get("backup_posture") or []:
        subscription = (posture.get("subscription_id") or "").lower()
        for item in posture.get("protected_items") or []:
            if item.get("workload_type") != "Files":
                continue
            account = _STORAGE_ACCOUNT_IN_ID.search(item.get("source_resource_id") or "")
            if not account:
                continue
            share = item.get("friendly_name") or (item.get("name") or "").split(";")[-1] or None
            found.append((subscription, account.group(1), share, item.get("policy_name")))
    return found


def _vault_protection(
    result: dict,
) -> tuple[list[tuple[str, str, Optional[str]]], list[tuple[str, str, Optional[str]]]]:
    """The Blob and PostgreSQL backup instances of the Backup Vaults, keyed for the flag lookups."""
    blob, postgres = [], []
    for entry in result.get("data_protection") or []:
        subscription = (entry.get("subscription_id") or "").lower()
        for item in entry.get("items") or []:
            policy = item.get("protection_policy_name")
            if item.get("workload") == "AzureBlob":
                blob.append((subscription, (item.get("datasource_name") or "").lower(), policy))
            elif item.get("workload") == "AzurePostgreSQL":
                resource_id = (item.get("datasource_resource_id") or "").lower()
                postgres.append((subscription, resource_id, policy))
    return blob, postgres


def _backup_cells(policies: list[Optional[str]], protected: bool) -> dict[str, Any]:
    """``BackupPolicies`` (distinct names in the order met, ``-`` for none) and ``InBackupPolicy``."""
    names = list(dict.fromkeys(p for p in policies if p))
    return {"BackupPolicies": ", ".join(names) if names else "-", "InBackupPolicy": protected}


def _storage_backup(
    ctx: "_Context", subscription_id: str, account: str, share: Optional[str] = None
) -> dict[str, Any]:
    """The backup cells of a storage account, or of one of its file shares when ``share`` is given.

    An account is protected by Blob backup (a Backup Vault) or by any of its shares (a Recovery
    Services vault); a share only by its own Azure Files backup. Blob policies come first, as
    PowerShell collects the Backup Vaults before the Recovery Services vaults.
    """
    hits = []
    if share is None:
        hits += [
            policy
            for sub, name, policy in ctx.blob_protection
            if sub == subscription_id.lower() and name == account.lower()
        ]
    hits += [
        policy
        for sub, name, target, policy in ctx.files_protection
        if sub == subscription_id.lower()
        and name.lower() == account.lower()
        and (share is None or (target or "").lower() == share.lower())
    ]
    return _backup_cells(hits, bool(hits))


def _postgres_backup(
    ctx: "_Context", subscription_id: str, resource_group: str, server: str
) -> dict[str, Any]:
    """The backup cells of a PostgreSQL server. PowerShell rebuilds the server's resource id from the
    subscription, resource group and name, because its server rows carry none.
    """
    server_id = (
        f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}"
        f"/providers/Microsoft.DBforPostgreSQL/flexibleServers/{server}"
    ).lower()
    hits = [
        policy
        for sub, resource_id, policy in ctx.postgres_protection
        if sub == subscription_id.lower() and resource_id == server_id
    ]
    return _backup_cells(hits, bool(hits))


# ── azure_vmdisk_info ─────────────────────────────────────────────────────────

_VM_COLUMNS = [
    "Name",
    "Disks",
    "SizeGiB",
    "SizeTiB",
    "SizeGB",
    "SizeTB",
    "Subscription",
    "Tenant",
    "Region",
    "ResourceGroup",
    "vmID",
    "InstanceType",
    "Status",
    "HasMSSQL",
    "BackupPolicies",
    "InBackupPolicy",
]

# Get-AzVM's list output carries this in StatusCode.
_VM_STATUS = "OK"


def _vm_rows(ctx: _Context, result: dict) -> list[dict[str, Any]]:
    rows = []
    for entry in result.get("compute") or []:
        subscription_id = entry.get("subscription_id", "")
        for vm in entry.get("vms") or []:
            policies = ctx.vm_policies.get(
                (
                    subscription_id.lower(),
                    (vm.get("name") or "").lower(),
                    (vm.get("location") or "").lower(),
                ),
                [],
            )
            row: dict[str, Any] = {
                "Name": vm.get("name"),
                "Disks": len(vm.get("disks") or []),
                **_units_from_gib(float(vm.get("total_disk_gb") or 0)),
                "Subscription": ctx.subscription(subscription_id),
                "Tenant": ctx.tenant,
                "Region": vm.get("location"),
                "ResourceGroup": vm.get("resource_group"),
                "vmID": vm.get("vm_id"),
                "InstanceType": vm.get("vm_size"),
                "Status": _VM_STATUS,
                "HasMSSQL": "Yes" if vm.get("sql_server") else "No",
                "BackupPolicies": ", ".join(policies) if policies else "-",
                "InBackupPolicy": bool(policies),
                **_tag_cells(vm.get("tags"), ctx.tag_names),
            }
            rows.append(row)
    return rows


# ── azure_storage_account_info ────────────────────────────────────────────────

_SIZE_SUFFIXES = ("Bytes", "GiB", "TiB", "GB", "TB")

_STORAGE_ACCOUNT_COLUMNS = [
    "StorageAccount",
    "StorageAccountType",
    "HNSEnabled(ADLSGen2)",
    "StorageAccountSkuName",
    "StorageAccountAccessTier",
    "Tenant",
    "Subscription",
    "Region",
    "ResourceGroup",
    *[f"UsedCapacity{s}" for s in _SIZE_SUFFIXES],
    *[f"UsedBlobCapacity{s}" for s in _SIZE_SUFFIXES],
    "BlobContainerCount",
    "BlobCount",
    *[f"UsedFileShareCapacity{s}" for s in _SIZE_SUFFIXES],
    "FileShareCount",
    "FileCountInFileShares",
    "BackupPolicies",
    "InBackupPolicy",
]


def _storage_account_rows(ctx: _Context, result: dict) -> list[dict[str, Any]]:
    rows = []
    for entry in result.get("storage") or []:
        subscription_id = entry.get("subscription_id", "")
        for account in entry.get("accounts") or []:
            rows.append(
                {
                    "StorageAccount": account.get("name"),
                    "StorageAccountType": account.get("kind"),
                    "HNSEnabled(ADLSGen2)": account.get("hns_enabled"),
                    "StorageAccountSkuName": account.get("sku"),
                    "StorageAccountAccessTier": account.get("access_tier"),
                    "Tenant": ctx.tenant,
                    "Subscription": ctx.subscription(subscription_id),
                    "Region": account.get("location"),
                    "ResourceGroup": account.get("resource_group"),
                    **_size_columns("UsedCapacity", account.get("capacity_bytes")),
                    **_size_columns("UsedBlobCapacity", account.get("blob_capacity_bytes")),
                    "BlobContainerCount": account.get("blob_container_count"),
                    "BlobCount": account.get("blob_count"),
                    **_size_columns("UsedFileShareCapacity", account.get("file_capacity_bytes")),
                    "FileShareCount": account.get("file_share_count"),
                    "FileCountInFileShares": account.get("file_count"),
                    **_storage_backup(ctx, subscription_id, account.get("name") or ""),
                    **_tag_cells(account.get("tags"), ctx.tag_names),
                }
            )
    return rows


# ── azure_storage_account_container_info ──────────────────────────────────────

_CONTAINER_TIERS = (
    ("HotTier", "hot"),
    ("CoolTier", "cool"),
    ("ArchiveTier", "archive"),
    ("UnknownTier", "unknown"),
)
_CONTAINER_COLUMNS = [
    "Name",
    "StorageAccount",
    "StorageAccountType",
    "HNSEnabled(ADLSGen2)",
    "StorageAccountSkuName",
    "StorageAccountAccessTier",
    "Tenant",
    "Subscription",
    "Region",
    "ResourceGroup",
    *[
        column
        for tier, _ in _CONTAINER_TIERS
        for column in (
            *[f"UsedCapacity{tier}{s}" for s in _SIZE_SUFFIXES],
            f"{tier}BlobCount",
        )
    ],
    *[f"UsedCapacityAllTiers{s}" for s in _SIZE_SUFFIXES],
]


def _container_sizes(prefix: str, num_bytes: Optional[int]) -> dict[str, Any]:
    """The Bytes and unit columns; all empty for a container whose blobs could not be listed."""
    if num_bytes is None:
        return {f"{prefix}{s}": None for s in _SIZE_SUFFIXES}
    return _size_columns(prefix, num_bytes)


def _container_rows(ctx: _Context, result: dict) -> list[dict[str, Any]]:
    accounts = {
        (entry.get("subscription_id", ""), account.get("name")): account
        for entry in result.get("storage") or []
        for account in entry.get("accounts") or []
    }
    rows = []
    for entry in result.get("containers") or []:
        subscription_id = entry.get("subscription_id", "")
        for container in entry.get("containers") or []:
            account = accounts.get((subscription_id, container.get("storage_account"))) or {}
            row: dict[str, Any] = {
                "Name": container.get("name"),
                "StorageAccount": container.get("storage_account"),
                "StorageAccountType": account.get("kind"),
                "HNSEnabled(ADLSGen2)": account.get("hns_enabled"),
                "StorageAccountSkuName": account.get("sku"),
                "StorageAccountAccessTier": account.get("access_tier"),
                "Tenant": ctx.tenant,
                "Subscription": ctx.subscription(subscription_id),
                "Region": account.get("location"),
                "ResourceGroup": account.get("resource_group"),
            }
            for tier, key in _CONTAINER_TIERS:
                row.update(_container_sizes(f"UsedCapacity{tier}", container.get(f"{key}_bytes")))
                row[f"{tier}BlobCount"] = container.get(f"{key}_count")
            # PowerShell's UnknownTierBlobCount counts every blob that is not a snapshot, whatever
            # its tier (line 792 of Get-AzureSizingInfo.ps1); kept as it writes it.
            row["UnknownTierBlobCount"] = container.get("all_count")
            row.update(_container_sizes("UsedCapacityAllTiers", container.get("all_bytes")))
            # Containers have no tags, so every tag column is "-", as PowerShell writes it.
            row.update(_tag_cells(None, ctx.tag_names))
            rows.append(row)
    return rows


# ── azure_key_vault ───────────────────────────────────────────────────────────

_KEY_VAULT_COLUMNS = [
    "VaultName",
    "Location",
    "Tenant",
    "Subscription",
    "NumCertificates",
    "NumSecrets",
    "NumKeys",
]


def _key_vault_rows(ctx: _Context, result: dict) -> list[dict[str, Any]]:
    rows = []
    for entry in result.get("key_vaults") or []:
        subscription_id = entry.get("subscription_id", "")
        for vault in entry.get("vaults") or []:
            rows.append(
                {
                    "VaultName": vault.get("name"),
                    "Location": vault.get("location"),
                    "Tenant": ctx.tenant,
                    "Subscription": ctx.subscription(subscription_id),
                    "NumCertificates": vault.get("certificates"),
                    "NumSecrets": vault.get("secrets"),
                    "NumKeys": vault.get("keys"),
                }
            )
    return rows


# ── azure_file_share_info ─────────────────────────────────────────────────────

_FILE_SHARE_COLUMNS = [
    "Name",
    "StorageAccount",
    "StorageAccountType",
    "StorageAccountSkuName",
    "StorageAccountAccessTier",
    "Tenant",
    "Subscription",
    "Region",
    "ResourceGroup",
    "QuotaGiB",
    "QuotaTiB",
    *[f"UsedCapacity{s}" for s in _SIZE_SUFFIXES],
    "BackupPolicies",
    "InBackupPolicy",
]


def _file_share_rows(ctx: _Context, result: dict) -> list[dict[str, Any]]:
    rows = []
    for entry in result.get("storage") or []:
        subscription_id = entry.get("subscription_id", "")
        for account in entry.get("accounts") or []:
            for share in account.get("file_shares") or []:
                quota = share.get("quota_gib")
                rows.append(
                    {
                        "Name": share.get("name"),
                        "StorageAccount": account.get("name"),
                        "StorageAccountType": account.get("kind"),
                        "StorageAccountSkuName": account.get("sku"),
                        "StorageAccountAccessTier": account.get("access_tier"),
                        "Tenant": ctx.tenant,
                        "Subscription": ctx.subscription(subscription_id),
                        "Region": account.get("location"),
                        "ResourceGroup": account.get("resource_group"),
                        "QuotaGiB": quota,
                        "QuotaTiB": _ps_round((quota or 0) / 1024, 3),
                        **_size_columns("UsedCapacity", share.get("usage_bytes")),
                        **_storage_backup(
                            ctx, subscription_id, account.get("name") or "", share.get("name")
                        ),
                    }
                )
    return rows


# ── azure_backup_vault_info and azure_backup_costs ────────────────────────────

_VAULT_COLUMNS = [
    "Name",
    "Type",
    "Tenant",
    "Subscription",
    "Region",
    "ResourceGroup",
    "ProvisioningState",
    "CrossSubscriptionRestoreState",
    "ImmutabilitySettings",
]

_IMMUTABILITY_NAMES = {"disabled": "Disabled", "unlocked": "Unlocked", "locked": "Locked"}


def _immutability_text(state: Optional[str]) -> Optional[str]:
    """The text of PowerShell's ``ImmutabilitySettings`` object, whose ``ToString()`` is
    ``ImmutabilityState: <name>``. A state that is not one of the enum names parses to 0.
    """
    if state is None:
        return None
    return f"ImmutabilityState: {_IMMUTABILITY_NAMES.get(state.casefold(), '0')}"


def _vault_rows(ctx: _Context, result: dict) -> list[dict[str, Any]]:
    rows = []
    for posture in result.get("backup_posture") or []:
        subscription_id = posture.get("subscription_id", "")
        for vault in posture.get("vaults") or []:
            rows.append(
                {
                    "Name": vault.get("name"),
                    "Type": vault.get("type"),
                    "Tenant": ctx.tenant,
                    "Subscription": ctx.subscription(subscription_id),
                    "Region": vault.get("location"),
                    "ResourceGroup": vault.get("resource_group"),
                    "ProvisioningState": vault.get("provisioning_state"),
                    "CrossSubscriptionRestoreState": vault.get("cross_subscription_restore_state"),
                    "ImmutabilitySettings": _immutability_text(vault.get("immutability_state")),
                }
            )
    return rows


_BACKUP_COST_COLUMNS = [
    "SubscriptionId",
    "Subscription",
    "Tenant",
    "BillingMonth",
    "PreTaxCostUSD",
    "CostUSD",
]


def _ps_datetime(iso: str) -> str:
    """A date and time as PowerShell writes a ``[datetime]``: ``9/1/2026 12:00:00 AM``."""
    moment = datetime.fromisoformat(iso)
    hour = moment.hour % 12 or 12
    meridiem = "AM" if moment.hour < 12 else "PM"
    return f"{moment.month}/{moment.day}/{moment.year} {hour}:{moment:%M:%S} {meridiem}"


def _money(amount: Optional[float]) -> str:
    """PowerShell's ``"$" + [math]::round([double]$x, 2)``."""
    return "$" + _format(_ps_round(float(amount or 0), 2))


def _backup_cost_rows(ctx: _Context, result: dict) -> list[dict[str, Any]]:
    rows = []
    for summary in result.get("cost") or []:
        subscription_id = summary.get("subscription_id", "")
        for month in summary.get("backup_cost_months") or []:
            rows.append(
                {
                    "SubscriptionId": subscription_id,
                    "Subscription": ctx.subscription(subscription_id),
                    "Tenant": ctx.tenant,
                    "BillingMonth": _ps_datetime(month["billing_month"]),
                    "PreTaxCostUSD": _money(month.get("pre_tax_cost_usd")),
                    "CostUSD": _money(month.get("cost_usd")),
                }
            )
    return rows


# ── azure_aks_info and azure_cosmos_db ────────────────────────────────────────

_AKS_COLUMNS = [
    "Subscription",
    "Tenant",
    "Name",
    "ResourceGroup",
    "Location",
    "Id",
    "KubernetesVersion",
    "ProvisioningState",
    "PowerState",
    "DnsPrefix",
    "Fqdn",
    "NodeResourceGroup",
    "NodePoolCount",
    "NodePoolNames",
    "NodePoolVMSizes",
    "NodePoolNodeCounts",
    "NodePoolMaxCounts",
    "NodePoolOSDiskSizes",
    "TotalNodes",
]

# PowerShell joins the node pool values into a string, which is "" when there are no pools.
_AKS_QUOTED_EMPTY = frozenset(
    [
        "NodePoolNames",
        "NodePoolVMSizes",
        "NodePoolNodeCounts",
        "NodePoolMaxCounts",
        "NodePoolOSDiskSizes",
    ]
)


def _dash(value: Any) -> Any:
    """PowerShell's ``$value ?? "-"``."""
    return "-" if value is None else value


def _aks_rows(ctx: _Context, result: dict) -> list[dict[str, Any]]:
    rows = []
    for entry in result.get("aks") or []:
        subscription_id = entry.get("subscription_id", "")
        for cluster in entry.get("clusters") or []:
            pools = cluster.get("node_pools") or []
            rows.append(
                {
                    "Subscription": ctx.subscription(subscription_id),
                    "Tenant": ctx.tenant,
                    "Name": cluster.get("name"),
                    "ResourceGroup": cluster.get("resource_group"),
                    "Location": cluster.get("location"),
                    "Id": cluster.get("resource_id"),
                    "KubernetesVersion": _dash(cluster.get("kubernetes_version")),
                    "ProvisioningState": _dash(cluster.get("provisioning_state")),
                    "PowerState": _dash(cluster.get("power_state")),
                    "DnsPrefix": _dash(cluster.get("dns_prefix")),
                    "Fqdn": _dash(cluster.get("fqdn")),
                    "NodeResourceGroup": _dash(cluster.get("node_resource_group")),
                    "NodePoolCount": len(pools),
                    "NodePoolNames": "; ".join(str(_dash(p.get("name"))) for p in pools),
                    "NodePoolVMSizes": "; ".join(str(_dash(p.get("vm_size"))) for p in pools),
                    "NodePoolNodeCounts": "; ".join(str(p.get("count") or 0) for p in pools),
                    "NodePoolMaxCounts": "; ".join(str(_dash(p.get("max_count"))) for p in pools),
                    "NodePoolOSDiskSizes": "; ".join(
                        str(_dash(p.get("os_disk_size_gb"))) for p in pools
                    ),
                    "TotalNodes": sum(p.get("count") or 0 for p in pools),
                    **_tag_cells(cluster.get("tags"), ctx.tag_names, case_sensitive=True),
                }
            )
    return rows


_COSMOS_COLUMNS = [
    "Subscription",
    "Tenant",
    "Name",
    "Location",
    "Id",
    "Kind",
    "InstanceId",
    "BackupPolicyBackupIntervalInMinutes",
    "BackupPolicyBackupRetentionIntervalInHours",
    "BackupPolicyBackupType",
    "BackupPolicyBackupStorageRedundancy",
    "BackupPolicyTier",
    "MinimalTlsVersion",
    "NameDatabaseAccountOfferType",
    "DocumentCount",
    "DataUsage",
    "PhysicalPartitionSizeInfo",
    "PhysicalPartitionCount",
    "IndexUsage",
]


def _cosmos_rows(ctx: _Context, result: dict) -> list[dict[str, Any]]:
    rows = []
    for entry in result.get("cosmos_db") or []:
        subscription_id = entry.get("subscription_id", "")
        for account in entry.get("accounts") or []:
            rows.append(
                {
                    "Subscription": ctx.subscription(subscription_id),
                    "Tenant": ctx.tenant,
                    "Name": account.get("name"),
                    "Location": account.get("location"),
                    "Id": account.get("resource_id"),
                    "Kind": account.get("kind"),
                    "InstanceId": account.get("instance_id"),
                    "BackupPolicyBackupIntervalInMinutes": account.get("backup_interval_minutes"),
                    "BackupPolicyBackupRetentionIntervalInHours": account.get(
                        "backup_retention_hours"
                    ),
                    "BackupPolicyBackupType": account.get("backup_type"),
                    "BackupPolicyBackupStorageRedundancy": account.get("backup_storage_redundancy"),
                    "BackupPolicyTier": account.get("backup_tier"),
                    "MinimalTlsVersion": account.get("minimal_tls_version"),
                    "NameDatabaseAccountOfferType": account.get("offer_type"),
                    "DocumentCount": account.get("document_count"),
                    "DataUsage": account.get("data_usage"),
                    "PhysicalPartitionSizeInfo": account.get("physical_partition_size_info"),
                    "PhysicalPartitionCount": account.get("physical_partition_count"),
                    "IndexUsage": account.get("index_usage"),
                    **_tag_cells(account.get("tags"), ctx.tag_names, case_sensitive=True),
                }
            )
    return rows


# ── azure_sql_info and azure_mi_sql_info ──────────────────────────────────────

_SQL_IDENTITY_COLUMNS = ["Database", "Server", "ElasticPool", "ManagedInstance"]
_SQL_PLACEMENT_COLUMNS = [
    "Subscription",
    "Tenant",
    "Region",
    "ResourceGroup",
    "DatabaseID",
    "InstanceType",
    "Status",
]

# PowerShell writes "" for these, not a null.
_SQL_QUOTED_EMPTY = frozenset([*_SQL_IDENTITY_COLUMNS, "DatabaseID"])

_SQL_COLUMNS = [
    *_SQL_IDENTITY_COLUMNS,
    *[f"MaxSize{s}" for s in ("GiB", "TiB", "GB", "TB")],
    *_SQL_PLACEMENT_COLUMNS,
    "Allocated_Bytes",
    "Utilized_Bytes",
    "LTRWeeklyRetention",
    "LTRMonthlyRetention",
    "LTRYearlyRetention",
    "LTRWeekOfYear",
    "PITR (Days)",
    "DiffBackupFrequency (Hours)",
]

_MI_COLUMNS = [
    *_SQL_IDENTITY_COLUMNS,
    *[f"MaxSize{s}" for s in ("GiB", "TiB", "GB", "TB")],
    *_SQL_PLACEMENT_COLUMNS,
    "Databases",
    "storage_space_used_mb",
]


def _sql_row(
    ctx: _Context,
    subscription_id: str,
    identity: dict[str, str],
    sizes: dict[str, Any],
    placement: dict[str, Any],
    rest: dict[str, Any],
    tags: dict[str, Any],
) -> dict[str, Any]:
    return {
        **{c: identity.get(c, "") for c in _SQL_IDENTITY_COLUMNS},
        **sizes,
        "Subscription": ctx.subscription(subscription_id),
        "Tenant": ctx.tenant_key,
        **placement,
        **rest,
        **tags,
    }


_DTU_TIERS = ((re.compile(r"S\d+"), "Standard"), (re.compile(r"P\d+"), "Premium"))
_TRAILING_CAPACITY = re.compile(r"_\d+$")


def _ps_sku_name(sku: Optional[str]) -> Optional[str]:
    """The SKU name as Az.Sql's ``SkuName`` gives it, which PowerShell writes as ``InstanceType``.

    The REST list names a vCore SKU with its capacity (``GP_S_Gen5_4``) and a DTU SKU by its objective
    (``S0``, ``P1``); Az.Sql splits the capacity off and reports the tier name. ``Basic`` and the pool
    SKUs are the same in both. Matches every database and pool of a real run.
    """
    if not sku:
        return sku
    for pattern, tier in _DTU_TIERS:
        if pattern.fullmatch(sku):
            return tier
    return _TRAILING_CAPACITY.sub("", sku)


def _sql_rows(ctx: _Context, result: dict) -> list[dict[str, Any]]:
    """Databases and elastic pools in the order PowerShell adds them.

    A database in a pool adds every pool of its server that is not listed yet, in place of the
    database. PowerShell skips a pool whose name another server already used; here each server's
    pools are listed once.
    """
    rows = []
    for entry in result.get("database") or []:
        subscription_id = entry.get("subscription_id", "")
        for server in entry.get("sql_servers") or []:
            listed_pools: set[str] = set()
            for db in server.get("databases") or []:
                if db.get("sku_name") == "System":
                    continue
                if db.get("sku_name") == "ElasticPool":
                    for pool in server.get("elastic_pools") or []:
                        if pool["name"] in listed_pools:
                            continue
                        listed_pools.add(pool["name"])
                        rows.append(
                            _sql_row(
                                ctx,
                                subscription_id,
                                {"ElasticPool": pool["name"]},
                                _units_from_bytes(pool.get("max_size_bytes"), "MaxSize"),
                                {
                                    "Region": pool.get("location"),
                                    "ResourceGroup": pool.get("resource_group"),
                                    "DatabaseID": "",
                                    "InstanceType": _ps_sku_name(pool.get("sku_name")),
                                    "Status": None,
                                },
                                {},
                                _tag_cells(None, ctx.tag_names),
                            )
                        )
                    continue
                rows.append(
                    _sql_row(
                        ctx,
                        subscription_id,
                        {"Database": db.get("name"), "Server": db.get("server_name")},
                        _units_from_bytes(db.get("max_size_bytes"), "MaxSize"),
                        {
                            "Region": db.get("location"),
                            "ResourceGroup": db.get("resource_group"),
                            "DatabaseID": db.get("database_id"),
                            "InstanceType": _ps_sku_name(db.get("sku_name")),
                            "Status": db.get("status"),
                        },
                        {
                            "Allocated_Bytes": db.get("allocated_bytes"),
                            "Utilized_Bytes": db.get("utilized_bytes"),
                            "LTRWeeklyRetention": db.get("ltr_weekly"),
                            "LTRMonthlyRetention": db.get("ltr_monthly"),
                            "LTRYearlyRetention": db.get("ltr_yearly"),
                            "LTRWeekOfYear": db.get("ltr_week_of_year"),
                            "PITR (Days)": db.get("short_term_retention_days"),
                            "DiffBackupFrequency (Hours)": db.get("diff_backup_interval_hours"),
                        },
                        _tag_cells(db.get("db_tags"), ctx.tag_names, case_sensitive=True),
                    )
                )
    return rows


def _mi_rows(ctx: _Context, result: dict) -> list[dict[str, Any]]:
    rows = []
    for entry in result.get("database") or []:
        subscription_id = entry.get("subscription_id", "")
        for mi in entry.get("managed_instances") or []:
            rows.append(
                _sql_row(
                    ctx,
                    subscription_id,
                    {"ManagedInstance": mi.get("name")},
                    _units_from_gib(float(mi.get("storage_size_gb") or 0), "MaxSize"),
                    {
                        "Region": mi.get("location"),
                        "ResourceGroup": mi.get("resource_group"),
                        "DatabaseID": "",
                        "InstanceType": mi.get("sku_name"),
                        "Status": None,
                    },
                    {
                        "Databases": mi.get("database_count"),
                        "storage_space_used_mb": mi.get("storage_space_used_mb"),
                    },
                    _tag_cells(mi.get("tags"), ctx.tag_names, case_sensitive=True),
                )
            )
    return rows


# ── azure_postgres_info ───────────────────────────────────────────────────────

_POSTGRES_COLUMNS = [
    "Server",
    "ResourceGroup",
    "Subscription",
    "Tenant",
    "Region",
    "Version",
    "SkuName",
    "SkuTier",
    "SkuCapacity",
    "MaxSizeGiB",
    "MaxSizeTiB",
    "MaxSizeGB",
    "MaxSizeTB",
    "SizeBucket",
    "Status",
    "AdministratorLogin",
    "BackupRetentionDays",
    "GeoRedundantBackup",
    "HighAvailabilityMode",
    "DatabaseCount",
    "Utilized_Bytes",
    "Utilized_GiB",
    "Utilized_TiB",
    "Utilized_GB",
    "Utilized_TB",
    "BackupPolicies",
    "InBackupPolicy",
]

_SKU_VCORES = re.compile(r"_[A-Za-z]+(\d+)")


def _sku_vcores(sku_name: Optional[str]) -> Optional[int]:
    """The vCore count in a SKU name such as ``Standard_D4ds_v5``, as PowerShell's ``-match`` reads it."""
    found = _SKU_VCORES.search(sku_name or "")
    return int(found.group(1)) if found else None


def _size_bucket(storage_gib: Optional[float]) -> Optional[str]:
    """Which of the two sizer size ranges a server's provisioned size falls in; 1 TiB is the larger."""
    if storage_gib is None:
        return None
    return "1 TiB and over" if storage_gib >= 1024 else "Under 1 TiB"


def _tag_cells_keep_empty(tags: Optional[dict[str, str]], names: list[str]) -> dict[str, Any]:
    """One ``Tag: <name>`` cell per name. The lookup is case sensitive and a tag that exists with an
    empty value stays empty; only a tag that is not there is ``-``.
    """
    lookup = tags or {}
    return {f"Tag: {name}": "-" if lookup.get(name) is None else lookup[name] for name in names}


def _postgres_rows(ctx: _Context, result: dict) -> list[dict[str, Any]]:
    rows = []
    for entry in result.get("database") or []:
        subscription_id = entry.get("subscription_id", "")
        for server in entry.get("flexible_servers") or []:
            if server.get("engine") != "PostgreSQL":
                continue
            storage_gib = server.get("storage_gb")
            sizes = (
                _units_from_gib(float(storage_gib), "MaxSize", 3)
                if storage_gib is not None
                else {f"MaxSize{u}": None for u in ("GiB", "TiB", "GB", "TB")}
            )
            utilized = server.get("utilized_bytes")
            used = (
                _units_from_bytes_4(float(utilized), "Utilized")
                if utilized is not None
                else {f"Utilized{u}": None for u in ("GiB", "TiB", "GB", "TB")}
            )
            rows.append(
                {
                    "Server": server.get("name"),
                    "ResourceGroup": server.get("resource_group"),
                    "Subscription": ctx.subscription(subscription_id),
                    "Tenant": ctx.tenant,
                    "Region": server.get("raw_location") or server.get("location"),
                    "Version": server.get("version"),
                    "SkuName": server.get("sku_name"),
                    "SkuTier": server.get("tier"),
                    "SkuCapacity": _sku_vcores(server.get("sku_name")),
                    **{k: sizes[k] for k in ("MaxSizeGiB", "MaxSizeTiB", "MaxSizeGB", "MaxSizeTB")},
                    "SizeBucket": _size_bucket(storage_gib),
                    "Status": server.get("state"),
                    "AdministratorLogin": server.get("administrator_login"),
                    "BackupRetentionDays": server.get("backup_retention_days"),
                    "GeoRedundantBackup": server.get("geo_redundant_backup_text"),
                    "HighAvailabilityMode": server.get("high_availability_mode"),
                    "DatabaseCount": server.get("database_count"),
                    "Utilized_Bytes": utilized,
                    "Utilized_GiB": used["UtilizedGiB"],
                    "Utilized_TiB": used["UtilizedTiB"],
                    "Utilized_GB": used["UtilizedGB"],
                    "Utilized_TB": used["UtilizedTB"],
                    **_postgres_backup(
                        ctx,
                        subscription_id,
                        server.get("resource_group") or "",
                        server.get("name") or "",
                    ),
                    **_tag_cells_keep_empty(server.get("tags"), ctx.tag_names),
                }
            )
    return rows


# ── Backup Vault files (Blob and PostgreSQL backup) ───────────────────────────

_DP_VAULT_COLUMNS = ["Name", "Type", "Tenant", "Subscription", "Region", "ResourceGroup"]

_DP_ITEM_COLUMNS = [
    "Tenant",
    "Subscription",
    "Region",
    "ResourceGroup",
    "VaultName",
    "InstanceName",
    "Workload",
    "DatasourceType",
    "DatasourceName",
    "DatasourceDatabase",
    "DatasourceResourceId",
    "ProtectionPolicyName",
    "PolicyId",
    "ProtectionState",
]


def _dp_vault_rows(ctx: _Context, result: dict) -> list[dict[str, Any]]:
    rows = []
    for entry in result.get("data_protection") or []:
        subscription_id = entry.get("subscription_id", "")
        for vault in entry.get("vaults") or []:
            rows.append(
                {
                    "Name": vault.get("name"),
                    "Type": vault.get("type"),
                    "Tenant": ctx.tenant,
                    "Subscription": ctx.subscription(subscription_id),
                    "Region": vault.get("location"),
                    "ResourceGroup": vault.get("resource_group"),
                }
            )
    return rows


def _dp_item_rows(ctx: _Context, result: dict) -> list[dict[str, Any]]:
    rows = []
    for entry in result.get("data_protection") or []:
        subscription_id = entry.get("subscription_id", "")
        for item in entry.get("items") or []:
            rows.append(
                {
                    "Tenant": ctx.tenant,
                    "Subscription": ctx.subscription(subscription_id),
                    "Region": item.get("location"),
                    "ResourceGroup": item.get("resource_group"),
                    "VaultName": item.get("vault_name"),
                    "InstanceName": item.get("instance_name"),
                    "Workload": item.get("workload"),
                    "DatasourceType": item.get("datasource_type"),
                    "DatasourceName": item.get("datasource_name"),
                    "DatasourceDatabase": item.get("datasource_database"),
                    "DatasourceResourceId": item.get("datasource_resource_id"),
                    "ProtectionPolicyName": item.get("protection_policy_name"),
                    "PolicyId": item.get("policy_id"),
                    "ProtectionState": item.get("protection_state"),
                }
            )
    return rows


# Az.DataProtection returns a policy as an object whose names differ from the API's: arrays are
# singular, a few nested objects are flattened into their parent, and some are kept and flattened.
# These tables are what the PostgreSQL policies of a real PowerShell run show; the Blob policy shapes
# have not been compared.
_AZ_SINGULAR = {
    "datasourceTypes": "DatasourceType",
    "policyRules": "PolicyRule",
    "lifecycles": "Lifecycle",
    "targetDataStoreCopySettings": "TargetDataStoreCopySetting",
    "taggingCriteria": "TaggingCriterion",
    "repeatingTimeIntervals": "RepeatingTimeInterval",
    "backupParameters": "BackupParameter",
}
# Left out as a nested object; each of its fields becomes a field of the parent.
_AZ_FLATTENED_ONLY = frozenset({"dataStore", "sourceDataStore", "schedule", "tagInfo"})
# Kept as a nested object and also copied up: the fields named here.
_AZ_KEPT_AND_COPIED = {
    "backupParameters": ("objectType",),
    "trigger": ("objectType",),
    "deleteAfter": ("duration", "objectType"),
}


def _pascal(name: str) -> str:
    return _AZ_SINGULAR.get(name) or name[:1].upper() + name[1:]


def _joined(parent: str, child: str) -> str:
    """``parent`` + ``child``, without repeating what they share: ``SourceDataStore`` and
    ``DataStoreType`` give ``SourceDataStoreType``, ``TagInfo`` and ``Id`` give ``TagInfoId``.
    """
    for size in range(min(len(parent), len(child)), 0, -1):
        if parent.endswith(child[:size]):
            return parent + child[size:]
    return parent + child


def _az_value(value: Any) -> Any:
    if isinstance(value, dict):
        return _az_object(value)
    if isinstance(value, list):
        return [_az_value(v) for v in value]
    return value


def _az_object(source: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in source.items():
        if key in _AZ_FLATTENED_ONLY and isinstance(value, dict):
            parent = _pascal(key)
            for child, child_value in value.items():
                out[_joined(parent, _pascal(child))] = _az_value(child_value)
            continue
        name = _pascal(key)
        out[name] = _az_value(value)
        if isinstance(value, dict):
            for child in _AZ_KEPT_AND_COPIED.get(key, ()):
                out[name + _pascal(child)] = _az_value(value.get(child))
    # Properties the object always has, empty when the API leaves them out.
    if "tagInfo" in source:
        out.setdefault("Criterion", None)
        out.setdefault("TagInfoETag", None)
    if "deleteAfter" in source:
        out.setdefault("TargetDataStoreCopySetting", [])
    return dict(sorted(out.items()))


def az_policy_property(properties: dict[str, Any]) -> dict[str, Any]:
    """A Backup Vault policy's ``properties`` as ``Get-AzDataProtectionBackupPolicy`` shows them."""
    return _az_object(properties or {})


def _dp_policy_rows(ctx: _Context, result: dict) -> list[dict[str, Any]]:
    rows = []
    for entry in result.get("data_protection") or []:
        subscription_id = entry.get("subscription_id", "")
        for policy in entry.get("policies") or []:
            system = policy.get("system_data") or {}
            rows.append(
                {
                    "Tenant": ctx.tenant,
                    "Subscription": ctx.subscription(subscription_id),
                    "Region": policy.get("location"),
                    "ResourceGroup": policy.get("resource_group"),
                    "VaultName": policy.get("vault_name"),
                    "Workload": policy.get("workload"),
                    "DatasourceType": policy.get("datasource_types"),
                    "Id": policy.get("id"),
                    "Name": policy.get("name"),
                    "ObjectType": policy.get("object_type"),
                    "Property": az_policy_property(policy.get("properties") or {}),
                    "ResourceGroupName": policy.get("resource_group"),
                    "SystemDataCreatedAt": system.get("createdAt"),
                    "SystemDataCreatedBy": system.get("createdBy"),
                    "SystemDataCreatedByType": system.get("createdByType"),
                    "SystemDataLastModifiedAt": system.get("lastModifiedAt"),
                    "SystemDataLastModifiedBy": system.get("lastModifiedBy"),
                    "SystemDataLastModifiedByType": system.get("lastModifiedByType"),
                    "Type": policy.get("type"),
                }
            )
    return rows


def _mi_db_rows(ctx: _Context, result: dict) -> list[dict[str, Any]]:
    """One row holding the whole file: tenant, then subscription, then managed instance, then its
    databases. PowerShell creates a subscription's key before it lists the instances, so a subscription
    with none is an empty object, and one database comes out as an object, not a one-item array, because
    its list is unwrapped on the way through ``ConvertFrom-Json``.
    """
    nested: dict[str, dict[str, dict[str, Any]]] = {}
    for entry in result.get("database") or []:
        subscription = nested.setdefault(ctx.tenant_key, {}).setdefault(
            ctx.subscription(entry.get("subscription_id", "")), {}
        )
        for instance in entry.get("managed_instances") or []:
            databases = instance.get("databases_az") or []
            subscription[instance.get("name")] = databases[0] if len(databases) == 1 else databases
    return [nested]


def _render_mi_json(rows: list[dict[str, Any]]) -> str:
    return json.dumps(rows[0] if rows else {}, indent=2, ensure_ascii=False) + "\n"


def _render_json(rows: list[dict[str, Any]]) -> str:
    """The rows as a JSON array, even for one row (``ConvertTo-Json -InputObject @(...)``)."""
    return json.dumps(rows, indent=2, ensure_ascii=False) + "\n"


# ── Recovery Services vault items and policies ────────────────────────────────
#
# ``Get-AzRecoveryServicesBackupItem`` and ``Get-AzRecoveryServicesBackupProtectionPolicy`` objects,
# piped through ``Select-Object Tenant, Subscription, Region, ResourceGroup, *``: the items go to
# ``Export-Csv`` (an enum is written as its name, a nested object as its .NET type name), the policies
# to ``ConvertTo-Json -Depth 10`` (an enum is written as its number). The rows are built from the REST
# payload the collector keeps (``rest_properties``), mapped to the Az property names.
#
# Checked cell for cell against Az.RecoveryServices 7.15.0 on a real vault: the VM and Azure Files
# items, and the VM (standard and enhanced), Azure Files and SQL in VM policies. The SQL in VM and
# Azure SQL Database *items* and the Azure SQL Database *policies* are built from the Az model and
# the SDK's field names, and have not been compared with a real run.

# Az enum tables (name -> number), read from Az.RecoveryServices 7.15.0 by reflection.
_AZ_WORKLOAD_TYPE = {
    "AzureVM": 1,
    "AzureSQLDatabase": 2,
    "AzureFiles": 3,
    "MSSQL": 4,
    "FileFolder": 5,
    "SAPHanaDatabase": 6,
}
_AZ_BACKUP_MANAGEMENT_TYPE = {
    "AzureVM": 1,
    "SCDPM": 2,
    "AzureBackupServer": 3,
    "AzureSQL": 4,
    "AzureStorage": 5,
    "AzureWorkload": 6,
    "MAB": 7,
    "NA": 8,
}
_AZ_CONTAINER_TYPE = {
    "AzureVM": 1,
    "Windows": 2,
    "AzureSQL": 3,
    "AzureStorage": 4,
    "AzureVMAppContainer": 5,
}
_AZ_SCHEDULE_RUN_TYPE = {"Daily": 1, "Weekly": 2, "Hourly": 3}
_AZ_TIERING_MODE = {"TierRecommended": 1, "TierAllEligible": 2, "DoNotTier": 3}
_AZ_RECOVERY_POINT_TIER = {
    "VaultStandard": 1,
    "Snapshot": 2,
    "VaultArchive": 3,
    "VaultStandardRehydrated": 4,
    "SnapshotAndVaultStandard": 5,
    "SnapshotAndVaultArchive": 6,
}
_AZ_RETENTION_DURATION_TYPE = {"Days": 1, "Weeks": 2, "Months": 3, "Years": 4}
_AZ_RETENTION_SCHEDULE_FORMAT = {"Daily": 1, "Weekly": 2}
_AZ_DAY_OF_WEEK = {
    "Sunday": 0,
    "Monday": 1,
    "Tuesday": 2,
    "Wednesday": 3,
    "Thursday": 4,
    "Friday": 5,
    "Saturday": 6,
}
_AZ_WEEK_OF_MONTH = {"First": 1, "Second": 2, "Third": 3, "Fourth": 4, "Last": 5}
_AZ_MONTH = {
    m: i
    for i, m in enumerate(
        (
            "January",
            "February",
            "March",
            "April",
            "May",
            "June",
            "July",
            "August",
            "September",
            "October",
            "November",
            "December",
        ),
        1,
    )
}

# REST backupManagementType / workloadType -> the Az names the cmdlets show.
_REST_TO_AZ_BACKUP_MANAGEMENT = {
    "AzureIaasVM": "AzureVM",
    "AzureStorage": "AzureStorage",
    "AzureWorkload": "AzureWorkload",
    "AzureSql": "AzureSQL",
    "MAB": "MAB",
    "DPM": "SCDPM",
    "AzureBackupServer": "AzureBackupServer",
}
_REST_TO_AZ_WORKLOAD = {
    "VM": "AzureVM",
    "AzureFileShare": "AzureFiles",
    "SQLDataBase": "MSSQL",
    "SQLDB": "AzureSQLDatabase",
    "AzureSqlDb": "AzureSQLDatabase",
    "SAPHanaDatabase": "SAPHanaDatabase",
    "FileFolder": "FileFolder",
}
# The container type Az gives an item, from its backup management type.
_AZ_CONTAINER_FOR_MANAGEMENT = {
    "AzureVM": "AzureVM",
    "AzureStorage": "AzureStorage",
    "AzureWorkload": "AzureVMAppContainer",
    "AzureSQL": "AzureSQL",
}

# The four files of each kind, in PowerShell's order, keyed by (Az backup management, Az workload).
_VAULT_KINDS = {
    ("AzureVM", "AzureVM"): ("VM", "azure_backup_vault_VM_items", "azure_backup_vault_VM_policies"),
    ("AzureWorkload", "MSSQL"): (
        "VM_SQL",
        "azure_backup_vault_VM_SQL_items",
        "azure_backup_vault_VM_SQL_policies",
    ),
    ("AzureSQL", "AzureSQLDatabase"): (
        "Azure_SQL_Database",
        "azure_backup_vault_Azure_SQL_Database_items",
        "azure_backup_vault_Azure_SQL_Database_Policies",
    ),
    ("AzureStorage", "AzureFiles"): (
        "Azure_Files",
        "azure_backup_vault_Azure_Files_items",
        "azure_backup_vault_Azure_Files_Policies",
    ),
}

# Item columns after the four leading ones, in the order Get-AzRecoveryServicesBackupItem's
# objects have them (Az.RecoveryServices 7.15.0). VM and Azure Files are from a real run; SQL in VM
# and Azure SQL Database follow the Az model classes (AzureWorkloadSQLDatabaseProtectedItem,
# AzureSqlItem) and the column list of EXAMPLES/azure_backup_vault_VM_SQL_items-example.csv.
_ITEM_TAIL = [
    "ProtectionStatus",
    "PolicyId",
    "ProtectionState",
    "LastBackupStatus",
    "LastBackupTime",
    "ProtectionPolicyName",
    "ExtendedInfo",
    "DateOfPurge",
    "DeleteState",
    "IsArchiveEnabled",
    "SoftDeleteRetentionPeriodInDays",
    "IsScheduledForDeferredDelete",
    "DeferredDeleteTimeInUtc",
    "DeferredDeleteTimeRemaining",
    "Name",
    "Id",
    "LatestRecoveryPoint",
    "SourceResourceId",
    "SourceSideScanStatus",
    "SourceSideScanSummary",
    "WorkloadType",
    "ContainerName",
    "ContainerType",
    "BackupManagementType",
]
_LEADING = ["Tenant", "Subscription", "Region", "ResourceGroup"]
_ITEM_COLUMNS = {
    "VM": [
        *_LEADING,
        "VirtualMachineId",
        "ContainerSubscriptionId",
        "HealthStatus",
        "IsInclusionList",
        "DiskLunList",
        *_ITEM_TAIL,
    ],
    "Azure_Files": [
        *_LEADING,
        "ParentContainerFabricId",
        "FriendlyName",
        "ResourceState",
        *_ITEM_TAIL,
    ],
    # Not compared with a real run (no SQL in VM item in the test vault).
    "VM_SQL": [
        *_LEADING,
        "FriendlyName",
        "ServerName",
        "ParentName",
        "ParentType",
        "LastBackupErrorDetail",
        "ProtectedItemDataSourceId",
        "ProtectedItemHealthStatus",
        *_ITEM_TAIL,
    ],
    # Not compared with a real run (no Azure SQL Database item in the test vault).
    "Azure_SQL_Database": [*_LEADING, "ProtectedItemDataId", *_ITEM_TAIL],
}


def _az_name(table: dict[str, str], value: Any) -> Optional[str]:
    return table.get(value, value) if value else None


def _az_enum(table: dict[str, int], name: Any) -> Any:
    """An Az enum as ConvertTo-Json writes it: its number; a name the table lacks stays text."""
    if name is None or name == "":
        return None
    return table.get(name, name)


def _az_enums(table: dict[str, int], names: Any) -> list:
    """A list of Az enums as numbers (an empty list when there are none)."""
    return [_az_enum(table, name) for name in names or []]


# The collector's workload label -> the REST backup management type, for rows with no payload
# (a --mock run), and the workload each management type implies when the payload has none (a VM
# policy's payload carries no workLoadType).
_MANAGEMENT_FROM_WORKLOAD = {"VM": "AzureIaasVM", "Files": "AzureStorage", "SQL": "AzureWorkload"}
_WORKLOAD_FROM_MANAGEMENT = {
    "AzureVM": "AzureVM",
    "AzureStorage": "AzureFiles",
    "AzureWorkload": "MSSQL",
    "AzureSQL": "AzureSQLDatabase",
}


def _az_types(row: dict) -> tuple[Optional[str], Optional[str]]:
    """The Az backup management type and workload type of an item or policy row, as the names the
    Az cmdlets show (``AzureVM``, ``MSSQL``, ...).

    Read from the REST payload: an item's key is ``workloadType`` and a policy's ``workLoadType``.
    A row with no payload (a mock run) falls back to the collector's workload label, and a payload
    with no workload (a VM policy has none) to the one its management type implies.
    """
    rest = row.get("rest_properties") or {}
    management = _az_name(
        _REST_TO_AZ_BACKUP_MANAGEMENT,
        rest.get("backupManagementType") or _MANAGEMENT_FROM_WORKLOAD.get(row.get("workload_type")),
    )
    workload = rest.get("workloadType") or rest.get("workLoadType")
    if workload:
        return management, _az_name(_REST_TO_AZ_WORKLOAD, workload)
    return management, _WORKLOAD_FROM_MANAGEMENT.get(management)


def _vault_kind(row: dict) -> Optional[str]:
    """``VM``, ``VM_SQL``, ``Azure_SQL_Database`` or ``Azure_Files``, or None for any other kind
    (PowerShell does not list items or policies of other workloads).
    """
    kind = _VAULT_KINDS.get(_az_types(row))
    return kind[0] if kind else None


def _ps_datetime_or_none(value: Any) -> Optional[str]:
    """A REST timestamp as Export-Csv writes a ``[datetime]``, or None.

    The API sends up to seven fraction digits (``...06.3921437Z``), which ``fromisoformat`` does
    not read before Python 3.11, so the fraction is dropped: PowerShell's format has whole seconds.
    """
    if not value:
        return None
    text = str(value)
    text = re.sub(r"\.\d+", "", text).replace("Z", "+00:00")
    try:
        return _ps_datetime(text)
    except ValueError:
        return text


def _item_row(ctx: _Context, item: dict, region: Optional[str], kind: str) -> dict[str, Any]:
    """One item as ``Get-AzRecoveryServicesBackupItem | Select-Object ... *`` gives it to Export-Csv."""
    rest = item.get("rest_properties") or {}
    management, workload = _az_types(item)
    scan = rest.get("sourceSideScanInfo") or {}
    policy_id = rest.get("policyId") or item.get("policy_id")
    resource_id = item.get("resource_id") or ""
    row: dict[str, Any] = {
        "Tenant": ctx.tenant,
        "Subscription": ctx.subscription(item.get("subscription_id", "")),
        "Region": region,
        "ResourceGroup": item.get("resource_group"),
        "ProtectionStatus": rest.get("protectionStatus"),
        "PolicyId": policy_id,
        "ProtectionState": rest.get("protectionState") or item.get("protection_state"),
        "LastBackupStatus": rest.get("lastBackupStatus") or item.get("last_backup_status"),
        "LastBackupTime": _ps_datetime_or_none(
            rest.get("lastBackupTime") or item.get("last_backup_time")
        ),
        "ProtectionPolicyName": rest.get("policyName")
        or item.get("policy_name")
        or (_resource_name(policy_id) or None),
        # Az fills these from an extended-info call the plain listing does not make: empty in every
        # real row seen, so left empty here.
        "ExtendedInfo": None,
        "DateOfPurge": None,
        # Only "NotDeleted" has been seen on a real vault. A soft-deleted item is written "ToBeDeleted"
        # (the Az enum has no other name for it); that branch is not compared with a real item.
        "DeleteState": "ToBeDeleted" if rest.get("isScheduledForDeferredDelete") else "NotDeleted",
        "IsArchiveEnabled": rest.get("isArchiveEnabled"),
        # The API sends 0 where Az shows nothing (seen on a real vault). A non-zero period is
        # passed through; no real item with one has been compared.
        "SoftDeleteRetentionPeriodInDays": rest.get("softDeleteRetentionPeriod") or None,
        "IsScheduledForDeferredDelete": rest.get("isScheduledForDeferredDelete"),
        "DeferredDeleteTimeInUtc": _ps_datetime_or_none(rest.get("deferredDeleteTimeInUTC")),
        "DeferredDeleteTimeRemaining": rest.get("deferredDeleteTimeRemaining"),
        "Name": item.get("name"),
        "Id": resource_id,
        "LatestRecoveryPoint": _ps_datetime_or_none(rest.get("lastRecoveryPoint")),
        "SourceResourceId": rest.get("sourceResourceId") or item.get("source_resource_id"),
        "SourceSideScanStatus": scan.get("sourceSideScanStatus"),
        "SourceSideScanSummary": scan.get("sourceSideScanSummary"),
        "WorkloadType": workload,
        "ContainerName": rest.get("containerName"),
        "ContainerType": _AZ_CONTAINER_FOR_MANAGEMENT.get(management),
        "BackupManagementType": management,
    }
    if kind == "VM":
        vm_id = rest.get("virtualMachineId") or item.get("source_resource_id")
        row.update(
            {
                "VirtualMachineId": vm_id,
                # The VM's subscription: Az reads it from the VM id.
                "ContainerSubscriptionId": _subscription_in_id(vm_id),
                "HealthStatus": rest.get("healthStatus"),
                "IsInclusionList": None,
                "DiskLunList": None,
            }
        )
    elif kind == "Azure_Files":
        extended = rest.get("extendedInfo") or {}
        row.update(
            {
                "ParentContainerFabricId": None,
                "FriendlyName": rest.get("friendlyName") or item.get("friendly_name"),
                "ResourceState": extended.get("resourceState") or "",
            }
        )
    elif kind == "VM_SQL":
        row.update(
            {
                "FriendlyName": rest.get("friendlyName"),
                "ServerName": rest.get("serverName"),
                "ParentName": rest.get("parentName"),
                "ParentType": rest.get("parentType"),
                # A nested object: Export-Csv would write its .NET type name when it is set, which
                # no real run has shown, so it is left empty rather than guessed.
                "LastBackupErrorDetail": None,
                "ProtectedItemDataSourceId": rest.get("protectedItemDataSourceId"),
                "ProtectedItemHealthStatus": rest.get("protectedItemHealthStatus"),
            }
        )
    elif kind == "Azure_SQL_Database":
        row["ProtectedItemDataId"] = rest.get("protectedItemDataId")
    return row


_SUBSCRIPTION_IN_ID = re.compile(r"/subscriptions/([^/]+)", re.IGNORECASE)


def _subscription_in_id(resource_id: Optional[str]) -> Optional[str]:
    found = _SUBSCRIPTION_IN_ID.search(resource_id or "")
    return found.group(1) if found else None


def _vault_regions(posture: dict) -> dict[str, str]:
    return {(v.get("name") or "").lower(): v.get("location") for v in posture.get("vaults") or []}


def _vault_item_rows(kind: str) -> Callable[[_Context, dict], list[dict[str, Any]]]:
    def rows(ctx: _Context, result: dict) -> list[dict[str, Any]]:
        out = []
        for posture in result.get("backup_posture") or []:
            regions = _vault_regions(posture)
            for item in posture.get("protected_items") or []:
                if _vault_kind(item) != kind:
                    continue
                region = regions.get((item.get("vault_name") or "").lower())
                out.append(_item_row(ctx, item, region, kind))
        return out

    return rows


# ── policies (ConvertTo-Json) ──


def _az_retention_times(times: Any) -> list:
    return list(times or [])


def _az_simple_schedule(schedule: dict, time_zone: Optional[str]) -> dict[str, Any]:
    """A REST SimpleSchedulePolicy as Az's SimpleSchedulePolicy (V1)."""
    days = schedule.get("scheduleRunDays")
    return {
        "ScheduleRunFrequency": _az_enum(
            _AZ_SCHEDULE_RUN_TYPE, schedule.get("scheduleRunFrequency")
        ),
        "ScheduleRunDays": _az_enums(_AZ_DAY_OF_WEEK, days) or None,
        "ScheduleRunTimes": _az_retention_times(schedule.get("scheduleRunTimes")) or None,
        # An hourly schedule (Azure Files): not seen on a real vault, whose policies are daily.
        "ScheduleInterval": (schedule.get("hourlySchedule") or {}).get("interval"),
        "ScheduleWindowStartTime": (schedule.get("hourlySchedule") or {}).get(
            "scheduleWindowStartTime"
        ),
        "ScheduleWindowDuration": (schedule.get("hourlySchedule") or {}).get(
            "scheduleWindowDuration"
        ),
        "ScheduleRunTimeZone": time_zone,
    }


def _az_simple_schedule_v2(schedule: dict, time_zone: Optional[str]) -> dict[str, Any]:
    """A REST SimpleSchedulePolicyV2 (enhanced VM policy) as Az's SimpleSchedulePolicyV2."""
    hourly = schedule.get("hourlySchedule")
    daily = schedule.get("dailySchedule")
    weekly = schedule.get("weeklySchedule")
    return {
        "ScheduleRunFrequency": _az_enum(
            _AZ_SCHEDULE_RUN_TYPE, schedule.get("scheduleRunFrequency")
        ),
        "HourlySchedule": None
        if not hourly
        else {
            "Interval": hourly.get("interval"),
            "WindowStartTime": hourly.get("scheduleWindowStartTime"),
            "WindowDuration": hourly.get("scheduleWindowDuration"),
        },
        "DailySchedule": None
        if not daily
        else {"ScheduleRunTimes": _az_retention_times(daily.get("scheduleRunTimes"))},
        "WeeklySchedule": None
        if not weekly
        else {
            "ScheduleRunDays": _az_enums(_AZ_DAY_OF_WEEK, weekly.get("scheduleRunDays")),
            "ScheduleRunTimes": _az_retention_times(weekly.get("scheduleRunTimes")),
        },
        "ScheduleRunTimeZone": time_zone,
    }


def _az_schedule(schedule: Optional[dict], time_zone: Optional[str]) -> Optional[dict[str, Any]]:
    if not schedule:
        return None
    if schedule.get("schedulePolicyType") == "SimpleSchedulePolicyV2":
        return _az_simple_schedule_v2(schedule, time_zone)
    if schedule.get("schedulePolicyType") == "LogSchedulePolicy":
        return {"ScheduleFrequencyInMins": schedule.get("scheduleFrequencyInMins")}
    return _az_simple_schedule(schedule, time_zone)


def _az_month_days(daily: Optional[dict]) -> Optional[dict[str, Any]]:
    if not daily:
        return None
    return {
        "DaysOfTheMonth": [
            {"Date": d.get("date"), "IsLast": bool(d.get("isLast"))}
            for d in daily.get("daysOfTheMonth") or []
        ]
    }


def _az_month_weeks(weekly: Optional[dict]) -> Optional[dict[str, Any]]:
    if not weekly:
        return None
    return {
        "DaysOfTheWeek": _az_enums(_AZ_DAY_OF_WEEK, weekly.get("daysOfTheWeek")),
        "WeeksOfTheMonth": [
            _az_enum(_AZ_WEEK_OF_MONTH, w) for w in weekly.get("weeksOfTheMonth") or []
        ],
    }


def _az_long_term_retention(retention: dict, management: str) -> dict[str, Any]:
    """A REST LongTermRetentionPolicy as Az's LongTermRetentionPolicy.

    Az writes the policy's backup management type into each schedule (``AzureIaasVM`` and
    ``AzureStorage`` seen in real runs, the empty string for a SQL in VM policy). The daily schedule
    shape is from real runs; the weekly, monthly and yearly property names and order are those of
    the Az objects, with values mapped the same way, not seen from a real vault.
    """
    daily = retention.get("dailySchedule")
    weekly = retention.get("weeklySchedule")
    monthly = retention.get("monthlySchedule")
    yearly = retention.get("yearlySchedule")

    def count(schedule: Optional[dict]) -> Any:
        return ((schedule or {}).get("retentionDuration") or {}).get("count")

    return {
        "IsDailyScheduleEnabled": bool(daily),
        "IsWeeklyScheduleEnabled": bool(weekly),
        "IsMonthlyScheduleEnabled": bool(monthly),
        "IsYearlyScheduleEnabled": bool(yearly),
        "DailySchedule": None
        if not daily
        else {
            "DurationCountInDays": count(daily),
            "RetentionTimes": _az_retention_times(daily.get("retentionTimes")),
            "BackupManagementType": management,
        },
        "WeeklySchedule": None
        if not weekly
        else {
            "DurationCountInWeeks": count(weekly),
            "DaysOfTheWeek": _az_enums(_AZ_DAY_OF_WEEK, weekly.get("daysOfTheWeek")),
            "RetentionTimes": _az_retention_times(weekly.get("retentionTimes")),
            "BackupManagementType": management,
        },
        "MonthlySchedule": None
        if not monthly
        else {
            "DurationCountInMonths": count(monthly),
            "RetentionScheduleFormatType": _az_enum(
                _AZ_RETENTION_SCHEDULE_FORMAT, monthly.get("retentionScheduleFormatType")
            ),
            "RetentionScheduleDaily": _az_month_days(monthly.get("retentionScheduleDaily")),
            "RetentionScheduleWeekly": _az_month_weeks(monthly.get("retentionScheduleWeekly")),
            "RetentionTimes": _az_retention_times(monthly.get("retentionTimes")),
            "BackupManagementType": management,
        },
        "YearlySchedule": None
        if not yearly
        else {
            "DurationCountInYears": count(yearly),
            "RetentionScheduleFormatType": _az_enum(
                _AZ_RETENTION_SCHEDULE_FORMAT, yearly.get("retentionScheduleFormatType")
            ),
            "MonthsOfYear": _az_enums(_AZ_MONTH, yearly.get("monthsOfYear")),
            "RetentionScheduleDaily": _az_month_days(yearly.get("retentionScheduleDaily")),
            "RetentionScheduleWeekly": _az_month_weeks(yearly.get("retentionScheduleWeekly")),
            "RetentionTimes": _az_retention_times(yearly.get("retentionTimes")),
            "BackupManagementType": management,
        },
        "BackupManagementType": management,
    }


def _az_simple_retention(retention: dict) -> dict[str, Any]:
    duration = retention.get("retentionDuration") or {}
    return {
        "RetentionDurationType": _az_enum(
            _AZ_RETENTION_DURATION_TYPE, duration.get("durationType")
        ),
        "RetentionCount": duration.get("count"),
    }


def _az_retention(retention: Optional[dict], management: str) -> Optional[dict[str, Any]]:
    if not retention:
        return None
    if retention.get("retentionPolicyType") == "SimpleRetentionPolicy":
        return _az_simple_retention(retention)
    return _az_long_term_retention(retention, management)


def _az_tiering(tiering: Optional[dict]) -> Optional[dict[str, Any]]:
    """The REST ``tieringPolicy`` (keyed by tier, ``ArchivedRP``) as Az's TieringPolicy."""
    archived = (tiering or {}).get("ArchivedRP")
    if not archived:
        return None
    return {
        "TargetTier": _AZ_RECOVERY_POINT_TIER["VaultArchive"],
        "TieringMode": _az_enum(_AZ_TIERING_MODE, archived.get("tieringMode")),
        "TierAfterDuration": archived.get("duration"),
        "TierAfterDurationType": archived.get("durationType"),
    }


def _policy_common_head(ctx: _Context, policy: dict, region: Optional[str]) -> dict[str, Any]:
    return {
        "Tenant": ctx.tenant,
        "Subscription": ctx.subscription(policy.get("subscription_id", "")),
        "Region": region,
        "ResourceGroup": policy.get("resource_group"),
    }


def _policy_common_tail(policy: dict, workload: str, management: str) -> dict[str, Any]:
    return {
        "Name": policy.get("name"),
        "WorkloadType": _az_enum(_AZ_WORKLOAD_TYPE, workload),
        "Id": policy.get("resource_id"),
        "BackupManagementType": _az_enum(_AZ_BACKUP_MANAGEMENT_TYPE, management),
    }


def _vm_policy(ctx: _Context, policy: dict, region: Optional[str]) -> dict[str, Any]:
    rest = policy.get("rest_properties") or {}
    zone = rest.get("timeZone")
    enhanced = rest.get("policyType") == "V2"
    tiering = _az_tiering(rest.get("tieringPolicy"))
    snapshot_rg = rest.get("instantRPDetails") or {}
    return {
        **_policy_common_head(ctx, policy, region),
        "SnapshotRetentionInDays": rest.get("instantRpRetentionRangeInDays"),
        "ProtectedItemsCount": rest.get("protectedItemsCount"),
        "AzureBackupRGName": snapshot_rg.get("azureBackupRGNamePrefix"),
        "AzureBackupRGNameSuffix": snapshot_rg.get("azureBackupRGNameSuffix"),
        "PolicySubType": 2 if enhanced else 1,
        "TieringPolicy": tiering,
        # "" when the API sends an empty value, null when it sends none (both seen on real policies).
        "SnapshotConsistencyType": rest.get("snapshotConsistencyType"),
        "SchedulePolicy": _az_schedule(rest.get("schedulePolicy"), zone),
        "RetentionPolicy": _az_retention(rest.get("retentionPolicy"), "AzureIaasVM"),
        **_policy_common_tail(policy, "AzureVM", "AzureVM"),
    }


def _files_policy(ctx: _Context, policy: dict, region: Optional[str]) -> dict[str, Any]:
    rest = policy.get("rest_properties") or {}
    zone = rest.get("timeZone")
    return {
        **_policy_common_head(ctx, policy, region),
        "ProtectedItemsCount": rest.get("protectedItemsCount"),
        "SchedulePolicy": _az_schedule(rest.get("schedulePolicy"), zone),
        "RetentionPolicy": _az_retention(rest.get("retentionPolicy"), "AzureStorage"),
        **_policy_common_tail(policy, "AzureFiles", "AzureStorage"),
    }


def _sql_vm_policy(ctx: _Context, policy: dict, region: Optional[str]) -> dict[str, Any]:
    rest = policy.get("rest_properties") or {}
    settings = rest.get("settings") or {}
    zone = settings.get("timeZone")
    subs = {s.get("policyType"): s for s in rest.get("subProtectionPolicy") or []}
    full, diff, log = subs.get("Full") or {}, subs.get("Differential") or {}, subs.get("Log") or {}
    return {
        **_policy_common_head(ctx, policy, region),
        "ProtectedItemsCount": rest.get("protectedItemsCount"),
        "IsCompression": bool(settings.get("isCompression")),
        "IsDifferentialBackupEnabled": bool(diff),
        "IsLogBackupEnabled": bool(log),
        "FullBackupSchedulePolicy": _az_schedule(full.get("schedulePolicy"), zone),
        "DifferentialBackupSchedulePolicy": _az_schedule(diff.get("schedulePolicy"), zone),
        "LogBackupSchedulePolicy": _az_schedule(log.get("schedulePolicy"), zone),
        # Az writes "" as the management type inside a SQL in VM policy's retention (real run).
        "FullBackupRetentionPolicy": _az_retention(full.get("retentionPolicy"), ""),
        "DifferentialBackupRetentionPolicy": _az_retention(diff.get("retentionPolicy"), ""),
        "LogBackupRetentionPolicy": _az_retention(log.get("retentionPolicy"), ""),
        "FullBackupTieringPolicy": _az_tiering(full.get("tieringPolicy")),
        **_policy_common_tail(policy, "MSSQL", "AzureWorkload"),
    }


def _sql_db_policy(ctx: _Context, policy: dict, region: Optional[str]) -> dict[str, Any]:
    """Not compared with a real run: no Azure SQL Database policy in the test vault. The shape
    follows Az's AzureSqlPolicy (a retention policy only)."""
    rest = policy.get("rest_properties") or {}
    return {
        **_policy_common_head(ctx, policy, region),
        "ProtectedItemsCount": rest.get("protectedItemsCount"),
        "RetentionPolicy": _az_retention(rest.get("retentionPolicy"), "AzureSql"),
        **_policy_common_tail(policy, "AzureSQLDatabase", "AzureSQL"),
    }


_POLICY_BUILDERS = {
    "VM": _vm_policy,
    "VM_SQL": _sql_vm_policy,
    "Azure_SQL_Database": _sql_db_policy,
    "Azure_Files": _files_policy,
}


def _vault_policy_rows(kind: str) -> Callable[[_Context, dict], list[dict[str, Any]]]:
    def rows(ctx: _Context, result: dict) -> list[dict[str, Any]]:
        out = []
        for posture in result.get("backup_posture") or []:
            regions = _vault_regions(posture)
            for policy in posture.get("policies") or []:
                if _vault_kind(policy) != kind:
                    continue
                region = regions.get((policy.get("vault_name") or "").lower())
                out.append(_POLICY_BUILDERS[kind](ctx, policy, region))
        return out

    return rows


def _render_ps_json(rows: list[dict[str, Any]]) -> str:
    """``$list | ConvertTo-Json -Depth 10 > file``: nothing for no rows, a bare object for one row
    and an array for more (checked in pwsh). ``>`` writes a trailing line end.
    """
    if not rows:
        return ""
    body = rows[0] if len(rows) == 1 else rows
    return json.dumps(body, indent=2, ensure_ascii=False) + "\n"


# ── azure_sizing_summary ──────────────────────────────────────────────────────

_SUMMARY_COLUMNS = ["ResourceType", "Region", "TotalSizeTiB", "TotalSizeTB", "Count"]

# Every empty cell of the summary is "" except the size and count cells of a section header.
_SUMMARY_QUOTED_EMPTY = frozenset(["ResourceType", "Region"])


def _ps_sum(values: list[Any]) -> Optional[float]:
    """``Measure-Object -Sum``: adds in order and skips nulls, so a group whose values are all
    null sums to 0. It is null only for an empty list.

    A plain loop on purpose: ``sum()`` of floats is compensated from Python 3.12, which can
    differ from .NET's running total in the last digit.
    """
    if not values:
        return None
    total = 0.0
    for number in values:
        if number is not None:
            total += number
    return total


def _group(rows: list[dict[str, Any]], key: str) -> list[tuple[str, list[dict]]]:
    """``Group-Object``: groups ignore case, a group keeps the first spelling it saw, and the
    groups come sorted by name. PowerShell 7.6 returns them sorted; Windows PowerShell and older
    7.x return them in first-seen order.
    """
    groups: dict[str, tuple[str, list[dict]]] = {}
    for row in rows:
        name = str(row.get(key) or "")
        groups.setdefault(name.casefold(), (name, []))[1].append(row)
    return sorted(groups.values(), key=lambda g: g[0].casefold())


def _section_header(title: str) -> dict[str, Any]:
    return {"ResourceType": title, "Region": "", "TotalSizeTiB": None, "TotalSizeTB": None}


def _summary_line(
    region: str, rows: list[dict], tib: Optional[str], tb: Optional[str]
) -> dict[str, Any]:
    return {
        "ResourceType": "",
        "Region": region,
        "TotalSizeTiB": _ps_sum([r.get(tib) for r in rows]) if tib else None,
        "TotalSizeTB": _ps_sum([r.get(tb) for r in rows]) if tb else None,
        "Count": len(rows),
    }


def _sized_section(
    title: str,
    rows: list[dict],
    region_key: str,
    tib: str,
    tb: str,
    all_label: str = "All Regions",
    region_label=lambda name, group: name,
) -> list[dict[str, Any]]:
    out = [_section_header(title), _summary_line(all_label, rows, tib, tb)]
    for name, group in _group(rows, region_key):
        out.append(_summary_line(region_label(name, group), group, tib, tb))
    return out


def _count_text(value: Optional[float]) -> str:
    return "" if value is None else _format(value)


def _summary(
    vm_rows: list[dict],
    storage_rows: list[dict],
    share_rows: list[dict],
    sql_rows: list[dict],
    mi_rows: list[dict],
    aks_rows: list[dict],
    postgres_rows: Optional[list[dict]] = None,
) -> list[dict[str, Any]]:
    """The rows of azure_sizing_summary, from the rows of the other files.

    For one VM in a ``HasMSSQL`` group PowerShell writes the number of entries of that VM's
    hashtable as the count, because ``.Count`` of a single hashtable is its key count. Here the
    count is the number of VMs.
    """
    out: list[dict[str, Any]] = []
    for has_mssql in ("Yes", "No"):
        group = [r for r in vm_rows if str(r.get("HasMSSQL")).casefold() == has_mssql.casefold()]
        if group:
            out.append(_section_header("[ Azure VMs and Managed Disks ]"))
            out.append({**_section_header(f"HasMSSQL = {has_mssql}")})
            out.append(_summary_line("All Regions", group, "SizeTiB", "SizeTB"))
            for name, rows in _group(group, "Region"):
                out.append(_summary_line(name, rows, "SizeTiB", "SizeTB"))

    if storage_rows:
        blobs = lambda rows: _count_text(_ps_sum([r.get("BlobCount") for r in rows]))  # noqa: E731
        out += _sized_section(
            "[ Azure Storage Accounts ]",
            storage_rows,
            "Region",
            "UsedBlobCapacityTiB",
            "UsedBlobCapacityTB",
            all_label=f"All Regions (Total Blob Count: {blobs(storage_rows)})",
            region_label=lambda name, rows: f"{name} (Blob Count: {blobs(rows)})",
        )
    if share_rows:
        out += _sized_section(
            "[ Azure File Shares ]",
            share_rows,
            "Region",
            "UsedCapacityTiB",
            "UsedCapacityTB",
        )
    databases = [r for r in sql_rows if str(r.get("InstanceType")).casefold() != "datawarehouse"]
    if databases:
        out += _sized_section(
            "[ Azure SQL Databases ]",
            databases,
            "Region",
            "MaxSizeTiB",
            "MaxSizeTB",
        )
    if mi_rows:
        out += _sized_section(
            "[ Azure SQL Managed Instances ]",
            mi_rows,
            "Region",
            "MaxSizeTiB",
            "MaxSizeTB",
        )
    if aks_rows:
        nodes = lambda rows: _count_text(_ps_sum([r.get("TotalNodes") for r in rows]))  # noqa: E731
        out += _sized_section(
            "[ Azure Kubernetes Service (AKS) Clusters ]",
            aks_rows,
            "Location",
            "",
            "",
            all_label=f"All Regions (Total Nodes: {nodes(aks_rows)})",
            region_label=lambda name, rows: f"{name} (Nodes: {nodes(rows)})",
        )
    if postgres_rows:
        out += _sized_section(
            "[ Azure PostgreSQL Flexible Servers ]",
            postgres_rows,
            "Region",
            "MaxSizeTiB",
            "MaxSizeTB",
        )
    return out


def _summary_rows(ctx: _Context, result: dict) -> list[dict[str, Any]]:
    return _summary(
        _vm_rows(ctx, result),
        _storage_account_rows(ctx, result),
        _file_share_rows(ctx, result),
        _sql_rows(ctx, result),
        _mi_rows(ctx, result),
        _aks_rows(ctx, result),
        _postgres_rows(ctx, result),
    )


# ── files ─────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class FileSpec:
    """One output file: its name prefix, fixed columns and row builder."""

    prefix: str
    columns: list[str]
    rows: Callable[[_Context, dict], list[dict[str, Any]]]
    quoted_empty: frozenset[str] = frozenset()
    no_tags: bool = False
    separator: str = "-"
    anonymize: bool = True
    # PowerShell writes some files only when there is something to put in them.
    write_empty: bool = True
    quote_empty_tags: bool = False
    extension: str = "csv"
    # Left out of an anonymized run, which this file cannot be made safe for.
    omit_when_anonymized: bool = False
    # Builds the file text from the rows when the file is not a CSV.
    renderer: Optional[Callable[[list[dict[str, Any]]], str]] = None


# The files each PowerShell -Skip* switch stops writing; the script does not write them at all.
SKIPPED_FILES: dict[str, tuple[str, ...]] = {
    "vms": ("azure_vmdisk_info",),
    "sql_mi": ("azure_sql_info", "azure_mi_sql_info", "azure_mi_db_items"),
    "storage": (
        "azure_storage_account_info",
        "azure_storage_account_container_info",
        "azure_file_share_info",
    ),
    "files": ("azure_file_share_info",),
    "backup": (
        "azure_backup_vault_info",
        "azure_backup_costs",
        "azure_backup_data_protection_vaults",
        "azure_backup_data_protection_policies",
        "azure_backup_data_protection_items",
        *(prefix for _, items, policies in _VAULT_KINDS.values() for prefix in (items, policies)),
    ),
    "aks": ("azure_aks_info",),
    "cosmos": ("azure_cosmos_db",),
    "postgres": ("azure_postgres_info",),
}

FILES: list[FileSpec] = [
    FileSpec("azure_vmdisk_info", _VM_COLUMNS, _vm_rows),
    FileSpec("azure_storage_account_info", _STORAGE_ACCOUNT_COLUMNS, _storage_account_rows),
    FileSpec("azure_storage_account_container_info", _CONTAINER_COLUMNS, _container_rows),
    FileSpec("azure_file_share_info", _FILE_SHARE_COLUMNS, _file_share_rows, no_tags=True),
    FileSpec("azure_backup_vault_info", _VAULT_COLUMNS, _vault_rows, no_tags=True),
    # The Recovery Services vault policies (JSON) and items (CSV), in the order PowerShell writes
    # them. Always written, empty when there is nothing, as the script writes them. The policy JSON
    # nests ids and names below the top level, where the row anonymizer does not reach, so an
    # anonymized run leaves it out, as it does azure_mi_db_items; the item CSVs are flat and are
    # anonymized.
    *[
        FileSpec(
            policies,
            [],
            _vault_policy_rows(kind),
            no_tags=True,
            extension="json",
            renderer=_render_ps_json,
            omit_when_anonymized=True,
        )
        for kind, _, policies in (
            ("VM", "", "azure_backup_vault_VM_policies"),
            ("VM_SQL", "", "azure_backup_vault_VM_SQL_policies"),
            ("Azure_SQL_Database", "", "azure_backup_vault_Azure_SQL_Database_Policies"),
            ("Azure_Files", "", "azure_backup_vault_Azure_Files_Policies"),
        )
    ],
    *[
        FileSpec(
            items,
            _ITEM_COLUMNS[kind],
            _vault_item_rows(kind),
            # Export-Csv writes an empty string as "" (an Azure Files item's ResourceState).
            frozenset({"ResourceState"}) if kind == "Azure_Files" else frozenset(),
            no_tags=True,
        )
        for kind, items in (
            ("VM", "azure_backup_vault_VM_items"),
            ("VM_SQL", "azure_backup_vault_VM_SQL_items"),
            ("Azure_SQL_Database", "azure_backup_vault_Azure_SQL_Database_items"),
            ("Azure_Files", "azure_backup_vault_Azure_Files_items"),
        )
    ],
    FileSpec("azure_backup_costs", _BACKUP_COST_COLUMNS, _backup_cost_rows, no_tags=True),
    FileSpec(
        "azure_backup_data_protection_vaults",
        _DP_VAULT_COLUMNS,
        _dp_vault_rows,
        no_tags=True,
        write_empty=False,
    ),
    FileSpec(
        "azure_backup_data_protection_policies",
        [],
        _dp_policy_rows,
        no_tags=True,
        write_empty=False,
        extension="json",
        renderer=_render_json,
    ),
    FileSpec(
        "azure_backup_data_protection_items",
        _DP_ITEM_COLUMNS,
        _dp_item_rows,
        no_tags=True,
        write_empty=False,
    ),
    FileSpec("azure_aks_info", _AKS_COLUMNS, _aks_rows, _AKS_QUOTED_EMPTY),
    FileSpec("azure_cosmos_db", _COSMOS_COLUMNS, _cosmos_rows),
    FileSpec(
        "azure_postgres_info",
        _POSTGRES_COLUMNS,
        _postgres_rows,
        write_empty=False,
        quote_empty_tags=True,
    ),
    FileSpec(
        "azure_sizing_summary",
        _SUMMARY_COLUMNS,
        _summary_rows,
        _SUMMARY_QUOTED_EMPTY,
        no_tags=True,
        separator="_",
        anonymize=False,
    ),
    FileSpec("azure_sql_info", _SQL_COLUMNS, _sql_rows, _SQL_QUOTED_EMPTY),
    FileSpec("azure_mi_sql_info", _MI_COLUMNS, _mi_rows, _SQL_QUOTED_EMPTY),
    FileSpec(
        "azure_mi_db_items",
        [],
        _mi_db_rows,
        no_tags=True,
        anonymize=False,
        extension="json",
        renderer=_render_mi_json,
        omit_when_anonymized=True,
    ),
    FileSpec("azure_key_vault", _KEY_VAULT_COLUMNS, _key_vault_rows, no_tags=True),
]

# Files written only when their option was given, as PowerShell's -GetContainerDetails and
# -GetKeyVaultAmounts write them: result key -> file.
_OPT_IN_FILES = {
    "containers": "azure_storage_account_container_info",
    "key_vaults": "azure_key_vault",
}


def _header_for(
    spec: FileSpec,
    rows: list[dict[str, Any]],
    tag_names: list[str],
    anonymizer: Optional[Anonymizer],
) -> list[str]:
    """The fixed columns, then the tag columns: one per tag name, or, in an anonymized run, the
    ones the rows carry, because their names were replaced.
    """
    if spec.no_tags:
        return list(spec.columns)
    if anonymizer is None:
        return [*spec.columns, *[f"Tag: {n}" for n in tag_names]]
    extra = [name for row in rows for name in row if name not in spec.columns]
    return [*spec.columns, *dict.fromkeys(extra)]


def _context_for(result: dict) -> tuple[list[str], _Context]:
    tag_names = unique_tag_names(result)
    return tag_names, _Context(
        tenant=result.get("tenant_name"),
        tenant_id=result.get("tenant_id") or "",
        subscription_names=result.get("subscription_names") or {},
        tag_names=tag_names,
        vm_policies=_vm_policies(result),
        files_protection=_files_protection(result),
        blob_protection=_vault_protection(result)[0],
        postgres_protection=_vault_protection(result)[1],
    )


def _active_specs(result: dict) -> list[FileSpec]:
    skipped = {p for key in result.get("skipped") or [] for p in SKIPPED_FILES.get(key, ())}
    if result.get("data_protection") is None:
        skipped |= {p for p in SKIPPED_FILES["backup"] if "data_protection" in p}
    skipped |= {prefix for key, prefix in _OPT_IN_FILES.items() if result.get(key) is None}
    return [spec for spec in FILES if spec.prefix not in skipped]


def rows_by_file(result: dict) -> dict[str, list[dict[str, Any]]]:
    """File prefix -> the row dicts that file is built from, before anonymizing, for the files the
    run did not skip.

    The same data the CSV files hold, so totals computed from it match the files.
    """
    _, ctx = _context_for(result)
    return {spec.prefix: spec.rows(ctx, result) for spec in _active_specs(result)}


def build_csv_files(
    result: dict, stamp: str, anonymizer: Optional[Anonymizer] = None
) -> dict[str, str]:
    """File name -> CSV text for every file in ``FILES`` that the run did not skip.

    ``stamp`` is the file name timestamp; ``result["skipped"]`` names the skipped collectors.
    With an ``anonymizer`` the values are replaced as the files are built, in the order PowerShell
    anonymizes its lists in, so the numbers in the labels follow the same order. The summary is not
    anonymized: it holds regions, sizes and counts.
    """
    tag_names, ctx = _context_for(result)
    specs = _active_specs(result)
    order = sorted(specs, key=lambda s: file_rank(s.prefix)) if anonymizer else specs
    texts: dict[str, str] = {}
    for spec in order:
        rows = spec.rows(ctx, result)
        if anonymizer is not None and spec.anonymize:
            rows = [anonymizer.anonymize_row(row) for row in rows]
        if not rows and not spec.write_empty:
            continue
        if anonymizer is not None and spec.omit_when_anonymized:
            continue
        texts[spec.prefix] = (
            spec.renderer(rows)
            if spec.renderer
            else render(
                _header_for(spec, rows, tag_names, anonymizer),
                rows,
                spec.quoted_empty,
                spec.quote_empty_tags,
            )
        )
    return {
        f"{spec.prefix}{spec.separator}{stamp}.{spec.extension}": texts[spec.prefix]
        for spec in specs
        if spec.prefix in texts
    }


def write_csv_files(
    result: dict, directory: str, stamp: str, anonymizer: Optional[Anonymizer] = None
) -> list[str]:
    """Write the CSV files into ``directory`` and return their paths."""
    os.makedirs(directory, exist_ok=True)
    paths = []
    for name, text in build_csv_files(result, stamp, anonymizer).items():
        path = os.path.join(directory, name)
        with open(path, "w", encoding="utf-8", newline="") as f:
            f.write(text)
        paths.append(path)
    return paths
