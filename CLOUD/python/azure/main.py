#!/usr/bin/env python3
"""Rubrik Discovery — Azure Edition

Lightweight Azure inventory + backup posture assessment for Rubrik SE
conversations.  Run it from Azure Cloud Shell, an Azure VM with Managed
Identity, or any machine with ``az login`` active.

Usage examples:
    # Every enabled subscription the sign-in can read (the default, as in PowerShell)
    python main.py

    # Only the subscription of the current az login
    python main.py --current-subscription

    # Explicit subscriptions, by id or by name, or everything under management groups
    python main.py --subs aaaa-1111,bbbb-2222
    python main.py --subscriptions "Prod East,Prod West"
    python main.py --management-groups mg-prod,mg-dev

    # All accessible subscriptions, filtered to two regions
    python main.py --all --regions eastus,westus2

    # Offline demo with mock data (development checkouts only; needs the test fixtures)
    python main.py --mock

    # Scan up to 8 subscriptions at a time (default 4; 1 = serial)
    python main.py --all --workers 8

    # Debug logging
    python main.py --all --verbose
"""

from __future__ import annotations

import argparse
import contextlib
import importlib.util
import logging
import pathlib
import sys
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Optional

from rich import box
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table

import checkpoint_core
import gaps
import manifest_core
import preflight
import preflight_core
import progress
import resume
import runlog
import totals
from anonymize import KEY_FILE_PREFIX, Anonymizer, anonymized_log_note
from cloud import DEFAULT_CLOUD

console = runlog.LoggedConsole(width=max(120, Console().width))

logger = logging.getLogger(__name__)

DEFAULT_WORKERS = 4


def _positive_int(value: str) -> int:
    try:
        n = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid int value: {value!r}") from None
    if n < 1:
        raise argparse.ArgumentTypeError("must be >= 1")
    return n


def _resolve_workers(args) -> int:
    """CLI flag (or the config value folded in by _apply_config_defaults) > default."""
    return args.workers if args.workers is not None else DEFAULT_WORKERS


# PowerShell -Skip* switches: key -> (flags, the PowerShell switch, what it skips). Both flags are
# accepted; the second is the PowerShell name in kebab case.
SKIP_SWITCHES: dict[str, tuple[tuple[str, str], str, str]] = {
    "vms": (
        ("--skip-vms", "--skip-azure-vm-and-managed-disks"),
        "-SkipAzureVMandManagedDisks",
        "Skip virtual machines and managed disks.",
    ),
    "sql_mi": (
        ("--skip-sql-mi", "--skip-azure-sql-and-mi"),
        "-SkipAzureSQLandMI",
        "Skip Azure SQL databases, elastic pools and managed instances (flexible servers are "
        "still collected).",
    ),
    "storage": (
        ("--skip-storage-accounts", "--skip-azure-storage-accounts"),
        "-SkipAzureStorageAccounts",
        "Skip storage accounts, which also skips their file shares.",
    ),
    "files": (
        ("--skip-files", "--skip-azure-files"),
        "-SkipAzureFiles",
        "Skip Azure Files shares; storage accounts are still collected.",
    ),
    "backup": (
        ("--skip-backup", "--skip-azure-backup"),
        "-SkipAzureBackup",
        "Skip Recovery Services vaults, backup items, job history and backup costs.",
    ),
    "aks": (("--skip-aks",), "-SkipAKS", "Skip AKS clusters."),
    "cosmos": (
        ("--skip-cosmos-db", "--skip-azure-cosmos-db"),
        "-SkipAzureCosmosDB",
        "Skip Cosmos DB accounts.",
    ),
    "postgres": (
        ("--skip-postgresql", "--skip-azure-postgresql"),
        "-SkipAzurePostgreSQL",
        "Skip PostgreSQL flexible servers.",
    ),
}


def _split_csv(value: Optional[str]) -> Optional[list[str]]:
    items = [v.strip() for v in value.split(",") if v.strip()] if value else None
    return items or None


def _scope_kind(args) -> str:
    """How the subscriptions were asked for: ``subs`` (ids), ``names``, ``groups`` (management
    groups), ``current`` (``--current-subscription``) or ``all``, which is also what no scope flag
    means, as in PowerShell. Both the scan scope and the resume fingerprint read this, so a resume
    can only continue a run that asked for its subscriptions the same way."""
    if args.all:
        return "all"
    if _split_csv(args.subs):
        return "subs"
    if _split_csv(getattr(args, "subscriptions", None)):
        return "names"
    if _split_csv(getattr(args, "management_groups", None)):
        return "groups"
    if getattr(args, "current_subscription", False):
        return "current"
    return "all"


def _resolve_scope(credential, args, cloud, skipped: Optional[list] = None) -> list[str]:
    """Subscription ids for the scope flags. With no scope flag every accessible subscription
    is scanned, as in PowerShell; ``--current-subscription`` limits it to the current login."""
    import auth

    sub_ids = _split_csv(args.subs)
    names = _split_csv(getattr(args, "subscriptions", None))
    groups = _split_csv(getattr(args, "management_groups", None))
    all_subs = _scope_kind(args) == "all"
    extra = {}
    if names:
        extra["names"] = names
    if groups:
        extra["management_groups"] = groups
    return auth.resolve_subscriptions(
        credential, sub_ids, all_subs, cloud, skipped=skipped, **extra
    )


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="rubrik-discovery",
        description="Rubrik Discovery — Azure Edition",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--config",
        action="append",
        type=pathlib.Path,
        metavar="FILE",
        help="Path to rubrik.yaml (see docs/config_schema.md).  Pass twice "
        "for base + overlay.  Values from the config are overridden "
        "by explicit flags.",
    )
    scope = p.add_mutually_exclusive_group()
    scope.add_argument(
        "--subs",
        metavar="ID,...",
        help="Comma-separated subscription IDs to scan",
    )
    scope.add_argument(
        "--subscriptions",
        metavar="NAME,...",
        help="Comma-separated subscription names to scan (PowerShell's -Subscriptions)",
    )
    scope.add_argument(
        "--management-groups",
        metavar="GROUP,...",
        help="Comma-separated management group names or ids; every subscription under them "
        "is scanned (PowerShell's -ManagementGroups)",
    )
    scope.add_argument(
        "--current-subscription",
        action="store_true",
        help="Scan only the subscription of the current az login (PowerShell's "
        "-CurrentSubscription)",
    )
    scope.add_argument(
        "--all",
        action="store_true",
        help="Scan all accessible subscriptions (the default when no scope flag is given)",
    )
    p.add_argument(
        "--regions",
        metavar="REGION,...",
        help="Comma-separated regions to include (default: all)",
    )
    p.add_argument(
        "--cloud",
        metavar="NAME",
        help="Target Azure cloud: AzureCloud (public) or AzureUSGovernment.  "
        "Default: auto-detect from the active Azure CLI cloud "
        "(az cloud show), or set AZURE_CLOUD.  Use this for Government / "
        "sovereign-cloud tenants.",
    )
    p.add_argument(
        "--workers",
        type=_positive_int,
        metavar="N",
        help=f"Subscriptions to scan in parallel (default: {DEFAULT_WORKERS}; 1 = serial).  "
        "Throttling is per-subscription, so modest parallelism is safe.",
    )
    p.add_argument(
        "--output",
        metavar="DIR",
        help="Output directory for JSON report (default: ~/clouddrive or ./output)",
    )
    p.add_argument(
        "--mock",
        action="store_true",
        help="Development checkouts only: run against the built-in test fixtures, no Azure "
        "credentials required (not available in the public distribution)",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        dest="dry_run",
        help="Preview what the tool would collect without calling any "
        "collector APIs.  Lists in-scope subscriptions + the exact "
        "Azure APIs that would be called, then exits.  Safe to show "
        "a security team before approving a real run.",
    )
    p.add_argument(
        "--manifest",
        "--audit",
        action="store_true",
        dest="manifest",
        help="Print the audit manifest (source of docs/audit.md shipped inside "
        "the installed wheel) and exit.  No Azure calls are made.  Use "
        "this to confirm the version on disk matches the doc.",
    )
    p.add_argument(
        "--verbose",
        action="store_true",
        help="Show SE-focused terminal output (environment summary, "
        "protection gap) + debug logging "
        "from collectors.  Customer runs should omit this.",
    )
    p.add_argument(
        "--devops-orgs",
        metavar="ORG,...",
        help="Comma-separated Azure DevOps org names to scan.  "
        "Default: auto-discover all orgs the identity belongs to.",
    )
    p.add_argument(
        "--no-devops",
        action="store_true",
        help="Skip Azure DevOps repository discovery.",
    )
    # Optional scans — skip flags for scripted/non-interactive runs. In an
    # interactive terminal the tool also asks yes/no for each of these before
    # collecting; the flag hard-skips (no prompt).
    p.add_argument(
        "--no-cost",
        action="store_true",
        help="Skip Cost Management collection (6-month spend).",
    )
    p.add_argument(
        "--no-capacity",
        action="store_true",
        help="Skip the storage Azure Monitor metrics pass (used-capacity AND "
        "blob/file object counts).  Storage accounts are still inventoried; "
        "only the metrics pass is skipped.",
    )
    p.add_argument(
        "--no-security",
        action="store_true",
        help="Skip security-posture collection (Microsoft Defender).",
    )
    p.add_argument(
        "--no-backup-jobs",
        action="store_true",
        help="Skip backup job-history collection (last 60 days).",
    )
    # Opt-in collections, off unless asked for, as in PowerShell: both read inside every vault or
    # container, which needs a data-plane role and can take a long time.
    p.add_argument(
        "--get-container-details",
        action="store_true",
        help="List every blob of every container and write azure_storage_account_container_info "
        "with sizes and counts per access tier. Needs Storage Blob Data Reader. Can take a long "
        "time on large accounts. Same as PowerShell -GetContainerDetails.",
    )
    p.add_argument(
        "--get-key-vault-amounts",
        action="store_true",
        help="Count the certificates, secrets and keys in each Key Vault and write "
        "azure_key_vault. Needs read access to each vault's contents (for example Key Vault "
        "Reader). Same as PowerShell -GetKeyVaultAmounts.",
    )
    for key, (flags, powershell, text) in SKIP_SWITCHES.items():
        p.add_argument(
            *flags,
            action="store_true",
            dest=f"skip_{key}",
            help=f"{text} Same as PowerShell {powershell}. No prompt; the collector does not run "
            "and its CSV file is not written.",
        )
    p.add_argument(
        "--anonymize",
        action="store_true",
        help="Anonymize names, ids and tags in the CSV files (PowerShell's -Anonymize). The ZIP "
        "then has no raw JSON; the file that maps the labels back to the real values and the "
        "real run log are written next to the ZIP, not into it.",
    )
    p.add_argument(
        "--anonymize-fields",
        default="",
        metavar="FIELDS",
        help="Comma-separated extra fields to anonymize (with --anonymize). "
        "Same as PowerShell -AnonymizeFields.",
    )
    p.add_argument(
        "--not-anonymize-fields",
        default="",
        metavar="FIELDS",
        help="Comma-separated fields to leave as they are (with --anonymize); 'Tags' leaves all "
        "tag columns alone. Same as PowerShell -NotAnonymizeFields.",
    )
    p.add_argument(
        "--no-csv",
        action="store_true",
        help="Write only the JSON. By default the ZIP also holds the PowerShell-style CSV "
        "files that Get-AzureSizingInfo.ps1 writes.",
    )
    p.add_argument(
        "--no-preflight",
        action="store_true",
        help="Skip the pre-flight access check that runs before the scan. The check makes one "
        "read-only call per service in each subscription and writes "
        "azure_preflight_check-<timestamp>.csv, which lists what will be captured and what "
        "will be dropped.",
    )
    p.add_argument(
        "--preflight-only",
        action="store_true",
        help="Only run the access check: resolve the subscriptions, check what the sign-in can "
        "read in each, write azure_preflight_check-<timestamp>.csv into "
        "azure_access_check_<timestamp>.zip and stop. Nothing is collected. A subscription "
        "named with --subs that cannot be read gets a row of its own.",
    )
    p.add_argument(
        "--keep-artifacts",
        action="store_true",
        help="Leave the loose JSON / log files on disk alongside the ZIP.  "
        "Default: only the single ZIP is kept (the loose files are bundled "
        "inside it).",
    )
    resume_group = p.add_mutually_exclusive_group()
    resume_group.add_argument(
        "--resume",
        action="store_true",
        help="Carry on with the unfinished run in the output folder: subscriptions it finished are "
        "not scanned again. Needs the same options as that run. Without --resume or --fresh, a "
        "terminal is asked what to do; a run with no terminal stops until one is given.",
    )
    resume_group.add_argument(
        "--fresh",
        action="store_true",
        help="Delete the unfinished run in the output folder and scan everything again.",
    )
    p.add_argument(
        "--keep-partial",
        action="store_true",
        help="With --resume, keep the subscriptions the earlier run finished with errors, "
        "instead of scanning them again (the default). The zip then holds them with their gaps.",
    )
    return p


def _tag_names_from_results(comp_results: list, stor_results: list) -> dict[str, list[str]]:
    """Tag names seen on the collected resources, per subscription (mock runs have no tag API)."""
    names: dict[str, set[str]] = {}
    for comp in comp_results:
        for vm in comp.vms:
            names.setdefault(comp.subscription_id, set()).update(vm.tags)
    for stor in stor_results:
        for account in stor.accounts:
            names.setdefault(stor.subscription_id, set()).update(account.tags)
    return {sub: sorted(found) for sub, found in names.items()}


def _resolve_output_dir(override: Optional[str]) -> pathlib.Path:
    """Return the output directory, creating it if necessary.

    Priority: explicit --output flag > ~/clouddrive (Azure Cloud Shell) > output/.
    """
    if override:
        path = pathlib.Path(override).expanduser()
    elif pathlib.Path("~/clouddrive").expanduser().is_dir():
        path = pathlib.Path("~/clouddrive").expanduser()
    else:
        path = pathlib.Path("./output")

    path.mkdir(parents=True, exist_ok=True)
    return path


def _mock_fixtures_available() -> bool:
    """True only in a development checkout: the fixtures live in tests/, which is not shipped."""
    try:
        return importlib.util.find_spec("tests.fixtures") is not None
    except ImportError:  # the parent package "tests" is absent from the public distribution
        return False


def _run_mock(
    skips: frozenset[str] = frozenset(),
) -> tuple[list, list, list, list, list, list, str]:
    """Patch Azure SDK clients with fixture data and run real collectors."""
    from unittest.mock import MagicMock, patch

    from collectors.backup_jobs import BackupJobsCollector, BackupJobsInventory
    from collectors.backup_posture import BackupPostureCollector, BackupPostureInventory
    from collectors.compute import ComputeCollector, ComputeInventory
    from collectors.cost import CostCollector
    from collectors.database import DatabaseCollector
    from collectors.storage import StorageCollector, StorageInventory
    from tests.fixtures import (
        MOCK_DISKS,
        MOCK_MYSQL_SERVERS,
        MOCK_PG_SERVERS,
        MOCK_POLICIES,
        MOCK_PROTECTED_ITEMS,
        MOCK_SQL_MANAGED_INSTANCES,
        MOCK_SQL_SERVERS,
        MOCK_STORAGE_ACCOUNTS,
        MOCK_STORAGE_CONFIGS,
        MOCK_VAULTS,
        MOCK_VMS,
        SUB_ID,
        mock_backup_jobs_effect,
        mock_blob_inventory_effect,
        mock_blob_props_effect,
        mock_cost_query_effect,
        mock_monitor_metrics_effect,
        mock_mysql_dbs_effect,
        mock_pg_dbs_effect,
        mock_sql_dbs_effect,
        mock_sql_ltr_effect,
        mock_sql_short_term_retention_effect,
    )

    mock_compute = MagicMock()
    mock_compute.virtual_machines.list_all.return_value = iter(MOCK_VMS)
    mock_compute.disks.list.return_value = iter(MOCK_DISKS)
    mock_compute.snapshots.list.return_value = iter([])

    # ResourceManagementClient is used by ComputeCollector for SQL-on-VM detection
    # (and elsewhere). No SQL VMs in the mock dataset → empty resource list.
    mock_rm_compute = MagicMock()
    mock_rm_compute.resources.list.return_value = iter([])

    mock_rs = MagicMock()
    mock_rs.vaults.list_by_subscription_id.return_value = iter(MOCK_VAULTS)

    mock_backup = MagicMock()
    mock_backup.backup_resource_storage_configs_non_crr.get.side_effect = lambda name, rg: (
        MOCK_STORAGE_CONFIGS.get(name, MagicMock(properties=MagicMock(storage_type="Unknown")))
    )
    mock_backup.backup_policies.list.side_effect = lambda name, rg: iter(
        MOCK_POLICIES.get(name, [])
    )
    mock_backup.backup_protected_items.list.side_effect = lambda name, rg: iter(
        MOCK_PROTECTED_ITEMS.get(name, [])
    )

    mock_stor_client = MagicMock()
    mock_stor_client.storage_accounts.list.return_value = iter(MOCK_STORAGE_ACCOUNTS)
    mock_stor_client.blob_services.get_service_properties.side_effect = mock_blob_props_effect
    mock_stor_client.blob_inventory_policies.get.side_effect = mock_blob_inventory_effect

    mock_monitor_client = MagicMock()
    mock_monitor_client.metrics.list.side_effect = mock_monitor_metrics_effect

    mock_sql_client = MagicMock()
    mock_sql_client.servers.list.return_value = iter(MOCK_SQL_SERVERS)
    mock_sql_client.databases.list_by_server.side_effect = mock_sql_dbs_effect
    mock_sql_client.backup_short_term_retention_policies.get.side_effect = (
        mock_sql_short_term_retention_effect
    )
    mock_sql_client.long_term_retention_policies.get.side_effect = mock_sql_ltr_effect
    mock_sql_client.managed_instances.list.return_value = iter(MOCK_SQL_MANAGED_INSTANCES)

    mock_pg_client = MagicMock()
    mock_pg_client.servers.list.return_value = iter(MOCK_PG_SERVERS)
    mock_pg_client.databases.list_by_server.side_effect = mock_pg_dbs_effect

    mock_mysql_client = MagicMock()
    mock_mysql_client.servers.list.return_value = iter(MOCK_MYSQL_SERVERS)
    mock_mysql_client.databases.list_by_server.side_effect = mock_mysql_dbs_effect

    # BackupJobsCollector uses both the RS client (to list vaults) and the
    # backup client (to list jobs).  Reuse the same mocks via a second pair
    # of patches so the vault list is visible to the jobs collector too.
    mock_rs_for_jobs = MagicMock()
    mock_rs_for_jobs.vaults.list_by_subscription_id.return_value = iter(MOCK_VAULTS)

    mock_backup_for_jobs = MagicMock()
    mock_backup_for_jobs.backup_jobs.list.side_effect = mock_backup_jobs_effect

    mock_cost_client = MagicMock()
    mock_cost_client.query.usage.side_effect = mock_cost_query_effect

    fake_cred = MagicMock()

    with (
        patch("collectors.compute.ComputeManagementClient", return_value=mock_compute),
        patch("collectors.compute.ResourceManagementClient", return_value=mock_rm_compute),
        patch("collectors.backup_posture.RecoveryServicesClient", return_value=mock_rs),
        patch("collectors.backup_posture.RecoveryServicesBackupClient", return_value=mock_backup),
        patch("collectors.storage.StorageManagementClient", return_value=mock_stor_client),
        patch("collectors.storage.MonitorManagementClient", return_value=mock_monitor_client),
        patch("collectors.database.SqlManagementClient", return_value=mock_sql_client),
        patch("collectors.database.PostgreSQLFlexClient", return_value=mock_pg_client),
        patch("collectors.database.MySQLFlexClient", return_value=mock_mysql_client),
        patch("collectors.database.MonitorManagementClient", return_value=mock_monitor_client),
        patch("collectors.backup_jobs.RecoveryServicesClient", return_value=mock_rs_for_jobs),
        patch(
            "collectors.backup_jobs.RecoveryServicesBackupClient", return_value=mock_backup_for_jobs
        ),
        patch("collectors.cost.CostManagementClient", return_value=mock_cost_client),
    ):
        comp = (
            ComputeInventory(subscription_id=SUB_ID)
            if "vms" in skips
            else ComputeCollector(SUB_ID, fake_cred).collect()
        )
        bp = (
            BackupPostureInventory(subscription_id=SUB_ID)
            if "backup" in skips
            else BackupPostureCollector(
                SUB_ID,
                fake_cred,
                vm_resource_ids=[v.resource_id for v in comp.vms],
                vm_snapshot_ids=[v.resource_id for v in comp.vms if v.has_adhoc_snapshot],
            ).collect()
        )
        stor = (
            StorageInventory(subscription_id=SUB_ID)
            if "storage" in skips
            else StorageCollector(
                SUB_ID, fake_cred, collect_file_shares="files" not in skips
            ).collect()
        )
        db = DatabaseCollector(
            SUB_ID,
            fake_cred,
            collect_sql_mi="sql_mi" not in skips,
            collect_postgres="postgres" not in skips,
        ).collect()
        jobs = (
            BackupJobsInventory(subscription_id=SUB_ID)
            if "backup" in skips
            else BackupJobsCollector(SUB_ID, fake_cred).collect()
        )
        cost = CostCollector(SUB_ID, fake_cred).collect()

    return [comp], [bp], [stor], [db], [jobs], [cost], SUB_ID


# ── Optional-scan opt-in ────────────────────────────────────────────────────
# Each optional scan can be hard-skipped with a --no-<scan> flag. In an
# interactive terminal (a TTY — which the `bash <(curl …)` Cloud Shell form
# preserves) the tool also asks yes/no per scan before collecting. Non-interactive
# runs (piped / CI) default to scanning unless the flag says otherwise.
_OPTIONAL_SCANS: tuple[tuple[str, str, str], ...] = (
    ("cost", "no_cost", "Scan cost data (include current backup spend)?"),
    ("capacity", "no_capacity", "Scan storage used-capacity + object counts (Azure Monitor)?"),
    ("security", "no_security", "Scan security posture (Microsoft Defender)?"),
    ("backup_jobs", "no_backup_jobs", "Scan backup job history (last 60 days)?"),
)


def _ask_yes_no(question: str, *, default: bool = True) -> bool:
    """Prompt with a yes/no question; return ``default`` on empty input or EOF."""
    suffix = "[Y/n]" if default else "[y/N]"
    try:
        answer = input(f"  {question} {suffix} ").strip().lower()
    except EOFError:
        runlog.answered(question, suffix, "(no input)")
        return default
    runlog.answered(question, suffix, answer)
    return default if not answer else answer in ("y", "yes")


def _unavailable_scans() -> dict[str, str]:
    """Optional scans that cannot run here, and why (scan key -> reason).

    Defender needs ``azure-mgmt-security``. If it is missing from the environment, asking whether to
    run a scan that cannot run would only mislead, so it is not offered.
    """
    try:
        from collectors.defender import HAS_SDK
    except Exception:  # noqa: BLE001 - if this check fails, leave the scan as it was
        return {}
    if HAS_SDK:
        return {}
    return {"security": "Microsoft Defender needs azure-mgmt-security, which is not installed."}


# How to install what an unavailable scan needs, printed on a line of its own so a narrow terminal
# cannot split the command.
_INSTALL_HINTS = {"security": "pip install -r requirements.txt"}


def _resolve_scans(args) -> dict[str, bool]:
    """Decide which optional scans run: flag hard-skips, a scan that cannot run is off, else prompt
    on a TTY, else on."""
    interactive = sys.stdin.isatty() and not args.mock and not args.dry_run
    unavailable = _unavailable_scans()
    choices: dict[str, bool] = {}
    for key, flag_attr, question in _OPTIONAL_SCANS:
        if getattr(args, flag_attr, False):
            choices[key] = False
        elif key in unavailable:
            choices[key] = False
            console.print(
                f"  [dim]Skipping the {key.replace('_', ' ')} scan: {unavailable[key]}[/dim]"
            )
            if key in _INSTALL_HINTS:
                console.print(f"  [dim]To enable it: {_INSTALL_HINTS[key]}[/dim]")
        elif interactive:
            choices[key] = _ask_yes_no(question)
        else:
            choices[key] = True
    logger.info(
        "Optional scans — %s",
        ", ".join(f"{k}={'on' if v else 'off'}" for k, v in choices.items()),
    )
    skipped = [k for k, v in choices.items() if not v]
    if skipped:
        console.print(f"  [dim]Skipping optional scan(s): {', '.join(skipped)}[/dim]")
    return choices


def _preflight_monitor_access(
    subscriptions: list[str], credential, regions: Optional[list[str]], cloud
) -> None:
    """Pre-flight Monitor metrics access before the full scan.

    Storage capacity + object counts come exclusively from the Azure Monitor
    metrics API. If the discovery identity lacks Monitor read, those numbers come
    back blank and look identical to an empty environment. Probe one in-scope
    subscription up front so the operator can fix RBAC and re-run rather than
    discovering blank capacity only at report time. Best-effort — never blocks the
    scan; an inconclusive probe stays silent.
    """
    from collectors.storage import StorageCollector

    for sub_id in subscriptions:
        try:
            status = StorageCollector(
                sub_id, credential, regions, cloud=cloud, collect_capacity=True
            ).probe_monitor_access()
        except Exception as exc:  # noqa: BLE001 — pre-flight is strictly best-effort
            logger.debug("[%s] Monitor pre-flight skipped: %s", sub_id, exc)
            continue
        # Probe the first subscription that actually has accounts to test against.
        if status == "no_accounts":
            continue
        if status == "denied":
            console.print(
                "  [yellow]⚠[/yellow] Azure Monitor metrics read appears [bold]denied[/bold] — "
                "storage capacity and object counts will be [bold]blank[/bold].\n"
                "    Grant [cyan]Monitoring Reader[/cyan] (or [cyan]Reader[/cyan]) at "
                "subscription scope and re-run, or pass [cyan]--no-capacity[/cyan] to skip.\n"
            )
            logger.warning(
                "Monitor pre-flight: metrics read denied on %s — capacity will be blank.",
                sub_id,
            )
        return  # one conclusive probe (ok/denied/error) is representative


# A scan of this many subscriptions or fewer prints the full permissions table for each; a larger
# one prints the table only for a subscription with something blocked.
_TABLE_SUBSCRIPTIONS = 3


def _run_access_check(
    subscriptions: list[str],
    subscription_names: dict[str, str],
    credential,
    regions: Optional[list[str]],
    cloud,
    scans: dict[str, bool],
    skips: frozenset[str],
    workers: int,
) -> list[dict]:
    """Check what the sign-in can read in each subscription, print the result, return its rows."""
    with console.status("[bold]Checking access…[/bold]"):
        per_subscription = preflight.run_all(
            subscriptions, subscription_names, credential, cloud, regions, scans, skips, workers
        )
    rows: list[dict] = []
    for sub_id, checks in zip(subscriptions, per_subscription):
        if not checks:
            continue
        label = subscription_names.get(sub_id) or sub_id
        headline = preflight.report_lines(checks, label)[0]
        blocked = preflight_core.blocked_groups(checks)
        console.print(f"  [dim]{escape(headline)}[/dim]")
        if len(subscriptions) <= _TABLE_SUBSCRIPTIONS or blocked:
            for line in preflight.table_lines(checks):
                console.print(escape(line))
        if blocked:
            console.print("  [yellow]⚠[/yellow] Problems found by the pre-flight check:")
            for line in runlog.problem_block(blocked):
                console.print(escape(line))
        rows.extend(check.to_row() for check in checks)
    console.print()
    return rows


def _manifest_text(files: dict) -> Optional[str]:
    """The manifest.json of a results zip, or None when it could not be built.

    ``files`` maps each file name in the zip to its bytes. Never raises: a problem with the
    manifest must not cost the zip, so it is only logged.
    """
    try:
        return manifest_core.build(
            files,
            tool="azure",
            tool_version=manifest_core.installed_version("rubrik-discovery-azure"),
            code_version=runlog.core.code_version(runlog.HERE),
            generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not build %s: %s", manifest_core.FILE_NAME, exc)
        return None


def _write_access_report(
    output_dir: pathlib.Path, stamp: str, rows: list[dict], anonymizer: Optional[Anonymizer]
) -> str:
    """Write the pre-flight report beside the other CSV files and return its path."""
    path = output_dir / preflight_core.file_name(preflight.FILE_PREFIX, stamp)
    path.write_text(preflight.csv_for(rows, anonymizer), encoding="utf-8", newline="")
    return str(path)


# The end of a run names this many subscriptions that were not scanned; the CSV has all of them.
_NOT_SCANNED_SHOWN = 20


def _print_not_scanned(not_scanned: list[dict], heading: str) -> None:
    """Each subscription that is not in the results and why, on the screen and in the log."""
    if not not_scanned:
        return
    console.print()
    console.print(f"[yellow]{escape(heading)}[/yellow]")
    ordered = sorted(not_scanned, key=lambda e: (e["why"], e["id"]))
    for entry in ordered[:_NOT_SCANNED_SHOWN]:
        who = entry["id"] + (f" ({entry['name']})" if entry["name"] else "")
        console.print(f"   {escape(who)}  {escape(entry['why'])}")
    if len(not_scanned) > _NOT_SCANNED_SHOWN:
        console.print(
            f"   ... and {len(not_scanned) - _NOT_SCANNED_SHOWN} more; every one is in "
            f"{preflight.FILE_PREFIX}-<timestamp>.csv"
        )


def _finish_access_check(
    args,
    output_dir: pathlib.Path,
    started: datetime,
    access_rows: list[dict],
    not_scanned: list[dict],
    checked: int,
    log_handler: logging.Handler,
    log_path: pathlib.Path,
) -> pathlib.Path:
    """End a --preflight-only run: the pre-flight CSV and the run log in
    ``azure_access_check_<stamp>.zip``. Nothing was collected."""
    import zipfile

    import csv_export

    anonymizer = (
        Anonymizer.from_options(args.anonymize_fields, args.not_anonymize_fields)
        if args.anonymize
        else None
    )
    _print_not_scanned(not_scanned, "Not checked:")
    console.print(
        f"\n[bold]Access check complete:[/bold] {checked} subscription(s) checked, "
        f"{len(not_scanned)} could not be read. Nothing was collected."
    )
    logger.info("Access check complete — bundling the report.")
    runlog.finish(console)
    logging.getLogger().removeHandler(log_handler)
    log_handler.close()

    file_stamp = started.strftime(csv_export.FILE_TIMESTAMP_FORMAT)
    run_stamp = f"{started:%Y-%m-%d_%H%M%S}"
    rows = [*access_rows, *(row for entry in not_scanned for row in entry["rows"])]
    in_zip: dict[str, bytes] = {}
    if rows:
        name = preflight_core.file_name(preflight.FILE_PREFIX, file_stamp)
        in_zip[name] = preflight.csv_for(rows, anonymizer).encode("utf-8")
    manifest_text = _manifest_text(dict(in_zip))
    zip_path = output_dir / f"azure_access_check_{started:%Y-%m-%d_%H%M}.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in in_zip.items():
            zf.writestr(name, data)
        if manifest_text is not None:
            zf.writestr(manifest_core.FILE_NAME, manifest_text)
        if anonymizer is not None:
            zf.writestr(f"output_azure_{run_stamp}.log", anonymized_log_note())
        elif log_path.exists():
            zf.write(log_path, log_path.name)

    console.print()
    console.print(Rule())
    if anonymizer is not None:
        key_path = output_dir / f"{KEY_FILE_PREFIX}-{run_stamp}.csv"
        key_path.write_text(anonymizer.key_file_text(), encoding="utf-8", newline="")
        kept_log_path = output_dir / f"output_azure_not_anonymized_{run_stamp}.log"
        if log_path.exists():
            log_path.replace(kept_log_path)
        console.print(
            f"[green]✓[/green] Keys → [bold]{key_path}[/bold] [dim](not in the ZIP)[/dim]"
        )
        console.print(
            f"[green]✓[/green] Log  → [bold]{kept_log_path}[/bold] [dim](not in the ZIP)[/dim]"
        )
    else:
        try:
            log_path.unlink()
        except OSError as exc:
            logger.debug("Could not remove %s after zipping: %s", log_path, exc)
    console.print(f"[green]✓[/green] Access report → [bold]{zip_path}[/bold]")
    console.print()
    return zip_path


class _BufferedOutput:
    """Console stand-in that records print calls so a worker thread never touches the
    shared Rich console; the main thread replays them as one atomic block."""

    def __init__(self) -> None:
        self._calls: list[tuple[tuple, dict]] = []

    def print(self, *args, **kwargs) -> None:
        self._calls.append((args, kwargs))

    def replay(self, target) -> None:
        for args, kwargs in self._calls:
            target.print(*args, **kwargs)


def _step_text(msg: str, sub_id: str) -> str:
    """The spinner of one step, with its count once it has one: ``Collecting storage… 3/9``."""
    counted = progress.counter(sub_id)
    return msg.replace("…", f"… {counted}") if counted else msg


def _parallel_status(finished: int, total: int) -> str:
    """The spinner of a parallel scan. Each subscription's lines are printed when it finishes;
    until then this says which step each running one is in, and how far."""
    steps = [f"{sub[:8]}…: {progress.describe(sub)}" for sub in progress.running()]
    where = f" · {' · '.join(steps)}" if steps else ""
    return f"[dim]Scanning subscriptions… {finished}/{total} complete{escape(where)}[/dim]"


def _collect_subscription(
    sub_id: str,
    credential,
    regions: Optional[list[str]],
    cloud=DEFAULT_CLOUD,
    scans: Optional[dict[str, bool]] = None,
    out=None,
    skips: frozenset[str] = frozenset(),
) -> tuple:
    """Run all available collectors for one subscription.

    ``out`` defaults to the live console (with per-collector spinners).  Pass a
    _BufferedOutput when running concurrently: spinners are skipped because Rich
    allows only one live display at a time.

    Returns:
        (ComputeInventory, BackupPostureInventory, StorageInventory,
         DatabaseInventory, BackupJobsInventory, CostSummary)
    """
    from collectors.backup_jobs import BackupJobsCollector, BackupJobsInventory
    from collectors.backup_posture import BackupPostureCollector, BackupPostureInventory
    from collectors.compute import ComputeCollector, ComputeInventory
    from collectors.cost import CostCollector, CostSummary
    from collectors.database import DatabaseCollector
    from collectors.storage import StorageCollector, StorageInventory

    scans = scans or {}
    live = out is None
    out = console if live else out

    def _spin(msg: str):
        name = msg.split("Collecting ", 1)[-1].split("…", 1)[0]
        progress.step(sub_id, name)
        if not live:
            return contextlib.nullcontext()

        return console.status(progress.Live(lambda: _step_text(msg, sub_id)))

    if "vms" in skips:
        comp = ComputeInventory(subscription_id=sub_id)
        out.print("  [dim]– Compute        skipped[/dim]")
    else:
        with _spin("  [dim]Collecting compute…[/dim]"):
            comp = ComputeCollector(sub_id, credential, regions, cloud=cloud).collect()
        sql_vm_note = (
            f" · [cyan]{comp.total_sql_vms}[/cyan] running SQL" if comp.total_sql_vms else ""
        )
        out.print(
            f"  [green]✓[/green] Compute       "
            f"[cyan]{comp.total_vms}[/cyan] VMs · "
            f"[cyan]{comp.total_disk_tb}[/cyan] TB"
            f"{sql_vm_note}"
        )

    if "backup" in skips:
        bp = BackupPostureInventory(subscription_id=sub_id)
        out.print("  [dim]– Backup Posture skipped[/dim]")
    else:
        with _spin("  [dim]Collecting backup posture…[/dim]"):
            bp = BackupPostureCollector(
                sub_id,
                credential,
                regions,
                vm_resource_ids=[v.resource_id for v in comp.vms],
                vm_snapshot_ids=[v.resource_id for v in comp.vms if v.has_adhoc_snapshot],
                cloud=cloud,
            ).collect()

        out.print(
            f"  [green]✓[/green] Backup Posture "
            f"[cyan]{bp.vault_count}[/cyan] vaults · "
            f"[red]{bp.unprotected_vm_count}[/red] unprotected VMs"
        )

    if "backup" not in skips and scans.get("backup_jobs", True):
        with _spin("  [dim]Collecting backup job history…[/dim]"):
            jobs = BackupJobsCollector(sub_id, credential, cloud=cloud).collect()

        job_color = (
            "green"
            if jobs.total_jobs > 0 and jobs.failed_jobs == 0
            else ("yellow" if jobs.total_jobs > 0 else "dim")
        )
        out.print(
            f"  [green]✓[/green] Job History    "
            f"[cyan]{jobs.total_jobs}[/cyan] jobs · "
            f"[green]{jobs.successful_jobs}[/green] successful · "
            f"[{job_color}]{jobs.failed_jobs}[/{job_color}] failed"
        )
    else:
        jobs = BackupJobsInventory(subscription_id=sub_id)
        out.print("  [dim]– Job History    skipped[/dim]")

    if "storage" in skips:
        stor = StorageInventory(subscription_id=sub_id)
        out.print("  [dim]– Storage        skipped[/dim]")
    else:
        with _spin("  [dim]Collecting storage…[/dim]"):
            stor = StorageCollector(
                sub_id,
                credential,
                regions,
                cloud=cloud,
                collect_capacity=scans.get("capacity", True),
                collect_file_shares="files" not in skips,
            ).collect()

        cap_str = (
            f"{stor.total_capacity_gb:.1f} GB" if stor.total_capacity_gb is not None else "n/a"
        )
        out.print(
            f"  [green]✓[/green] Storage        "
            f"[cyan]{stor.total_accounts}[/cyan] accounts · "
            f"[cyan]{cap_str}[/cyan]"
        )

    with _spin("  [dim]Collecting databases…[/dim]"):
        db = DatabaseCollector(
            sub_id,
            credential,
            regions,
            cloud=cloud,
            collect_sql_mi="sql_mi" not in skips,
            collect_postgres="postgres" not in skips,
        ).collect()

    out.print(
        f"  [green]✓[/green] Database       "
        f"[cyan]{db.total_sql_databases}[/cyan] SQL dbs · "
        f"[cyan]{db.total_flexible_servers}[/cyan] flexible servers"
        + (" [dim](SQL and MI skipped)[/dim]" if "sql_mi" in skips else "")
        + (" [dim](PostgreSQL skipped)[/dim]" if "postgres" in skips else "")
    )

    if scans.get("cost", True):
        with _spin("  [dim]Collecting cost data…[/dim]"):
            cost_collector = CostCollector(sub_id, credential, cloud=cloud, backup_only=True)
            cost = cost_collector.collect()
            if "backup" not in skips:
                cost.backup_cost_months = cost_collector.collect_backup_months()

        if cost.total_6mo_spend > 0:
            out.print(
                f"  [green]✓[/green] Cost           "
                f"[cyan]${cost.total_6mo_spend:,.0f}[/cyan] 6mo · "
                f"[cyan]{len(cost.months_collected)}[/cyan] months · "
                f"top: {cost.top_services[0]['service'] if cost.top_services else 'n/a'}"
            )
        elif bp.vault_count == 0:
            # The scan covers backup-attributable services only (Recovery Services, Azure Backup,
            # Site Recovery). With no backup vault there is nothing for it to find, so an empty
            # result is the expected answer, not a missing Cost Management role.
            logger.info("[%s] No cost data: the subscription has no backup vaults", sub_id)
            out.print(
                "  [dim]– Cost           no backup vaults, so no backup cost to report[/dim]"
            )
        else:
            # Opted into cost, has backup vaults, and got nothing back — surface it (likely
            # missing Cost Management reader, or a brand-new subscription).
            logger.warning("[%s] Cost data requested but none returned", sub_id)
            out.print(
                f"  [yellow]⚠[/yellow] Cost           [dim]{cost.data_note or 'no data'}[/dim]"
            )
    else:
        cost = CostSummary(subscription_id=sub_id)
        out.print("  [dim]– Cost           skipped[/dim]")

    return comp, bp, stor, db, jobs, cost


def _scan_subscriptions(
    subscriptions: list[str],
    collect: Callable[[int, str], tuple],
    workers: int,
    on_done: Optional[Callable[[int, str, Optional[tuple], Optional[BaseException]], None]] = None,
    on_scanned: Optional[Callable[[str, tuple], None]] = None,
) -> tuple[list[Optional[tuple]], dict[int, BaseException]]:
    """Run ``collect(index, sub_id)`` for every subscription, up to ``workers`` at a time.

    ``on_scanned(sub_id, result)``, when given, runs in the calling thread for each subscription
    whose scan succeeded, before ``on_done``: this is where a finished scan is saved.

    Returns ``(results, errors)``: ``results`` is indexed like ``subscriptions`` regardless
    of completion order (a failed slot is None); ``errors`` maps index -> exception.  One
    subscription raising never aborts the rest.  ``on_done`` runs in the calling thread
    as each subscription finishes, so it may safely drive the console.
    """
    results: list[Optional[tuple]] = [None] * len(subscriptions)
    errors: dict[int, BaseException] = {}

    def _finish(i: int, result: Optional[tuple], exc: Optional[BaseException]) -> None:
        progress.finish(subscriptions[i])
        if exc is not None:
            errors[i] = exc
            logger.error("[%s] subscription scan failed: %s", subscriptions[i], exc, exc_info=exc)
        else:
            results[i] = result
            if on_scanned is not None:
                # Saved the moment the scan returns: this is the expensive, parallel part.
                try:
                    on_scanned(subscriptions[i], result)
                except OSError as e:  # a full disk must not end a scan that is otherwise working
                    logger.warning("Could not save the checkpoint of %s: %s", subscriptions[i], e)
        if on_done is not None:
            on_done(i, subscriptions[i], result, exc)

    if workers <= 1 or len(subscriptions) <= 1:
        for i, sub_id in enumerate(subscriptions):
            try:
                result, exc = collect(i, sub_id), None
            except Exception as e:  # noqa: BLE001 — isolated per subscription, logged in _finish
                result, exc = None, e
            _finish(i, result, exc)
        return results, errors

    pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="sub-scan")
    try:
        futures = {pool.submit(collect, i, sub_id): i for i, sub_id in enumerate(subscriptions)}
        for fut in as_completed(futures):
            i = futures[fut]
            try:
                result, exc = fut.result(), None
            except Exception as e:  # noqa: BLE001 — isolated per subscription, logged in _finish
                result, exc = None, e
            _finish(i, result, exc)
    except BaseException:
        pool.shutdown(wait=False, cancel_futures=True)
        raise
    pool.shutdown(wait=True)
    return results, errors


def _backup_vault_scan(skips: frozenset[str]) -> tuple[bool, Optional[str]]:
    """Whether to collect Backup Vaults (Blob and PostgreSQL backup), and what to tell the user.

    They are part of backup, so ``--skip-backup`` skips them. They need the optional
    ``azure-mgmt-dataprotection`` package; without it the run goes on and says what is missing, as the
    PowerShell script does for a missing ``Az.DataProtection``.
    """
    from collectors import data_protection

    if "backup" in skips:
        return False, None
    if data_protection.HAS_SDK:
        return True, None
    return False, (
        "[yellow]⚠[/yellow]  Azure Backup for Blobs and PostgreSQL (Backup Vaults) will not be "
        "reported: azure-mgmt-dataprotection is not installed.\n"
        "    To include it, run: pip install -r requirements.txt\n"
    )


def _collect_containers(sub_id: str, credential, cloud, accounts: list, out=None):
    """Sum the blobs of every container of one subscription's storage accounts, and say so."""
    from collectors.containers import ContainerCollector

    out = out or console
    with out.status("  [dim]Listing blob containers…[/dim]"):
        inventory = ContainerCollector(sub_id, credential, accounts, cloud=cloud).collect()
    note = (
        f" · [yellow]{len(inventory.account_errors)} account(s) could not be listed[/yellow]"
        if inventory.account_errors
        else ""
    )
    out.print(
        f"  [green]✓[/green] Containers     [cyan]{inventory.total_containers}[/cyan] "
        f"containers{note}"
    )
    return inventory


def _collect_key_vaults(sub_id: str, credential, regions, cloud, out=None):
    """Count what each Key Vault of one subscription holds, and say so."""
    from collectors.key_vault import KeyVaultCollector

    out = out or console
    with out.status("  [dim]Counting Key Vault contents…[/dim]"):
        inventory = KeyVaultCollector(sub_id, credential, regions, cloud=cloud).collect()
    blank = sum(1 for vault in inventory.vaults if vault.errors)
    note = f" · [yellow]{blank} with counts left blank[/yellow]" if blank else ""
    out.print(
        f"  [green]✓[/green] Key Vaults     [cyan]{inventory.total_vaults}[/cyan] vaults{note}"
    )
    return inventory


def _collect_backup_vaults(sub_id: str, credential, cloud, out=None):
    """Collect one subscription's Backup Vaults and say what was found."""
    from collectors import data_protection

    out = out or console
    with out.status("  [dim]Collecting Backup Vaults…[/dim]"):
        inventory = data_protection.DataProtectionCollector(
            sub_id, credential, cloud=cloud
        ).collect()
    if inventory.error:
        out.print(
            f"  [yellow]⚠[/yellow] Backup Vaults  [dim]could not be listed: {inventory.error}[/dim]"
        )
        return inventory
    out.print(
        f"  [green]✓[/green] Backup Vaults  "
        f"[cyan]{inventory.total_vaults}[/cyan] vaults · "
        f"[cyan]{len(inventory.items)}[/cyan] Blob/PostgreSQL backups"
    )
    if inventory.ignored_types:
        ignored = ", ".join(f"{k} x{v}" for k, v in sorted(inventory.ignored_types.items()))
        out.print(f"    [dim]Not reported (other datasource types): {ignored}[/dim]")
    return inventory


def _open_progress(args, output_dir: pathlib.Path, request: dict):
    """Open this run's progress folder, or resume the unfinished one in output_dir.

    Returns the checkpoint store and whether it is a resumed run. A previous run that cannot be
    resumed (different options, or no terminal to ask on) ends the run with what to do, not a
    traceback; nothing is deleted unless --fresh or the person's answer says so.
    """
    try:
        store, resumed = checkpoint_core.prepare(
            str(output_dir),
            prefix=resume.PREFIX,
            tool="azure",
            request=request,
            mode=resume.mode_of(args),
            code_version=runlog.core.code_version(runlog.HERE),
            say=lambda text: console.print(f"[dim]{escape(text)}[/dim]"),
        )
    except checkpoint_core.ResumeRefused as exc:
        console.print(f"[red]Cannot start:[/red] {escape(str(exc))}")
        runlog.core.end_run("not started: an unfinished run is in the way", [str(exc)])
        sys.exit(2)
    runlog.core.set_stop_hint(
        f"Subscriptions that finished are saved in {store.root}; run the same command with "
        "--resume to carry on where this one stopped."
    )
    return store, resumed


def _close_progress(store, keep: bool) -> None:
    """The results are written: remove the progress folder, unless a subscription has no result yet.

    keep is True when a subscription could not be read or its scan failed, so a later --resume can
    scan just those. The folder is then left marked as unfinished.
    """
    if store is None:
        return
    if keep:
        console.print(
            f"[dim]Progress kept in {escape(store.root)}: run again with --resume to scan the "
            "subscriptions that were not finished.[/dim]"
        )
        return
    store.finish()


def _merge_scans(
    subscriptions: list[str],
    todo: list[str],
    fresh: list[Optional[tuple]],
    fresh_errors: dict[int, BaseException],
    store,
) -> tuple[list[Optional[tuple]], dict[int, BaseException]]:
    """The scan of every subscription, in the order of ``subscriptions``: ``(scanned, errors)``.

    ``fresh`` and ``fresh_errors`` are indexed like ``todo`` (what was just scanned); the rest are
    read back from the saved run. The result is indexed like ``subscriptions``, as ``_drop_failed``
    and the code after it expect.
    """
    position = {sub: i for i, sub in enumerate(todo)}
    scanned: list[Optional[tuple]] = []
    errors: dict[int, BaseException] = {}
    for i, sub in enumerate(subscriptions):
        if sub in position:
            j = position[sub]
            scanned.append(fresh[j])
            if j in fresh_errors:
                errors[i] = fresh_errors[j]
        else:
            scanned.append(resume.restore(store.load(sub)[0]))
    return scanned, errors


def _subscription_gaps(store, subscriptions: list[str], names: dict) -> list:
    """``(subscription, why)`` for each subscription with a saved scan that finished with gaps.

    A subscription whose scan failed has no checkpoint and is in the not-scanned list instead.
    ``why`` is the first failure its scan logged and how many more there were, or, when the scan
    logged nothing, that its access check found a service it could not read (see
    ``_is_partial``).
    """
    if store is None:
        return []
    gaps = []
    for sub in subscriptions:
        loaded = store.load(sub)
        if loaded is None or not resume.valid(loaded[0]):
            continue
        data = loaded[0]
        found = resume.gaps_of(data)
        label = f"{sub} ({names[sub]})" if names.get(sub) else sub
        if found["count"]:
            first = found["examples"][0] if found["examples"] else "a failure was logged"
            first = first.split("] ", 1)[-1][:110]  # the subscription is already named
            why = first + (f" (+{found['count'] - 1} more)" if found["count"] > 1 else "")
            gaps.append((label, why))
        elif _is_partial(data.get("access", [])):
            gaps.append((label, "the access check found a service it could not read"))
    return gaps


def _print_gaps(gaps: list, total: int, kept: bool) -> None:
    """End the run by saying which subscriptions finished with gaps, and what to do about them.

    A subscription that finished is complete as far as the scan got, not as far as the subscription
    goes: a listing that failed or a query that was denied leaves something out, and the zip alone
    does not say so.
    """
    lines = checkpoint_core.gaps_summary("subscription", gaps, total, kept=kept)
    if not lines:
        return
    console.print()
    console.print(f"[yellow]{escape(lines[0])}[/yellow]")
    for line in lines[1:]:
        console.print(escape(line))


def _access_by_subscription(rows: list[dict]) -> dict:
    """The access-check rows of each subscription, keyed by subscription id (the row's Owner)."""
    grouped: dict = {}
    for row in rows:
        grouped.setdefault(row.get("Owner"), []).append(row)
    return grouped


def _is_partial(access_rows: list[dict], warnings: int = 0) -> bool:
    """A subscription finished with gaps when its scan logged a failure, or the access check found a
    service it cannot read.

    Every warning in the scan collectors is something left out (a listing that failed, an item that
    was skipped, a query that was denied), so ``warnings`` is the count of them for this
    subscription (see gaps.py). The access check adds what a person fixes by being granted a role
    and then wants scanned again, even when the scan did not get far enough to log it.
    """
    blocked = {
        preflight_core.STATUS_TEXT[s] for s in (preflight_core.DENIED, preflight_core.NOT_ENABLED)
    }
    return warnings > 0 or any(row.get("Access") in blocked for row in access_rows)


def _drop_failed(
    subscriptions: list[str],
    scanned: list[Optional[tuple]],
    errors: dict[int, BaseException],
) -> tuple[list[str], list[list]]:
    """Drop failed subscriptions so the subscription list and the six per-collector result
    lists stay index-aligned (DiscoveryResult.build and the zip() over them rely on it)."""
    kept = [i for i in range(len(subscriptions)) if i not in errors]
    return (
        [subscriptions[i] for i in kept],
        [[scanned[i][k] for i in kept] for k in range(6)],
    )


def _print_sub_failure(sub_id: str, exc: BaseException) -> None:
    console.print(
        f"  [red]✗[/red] Subscription [cyan]{sub_id}[/cyan] failed and was skipped: "
        f"{type(exc).__name__}: {exc}"
    )


def _collect_all(
    subscriptions: list[str],
    credential,
    regions: Optional[list[str]],
    cloud,
    scans: dict[str, bool],
    workers: int,
    skips: frozenset[str] = frozenset(),
    on_scanned: Optional[Callable[[str, tuple], None]] = None,
) -> tuple[list[Optional[tuple]], dict[int, BaseException]]:
    """Scan every subscription with the console UX appropriate to the worker count.

    ``on_scanned(sub_id, result)`` is called for each subscription whose scan succeeded, as it
    finishes (see ``_scan_subscriptions``).
    """
    total = len(subscriptions)
    workers = max(1, min(workers, total))

    if workers == 1:

        def collect_serial(i: int, sub_id: str) -> tuple:
            console.print(f"[bold][{i + 1}/{total}][/bold] [cyan]{sub_id}[/cyan]")
            result = _collect_subscription(
                sub_id, credential, regions, cloud, scans=scans, skips=skips
            )
            console.print()
            return result

        def done_serial(i, sub_id, result, exc) -> None:
            if exc is not None:
                _print_sub_failure(sub_id, exc)
                console.print()

        return _scan_subscriptions(
            subscriptions, collect_serial, 1, done_serial, on_scanned=on_scanned
        )

    buffers = [_BufferedOutput() for _ in subscriptions]

    def collect_parallel(i: int, sub_id: str) -> tuple:
        return _collect_subscription(
            sub_id, credential, regions, cloud, scans=scans, out=buffers[i], skips=skips
        )

    finished = 0

    def status_text() -> str:
        return _parallel_status(finished, total)

    console.print(f"[dim]Scanning {total} subscriptions, {workers} in parallel[/dim]\n")
    with console.status(progress.Live(status_text)) as status:

        def done_parallel(i, sub_id, result, exc) -> None:
            nonlocal finished
            finished += 1
            console.print(f"[bold][{i + 1}/{total}][/bold] [cyan]{sub_id}[/cyan]")
            buffers[i].replay(console)
            if exc is not None:
                _print_sub_failure(sub_id, exc)
            console.print()
            status.update(progress.Live(status_text))

        return _scan_subscriptions(
            subscriptions, collect_parallel, workers, done_parallel, on_scanned=on_scanned
        )


def _print_totals(result: dict) -> None:
    """The per-resource totals, as the PowerShell script prints them, on the screen and in the log.

    Worked out from the rows the CSV files are built from, so the two agree. It holds counts and
    sizes only, so it is safe in an anonymized run. A failure here is a warning, never a crash.
    """
    import csv_export

    try:
        scope = result.get("subscriptions") or []
        seen = {
            entry.get("subscription_id")
            for key in ("compute", "backup_posture", "storage", "database")
            for entry in result.get(key) or []
        }
        lines = totals.summary_lines(
            csv_export.rows_by_file(result),
            result.get("backup_posture") or [],
            len(scope),
            len(seen & set(scope)),
        )
    except Exception as exc:  # noqa: BLE001 - the totals must never stop the run
        logger.warning("Could not work out the totals: %s", exc)
        return
    console.print()
    for line in lines:
        console.print(line, markup=False, highlight=False, style="green")


def _print_summary(comp_results: list, bp_results: list) -> None:
    console.print()
    console.print(Rule("[bold]Discovery Summary[/bold]"))
    console.print()

    t = Table(box=box.ROUNDED, show_lines=False)
    t.add_column("Subscription", style="cyan", min_width=20)
    t.add_column("VMs", justify="right", min_width=6)
    t.add_column("Disk TB", justify="right", min_width=9)
    t.add_column("Vaults", justify="right", min_width=7)
    t.add_column("Protected", justify="right", min_width=10)
    t.add_column("Unprotected", justify="right", min_width=12)

    total_vms = total_tb = total_vaults = total_prot = total_unprot = 0

    for comp, bp in zip(comp_results, bp_results):
        prot = bp.total_vm_count - bp.unprotected_vm_count
        short_id = f"…{bp.subscription_id[-12:]}"

        t.add_row(
            short_id,
            str(comp.total_vms),
            str(comp.total_disk_tb),
            str(bp.vault_count),
            str(prot),
            str(bp.unprotected_vm_count),
        )

        total_vms += comp.total_vms
        total_tb += comp.total_disk_tb
        total_vaults += bp.vault_count
        total_prot += prot
        total_unprot += bp.unprotected_vm_count

    if len(comp_results) > 1:
        t.add_section()
        t.add_row(
            "[bold]TOTAL[/bold]",
            f"[bold]{total_vms}[/bold]",
            f"[bold]{round(total_tb, 3)}[/bold]",
            f"[bold]{total_vaults}[/bold]",
            f"[bold]{total_prot}[/bold]",
            f"[bold]{total_unprot}[/bold]",
        )

    console.print(t)


def _print_protection_gap(comp_results: list, bp_results: list) -> None:
    """Print the unprotected VMs table across all subscriptions."""
    vm_lookup: dict[str, object] = {}
    for comp in comp_results:
        for vm in comp.vms:
            vm_lookup[vm.resource_id.lower()] = vm

    all_unprotected: list[object] = []
    for bp in bp_results:
        for vm_id in bp.unprotected_vms:
            vm = vm_lookup.get(vm_id)
            if vm:
                all_unprotected.append(vm)

    if not all_unprotected:
        console.print("\n  [green]All VMs are protected.[/green]")
        return

    console.print()
    console.print(Rule("[bold red]Unprotected VMs[/bold red]"))
    console.print()

    t = Table(box=box.ROUNDED, show_lines=False)
    t.add_column("VM Name", style="cyan", min_width=22)
    t.add_column("Resource Group", style="dim", min_width=20)
    t.add_column("Region", style="dim", min_width=12)
    t.add_column("Size", min_width=18)
    t.add_column("OS", justify="center", min_width=8)
    t.add_column("Disk", justify="right", min_width=9)

    # Sort by disk size descending — biggest exposure first
    for vm in sorted(all_unprotected, key=lambda v: -v.total_disk_gb):
        disk_tb = vm.total_disk_gb / 1024
        disk_str = f"{disk_tb:.1f} TB" if disk_tb >= 1 else f"{vm.total_disk_gb} GB"
        t.add_row(
            vm.name,
            vm.resource_group,
            vm.location,
            vm.vm_size,
            vm.os_type,
            disk_str,
        )

    console.print(t)

    total_unprotected_gb = sum(v.total_disk_gb for v in all_unprotected)
    console.print(
        f"  [dim]{len(all_unprotected)} unprotected VMs · "
        f"~{total_unprotected_gb / 1024:.1f} TB exposed[/dim]"
    )


def _print_manifest() -> None:
    """Print the audit manifest (source of docs/audit.md, no Azure calls)."""
    from audit_manifest import (
        CORE_API_CALLS,
        EXTERNAL_ENDPOINTS,
        MANIFEST_SUMMARY,
        OPTIONAL_API_CALLS,
    )

    console.print()
    console.print(
        Panel(
            "[bold white]Rubrik Discovery — Audit Manifest[/bold white]",
            subtitle="[dim]No Azure APIs are called by this command.[/dim]",
            border_style="bold blue",
            padding=(0, 2),
        )
    )
    console.print()
    console.print(MANIFEST_SUMMARY)

    def _render_table(title: str, calls) -> Table:
        t = Table(
            title=title, box=box.SIMPLE_HEAVY, expand=True, title_style="bold", show_lines=False
        )
        t.add_column("Collector", style="cyan", no_wrap=True)
        t.add_column("Azure API call", style="white")
        t.add_column("RBAC action", style="dim")
        t.add_column("Purpose", style="white")
        for c in calls:
            t.add_row(c.collector, c.api_call, c.rbac_action, c.purpose)
        return t

    console.print(_render_table("Core API calls (always run)", CORE_API_CALLS))
    console.print()
    console.print(
        _render_table(
            "Optional API calls (tool skips cleanly if permission denied)",
            OPTIONAL_API_CALLS,
        )
    )
    console.print()

    ext = Table(
        title="External endpoints (outside your tenant)",
        box=box.SIMPLE_HEAVY,
        expand=True,
        title_style="bold",
    )
    ext.add_column("Endpoint", style="cyan", no_wrap=True)
    ext.add_column("Purpose", style="white")
    for url, purpose in EXTERNAL_ENDPOINTS:
        ext.add_row(url, purpose)
    console.print(ext)
    console.print()
    console.print(
        "[dim]See docs/audit.md for the full write-up, and "
        "docs/rubrik-discovery-reader-role.json for a least-privilege custom "
        "role definition.[/dim]"
    )
    console.print()


def _dry_run(args) -> None:
    """Preview in-scope subscriptions + API calls without collecting.

    Makes ONE real call: ``subscriptions.list()`` (or the resolver for
    an explicit --subs list) so the customer sees the concrete scope.
    No collector APIs are invoked.
    """
    from audit_manifest import CORE_API_CALLS, OPTIONAL_API_CALLS

    console.print()
    console.print(
        Panel(
            "[bold white]Rubrik Discovery — Dry Run[/bold white]",
            subtitle="[dim]No collector APIs are called.  Scope is read via subscriptions.list() only.[/dim]",
            border_style="bold yellow",
            padding=(0, 2),
        )
    )
    console.print()

    import auth
    from cloud import resolve_cloud

    cloud = resolve_cloud(getattr(args, "cloud", None))
    if cloud is not DEFAULT_CLOUD:
        console.print(f"[bold]Cloud:[/bold] [cyan]{cloud.name}[/cyan] ({cloud.arm_endpoint})\n")

    with console.status("[bold]Authenticating…[/bold]"):
        credential = auth.get_credential(cloud)

    regions = auth.normalise_regions(
        [r.strip() for r in args.regions.split(",")] if args.regions else None
    )

    with console.status("[bold]Resolving subscriptions (read-only)…[/bold]"):
        subscriptions = _resolve_scope(credential, args, cloud)

    scope = Table(title="Scope", box=box.SIMPLE_HEAVY, expand=True, title_style="bold")
    scope.add_column("Subscription ID", style="cyan", no_wrap=True)
    for sid in subscriptions:
        scope.add_row(sid)
    console.print(scope)
    console.print(
        "[bold]Regions:[/bold] " + (", ".join(regions) if regions else "[dim]all regions[/dim]")
    )
    console.print(
        f"[bold]Parallelism:[/bold] up to {_resolve_workers(args)} subscription(s) at a time"
    )
    console.print()

    preview = Table(
        title=f"API calls the tool WOULD make per subscription "
        f"(×{len(subscriptions)} subscriptions in scope)",
        box=box.SIMPLE_HEAVY,
        expand=True,
        title_style="bold",
    )
    preview.add_column("Collector", style="cyan", no_wrap=True)
    preview.add_column("Azure API call", style="white")
    preview.add_column("RBAC action", style="dim")
    preview.add_column("Required?", style="white", no_wrap=True)
    for c in CORE_API_CALLS:
        preview.add_row(c.collector, c.api_call, c.rbac_action, "required")
    for c in OPTIONAL_API_CALLS:
        preview.add_row(c.collector, c.api_call, c.rbac_action, "[dim]optional[/dim]")
    console.print(preview)
    console.print()
    console.print(
        "[green]✓[/green] Dry run complete.  Nothing was collected, nothing "
        "was written to disk.  Re-run without [cyan]--dry-run[/cyan] when "
        "you're ready."
    )
    console.print()


def _apply_config_defaults(args) -> None:
    """Fold values from --config files into ``args`` where the user did
    not pass an explicit flag.  CLI flags always win.

    Only the main-discovery-relevant sections are applied here; the
    other CLIs handle their own sections.
    """
    if not args.config:
        return

    from config import load_config

    try:
        cfg = load_config(args.config)
    except Exception as exc:  # noqa: BLE001 — friendlier than a raw traceback
        console.print(f"[red]✗[/red] Config error: {exc}")
        sys.exit(1)

    # Scope
    flagged_scope = bool(
        args.subs or args.subscriptions or args.management_groups or args.current_subscription
    )
    if not flagged_scope and cfg.scope.subscriptions:
        args.subs = ",".join(cfg.scope.subscriptions)
    if args.regions is None and cfg.scope.regions:
        args.regions = ",".join(cfg.scope.regions)
    if not flagged_scope and not args.all and cfg.scope.effective_all_subs():
        args.all = True

    # Discovery
    if args.output is None and cfg.discovery.output_dir:
        args.output = cfg.discovery.output_dir
    if not args.mock and cfg.discovery.mock:
        args.mock = True
    if not args.verbose and cfg.discovery.verbose:
        args.verbose = True
    if getattr(args, "cloud", None) is None and cfg.discovery.cloud:
        args.cloud = cfg.discovery.cloud
    if args.workers is None and cfg.discovery.workers is not None:
        args.workers = cfg.discovery.workers


def main() -> None:
    try:
        _main()
    except BaseException as exc:
        runlog.crashed(exc)
        raise


def _main() -> None:
    parser = _build_parser()
    args = parser.parse_args()
    for flag, value in (
        ("--subs", args.subs),
        ("--subscriptions", args.subscriptions),
        ("--management-groups", args.management_groups),
    ):
        if value is not None and _split_csv(value) is None:
            parser.error(
                f"{flag} was given no values, which would scan every subscription. "
                "Pass at least one, or leave the flag out."
            )

    if (args.anonymize_fields or args.not_anonymize_fields) and not args.anonymize:
        parser.error("--anonymize-fields and --not-anonymize-fields need --anonymize")
    if args.anonymize and args.no_csv:
        parser.error("--anonymize works on the CSV files, so it cannot be used with --no-csv")
    if args.preflight_only and args.no_preflight:
        parser.error("--preflight-only runs only the access check, so it cannot skip it")
    if args.preflight_only and args.no_csv:
        parser.error("--preflight-only writes only the access-check CSV, so it cannot use --no-csv")
    if args.preflight_only and args.dry_run:
        parser.error("--preflight-only already collects nothing; use it or --dry-run, not both")

    _apply_config_defaults(args)
    if args.preflight_only and args.mock:
        parser.error("--preflight-only checks real access, so it cannot be used with --mock")
    if args.keep_partial and not args.resume:
        parser.error(
            "--keep-partial keeps what an earlier run finished with gaps instead of scanning it "
            "again, so it needs --resume"
        )
    if (args.resume or args.fresh) and (args.mock or args.dry_run or args.preflight_only):
        parser.error(
            "--resume and --fresh apply to a scan, not to --mock, --dry-run or --preflight-only"
        )

    if args.manifest:
        _print_manifest()
        return

    # Check before any output dir or log file is created: _run_mock() imports tests/fixtures.
    if args.mock and not _mock_fixtures_available():
        console.print(
            "[red]✗[/red] --mock is not available in the public distribution "
            "(its test fixtures are not shipped); omit --mock for a real run."
        )
        sys.exit(1)

    from logging_setup import add_log_file, setup_logging

    setup_logging(verbose=args.verbose)

    if args.dry_run:
        if args.mock:
            console.print("[yellow]⚠[/yellow]  --dry-run is ignored when combined with --mock.\n")
        else:
            _dry_run(args)
            return

    # Resolve the output location up front and start capturing a full DEBUG run
    # log to disk. It is bundled into the ZIP so the SE can debug a failed or
    # partial scan; this is independent of --verbose, which only gates the
    # console. The timestamp marks run start and names every artefact.
    output_dir = _resolve_output_dir(args.output)
    started = datetime.now(timezone.utc)
    timestamp = started.strftime("%Y%m%d-%H%M%S")
    log_path = output_dir / f"output_azure_{started:%Y-%m-%d_%H%M%S}.log"
    log_handler = add_log_file(log_path)
    runlog.start(sys.argv[1:])
    runlog.install_stop_handlers()
    logger.info("Discovery run started (mock=%s)", args.mock)

    console.print()
    console.print(
        Panel(
            "[bold white]Rubrik Discovery — Azure Edition[/bold white]"
            + (" [dim](mock)[/dim]" if args.mock else ""),
            subtitle=f"[dim]{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}[/dim]",
            border_style="bold blue",
            padding=(0, 2),
        )
    )
    console.print()

    scans: dict[str, bool] = {}  # optional-scan choices; populated for real (non-mock) runs
    skips = frozenset(key for key in SKIP_SWITCHES if getattr(args, f"skip_{key}", False))
    if skips:
        console.print(
            "[bold]Skipping:[/bold] "
            + ", ".join(SKIP_SWITCHES[key][1] for key in SKIP_SWITCHES if key in skips)
            + "\n"
        )
    tenant_name: Optional[str] = None
    tag_names: dict[str, list[str]] = {}
    aks_results: list = []
    cosmos_results: list = []
    # Backup Vaults: None until a subscription is collected, so a run that skipped them says nothing.
    dp_results: Optional[list] = None
    # Opt-in collections: None unless their option was given, so their files are not written.
    kv_results: Optional[list] = None
    container_results: Optional[list] = None
    access_rows: list[dict] = []
    store = None  # the checkpoint store of a real scan; None for --mock, which saves nothing
    # (subscription, why) for each one that finished with gaps; empty for --mock
    sub_gaps: list = []
    # Subscriptions that are not in the results, and why: each keeps rows in the pre-flight CSV
    # and is named at the end.
    not_scanned: list[dict] = []

    if args.mock:
        console.print("[dim]Running with mock fixture data — no Azure credentials used.[/dim]\n")
        comp_results, bp_results, stor_results, db_results, job_results, cost_results, tenant_id = (
            _run_mock(skips)
        )
        subscriptions = [c.subscription_id for c in comp_results]
        subscription_names = {}
        regions = None
        tag_names = _tag_names_from_results(comp_results, stor_results)

    else:
        import auth
        from cloud import resolve_cloud
        from collectors.aks_cosmos import (
            AksCollector,
            AksInventory,
            CosmosCollector,
            CosmosInventory,
        )
        from collectors.tags import collect_tag_names

        cloud = resolve_cloud(getattr(args, "cloud", None))
        if cloud is not DEFAULT_CLOUD:
            console.print(f"[bold]Cloud:[/bold] [cyan]{cloud.name}[/cyan] ({cloud.arm_endpoint})\n")

        with console.status("[bold]Authenticating…[/bold]"):
            credential = auth.get_credential(cloud)

        regions = auth.normalise_regions(
            [r.strip() for r in args.regions.split(",")] if args.regions else None
        )

        skipped_subs: list = []
        with console.status("[bold]Resolving subscriptions…[/bold]"):
            subscriptions = _resolve_scope(credential, args, cloud, skipped=skipped_subs)
        for sub_id, exc in skipped_subs:
            check = preflight.unreadable_check(sub_id, exc)
            not_scanned.append(
                {
                    "id": sub_id,
                    "name": "",
                    "why": f"cannot read the subscription: {check.code}",
                    "rows": [check.to_row()],
                }
            )

        try:
            subscription_names = auth.resolve_subscription_names(credential, subscriptions, cloud)
        except Exception as exc:
            logger.debug("Subscription display-name lookup skipped: %s", exc)
            subscription_names = {}

        tenant_id = auth.resolve_tenant_id(credential, subscriptions[0], cloud) or "unknown"

        if tenant_id != "unknown":
            tenant_name = auth.resolve_tenant_name(credential, tenant_id, cloud)

        region_label = ", ".join(regions) if regions else "all regions"
        console.print(
            f"[bold]Scope:[/bold] {len(subscriptions)} subscription(s) · {region_label}\n"
        )

        # Decide optional scans once (prompts on a TTY, flags hard-skip) before scanning.
        scans = _resolve_scans(args)

        to_check = subscriptions
        if not args.preflight_only:
            store, resumed = _open_progress(
                args,
                output_dir,
                resume.request_of(
                    scope=_scope_kind(args),
                    regions=regions,
                    cloud=cloud.name,
                    scans={
                        **scans,
                        "containers": args.get_container_details,
                        "key_vault": args.get_key_vault_amounts,
                    },
                    skips=skips,
                    devops=not getattr(args, "no_devops", False),
                    devops_orgs=getattr(args, "devops_orgs", None),
                ),
            )
            if resumed:
                # Subscriptions the earlier run finished keep the access rows it saved: check only
                # the rest.
                to_check = resume.split(store, subscriptions, not args.keep_partial)[0]

        if args.no_preflight:
            # Without the full check, still warn up front if Monitor metrics read is denied.
            if scans.get("capacity", True):
                _preflight_monitor_access(to_check, credential, regions, cloud)
        else:
            access_rows = _run_access_check(
                to_check,
                subscription_names,
                credential,
                regions,
                cloud,
                {
                    **scans,
                    "containers": args.get_container_details,
                    "key_vault": args.get_key_vault_amounts,
                },
                skips,
                _resolve_workers(args),
            )

        if args.preflight_only:
            _finish_access_check(
                args,
                output_dir,
                started,
                access_rows,
                not_scanned,
                checked=len(subscriptions),
                log_handler=log_handler,
                log_path=log_path,
            )
            return

        todo, reuse = list(subscriptions), []
        if store is not None:
            todo, reuse, notes = resume.split(store, subscriptions, not args.keep_partial)
            for note in notes:
                console.print(f"[dim]{escape(note)}[/dim]")
            if reuse:
                console.print(
                    f"[dim]Resuming: {len(reuse)} of {len(subscriptions)} subscriptions are "
                    "already scanned and are not scanned again.[/dim]\n"
                )
        access_of = _access_by_subscription(access_rows)

        recorder = gaps.GapRecorder(todo).install()

        def save_scan(sub_id: str, result: tuple) -> None:
            if store is not None:
                found = {"count": recorder.count(sub_id), "examples": recorder.examples(sub_id)}
                store.save(
                    sub_id,
                    resume.scan_checkpoint(result, access_of.get(sub_id, []), found),
                    partial=_is_partial(access_of.get(sub_id, []), found["count"]),
                )

        try:
            fresh, fresh_errors = (
                _collect_all(
                    todo,
                    credential,
                    regions,
                    cloud,
                    scans,
                    _resolve_workers(args),
                    skips=skips,
                    on_scanned=save_scan,
                )
                if todo
                else ([], {})
            )
        finally:
            recorder.uninstall()
        scanned, scan_errors = _merge_scans(subscriptions, todo, fresh, fresh_errors, store)
        sub_gaps = _subscription_gaps(store, subscriptions, subscription_names)
        for sub_id in reuse:
            access_rows.extend(
                row for row in store.load(sub_id)[0]["access"] if row not in access_rows
            )
        # In scan order, as an uninterrupted run lists them (sorted() is stable: each subscription's
        # own rows keep their order).
        rank = {sub: i for i, sub in enumerate(subscriptions)}
        access_rows.sort(key=lambda row: rank.get(row.get("Owner"), len(rank)))
        failed_subs = [subscriptions[i] for i in sorted(scan_errors)]
        for i in sorted(scan_errors):
            sub_id = subscriptions[i]
            check = preflight.scan_failed_check(
                sub_id, subscription_names.get(sub_id) or "", scan_errors[i]
            )
            not_scanned.append(
                {
                    "id": sub_id,
                    "name": subscription_names.get(sub_id) or "",
                    "why": f"scan failed: {check.code}",
                    "rows": [check.to_row()],
                }
            )
        if failed_subs:
            if len(failed_subs) == len(subscriptions):
                console.print("[red]✗[/red] Every subscription failed; nothing to report.")
                sys.exit(1)
            console.print(
                f"[yellow]⚠[/yellow] {len(failed_subs)} of {len(subscriptions)} "
                f"subscription(s) failed and are excluded from the results: "
                f"{', '.join(failed_subs)}\n"
            )
        subscriptions, (
            comp_results,
            bp_results,
            stor_results,
            db_results,
            job_results,
            cost_results,
        ) = _drop_failed(subscriptions, scanned, scan_errors)

        collect_dp, dp_notice = _backup_vault_scan(skips)
        if dp_notice:
            console.print(dp_notice)
        if collect_dp:
            dp_results = []
        if args.get_key_vault_amounts:
            kv_results = []
        if args.get_container_details and "storage" not in skips:
            container_results = []

        for index, sub_id in enumerate(subscriptions):
            tag_names[sub_id] = collect_tag_names(sub_id, credential, cloud)
            # AKS and Cosmos DB are collected here, after the (possibly parallel) per-subscription
            # scan, so label them: the scan's output block has already been printed.
            console.print(f"[bold]Additional services[/bold] [cyan]{sub_id}[/cyan]")
            if "aks" in skips:
                aks = AksInventory(subscription_id=sub_id)
                console.print("  [dim]– AKS            skipped[/dim]")
            else:
                with console.status("  [dim]Collecting AKS…[/dim]"):
                    aks = AksCollector(sub_id, credential, regions, cloud=cloud).collect()
                console.print(
                    f"  [green]✓[/green] AKS            "
                    f"[cyan]{aks.total_clusters}[/cyan] clusters · "
                    f"[cyan]{aks.total_nodes}[/cyan] nodes"
                )
            if "cosmos" in skips:
                cosmos = CosmosInventory(subscription_id=sub_id)
                console.print("  [dim]– Cosmos DB      skipped[/dim]")
            else:
                with console.status("  [dim]Collecting Cosmos DB…[/dim]"):
                    cosmos = CosmosCollector(
                        sub_id,
                        credential,
                        regions,
                        cloud=cloud,
                        collect_capacity=scans.get("capacity", True),
                    ).collect()
                console.print(
                    f"  [green]✓[/green] Cosmos DB      "
                    f"[cyan]{cosmos.total_accounts}[/cyan] accounts"
                )
            if collect_dp:
                dp_results.append(_collect_backup_vaults(sub_id, credential, cloud))
            if container_results is not None:
                accounts = getattr(stor_results[index], "accounts", None) or []
                container_results.append(_collect_containers(sub_id, credential, cloud, accounts))
            if kv_results is not None:
                kv_results.append(_collect_key_vaults(sub_id, credential, regions, cloud))
            aks_results.append(aks)
            cosmos_results.append(cosmos)
            console.print()

    total_monthly_compute_cost: Optional[float] = None
    total_monthly_unprotected_compute_cost: Optional[float] = None

    try:
        from collectors.pricing import compute_workload_costs, fetch_vm_prices

        pairs = [
            (vm.vm_size, vm.location)
            for comp in comp_results
            for vm in comp.vms
            if vm.vm_size and vm.vm_size.lower() != "unknown"
        ]

        if pairs:
            with console.status("[dim]Fetching VM pricing from Azure Retail Prices API…[/dim]"):
                price_map = fetch_vm_prices(pairs)

            if price_map:
                # Build unprotected ID set for fast membership check
                unprotected_ids: set[str] = set()
                for bp in bp_results:
                    unprotected_ids.update(vid.lower() for vid in bp.unprotected_vms)

                vm_dicts = [
                    {
                        "vm_size": vm.vm_size,
                        "location": vm.location,
                        "os_type": vm.os_type or "Linux",
                        "resource_id": vm.resource_id,
                        "is_unprotected": vm.resource_id.lower() in unprotected_ids,
                    }
                    for comp in comp_results
                    for vm in comp.vms
                ]

                total_monthly_compute_cost, total_monthly_unprotected_compute_cost = (
                    compute_workload_costs(vm_dicts, price_map)
                )

                console.print(
                    f"  [green]✓[/green] VM Pricing     "
                    f"[cyan]{len(price_map)}[/cyan] SKUs · "
                    f"total [cyan]${total_monthly_compute_cost:,.0f}/mo[/cyan] · "
                    f"unprotected [red]${total_monthly_unprotected_compute_cost:,.0f}/mo[/red]"
                )
            else:
                console.print(
                    "  [yellow]⚠[/yellow]  VM Pricing     [dim]no SKUs found in retail API[/dim]"
                )
    except Exception as exc:
        console.print(f"  [yellow]⚠[/yellow]  VM Pricing     [dim]skipped: {exc}[/dim]")
        logger.debug("Pricing lookup traceback", exc_info=True)

    # Optional parity-SDK collectors (Defender / Purview / ASR).
    # Each gracefully degrades when the SDK isn't installed or the
    # identity lacks permission — never fails the discovery run.
    defender_results: list = []
    purview_results: list = []
    asr_results: list = []
    if not args.mock and subscriptions:
        try:
            from collectors.defender import HAS_SDK as _HAS_DEF_SDK
            from collectors.defender import DefenderCollector
            from collectors.purview import HAS_SDK as _HAS_PV_SDK
            from collectors.purview import PurviewCollector
            from collectors.site_recovery import HAS_SDK as _HAS_ASR_SDK
            from collectors.site_recovery import SiteRecoveryCollector

            any_sdk = _HAS_DEF_SDK or _HAS_PV_SDK or _HAS_ASR_SDK
            if any_sdk:
                for sub_id, bp in zip(subscriptions, bp_results):
                    if _HAS_DEF_SDK and scans.get("security", True):
                        defender_results.append(
                            DefenderCollector(sub_id, credential, cloud=cloud).collect()
                        )
                    if _HAS_PV_SDK:
                        purview_results.append(
                            PurviewCollector(sub_id, credential, cloud=cloud).collect()
                        )
                    if _HAS_ASR_SDK:
                        vault_refs = [
                            (v.resource_group, v.name) for v in getattr(bp, "vaults", None) or []
                        ]
                        asr_results.append(
                            SiteRecoveryCollector(
                                sub_id,
                                credential,
                                vault_refs=vault_refs,
                                cloud=cloud,
                            ).collect()
                        )
        except Exception as exc:
            console.print(f"[yellow]⚠[/yellow]  Parity SDK collection failed: {exc}")
            logger.debug("Parity SDK traceback", exc_info=True)

    # Azure DevOps repository discovery (org-scoped, not per-subscription).
    devops_inventory = None
    if not getattr(args, "no_devops", False) and not args.mock:
        try:
            with console.status("[dim]Discovering Azure DevOps repositories…[/dim]"):
                from collectors.devops import DevOpsCollector

                org_filter = None
                if getattr(args, "devops_orgs", None):
                    org_filter = [o.strip() for o in args.devops_orgs.split(",")]
                devops_col = DevOpsCollector(credential, org_filter=org_filter)
                devops_inventory = devops_col.collect()
                if devops_inventory.total_repos > 0:
                    logger.info(
                        "DevOps: %d org(s), %d project(s), %d repo(s), %.1f GB",
                        devops_inventory.total_orgs,
                        devops_inventory.total_projects,
                        devops_inventory.total_repos,
                        devops_inventory.total_repo_size_gb,
                    )
                elif devops_inventory.data_note:
                    logger.info("DevOps: %s", devops_inventory.data_note)
        except Exception as exc:
            console.print(f"[yellow]⚠[/yellow]  DevOps discovery skipped: {exc}")
            logger.debug("DevOps discovery traceback", exc_info=True)

    from models.inventory import DiscoveryResult

    result = DiscoveryResult.build(
        tenant_id=tenant_id if args.mock else tenant_id,
        subscriptions=subscriptions,
        subscription_names=subscription_names,
        tenant_name=tenant_name,
        tag_names=tag_names,
        skipped=sorted(skips),
        aks_results=aks_results,
        cosmos_results=cosmos_results,
        data_protection_results=dp_results,
        key_vault_results=kv_results,
        container_results=container_results,
        regions_in_scope=regions if not args.mock else None,
        compute_results=comp_results,
        bp_results=bp_results,
        storage_results=stor_results,
        database_results=db_results,
        cost_results=cost_results,
        job_results=job_results,
        total_monthly_compute_cost=total_monthly_compute_cost,
        total_monthly_unprotected_compute_cost=total_monthly_unprotected_compute_cost,
        defender_results=defender_results,
        purview_results=purview_results,
        asr_results=asr_results,
        access_check=access_rows,
    )

    if devops_inventory is not None and devops_inventory.total_repos > 0:
        import dataclasses as _dc

        result.devops = _dc.asdict(devops_inventory)

    anonymizer = (
        Anonymizer.from_options(args.anonymize_fields, args.not_anonymize_fields)
        if args.anonymize
        else None
    )
    json_path = output_dir / f"rubrik-discovery-{timestamp}.json"
    # The JSON holds every real name, so an anonymized run does not write it unless asked to keep
    # the artifacts.
    if anonymizer is None or args.keep_artifacts:
        json_path.write_text(result.to_json())

    csv_paths: list[str] = []
    if not args.no_csv:
        import csv_export

        file_stamp = started.strftime(csv_export.FILE_TIMESTAMP_FORMAT)
        csv_paths = csv_export.write_csv_files(
            result.model_dump(), str(output_dir), file_stamp, anonymizer
        )
        report_rows = [*access_rows, *(row for entry in not_scanned for row in entry["rows"])]
        if report_rows:
            csv_paths.append(_write_access_report(output_dir, file_stamp, report_rows, anonymizer))

    _print_totals(result.model_dump())
    _print_not_scanned(not_scanned, "Not scanned:")

    # SE-focused terminal output (environment summary + protection gap) is
    # suppressed by default so the customer sees a clean "here's your ZIP"
    # output.  Risk exposure is intentionally NOT computed here — the customer
    # run is a pure data pull; the Rubrik SE produces the Monte Carlo risk model
    # from this JSON via generate_report.py.  Re-enable the SE summary with
    # --verbose to smoke-test the pipeline end-to-end.
    if args.verbose:
        _print_summary(comp_results, bp_results)
        _print_protection_gap(comp_results, bp_results)

    # Bundle the discovery artefacts into a single ZIP for easy sharing: the
    # raw JSON plus the full DEBUG run log. The polished HTML / Excel report is
    # generated by the Rubrik SE via generate_report.py from this JSON.
    # Two-phase delivery keeps the customer's runtime fast and the analysis
    # lives with the SE.
    import zipfile

    # Flush + detach the run log so the file is complete and unlocked before we
    # bundle it; nothing after this needs the file handler.
    logger.info("Discovery run complete — bundling artefacts.")
    runlog.finish(console)
    logging.getLogger().removeHandler(log_handler)
    log_handler.close()

    zip_path = output_dir / f"azure_sizing_results_{started:%Y-%m-%d_%H%M}.zip"
    run_stamp = f"{started:%Y-%m-%d_%H%M%S}"
    if anonymizer is None:
        files_to_zip = [
            (json_path, json_path.exists()),
            (log_path, log_path.exists()),
            *[(pathlib.Path(p), True) for p in csv_paths],
        ]
    else:
        # The real log names real resources, so the ZIP gets a note under the log's name and the
        # log is kept beside it, with the file that maps the labels back.
        files_to_zip = [(pathlib.Path(p), True) for p in csv_paths]
    manifest_text = _manifest_text(
        {path.name: path.read_bytes() for path, written in files_to_zip if written}
    )
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for path, written in files_to_zip:
            if written:
                zf.write(path, path.name)
        if manifest_text is not None:
            zf.writestr(manifest_core.FILE_NAME, manifest_text)
        if anonymizer is not None:
            zf.writestr(f"output_azure_{run_stamp}.log", anonymized_log_note())
    if manifest_text is not None and args.keep_artifacts:
        (output_dir / manifest_core.FILE_NAME).write_text(
            manifest_text, encoding="utf-8", newline=""
        )
    key_path: Optional[pathlib.Path] = None
    kept_log_path: Optional[pathlib.Path] = None
    if anonymizer is not None:
        key_path = output_dir / f"{KEY_FILE_PREFIX}-{run_stamp}.csv"
        key_path.write_text(anonymizer.key_file_text(), encoding="utf-8", newline="")
        kept_log_path = output_dir / f"output_azure_not_anonymized_{run_stamp}.log"
        if log_path.exists():
            log_path.replace(kept_log_path)

    # Leave only the single ZIP behind so the customer has exactly one file to
    # share — the loose JSON / log are bundled inside it. --keep-artifacts (or
    # --verbose smoke tests) preserves them on disk.
    if not args.keep_artifacts:
        for path, written in files_to_zip:
            if written:
                try:
                    path.unlink()
                except OSError as exc:
                    logger.debug("Could not remove %s after zipping: %s", path, exc)

    kept = resume.keep_progress(not_scanned, sub_gaps)
    _close_progress(store, keep=kept)
    # Out of every subscription the run covers: the ones in the results, and the ones that were
    # not scanned (unreadable, or whose scan failed), which _drop_failed has already taken out of
    # the list.
    _print_gaps(sub_gaps, len(subscriptions) + len(not_scanned), kept)

    console.print()
    console.print(Rule())
    if args.keep_artifacts:
        console.print(f"[green]✓[/green] JSON → [bold]{json_path}[/bold]")
        if anonymizer is None:
            console.print(f"[green]✓[/green] Log  → [bold]{log_path}[/bold]")
    console.print(f"[green]✓[/green] ZIP  → [bold]{zip_path}[/bold]")
    if key_path is not None:
        console.print(
            f"[green]✓[/green] Keys → [bold]{key_path}[/bold] [dim](not in the ZIP)[/dim]"
        )
        console.print(
            f"[green]✓[/green] Log  → [bold]{kept_log_path}[/bold] [dim](not in the ZIP)[/dim]"
        )
        console.print("[dim]Keep these two files; they hold the real names.[/dim]")
    console.print()
    console.print("[bold]Share the ZIP file with your Rubrik SE.[/bold]")
    console.print(
        "[dim]Your SE will prepare a detailed analysis report and schedule a review.[/dim]"
    )
    console.print()


if __name__ == "__main__":
    main()
