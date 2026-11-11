"""Azure pre-flight access check: one read-only call per service, per subscription, before a scan.

Each call is the first one a collector makes, and only the first page is read, so a pass means the
scan can read that service in that subscription with the sign-in in use. Services switched off by
a ``--skip-*`` flag or an optional scan answered "no" are listed as not requested.

Calls that need a resource name (one storage account's file shares, one vault's protected items)
are not probed; they fail the same way as the list call that finds the resource. Azure DevOps is
organization-wide rather than per subscription, so it is not part of this check.
"""

from __future__ import annotations

import logging
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from functools import partial
from typing import Any, Callable, Optional

import preflight_core as core
from azure.core.exceptions import ClientAuthenticationError, HttpResponseError

log = logging.getLogger(__name__)

FILE_PREFIX = "azure_preflight_check"
SCOPE = "subscription"

SECURITY_JSON = "security posture in the JSON"
PURVIEW_JSON = "Purview accounts in the JSON"
NON_FILE_EFFECTS = frozenset({SECURITY_JSON, PURVIEW_JSON})

_TAG_FILES = (
    "azure_vmdisk_info",
    "azure_storage_account_info",
    "azure_sql_info",
    "azure_mi_sql_info",
    "azure_aks_info",
    "azure_cosmos_db",
)
_MONITOR_HINT = (
    "grant Monitoring Reader (or Reader) at subscription scope, or run with --no-capacity"
)


# The RBAC action each probe needs. Reader includes all of them; Monitoring Reader covers the metrics
# one, and Cost Management Reader the cost one. These are the provider operation names as documented
# by Azure; they are not checked against a live tenant.
PERMISSIONS = {
    "virtual machines": "Microsoft.Compute/virtualMachines/read",
    "managed disks": "Microsoft.Compute/disks/read",
    "disk snapshots": "Microsoft.Compute/snapshots/read",
    "storage accounts": "Microsoft.Storage/storageAccounts/read",
    "storage metrics (capacity)": "Microsoft.Insights/Metrics/Read",
    "sql servers": "Microsoft.Sql/servers/read",
    "sql managed instances": "Microsoft.Sql/managedInstances/read",
    "postgresql flexible servers": "Microsoft.DBforPostgreSQL/flexibleServers/read",
    "mysql flexible servers": "Microsoft.DBforMySQL/flexibleServers/read",
    "backup vaults": "Microsoft.RecoveryServices/vaults/read",
    "data protection backup vaults": "Microsoft.DataProtection/backupVaults/read",
    "cost management": "Microsoft.CostManagement/dimensions/read",
    "aks clusters": "Microsoft.Resources/subscriptions/resources/read",
    "cosmos db accounts": "Microsoft.Resources/subscriptions/resources/read",
    "tag names": "Microsoft.Resources/subscriptions/tagNames/read",
    "microsoft defender": "Microsoft.Security/pricings/read",
    "microsoft purview": "Microsoft.Purview/accounts/read",
    "key vaults": "Microsoft.KeyVault/vaults/read",
    "key vault contents": "Microsoft.KeyVault/vaults/certificates/read",
    "blob containers": "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
}
_KEY_VAULT_HINT = (
    "grant Key Vault Reader on the vault (or, for a vault that uses access policies, the List "
    "permission on certificates, secrets and keys)"
)
_BLOB_HINT = "grant Storage Blob Data Reader on the storage accounts (or the subscription)"


class Outcome(Exception):
    """A probe's own verdict, for when a call succeeds but says the service cannot be read."""

    def __init__(self, status: str, code: str) -> None:
        super().__init__(code)
        self.status, self.code = status, code


@dataclass(frozen=True)
class Context:
    sub_id: str
    credential: Any
    cloud: Any
    regions: Optional[list]

    def kwargs(self) -> dict:
        return self.cloud.client_kwargs()


@dataclass(frozen=True)
class Api:
    """One probe. It runs unless its ``skip`` switch is set or its optional ``scan`` is off."""

    label: str
    probe: Callable[[Context], Optional[bool]]
    affects: tuple
    skip: Optional[str] = None  # a key of the --skip-* switches
    scan: Optional[str] = None  # a key of the optional scans (cost, capacity, security, ...)
    hint: str = ""
    # Returns why this probe cannot run in this environment (an SDK that is not installed), or "".
    needs: Optional[Callable[[], str]] = None
    # For an opt-in collection: what to add to turn it on, shown when it is off.
    opt_in: str = ""

    @property
    def permission(self) -> str:
        return PERMISSIONS[self.label]


def _seen(items: Any) -> bool:
    return next(iter(items), None) is not None


def _vms(ctx: Context) -> bool:
    from azure.mgmt.compute import ComputeManagementClient

    client = ComputeManagementClient(ctx.credential, ctx.sub_id, **ctx.kwargs())
    return _seen(client.virtual_machines.list_all())


def _disks(ctx: Context) -> bool:
    from azure.mgmt.compute import ComputeManagementClient

    client = ComputeManagementClient(ctx.credential, ctx.sub_id, **ctx.kwargs())
    return _seen(client.disks.list())


def _snapshots(ctx: Context) -> bool:
    from azure.mgmt.compute import ComputeManagementClient

    client = ComputeManagementClient(ctx.credential, ctx.sub_id, **ctx.kwargs())
    return _seen(client.snapshots.list())


def _storage_accounts(ctx: Context) -> bool:
    from azure.mgmt.storage import StorageManagementClient

    client = StorageManagementClient(ctx.credential, ctx.sub_id, **ctx.kwargs())
    return _seen(client.storage_accounts.list())


def _monitor(ctx: Context) -> Optional[bool]:
    """The scan's own test of whether storage metrics can be read."""
    from collectors.storage import StorageCollector

    status = StorageCollector(
        ctx.sub_id, ctx.credential, ctx.regions, cloud=ctx.cloud, collect_capacity=True
    ).probe_monitor_access()
    if status == "ok":
        return None
    if status == "denied":
        raise Outcome(core.DENIED, "MetricsDenied")
    if status == "no_accounts":
        raise Outcome(core.SKIPPED, "no storage accounts to test against")
    raise Outcome(core.ERROR, "MetricsInconclusive")


def _sql_servers(ctx: Context) -> bool:
    from azure.mgmt.sql import SqlManagementClient

    client = SqlManagementClient(ctx.credential, ctx.sub_id, **ctx.kwargs())
    return _seen(client.servers.list())


def _sql_managed_instances(ctx: Context) -> bool:
    from azure.mgmt.sql import SqlManagementClient

    client = SqlManagementClient(ctx.credential, ctx.sub_id, **ctx.kwargs())
    return _seen(client.managed_instances.list())


def _postgresql_flexible(ctx: Context) -> bool:
    from collectors.database import PostgreSQLFlexClient

    return _seen(PostgreSQLFlexClient(ctx.credential, ctx.sub_id, **ctx.kwargs()).servers.list())


def _mysql_flexible(ctx: Context) -> bool:
    from collectors.database import MySQLFlexClient

    return _seen(MySQLFlexClient(ctx.credential, ctx.sub_id, **ctx.kwargs()).servers.list())


def _backup_vaults(ctx: Context) -> bool:
    from azure.mgmt.recoveryservices import RecoveryServicesClient

    client = RecoveryServicesClient(ctx.credential, ctx.sub_id, **ctx.kwargs())
    return _seen(client.vaults.list_by_subscription_id())


def _cost(ctx: Context) -> bool:
    from azure.mgmt.costmanagement import CostManagementClient

    client = CostManagementClient(ctx.credential, **ctx.kwargs())
    return _seen(client.dimensions.list(f"/subscriptions/{ctx.sub_id}"))


def _resources_of_type(ctx: Context, resource_type: str) -> bool:
    from azure.mgmt.resource import ResourceManagementClient

    client = ResourceManagementClient(ctx.credential, ctx.sub_id, **ctx.kwargs())
    return _seen(client.resources.list(filter=f"resourceType eq '{resource_type}'"))


def _tags(ctx: Context) -> bool:
    from azure.mgmt.resource import ResourceManagementClient

    client = ResourceManagementClient(ctx.credential, ctx.sub_id, **ctx.kwargs())
    return _seen(client.tags.list())


def _data_protection(ctx: Context) -> bool:
    from collectors import data_protection

    if not data_protection.HAS_SDK:
        raise Outcome(core.SKIPPED, "azure-mgmt-dataprotection is not installed")
    client = data_protection.DataProtectionMgmtClient(ctx.credential, ctx.sub_id, **ctx.kwargs())
    return _seen(client.backup_vaults.get_in_subscription())


def _data_protection_missing() -> str:
    from collectors import data_protection

    return "" if data_protection.HAS_SDK else "azure-mgmt-dataprotection is not installed"


def _defender(ctx: Context) -> bool:
    from collectors import defender

    if not defender.HAS_SDK:
        raise Outcome(core.SKIPPED, "azure-mgmt-security is not installed")
    client = defender._SecurityCenter(ctx.credential, ctx.sub_id, **ctx.kwargs())
    result = defender.list_pricings(client, ctx.sub_id)
    # azure-mgmt-security 7.x returns a PricingList with the plans in `.value`; older ones a list.
    items = getattr(result, "value", None)
    return _seen(items if items is not None else result)


def _defender_missing() -> str:
    from collectors import defender

    return "" if defender.HAS_SDK else "azure-mgmt-security is not installed"


def _key_vault_contents(ctx: Context) -> bool:
    """The first vault's certificates: the data-plane read --get-key-vault-amounts makes."""
    from azure.mgmt.resource import ResourceManagementClient
    from collectors import key_vault

    client = ResourceManagementClient(ctx.credential, ctx.sub_id, **ctx.kwargs())
    listed = client.resources.list(filter=f"resourceType eq '{key_vault.KEY_VAULT_RESOURCE_TYPE}'")
    vault = next(iter(listed), None)
    if vault is None:
        raise Outcome(core.SKIPPED, "no key vaults to test against")
    uri = f"https://{vault.name}.{ctx.cloud.key_vault_suffix}/"
    return _seen(key_vault.CertificateClient(uri, ctx.credential).list_properties_of_certificates())


def _blob_containers(ctx: Context) -> bool:
    """The first blob account's containers and the first page of blobs, as the container scan reads."""
    from azure.mgmt.storage import StorageManagementClient
    from collectors import containers

    client = StorageManagementClient(ctx.credential, ctx.sub_id, **ctx.kwargs())
    account = next(
        (
            a
            for a in client.storage_accounts.list()
            if (a.kind or "").lower() not in containers._NO_BLOB_KINDS
        ),
        None,
    )
    if account is None:
        raise Outcome(core.SKIPPED, "no storage accounts with blobs to test against")
    service = containers.BlobServiceClient(
        account_url=f"https://{account.name}.blob.{ctx.cloud.storage_suffix}",
        credential=ctx.credential,
    )
    container = next(iter(service.list_containers()), None)
    if container is None:
        return False
    return _seen(service.get_container_client(container.name).list_blobs())


def _purview(ctx: Context) -> bool:
    from collectors import purview

    if not purview.HAS_SDK:
        raise Outcome(core.SKIPPED, "azure-mgmt-purview is not installed")
    client = purview._PurviewClient(ctx.credential, ctx.sub_id, **ctx.kwargs())
    return _seen(client.accounts.list_by_subscription())


APIS = (
    Api(
        "virtual machines",
        _vms,
        ("azure_vmdisk_info", "azure_sizing_summary"),
        skip="vms",
    ),
    Api("managed disks", _disks, ("azure_vmdisk_info",), skip="vms"),
    Api("disk snapshots", _snapshots, ("azure_vmdisk_info",), skip="vms"),
    Api(
        "storage accounts",
        _storage_accounts,
        ("azure_storage_account_info", "azure_file_share_info"),
        skip="storage",
    ),
    Api(
        "storage metrics (capacity)",
        _monitor,
        ("azure_storage_account_info",),
        skip="storage",
        scan="capacity",
        hint=_MONITOR_HINT,
    ),
    Api("sql servers", _sql_servers, ("azure_sql_info",), skip="sql_mi"),
    Api(
        "sql managed instances",
        _sql_managed_instances,
        ("azure_mi_sql_info", "azure_mi_db_items"),
        skip="sql_mi",
    ),
    Api(
        "postgresql flexible servers",
        _postgresql_flexible,
        ("azure_postgres_info", "azure_sizing_summary"),
        skip="postgres",
    ),
    Api("mysql flexible servers", _mysql_flexible, ("azure_sizing_summary",)),
    Api(
        "backup vaults",
        _backup_vaults,
        ("azure_backup_vault_info", "azure_sizing_summary"),
        skip="backup",
    ),
    Api(
        "cost management",
        _cost,
        ("azure_backup_costs", "azure_sizing_summary"),
        scan="cost",
    ),
    Api(
        "aks clusters",
        partial(_resources_of_type, resource_type="Microsoft.ContainerService/managedClusters"),
        ("azure_aks_info",),
        skip="aks",
    ),
    Api(
        "cosmos db accounts",
        partial(_resources_of_type, resource_type="Microsoft.DocumentDB/databaseAccounts"),
        ("azure_cosmos_db",),
        skip="cosmos",
    ),
    Api(
        "data protection backup vaults",
        _data_protection,
        (
            "azure_backup_data_protection_vaults",
            "azure_backup_data_protection_policies",
            "azure_backup_data_protection_items",
            "azure_storage_account_info",
            "azure_postgres_info",
        ),
        skip="backup",
        needs=_data_protection_missing,
    ),
    Api("tag names", _tags, _TAG_FILES),
    Api(
        "microsoft defender",
        _defender,
        (SECURITY_JSON,),
        scan="security",
        needs=_defender_missing,
    ),
    Api("microsoft purview", _purview, (PURVIEW_JSON,)),
    Api(
        "blob containers",
        _blob_containers,
        ("azure_storage_account_container_info",),
        skip="storage",
        scan="containers",
        hint=_BLOB_HINT,
        opt_in="--get-container-details",
    ),
    Api(
        "key vaults",
        partial(_resources_of_type, resource_type="Microsoft.KeyVault/vaults"),
        ("azure_key_vault",),
        scan="key_vault",
        opt_in="--get-key-vault-amounts",
    ),
    Api(
        "key vault contents",
        _key_vault_contents,
        ("azure_key_vault",),
        scan="key_vault",
        hint=_KEY_VAULT_HINT,
        opt_in="--get-key-vault-amounts",
    ),
)

_NOT_ENABLED_CODES = frozenset(
    {
        "MissingSubscriptionRegistration",
        "NoRegisteredProviderFound",
        "ResourceProviderNotRegistered",
        "MissingRegistrationForResourceProvider",
    }
)
_DENIED_CODES = frozenset(
    {"AuthorizationFailed", "AuthorizationPermissionMismatch", "LinkedAuthorizationFailed"}
)
_SAFE_CODE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,60}$")
# What azure-identity says when the `az` process times out or fails to start.
_CLI_FAILED = "Failed to invoke the Azure CLI"


def _error_code(exc: HttpResponseError) -> str:
    """The service's short error code (for example ``AuthorizationFailed``), else ``HTTP <n>``."""
    code = getattr(getattr(exc, "error", None), "code", None) or getattr(exc, "error_code", None)
    if isinstance(code, str) and _SAFE_CODE.match(code):
        return code
    return f"HTTP {exc.status_code}" if exc.status_code else type(exc).__name__


def classify(exc: BaseException) -> tuple:
    """Whether a failed call means denied, not enabled, or could not be checked."""
    if isinstance(exc, Outcome):
        return exc.status, exc.code
    if isinstance(exc, ClientAuthenticationError) and _CLI_FAILED in str(exc):
        # `az` timed out or did not start: nothing reached Azure, so it says nothing of access.
        return core.ERROR, "AzureCliUnavailable"
    if isinstance(exc, ClientAuthenticationError):
        return core.DENIED, "AuthenticationFailed"
    if isinstance(exc, HttpResponseError):
        code = _error_code(exc)
        if code in _NOT_ENABLED_CODES:
            return core.NOT_ENABLED, code
        if exc.status_code in (401, 403) or code in _DENIED_CODES:
            return core.DENIED, code
        if exc.status_code == 429:
            return core.ERROR, "TooManyRequests"
        return core.ERROR, code
    return core.ERROR, type(exc).__name__


# A subscription the scan could not read, or whose scan stopped, is one row with these names.
SUBSCRIPTION = "subscription"
SCAN = "scan"
SUBSCRIPTION_READ = "Microsoft.Resources/subscriptions/read"
EVERY_FILE = "every output file of this subscription"
# Azure answers a subscription that does not exist and one this sign-in may not read the same way.
_UNREADABLE_CODES = frozenset({"SubscriptionNotFound", "InvalidSubscriptionId", "HTTP 404"})


def unreadable_check(sub_id: str, exc: BaseException) -> core.Check:
    """The row for a subscription named with --subs that the sign-in could not read."""
    status, code = classify(exc)
    if status == core.NOT_ENABLED or code in _UNREADABLE_CODES:
        status = core.DENIED
    return core.Check(
        sub_id,
        "",
        SCOPE,
        SUBSCRIPTION,
        status,
        None,
        code,
        (EVERY_FILE,),
        "",
        SUBSCRIPTION_READ,
        core.brief_message(exc),
    )


def scan_failed_check(sub_id: str, sub_name: str, exc: BaseException) -> core.Check:
    """The row for a subscription whose scan stopped on an error: it is left out of every file."""
    return core.Check(
        sub_id,
        sub_name,
        SCOPE,
        SCAN,
        core.ERROR,
        None,
        classify(exc)[1],
        (EVERY_FILE,),
        "",
        "",
        core.brief_message(exc),
    )


def _wanted(api: Api, skips: frozenset, scans: dict) -> bool:
    # An optional scan runs unless it was turned off; an opt-in one only when it was asked for.
    return (api.skip is None or api.skip not in skips) and (
        api.scan is None or scans.get(api.scan, not api.opt_in)
    )


def _skip_reason(api: Api, skips: frozenset) -> str:
    if api.needs is not None:
        missing = api.needs()
        if missing:
            return missing
    if api.skip in skips:
        return "skipped by a --skip switch"
    return f"not asked for (add {api.opt_in})" if api.opt_in else "optional scan is off"


def _run(
    sub_id: str,
    sub_name: str,
    credential: Any,
    cloud: Any,
    regions: Optional[list],
    scans: dict,
    skips: frozenset,
    max_workers: int,
) -> list:
    ctx = Context(sub_id, credential, cloud, regions)
    probes = [
        core.Probe(api.label, SCOPE, partial(api.probe, ctx), api.affects, api.hint, api.permission)
        for api in APIS
        if _wanted(api, skips, scans)
    ]
    checks = core.run_probes(sub_id, sub_name, probes, classify, max_workers)
    for api in APIS:
        if not _wanted(api, skips, scans):
            checks.append(
                core.skipped(
                    sub_id,
                    sub_name,
                    SCOPE,
                    api.label,
                    api.affects,
                    _skip_reason(api, skips),
                    api.permission,
                )
            )
    return checks


def run_access_check(
    sub_id: str,
    sub_name: str,
    credential: Any,
    cloud: Any,
    regions: Optional[list],
    scans: dict,
    skips: frozenset,
    max_workers: int = 6,
) -> list:
    """Check what this sign-in can read in one subscription. Never raises."""
    try:
        return _run(sub_id, sub_name, credential, cloud, regions, scans, skips, max_workers)
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "[%s] Access check could not run (%s); the scan goes on", sub_id, type(exc).__name__
        )
        return []


def run_all(
    subscriptions: list,
    names: dict,
    credential: Any,
    cloud: Any,
    regions: Optional[list],
    scans: dict,
    skips: frozenset,
    workers: int = 4,
) -> list:
    """The check for every subscription, a few at a time. One list of checks per subscription."""
    if not subscriptions:
        return []

    def one(sub_id: str) -> list:
        return run_access_check(
            sub_id, names.get(sub_id) or "", credential, cloud, regions, scans, skips
        )

    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(subscriptions)))) as pool:
        return list(pool.map(one, subscriptions))


def report_lines(checks: list, label: str) -> list:
    """The terminal summary for one subscription (see ``preflight_core.summary_lines``)."""
    return core.summary_lines(checks, label, show_scope=False) if checks else []


def table_lines(checks: list) -> list:
    """The permissions table for one subscription (see ``preflight_core.table_lines``)."""
    return core.table_lines(checks) if checks else []


def csv_for(rows: list, anonymizer: Any = None) -> str:
    """The report as CSV. With --anonymize the subscription id and name get the labels the other
    files use; call this after those files are built so it cannot change their numbering."""
    if anonymizer is not None:
        rows = [dict(row) for row in rows]
        for row in rows:
            labelled = anonymizer.anonymize_row(
                {
                    "SubscriptionId": row.get("Owner") or None,
                    "Subscription": row.get("OwnerName") or None,
                }
            )
            row["Owner"] = labelled["SubscriptionId"] or ""
            row["OwnerName"] = labelled["Subscription"] or ""
    return core.csv_text(rows)
