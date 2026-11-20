"""GCP pre-flight access check: one read-only call per service, per project, before a scan.

Each call is the first one a collector makes, limited to one result, so a pass means the scan can
read that service in that project with the sign-in in use. A service whose API is not enabled in
the project is reported as not enabled, which is a different fix from a missing permission.
Collectors left out with ``--collectors`` or ``--inventory-only`` are listed as not requested.

Calls that need a resource name (one Spanner instance's databases, one SQL instance's databases)
are not probed; they fail the same way as the list call that finds the resource. Security Command
Center findings (``--security``) are read at organization level, so they are not part of this
per-project check.
"""

from __future__ import annotations

import logging
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from functools import partial
from typing import Any, Callable, Optional

import auth
import preflight_core as core
from collectors.utils import classify_error

log = logging.getLogger(__name__)

FILE_PREFIX = "gcp_preflight_check"

ASSET_JSON = "asset inventory in the JSON"
ALLOYDB_JSON = "AlloyDB clusters in the JSON"
BIGTABLE_JSON = "Bigtable instances in the JSON"
NON_FILE_EFFECTS = frozenset({ASSET_JSON, ALLOYDB_JSON, BIGTABLE_JSON})


# The IAM permission each probe needs, as Google documents it (not checked against a live project).
# roles/viewer covers the list permissions; BigQuery metadata, Cloud Monitoring and Backup and DR
# need their own viewer roles.
PERMISSIONS = {
    "cloud asset inventory": "cloudasset.assets.listResource",
    "compute instances": "compute.instances.list",
    "compute disks": "compute.disks.list",
    "cloud storage buckets": "storage.buckets.list",
    "cloud monitoring bucket sizes": "monitoring.timeSeries.list",
    "cloud sql instances": "cloudsql.instances.list",
    "spanner instances": "spanner.instances.list",
    "alloydb clusters": "alloydb.clusters.list",
    "bigtable instances": "bigtable.instances.list",
    "bigquery datasets": "bigquery.datasets.get",
    "backup and dr plans": "backupdr.backupPlans.list",
    "backup and dr associations": "backupdr.backupPlanAssociations.list",
}


@dataclass(frozen=True)
class Context:
    project_id: str
    credentials: Any

    @property
    def parent(self) -> str:
        return f"projects/{self.project_id}"

    @property
    def any_location(self) -> str:
        return f"projects/{self.project_id}/locations/-"


@dataclass(frozen=True)
class Api:
    """One probe. It runs when its ``collector`` is one of the collectors being run."""

    collector: str
    label: str
    probe: Callable[[Context], Optional[bool]]
    affects: tuple

    @property
    def permission(self) -> str:
        return PERMISSIONS[self.label]


def _seen(items: Any) -> bool:
    return next(iter(items), None) is not None


def _first_page(pager: Any) -> None:
    """Make the one request an aggregated list needs and say nothing about what it held."""
    next(iter(pager.pages), None)
    return None


def _assets(ctx: Context) -> bool:
    from google.cloud import asset_v1

    client = asset_v1.AssetServiceClient(credentials=ctx.credentials)
    request = asset_v1.ListAssetsRequest(
        parent=ctx.parent, content_type=asset_v1.ContentType.RESOURCE, page_size=1
    )
    return _seen(client.list_assets(request=request))


def _instances(ctx: Context) -> Optional[bool]:
    from google.cloud import compute_v1

    client = compute_v1.InstancesClient(credentials=ctx.credentials)
    request = compute_v1.AggregatedListInstancesRequest(project=ctx.project_id, max_results=1)
    return _first_page(client.aggregated_list(request=request))


def _disks(ctx: Context) -> Optional[bool]:
    from google.cloud import compute_v1

    client = compute_v1.DisksClient(credentials=ctx.credentials)
    request = compute_v1.AggregatedListDisksRequest(project=ctx.project_id, max_results=1)
    return _first_page(client.aggregated_list(request=request))


def _buckets(ctx: Context) -> bool:
    from google.cloud import storage

    client = storage.Client(project=ctx.project_id, credentials=ctx.credentials)
    return _seen(client.list_buckets(max_results=1))


def _bucket_sizes(ctx: Context) -> Optional[bool]:
    import datetime

    from google.cloud import monitoring_v3

    from collectors.storage import BYTES_METRIC

    client = monitoring_v3.MetricServiceClient(credentials=ctx.credentials)
    end = datetime.datetime.now(datetime.timezone.utc)
    request = monitoring_v3.ListTimeSeriesRequest(
        name=ctx.parent,
        filter=f'metric.type="{BYTES_METRIC}" AND resource.type="gcs_bucket"',
        interval=monitoring_v3.TimeInterval(
            end_time=end, start_time=end - datetime.timedelta(days=1)
        ),
        view=monitoring_v3.ListTimeSeriesRequest.TimeSeriesView.HEADERS,
        page_size=1,
    )
    return _first_page(client.list_time_series(request=request))


def _cloud_sql(ctx: Context) -> bool:
    import googleapiclient.discovery

    service = googleapiclient.discovery.build(
        "sqladmin", "v1beta4", credentials=ctx.credentials, cache_discovery=False
    )
    response = service.instances().list(project=ctx.project_id, maxResults=1).execute()
    return bool(response.get("items"))


def _spanner(ctx: Context) -> bool:
    from google.cloud import spanner_admin_instance_v1

    client = spanner_admin_instance_v1.InstanceAdminClient(credentials=ctx.credentials)
    request = spanner_admin_instance_v1.ListInstancesRequest(parent=ctx.parent, page_size=1)
    return _seen(client.list_instances(request=request))


def _alloydb(ctx: Context) -> bool:
    from google.cloud import alloydb_v1

    client = alloydb_v1.AlloyDBAdminClient(credentials=ctx.credentials)
    request = alloydb_v1.ListClustersRequest(parent=ctx.any_location, page_size=1)
    return _seen(client.list_clusters(request=request))


def _bigtable(ctx: Context) -> bool:
    from google.cloud import bigtable

    client = bigtable.Client(project=ctx.project_id, credentials=ctx.credentials, admin=True)
    instances, _failed_locations = client.list_instances()
    return bool(instances)


def _bigquery(ctx: Context) -> bool:
    import googleapiclient.discovery

    service = googleapiclient.discovery.build(
        "bigquery", "v2", credentials=ctx.credentials, cache_discovery=False
    )
    response = service.datasets().list(projectId=ctx.project_id, maxResults=1).execute()
    return bool(response.get("datasets"))


def _backup_plans(ctx: Context) -> bool:
    from google.cloud import backupdr_v1

    client = backupdr_v1.BackupDRClient(credentials=ctx.credentials)
    request = backupdr_v1.ListBackupPlansRequest(parent=ctx.any_location, page_size=1)
    return _seen(client.list_backup_plans(request=request))


def _backup_associations(ctx: Context) -> bool:
    from google.cloud import backupdr_v1

    client = backupdr_v1.BackupDRClient(credentials=ctx.credentials)
    request = backupdr_v1.ListBackupPlanAssociationsRequest(parent=ctx.any_location, page_size=1)
    return _seen(client.list_backup_plan_associations(request=request))


APIS = (
    Api("asset", "cloud asset inventory", _assets, (ASSET_JSON,)),
    Api("compute", "compute instances", _instances, ("gce_vm_info", "gce_attached_disk_info")),
    Api(
        "compute",
        "compute disks",
        _disks,
        ("gce_attached_disk_info", "gce_unattached_disk_info"),
    ),
    Api("storage", "cloud storage buckets", _buckets, ("gce_storage_info",)),
    # Without it the buckets are still listed, but their size columns are blank.
    Api("storage", "cloud monitoring bucket sizes", _bucket_sizes, ("gce_storage_info",)),
    Api("database", "cloud sql instances", _cloud_sql, ("gce_cloudsql_info",)),
    Api("database", "spanner instances", _spanner, ("gce_spanner_info",)),
    Api("database", "alloydb clusters", _alloydb, (ALLOYDB_JSON,)),
    Api("database", "bigtable instances", _bigtable, (BIGTABLE_JSON,)),
    Api("bigquery", "bigquery datasets", _bigquery, ("gce_bigquery_info",)),
    Api("backup", "backup and dr plans", _backup_plans, ("gce_vm_info",)),
    Api("backup", "backup and dr associations", _backup_associations, ("gce_vm_info",)),
)


# The API each probe calls, for the ``gcloud services enable`` a fix prints.
API_NAMES = {
    "cloud asset inventory": "cloudasset.googleapis.com",
    "compute instances": "compute.googleapis.com",
    "compute disks": "compute.googleapis.com",
    "cloud storage buckets": "storage.googleapis.com",
    "cloud monitoring bucket sizes": "monitoring.googleapis.com",
    "cloud sql instances": "sqladmin.googleapis.com",
    "spanner instances": "spanner.googleapis.com",
    "alloydb clusters": "alloydb.googleapis.com",
    "bigtable instances": "bigtableadmin.googleapis.com",
    "bigquery datasets": "bigquery.googleapis.com",
    "backup and dr plans": "backupdr.googleapis.com",
    "backup and dr associations": "backupdr.googleapis.com",
}

# Google charges every call to the login's quota project. When that project is the one refusing,
# the row says nothing about the scanned project: these codes mark it "could not be checked".
QUOTA_API_OFF = "QuotaProjectServiceDisabled"
QUOTA_BILLING_OFF = "QuotaProjectBillingDisabled"
QUOTA_DENIED = "QuotaProjectDenied"
NO_QUOTA_PROJECT = "NoQuotaProject"
QUOTA_CODES = frozenset({QUOTA_API_OFF, QUOTA_BILLING_OFF, QUOTA_DENIED, NO_QUOTA_PROJECT})
_TO_QUOTA = {"ServiceDisabled": QUOTA_API_OFF, "BillingDisabled": QUOTA_BILLING_OFF}

_NO_QUOTA_PROJECT = re.compile(r"requires a quota project|without a quota project")
_ID = r"([\w.:-]*[\w])"
# Where Google names the project it refused the call for, most specific first.
_NAMED_PROJECT = (
    re.compile(rf"has not been used in project {_ID} before"),
    re.compile(rf"billing (?:on|for) project #?{_ID}"),
    re.compile(rf"billing (?:must be|to be) enabled for project #?{_ID}"),
    re.compile(rf"[Bb]illing account for (?:the )?project #?{_ID}"),
    re.compile(rf"Project '{_ID}' requires billing"),
    re.compile(rf"required permission to use project {_ID}"),
    re.compile(rf"consumer\W+(?:value\W+)?projects/{_ID}"),
    re.compile(rf"[?&]project={_ID}"),
)


def named_project(text: str) -> str:
    """The project an error says it refused the call for, or ``""`` when it names none.

    That is the scanned project when the API or billing is off there, and the quota project when
    the refusal is about the project the call was charged to.
    """
    for pattern in _NAMED_PROJECT:
        match = pattern.search(text or "")
        if match:
            return match.group(1)
    return ""


def attribute(checks: list, quota_project: str = "") -> list:
    """The checks, with every API or billing error that is about the quota project marked so.

    An error is about the quota project when the project it names is not the scanned one and is
    the quota project, is a project ID (not a number, which could be the scanned project's own),
    or is named by the errors of two or more scanned projects. Such a row becomes "could not be
    checked": it says nothing about whether the scanned project uses the service.
    """
    named_by: dict = {}
    for check in checks:
        if check.status == core.NOT_ENABLED and check.code in _TO_QUOTA:
            named = named_project(check.message)
            if named:
                named_by.setdefault(named, set()).add(check.owner)
    result = []
    for check in checks:
        named = named_project(check.message) if check.code in _TO_QUOTA else ""
        if (
            check.status == core.NOT_ENABLED
            and named
            and named != check.owner
            and (named == quota_project or not named.isdigit() or len(named_by[named]) > 1)
        ):
            check = replace(check, status=core.ERROR, code=_TO_QUOTA[check.code])
        result.append(check)
    return result


def quota_problems(checks: list) -> list:
    """The rows the quota project blocked, one entry per quota project and kind of refusal.

    Each entry: ``code``, ``project`` (the quota project, ``""`` when the login names none),
    ``services`` (labels), ``apis`` (to enable, in probe order), ``scopes`` (scanned projects) and
    ``message`` (Google's text, for the screen and the log only).
    """
    problems: dict = {}
    for check in checks:
        if check.code not in QUOTA_CODES:
            continue
        project = "" if check.code == NO_QUOTA_PROJECT else named_project(check.message)
        entry = problems.setdefault(
            (check.code, project),
            {
                "code": check.code,
                "project": project,
                "services": [],
                "apis": [],
                "scopes": [],
                "message": check.message,
            },
        )
        api = API_NAMES.get(check.service, "")
        for key, value in (("services", check.service), ("apis", api), ("scopes", check.owner)):
            if value and value not in entry[key]:
                entry[key].append(value)
    return list(problems.values())


def project_groups(checks: list) -> list:
    """The blocked services that are about the scanned projects themselves (``blocked_groups``
    without the quota project's rows), each with the ``api`` its fix enables."""
    groups = core.blocked_groups(c for c in checks if c.code not in QUOTA_CODES)
    for group in groups:
        group["api"] = API_NAMES.get(group["service"], "")
        group["permission"] = PERMISSIONS.get(group["service"], "")
    return groups


def _http_status(exc: BaseException) -> Optional[int]:
    code = getattr(exc, "code", None)
    if isinstance(code, int):
        return int(code)
    status = getattr(getattr(exc, "resp", None), "status", None)
    try:
        return int(status)
    except (TypeError, ValueError):
        return None


def classify(exc: BaseException) -> tuple:
    """Whether a failed call means denied, not enabled, or could not be checked.

    Uses the scan's own ``classify_error``, so the check and the scan agree on what "API
    disabled" and "permission denied" mean. A refusal by the quota project itself (it may not be
    used, or the login names none) says nothing about the scanned project, so it is "could not be
    checked"; ``attribute`` then moves the API and billing errors that name the quota project there
    too.
    """
    if auth.quota_project_denied(exc) is not None:
        return core.ERROR, QUOTA_DENIED
    if _NO_QUOTA_PROJECT.search(str(exc)):
        return core.ERROR, NO_QUOTA_PROJECT
    category = classify_error(exc)  # type: ignore[arg-type]
    if category == "API_DISABLED":
        return core.NOT_ENABLED, "ServiceDisabled"
    if category == "BILLING_DISABLED":
        return core.NOT_ENABLED, "BillingDisabled"
    if category == "PERMISSION_DENIED":
        return core.DENIED, "PermissionDenied"
    if category == "SDK_MISSING":
        return core.ERROR, "SdkMissing"
    if category == "RATE_LIMITED":
        return core.ERROR, "TooManyRequests"
    status = _http_status(exc)
    if status == 401:
        return core.DENIED, "Unauthenticated"
    if status == 403:
        return core.DENIED, "PermissionDenied"
    if status == 429:
        return core.ERROR, "TooManyRequests"
    return core.ERROR, type(exc).__name__


# A project the scan could not read, or whose collection stopped, is one row with these names.
PROJECT = "project"
SCAN = "scan"
PROJECT_GET = "resourcemanager.projects.get"
EVERY_FILE = "every output file of this project"


def unreadable_check(project_id: str, exc: BaseException) -> core.Check:
    """The row for a project named with --projects or --project-file that could not be read.

    Google answers a project that does not exist and one this sign-in may not read the same way,
    so anything but an API that is off counts as denied.
    """
    status, code = classify(exc)
    if status == core.ERROR and code not in ("TooManyRequests", "SdkMissing"):
        status = core.DENIED
    return core.Check(
        project_id,
        "",
        project_id,
        PROJECT,
        status,
        None,
        code,
        (EVERY_FILE,),
        "",
        PROJECT_GET,
        core.brief_message(exc),
    )


def scan_failed_check(project_id: str, exc: BaseException) -> core.Check:
    """The row for a project whose collection stopped on an error: its data is missing."""
    return core.Check(
        project_id,
        "",
        project_id,
        SCAN,
        core.ERROR,
        None,
        type(exc).__name__,
        (EVERY_FILE,),
        "",
        "",
        core.brief_message(exc),
    )


def _run(project_id: str, credentials: Any, selected: set, max_workers: int) -> list:
    ctx = Context(project_id, credentials)
    wanted = [api for api in APIS if api.collector in selected]
    probes = [
        core.Probe(
            api.label, project_id, partial(api.probe, ctx), api.affects, permission=api.permission
        )
        for api in wanted
    ]
    checks = core.run_probes(project_id, "", probes, classify, max_workers)
    for api in APIS:
        if api.collector not in selected:
            checks.append(
                core.skipped(
                    project_id,
                    "",
                    project_id,
                    api.label,
                    api.affects,
                    "collector not selected",
                    api.permission,
                )
            )
    return checks


def run_access_check(
    project_id: str, credentials: Any, selected: set, max_workers: int = 6
) -> list:
    """Check what this sign-in can read in one project. Never raises."""
    try:
        return _run(project_id, credentials, selected, max_workers)
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "[%s] Access check could not run (%s); the scan goes on", project_id, type(exc).__name__
        )
        return []


# The Google libraries each collector imports, as (module, pip package). Checked before sign-in so
# a missing library fails the run in seconds, not after an hour with half the collectors dead.
# Every project listing and the sign-in's project lookup need Resource Manager, whatever is chosen.
ALWAYS_NEEDED_SDKS = (("google.cloud.resourcemanager_v3", "google-cloud-resource-manager"),)
COLLECTOR_SDKS = {
    "asset": (("google.cloud.asset_v1", "google-cloud-asset"),),
    "compute": (("google.cloud.compute_v1", "google-cloud-compute"),),
    "storage": (
        ("google.cloud.storage", "google-cloud-storage"),
        ("google.cloud.monitoring_v3", "google-cloud-monitoring"),
    ),
    "database": (
        ("googleapiclient.discovery", "google-api-python-client"),
        ("google.cloud.spanner_admin_instance_v1", "google-cloud-spanner"),
        ("google.cloud.spanner_admin_database_v1", "google-cloud-spanner"),
        ("google.cloud.alloydb_v1", "google-cloud-alloydb"),
        ("google.cloud.bigtable", "google-cloud-bigtable"),
    ),
    "bigquery": (("googleapiclient.discovery", "google-api-python-client"),),
    "backup": (("google.cloud.backupdr_v1", "google-cloud-backupdr"),),
}


def missing_sdks(selected: set) -> list:
    """``[(package, [collector, ...])]`` for each library the chosen collectors need and the
    environment lacks, in a stable order. A library that is installed but broken counts as
    missing: the scan would fail on the same import."""
    import importlib

    needed: dict = {}
    for module, package in ALWAYS_NEEDED_SDKS:
        needed.setdefault((module, package), ["project lookup"])
    for collector, sdks in COLLECTOR_SDKS.items():
        if collector in selected:
            for sdk in sdks:
                needed.setdefault(sdk, []).append(collector)
    missing: dict = {}
    for (module, package), users in needed.items():
        try:
            importlib.import_module(module)
        except Exception:  # noqa: BLE001 - ImportError, or a library that fails while loading
            for user in users:
                if user not in missing.setdefault(package, []):
                    missing[package].append(user)
    return sorted(missing.items())


def sdk_problem_lines(missing: list) -> list:
    """What to tell the user when ``missing_sdks`` found something: the packages, the fix."""
    packages = " ".join(package for package, _ in missing)
    lines = ["These Google libraries are not installed, so the scan would skip what needs them:"]
    for package, users in missing:
        lines.append(f"   {package}  (needed by: {', '.join(users)})")
    lines += [
        "Install everything the tool needs, from the tool's folder:",
        "   pip install -r requirements.txt",
        f"or just these: pip install {packages}",
        "Or scan without them: name the collectors you can run with --collectors, or accept the "
        "gaps with --no-sdk-check.",
    ]
    return lines


# The quota project cannot serve the calls: they fail in every scanned project the same way.
_QUOTA_STOPPERS = frozenset({QUOTA_API_OFF, QUOTA_BILLING_OFF, QUOTA_DENIED})


def quota_blocking_rows(rows: list) -> list:
    """The access-check rows whose calls the quota project refuses (API off, billing off, denied)."""
    return [row for row in rows if row.get("Detail") in _QUOTA_STOPPERS]


def run_all(projects: list, credentials: Any, selected: set, workers: int = 8) -> list:
    """The check for every project, a few at a time. One list of checks per project."""
    if not projects:
        return []

    def one(project_id: str) -> list:
        return run_access_check(project_id, credentials, selected)

    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(projects)))) as pool:
        return list(pool.map(one, projects))


def switched_off_collectors(rows: list) -> dict:
    """Which collectors the pre-flight found switched off in each project: ``{project: {collector}}``.

    A collector is listed only when every one of its calls came back "not enabled" (API off or
    billing off). The scan then skips it there instead of making calls that are certain to fail.
    A collector with even one readable service, a denied one, or one that could not be checked
    still runs, so a check that guessed wrong costs a few calls and never costs data.
    """
    not_enabled = core.STATUS_TEXT[core.NOT_ENABLED]
    by_project: dict = {}
    for row in rows:
        by_project.setdefault(row.get("Owner"), {}).setdefault(row.get("Service"), []).append(
            row.get("Access")
        )
    result: dict = {}
    for project, services in by_project.items():
        for collector in {api.collector for api in APIS}:
            labels = [api.label for api in APIS if api.collector == collector]
            seen = [services[label] for label in labels if label in services]
            accesses = [access for per_label in seen for access in per_label]
            if accesses and len(seen) == len(labels) and all(a == not_enabled for a in accesses):
                result.setdefault(project, set()).add(collector)
    return result


def report_lines(checks: list, label: str) -> list:
    """The terminal summary for every project at once: each blocked service is one line that
    lists the projects it happened in (see ``preflight_core.summary_lines``)."""
    return core.summary_lines(checks, label) if checks else []


def table_lines(checks: list) -> list:
    """One permissions table across every project (see ``preflight_core.table_lines``)."""
    return core.table_lines(checks, "project") if checks else []


def csv_for(rows: list, anonymizer: Any = None) -> str:
    """The report as CSV. With --anonymize the project gets the label the other files use; call
    this after those files are built so it cannot change their numbering."""
    if anonymizer is not None:
        rows = [dict(row) for row in rows]
        for row in rows:
            for column in ("Owner", "Scope"):
                labelled = anonymizer.anonymize_row({"Project": row.get(column) or None})
                row[column] = labelled["Project"] or ""
    return core.csv_text(rows)
