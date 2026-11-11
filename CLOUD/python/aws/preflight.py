"""AWS pre-flight access check: one read-only call per service and region, before an account is scanned.

The calls are the first call each collector makes, limited to one page, so a pass means the scan
can read that service with the sign-in in use. Regions are checked the way the scan checks them:
a region blocked by a service control policy, or not enabled, is skipped by the scan, so the
report shows one line for it instead of one per service. Services outside ``--services`` and
cost data under ``--no-cost`` are listed as not requested.

Calls that need a resource name (an AWS Backup vault's recovery points, one bucket's tags) are
not probed; they fail the same way as the list call that finds the resource. The exception is S3
Tables and Glue, whose per-table calls are tried on the first table the listing finds: the table
bucket, then its first table, then that table's details, metadata location, maintenance settings
and metadata file, and the first Glue database, its first table and that table's tags. Where the
listing finds nothing there is nothing to try and those rows are left out, not reported as granted.
"""

from __future__ import annotations

import logging
import re
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Iterable, Optional

import preflight_core as core
import runlog
from botocore.config import Config
from botocore.exceptions import ClientError
from collectors import is_scp_denial
from collectors.arns import partition
from collectors.context import cost_explorer_available, query_region

log = logging.getLogger(__name__)

FILE_PREFIX = "aws_preflight_check"

# Short timeouts, because this runs before every scan and must not hold it up.
_CFG = Config(connect_timeout=5, read_timeout=15, retries={"max_attempts": 2, "mode": "standard"})

PLAN_COLUMNS = "BackupPlans and InBackupPlan columns"
PROTECTION_COLUMNS = "backup protection columns"
IAC_SUMMARY = "iac_summary in the JSON"
NON_FILE_EFFECTS = frozenset({PLAN_COLUMNS, PROTECTION_COLUMNS, IAC_SUMMARY})

_BACKUP_CONSUMERS = frozenset({"ec2", "rds", "dynamodb", "efs", "fsx"})


# The IAM action each probe needs. They match the AWS API names (a test checks them against
# botocore); three differ from the API name by design: listing buckets is s3:ListAllMyBuckets,
# CloudWatch actions are cloudwatch:..., not monitoring:..., and reading an object (HeadObject) is
# authorized by s3:GetObject. AWS's service reference maps each S3 Tables API to the s3tables: action
# of the same name.
PERMISSIONS = {
    "iam account summary": "iam:GetAccountSummary",
    "s3 buckets": "s3:ListAllMyBuckets",
    "route53 hosted zones": "route53:ListHostedZones",
    "cost explorer": "ce:GetCostAndUsage",
    "ec2 instances": "ec2:DescribeInstances",
    "ec2 volumes": "ec2:DescribeVolumes",
    "rds instances": "rds:DescribeDBInstances",
    "dynamodb tables": "dynamodb:ListTables",
    "efs file systems": "elasticfilesystem:DescribeFileSystems",
    "fsx file systems": "fsx:DescribeFileSystems",
    "fsx volumes": "fsx:DescribeVolumes",
    "kms keys": "kms:ListKeys",
    "secrets manager secrets": "secretsmanager:ListSecrets",
    "sqs queues": "sqs:ListQueues",
    "vpcs": "ec2:DescribeVpcs",
    "load balancers": "elasticloadbalancing:DescribeLoadBalancers",
    "classic load balancers": "elasticloadbalancing:DescribeLoadBalancers",
    "eks clusters": "eks:ListClusters",
    "redshift clusters": "redshift:DescribeClusters",
    "backup plans": "backup:ListBackupPlans",
    "backup vaults": "backup:ListBackupVaults",
    "backup protected resources": "backup:ListProtectedResources",
    "rds snapshots": "rds:DescribeDBSnapshots",
    "ebs snapshots": "ec2:DescribeSnapshots",
    "machine images": "ec2:DescribeImages",
    "glue databases": "glue:GetDatabases",
    "glue tables": "glue:GetTables",
    "glue table tags": "glue:GetTags",
    "s3 table buckets": "s3tables:ListTableBuckets",
    "s3 tables": "s3tables:ListTables",
    "s3 table details": "s3tables:GetTable",
    "s3 table metadata location": "s3tables:GetTableMetadataLocation",
    "s3 table maintenance settings": "s3tables:GetTableMaintenanceConfiguration",
    "s3 table metadata file": "s3:GetObject",
    "cloudformation stacks": "cloudformation:ListStacks",
    "cloudwatch capacity metrics": "cloudwatch:GetMetricStatistics",
}


@dataclass(frozen=True)
class Api:
    """One probe call. It runs when any service in ``gate`` is being collected."""

    gate: frozenset
    label: str
    client: str
    method: str
    kwargs: Any  # a dict, or a function returning one when the arguments depend on the date
    key: Optional[str]  # the response list that says whether a resource was seen
    affects: tuple
    permission: str
    # A probe that needs a resource name is made from what an earlier probe found: ``needs`` is that
    # probe's label, ``from_item(item, region, account_id)`` turns what it kept into this call's
    # arguments, and ``stash(response, item)`` keeps what the probes after this one need. A probe
    # whose earlier probe found nothing is not run, so it has no row.
    needs: str = ""
    from_item: Optional[Callable[[Any, str, str], dict]] = None
    stash: Optional[Callable[[dict, Any], Any]] = None


def _api(gate, label, client, method, kwargs, key, affects, **chain) -> Api:
    return Api(
        frozenset(gate),
        label,
        client,
        method,
        kwargs,
        key,
        tuple(affects),
        PERMISSIONS[label],
        **chain,
    )


def _first(items: Any) -> Any:
    return (items or [None])[0]


_S3_URI = re.compile(r"^s3://([^/]+)/(.+)$")


def _first_bucket(response: dict, _item: Any) -> Optional[str]:
    return (_first(response.get("tableBuckets")) or {}).get("arn") or None


def _tables_of(bucket_arn: str, _region: str, _account: str) -> dict:
    return {"tableBucketARN": bucket_arn, "maxTables": 1}


def _first_table(response: dict, bucket_arn: str) -> Optional[tuple]:
    table = _first(response.get("tables"))
    return (bucket_arn, table) if table else None


def _table_ids(item: tuple, _region: str, _account: str) -> dict:
    bucket_arn, table = item
    return {
        "tableBucketARN": bucket_arn,
        "namespace": "/".join(table.get("namespace") or []),
        "name": table.get("name", ""),
    }


def _metadata_location(response: dict, _item: Any) -> Optional[str]:
    return response.get("metadataLocation") or None


def _metadata_object(location: str, _region: str, _account: str) -> Optional[dict]:
    match = _S3_URI.match(location or "")
    if not match:
        return None
    return {"Bucket": match.group(1), "Key": match.group(2), "RequestPayer": "requester"}


def _first_database(response: dict, _item: Any) -> Optional[str]:
    return (_first(response.get("DatabaseList")) or {}).get("Name") or None


def _tables_in(database: str, _region: str, _account: str) -> dict:
    return {"DatabaseName": database, "MaxResults": 1}


def _first_glue_table(response: dict, database: str) -> Optional[tuple]:
    name = (_first(response.get("TableList")) or {}).get("Name")
    return (database, name) if name else None


def _glue_table_arn(item: tuple, region: str, account_id: str) -> dict:
    database, table = item
    return {
        "ResourceArn": f"arn:{partition(region)}:glue:{region}:{account_id}:table/{database}/{table}"
    }


def _metric_args() -> dict:
    now = datetime.now(timezone.utc)
    return dict(
        Namespace="AWS/S3",
        MetricName="BucketSizeBytes",
        Dimensions=[
            {"Name": "BucketName", "Value": "access-check"},
            {"Name": "StorageType", "Value": "StandardStorage"},
        ],
        StartTime=now - timedelta(days=2),
        EndTime=now,
        Period=86400,
        Statistics=["Maximum"],
    )


def _cost_args() -> dict:
    today = datetime.now(timezone.utc).date()
    return dict(
        TimePeriod={
            "Start": (today - timedelta(days=2)).isoformat(),
            "End": (today - timedelta(days=1)).isoformat(),
        },
        Granularity="DAILY",
        Metrics=["UnblendedCost"],
    )


# Calls made once per account.
ACCOUNT_APIS = (
    _api({"iam"}, "iam account summary", "iam", "get_account_summary", {}, None, ["aws_iam_info"]),
    _api({"s3"}, "s3 buckets", "s3", "list_buckets", {}, "Buckets", ["aws_s3_info"]),
    _api(
        {"route53"},
        "route53 hosted zones",
        "route53",
        "list_hosted_zones",
        {"MaxItems": "1"},
        "HostedZones",
        ["aws_route53_info"],
    ),
)

# Cost Explorer calls are billed by AWS, so this one runs once per account and only when cost
# data is being collected.
COST_API = _api(
    {"cost"},
    "cost explorer",
    "ce",
    "get_cost_and_usage",
    _cost_args,
    None,
    ["aws_backup_costs", "aws_snapshot_storage_costs"],
)

# Calls made in every region being scanned.
REGIONAL_APIS = (
    _api(
        {"ec2"},
        "ec2 instances",
        "ec2",
        "describe_instances",
        {"MaxResults": 5},
        "Reservations",
        ["aws_ec2_instance_info", "aws_ec2_attached_volume_info"],
    ),
    _api(
        {"ec2"},
        "ec2 volumes",
        "ec2",
        "describe_volumes",
        {"MaxResults": 5},
        "Volumes",
        ["aws_ec2_attached_volume_info", "aws_ec2_unattached_volume_info"],
    ),
    _api(
        {"rds"},
        "rds instances",
        "rds",
        "describe_db_instances",
        {"MaxRecords": 20},
        "DBInstances",
        ["aws_rds_info"],
    ),
    _api(
        {"dynamodb"},
        "dynamodb tables",
        "dynamodb",
        "list_tables",
        {"Limit": 1},
        "TableNames",
        ["aws_DynamoDB_info"],
    ),
    _api(
        {"efs"},
        "efs file systems",
        "efs",
        "describe_file_systems",
        {"MaxItems": 1},
        "FileSystems",
        ["aws_efs_info"],
    ),
    _api(
        {"fsx"},
        "fsx file systems",
        "fsx",
        "describe_file_systems",
        {"MaxResults": 1},
        "FileSystems",
        ["aws_fsx_filesystem_info"],
    ),
    _api(
        {"fsx"},
        "fsx volumes",
        "fsx",
        "describe_volumes",
        {"MaxResults": 1},
        "Volumes",
        ["aws_fsx_volume_info"],
    ),
    _api({"kms"}, "kms keys", "kms", "list_keys", {"Limit": 1}, "Keys", ["aws_kms_numbers"]),
    _api(
        {"secrets"},
        "secrets manager secrets",
        "secretsmanager",
        "list_secrets",
        {"MaxResults": 1},
        "SecretList",
        ["aws_secrets_numbers"],
    ),
    _api(
        {"sqs"},
        "sqs queues",
        "sqs",
        "list_queues",
        {"MaxResults": 1},
        "QueueUrls",
        ["aws_sqs_numbers"],
    ),
    _api({"vpc"}, "vpcs", "ec2", "describe_vpcs", {"MaxResults": 5}, "Vpcs", ["aws_vpc_info"]),
    _api(
        {"lb"},
        "load balancers",
        "elbv2",
        "describe_load_balancers",
        {"PageSize": 1},
        "LoadBalancers",
        ["aws_lb_info"],
    ),
    _api(
        {"lb"},
        "classic load balancers",
        "elb",
        "describe_load_balancers",
        {"PageSize": 1},
        "LoadBalancerDescriptions",
        ["aws_lb_info"],
    ),
    _api(
        {"eks"},
        "eks clusters",
        "eks",
        "list_clusters",
        {"maxResults": 1},
        "clusters",
        ["aws_eks_clusters_info", "aws_eks_nodegroups_info"],
    ),
    _api(
        {"redshift"},
        "redshift clusters",
        "redshift",
        "describe_clusters",
        {"MaxRecords": 20},
        "Clusters",
        ["aws_redshift_info"],
    ),
    _api(
        {"backup"},
        "backup plans",
        "backup",
        "list_backup_plans",
        {"MaxResults": 1},
        "BackupPlansList",
        [PLAN_COLUMNS],
    ),
    _api(
        {"backup", "snapshots"},
        "backup vaults",
        "backup",
        "list_backup_vaults",
        {"MaxResults": 1},
        "BackupVaultList",
        ["aws_backup_recovery_points"],
    ),
    _api(
        _BACKUP_CONSUMERS,
        "backup protected resources",
        "backup",
        "list_protected_resources",
        {"MaxResults": 1},
        "Results",
        [PROTECTION_COLUMNS],
    ),
    _api(
        {"snapshots"},
        "rds snapshots",
        "rds",
        "describe_db_snapshots",
        {"MaxRecords": 20},
        "DBSnapshots",
        ["aws_rds_snapshot_info"],
    ),
    _api(
        {"snapshots"},
        "ebs snapshots",
        "ec2",
        "describe_snapshots",
        {"OwnerIds": ["self"], "MaxResults": 5},
        "Snapshots",
        ["aws_ebs_and_ami_info"],
    ),
    _api(
        {"snapshots"},
        "machine images",
        "ec2",
        "describe_images",
        {"Owners": ["self"], "MaxResults": 5},
        "Images",
        ["aws_ebs_and_ami_info"],
    ),
    _api(
        {"glue"},
        "glue databases",
        "glue",
        "get_databases",
        {"MaxResults": 1},
        "DatabaseList",
        ["aws_glue_iceberg_info"],
        stash=_first_database,
    ),
    _api(
        {"glue"},
        "glue tables",
        "glue",
        "get_tables",
        {},
        "TableList",
        ["aws_glue_iceberg_info"],
        needs="glue databases",
        from_item=_tables_in,
        stash=_first_glue_table,
    ),
    _api(
        {"glue"},
        "glue table tags",
        "glue",
        "get_tags",
        {},
        None,
        ["aws_glue_iceberg_info"],
        needs="glue tables",
        from_item=_glue_table_arn,
    ),
    _api(
        {"s3tables"},
        "s3 table buckets",
        "s3tables",
        "list_table_buckets",
        {"maxBuckets": 1},
        "tableBuckets",
        ["aws_s3_tables_info"],
        stash=_first_bucket,
    ),
    _api(
        {"s3tables"},
        "s3 tables",
        "s3tables",
        "list_tables",
        {},
        "tables",
        ["aws_s3_tables_info"],
        needs="s3 table buckets",
        from_item=_tables_of,
        stash=_first_table,
    ),
    _api(
        {"s3tables"},
        "s3 table details",
        "s3tables",
        "get_table",
        {},
        None,
        ["aws_s3_tables_info"],
        needs="s3 tables",
        from_item=_table_ids,
    ),
    _api(
        {"s3tables"},
        "s3 table metadata location",
        "s3tables",
        "get_table_metadata_location",
        {},
        None,
        ["aws_s3_tables_info"],
        needs="s3 tables",
        from_item=_table_ids,
        stash=_metadata_location,
    ),
    _api(
        {"s3tables"},
        "s3 table maintenance settings",
        "s3tables",
        "get_table_maintenance_configuration",
        {},
        None,
        ["aws_s3_tables_info"],
        needs="s3 tables",
        from_item=_table_ids,
    ),
    _api(
        {"s3tables"},
        "s3 table metadata file",
        "s3",
        "head_object",
        {},
        None,
        ["aws_s3_tables_info"],
        needs="s3 table metadata location",
        from_item=_metadata_object,
    ),
    _api(
        {"iac"},
        "cloudformation stacks",
        "cloudformation",
        "list_stacks",
        {},
        "StackSummaries",
        [IAC_SUMMARY],
    ),
    _api(
        {"s3", "rds", "fsx"},
        "cloudwatch capacity metrics",
        "cloudwatch",
        "get_metric_statistics",
        _metric_args,
        None,
        ["aws_s3_info", "aws_rds_info", "aws_fsx_filesystem_info", "aws_fsx_volume_info"],
    ),
)

_DENIED_MARKERS = ("AccessDenied", "UnauthorizedOperation", "UnauthorizedAccess", "not authorized")
_NOT_ENABLED_CODES = frozenset(
    {
        "OptInRequired",
        "SubscriptionRequiredException",
        "UnrecognizedClientException",
        "InvalidClientTokenId",
        "AuthFailure",
        "DataUnavailableException",
    }
)

_client_lock = threading.Lock()


def _code(exc: BaseException) -> str:
    """The AWS error code, or the exception's class name when it has none."""
    if isinstance(exc, ClientError):
        return str(exc.response.get("Error", {}).get("Code") or type(exc).__name__)
    return type(exc).__name__


def classify(exc: BaseException) -> tuple:
    """Whether a failed service call means denied, not enabled, or could not be checked."""
    if is_scp_denial(exc):
        return core.DENIED, "ServiceControlPolicy"
    code = _code(exc)
    if any(marker in f"{code} {exc}" for marker in _DENIED_MARKERS):
        return core.DENIED, code
    if code in _NOT_ENABLED_CODES:
        return core.NOT_ENABLED, code
    return core.ERROR, code


# An account the scan could not enter, or whose scan stopped, is one row with these service names.
SIGN_IN = "sign in"
SCAN = "scan"
EVERY_FILE = "every output file of this account"
_SIGN_IN_DENIED_CODES = frozenset(
    {
        "AccessDenied",
        "AccessDeniedException",
        "ForbiddenException",
        "UnauthorizedException",
        "InvalidClientTokenId",
        "SignatureDoesNotMatch",
        "UnrecognizedClientException",
        "ExpiredToken",
    }
)


def _root_cause(exc: BaseException) -> BaseException:
    """The AWS error under any wrappers (``cannot assume ...`` is raised from the ClientError)."""
    seen = set()
    while exc.__cause__ is not None and id(exc) not in seen:
        seen.add(id(exc))
        exc = exc.__cause__
    return exc


def sign_in_check(
    account_id: str, account_name: str, exc: BaseException, permission: str
) -> core.Check:
    """The row for an account the scan could not sign in to: nothing in it can be read."""
    cause = _root_cause(exc)
    status, code = classify(cause)
    if status == core.NOT_ENABLED or code in _SIGN_IN_DENIED_CODES:
        status = core.DENIED
    return core.Check(
        account_id,
        account_name,
        "account",
        SIGN_IN,
        status,
        None,
        code,
        (EVERY_FILE,),
        "",
        permission,
        core.brief_message(cause),
    )


def scan_failed_check(account_id: str, account_name: str, exc: BaseException) -> core.Check:
    """The row for an account whose scan stopped on an error: its results are not in the zip."""
    cause = _root_cause(exc)
    return core.Check(
        account_id,
        account_name,
        "account",
        SCAN,
        core.ERROR,
        None,
        _code(cause),
        (EVERY_FILE,),
        "",
        "",
        core.brief_message(cause),
    )


def classify_region(exc: BaseException) -> tuple:
    """A region the scan would skip: blocked by a service control policy, or not enabled."""
    if is_scp_denial(exc):
        return core.DENIED, "ServiceControlPolicy"
    return core.NOT_ENABLED, _code(exc)


def _client(session: Any, name: str, region: str) -> Any:
    # boto3 sessions are not safe to create clients from in several threads at once.
    with _client_lock:
        return session.client(name, region_name=region, config=_CFG)


def _call(
    session: Any, api: Api, region: str, found: Optional[dict] = None, account_id: str = ""
) -> Callable[[], Optional[bool]]:
    """The probe's call. ``found`` holds what earlier probes kept, by (label, region)."""
    found = {} if found is None else found

    def call() -> Optional[bool]:
        item = found.get((api.needs, region))
        if api.from_item is not None:
            kwargs = api.from_item(item, region, account_id)
        else:
            kwargs = api.kwargs() if callable(api.kwargs) else api.kwargs
        method = getattr(_client(session, api.client, region), api.method)
        try:
            response = method(**kwargs)
        except Exception as exc:
            # The scan retries a bare 400 without requester-pays (collectors/iceberg.py); so does this.
            if _code(exc) != "400" or "RequestPayer" not in kwargs:
                raise
            response = method(**{k: v for k, v in kwargs.items() if k != "RequestPayer"})
        if api.stash is not None:
            found[(api.label, region)] = api.stash(response, item)
        return None if api.key is None else bool(response.get(api.key))

    return call


def _region_gate(session: Any, region: str) -> Callable[[], Optional[bool]]:
    """The scan's own region test: a region it would skip is blocked here too."""

    def call() -> Optional[bool]:
        try:
            _client(session, "ec2", region).describe_availability_zones(
                Filters=[{"Name": "state", "Values": ["available"]}]
            )
        except Exception as exc:
            message = str(exc)
            if is_scp_denial(exc):
                raise
            if "UnauthorizedOperation" in message or (
                "AccessDeniedException" in message and "DescribeAvailabilityZones" in message
            ):
                return (
                    None  # the region works; only this listing is not allowed, and the scan goes on
                )
            raise
        return None

    return call


def _wanted(api: Api, services: frozenset) -> bool:
    return bool(api.gate & services)


def _file_effects(apis: Iterable[Api]) -> tuple:
    return tuple(sorted({f for api in apis for f in api.affects if f not in NON_FILE_EFFECTS}))


def _run(
    session: Any,
    account_id: str,
    account_alias: str,
    regions: list,
    services: frozenset,
    collect_cost: bool,
    max_workers: int,
) -> list:
    wanted_services = frozenset(services)
    if collect_cost:
        wanted_services |= {"cost"}
    checks: list = []

    account_apis = [api for api in ACCOUNT_APIS if _wanted(api, wanted_services)]
    if collect_cost and cost_explorer_available():
        account_apis.append(COST_API)
    probes = [
        core.Probe(
            api.label,
            "global",
            _call(session, api, query_region()),
            api.affects,
            permission=api.permission,
        )
        for api in account_apis
    ]
    checks += core.run_probes(account_id, account_alias, probes, classify, max_workers)

    regional = [api for api in REGIONAL_APIS if _wanted(api, wanted_services)]
    gates = core.run_probes(
        account_id,
        account_alias,
        [core.Probe("region", region, _region_gate(session, region)) for region in regions],
        classify_region,
        max_workers,
    )
    live = [region for region, gate in zip(regions, gates) if gate.status == core.OK]
    for gate in gates:
        if gate.status != core.OK:
            gate.service = "all services in region"
            gate.affects = _file_effects(regional)
            checks.append(gate)
    found: dict = {}

    def probes_of(pairs: list) -> list:
        return [
            core.Probe(
                api.label,
                region,
                _call(session, api, region, found, account_id),
                api.affects,
                permission=api.permission,
            )
            for api, region in pairs
        ]

    checks += core.run_probes(
        account_id,
        account_alias,
        probes_of([(api, region) for region in live for api in regional if not api.needs]),
        classify,
        max_workers,
    )
    pending = [api for api in regional if api.needs]
    while pending:
        # A probe made from an earlier probe's finding runs once that finding is there, and only
        # where there is one: a region with no tables has nothing to try, so it gets no row.
        ready = [
            (api, region)
            for api in pending
            for region in live
            if found.get((api.needs, region)) is not None
        ]
        if not ready:
            break
        checks += core.run_probes(
            account_id, account_alias, probes_of(ready), classify, max_workers
        )
        ran = {api.label for api, _ in ready}
        pending = [api for api in pending if api.label not in ran]

    for api in [*ACCOUNT_APIS, COST_API, *REGIONAL_APIS]:
        if _wanted(api, wanted_services):
            continue
        reason = "--no-cost" if api is COST_API else "not in --services"
        checks.append(
            core.skipped(
                account_id, account_alias, "", api.label, api.affects, reason, api.permission
            )
        )
    if collect_cost and not cost_explorer_available():
        checks.append(
            core.skipped(
                account_id,
                account_alias,
                "",
                COST_API.label,
                COST_API.affects,
                "not available in this partition",
                COST_API.permission,
            )
        )
    return checks


def run_access_check(
    session: Any,
    account_id: str,
    account_alias: str,
    regions: list,
    services: frozenset,
    collect_cost: bool,
    max_workers: int = 8,
) -> list:
    """Check what this sign-in can read in one account, before it is scanned. Never raises, so it cannot stop a scan."""
    try:
        return _run(
            session, account_id, account_alias, regions, services, collect_cost, max_workers
        )
    except Exception as exc:  # noqa: BLE001
        log.warning("Access check could not run (%s); the scan goes on without it", _code(exc))
        return []


def report(checks: list, account_id: str, account_alias: str, table: bool = True) -> None:
    """Log the headline and, with ``table`` or whenever something is blocked, the permissions table.

    Blocked services also get one warning line, so they stand out in a long run.
    """
    if not checks:
        return
    label = f"{account_id} ({account_alias})" if account_alias else account_id
    lines = core.summary_lines(checks, label)
    blocked = core.blocked_groups(checks)
    if table or blocked:
        log.info("%s\n%s", lines[0], "\n".join(core.table_lines(checks, "region")))
    else:
        log.info(lines[0])
    if blocked:
        log.warning(
            "Problems found by the pre-flight check:\n%s", "\n".join(runlog.problem_block(blocked))
        )
