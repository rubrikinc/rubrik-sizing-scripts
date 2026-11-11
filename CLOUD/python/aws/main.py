"""AWS Sizing Tool — Lambda handler and CLI entrypoint.

Runs in several modes:
  - SSO scan (default): ``aws-sizing --sso --role-name <PermissionSet>``
    Uses IAM Identity Center credential vending — no IAM role creation needed.
    Uses the token ``aws sso login`` cached, if there is one; otherwise ``--sso-start-url``
    lets the tool sign in itself with the device flow.
    ``--sso-start-url`` is auto-detected from ~/.aws/config if not provided.
  - SSO scan with pre-assumed role: ``aws-sizing --sso --role-name <PermissionSet> --assume-role <ROLE_ARN>``
    Assumes the given IAM role before scanning. Use when the CloudShell identity
    lacks permissions and the customer has pre-deployed a runner role.
  - Org scan: ``aws-sizing --org``
    Assumes RubrikDiscoveryRole in every active account via sts:AssumeRole.
    Requires the StackSet role deployed in each spoke account.
  - Explicit accounts: ``aws-sizing --sso --role-name <PS> --accounts id1,id2,...``
    Skips account discovery; scans only the listed accounts.
  - Single account: ``aws-sizing [--output /path/to/dir]``
    Scans only the currently authenticated account. Useful for testing.
  - AWS Lambda: invoked via Lambda handler, uploads JSON to OUTPUT_BUCKET env var.

All modes output ``aws_sizing_discovery.json`` per account containing the full
inventory and roll-up summary.
"""

from __future__ import annotations

import argparse
import dataclasses
import glob
import json
import logging
import os
import shutil
import sys
import threading
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Optional

import boto3
import csv_export
import manifest_core
import plans_json
import preflight
import preflight_core
import runlog
import totals
from accounts import (
    SSO_DEFAULT_REGION,
    SsoLoginError,
    explain_credential_error,
    resolve_account_ids,
    role_arn,
    select_profiles,
    sso_device_login,
    use_profile_location,
)
from anonymize import KEY_FILE_PREFIX, Anonymizer, anonymized_log_note
from collectors import BOTO_CFG, DenialTracker
from collectors.arns import (
    efs_arn,
    fsx_file_system_arn,
    fsx_volume_arn,
    instance_arn,
    rds_db_arn,
    redshift_arn,
    s3_arn,
    volume_arn,
)
from collectors.backup import (
    fetch_backup_costs,
    fetch_backup_plans,
    fetch_backup_vaults,
    fetch_protected_arns,
)
from collectors.context import DEFAULT_RECOVERY_POINT_TIMEOUT_MINUTES
from collectors.context import configure as configure_partition
from collectors.context import cost_explorer_available, partition_id, query_region
from collectors.cost import (
    fetch_backup_cost_months,
    fetch_service_costs,
    fetch_snapshot_storage_costs,
)
from collectors.dynamodb import fetch_dynamodb
from collectors.ec2 import fetch_instances, fetch_unattached_volumes
from collectors.efs import fetch_efs
from collectors.fsx import fetch_fsx, fetch_fsx_volumes
from collectors.iac import build_iac_summary, fetch_cfn_stacks
from collectors.iceberg import apply_glue_iceberg_to_buckets, fetch_glue_iceberg, fetch_s3_tables
from collectors.eks import fetch_eks
from collectors.kms import fetch_kms_inventory
from collectors.network import fetch_load_balancers, fetch_vpcs
from collectors.redshift import fetch_redshift
from collectors.route53 import fetch_iam_summary, fetch_route53_zones
from collectors.rds import fetch_rds
from collectors.s3 import BucketLocator, StorageLensLookup, fetch_s3
from collectors.recovery_points import fetch_recovery_points, list_plan_names
from collectors.snapshots import (
    apply_backup_summaries,
    fetch_dynamodb_backups,
    fetch_ebs_and_ami,
    fetch_fsx_backups,
    fetch_rds_snapshots,
    fetch_redshift_snapshots,
    merge_backups,
    recovery_point_keys,
)
from collectors.secrets import fetch_secrets
from collectors.sqs import fetch_sqs

# ── Terminal colors + logging ───────────────────────────────────────────────────
# Color codes and logging config live in logging_setup.py so the convention is
# shared across the three cloud CLIs (see docs/observability.md). `_C` is aliased
# here for the terminal box-drawing helpers below.
from logging_setup import C as _C
from logging_setup import add_log_file, setup_logging
from models.discovery import DiscoveryResult, DiscoverySummary

setup_logging()  # default INFO; raised to DEBUG by --verbose in main(), and covers the Lambda path
log = logging.getLogger(__name__)


_ANSI_RE = __import__("re").compile(r"\x1b\[[0-9;]*m")


def _visible_len(s: str) -> int:
    return len(_ANSI_RE.sub("", s))


def _print_box(lines: list[str], color: str = _C.CYAN) -> None:
    width = max(_visible_len(l) for l in lines) + 4
    border = color + _C.BOLD
    rows = [f"\n{border}┌{'─' * width}┐{_C.RESET}"]
    for line in lines:
        pad = width - _visible_len(line) - 2
        rows.append(f"{border}│{_C.RESET}  {line}{' ' * pad}{border}│{_C.RESET}")
    rows.append(f"{border}└{'─' * width}┘{_C.RESET}\n")
    runlog.say("\n".join(rows))


# ── Region scanning ───────────────────────────────────────────────────────────


def _is_scp_denial(exc: Exception) -> bool:
    """Return True when an exception is an SCP explicit-deny (not a real error)."""
    msg = str(exc)
    return "service_control_policy" in msg or (
        "AccessDeniedException" in msg and "explicit deny" in msg
    )


ALL_SERVICES: frozenset[str] = frozenset(
    {
        "ec2",
        "rds",
        "dynamodb",
        "efs",
        "fsx",
        "s3",
        "kms",
        "secrets",
        "sqs",
        "backup",
        "snapshots",
        "vpc",
        "lb",
        "eks",
        "redshift",
        "route53",
        "iam",
        "s3tables",
        "glue",
        "iac",
    }
)

# What runs without --services: everything the PowerShell script collects. "iac" is Python-only
# and opt-in.
DEFAULT_SERVICES: frozenset[str] = ALL_SERVICES - {"iac"}

_BACKUP_PROTECTED_CONSUMERS = frozenset({"ec2", "rds", "dynamodb", "efs", "fsx"})

# The role --org and --cross-account-role take on without --role-name: the one the StackSet creates.
# --sso has no default, as IAM Identity Center has no default permission set.
DEFAULT_ORG_ROLE = "RubrikDiscoveryRole"


def _scan_region(
    session,
    region: str,
    account_id: str,
    account_alias: str,
    services: frozenset[str],
    tracker: "DenialTracker | None" = None,
    bucket_locator: "BucketLocator | None" = None,
    storage_lens: "StorageLensLookup | None" = None,
) -> dict[str, Any]:
    log.info("Scanning region: %s", region)

    # Probe cheaply before running all collectors — if the region is blocked by
    # an SCP we get one clean INFO line instead of ~10 WARNING lines.
    _EMPTY: dict[str, list] = {
        k: []
        for k in (
            "instances",
            "attached",
            "unattached",
            "rds",
            "dynamodb",
            "efs",
            "fsx",
            "s3",
            "kms",
            "secrets",
            "sqs",
            "plans",
            "vaults",
            "cfn",
            "native_backups",
            "rds_snapshots",
            "ebs_ami",
            "vpcs",
            "load_balancers",
            "eks_clusters",
            "eks_nodegroups",
            "kms_keys",
            "redshift",
            "fsx_volumes",
            "s3_tables",
            "glue_iceberg",
            "recovery_points",
            "recovery_aggregates",
            "truncated_backup_regions",
        )
    }
    try:
        session.client("ec2", region_name=region, config=BOTO_CFG).describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )
    except Exception as exc:
        msg = str(exc)
        if _is_scp_denial(exc):
            log.info("Region %s skipped — denied by SCP", region)
            return _EMPTY
        if "UnauthorizedOperation" in msg or (
            "AccessDeniedException" in msg and "DescribeAvailabilityZones" in msg
        ):
            # IAM policy lacks ec2:DescribeAvailabilityZones on the probe, but the
            # region itself IS accessible. Fall through and let collectors run;
            # they each have their own error handling.
            log.debug("Region %s: availability-zone probe denied, scanning anyway", region)
        else:
            # Opt-in region not enabled, unreachable endpoint, etc.
            log.debug("Region %s skipped: %s", region, exc)
            return _EMPTY

    need_protected = bool(services & _BACKUP_PROTECTED_CONSUMERS)
    protected_arns = fetch_protected_arns(session, region, tracker) if need_protected else set()

    instances, attached = (
        fetch_instances(session, region, account_id, account_alias, protected_arns, tracker)
        if "ec2" in services
        else ([], [])
    )
    unattached = (
        fetch_unattached_volumes(
            session, region, account_id, account_alias, protected_arns, tracker
        )
        if "ec2" in services
        else []
    )
    rds = (
        fetch_rds(session, region, account_id, account_alias, protected_arns, tracker)
        if "rds" in services
        else []
    )
    dynamodb = (
        fetch_dynamodb(session, region, account_id, account_alias, protected_arns, tracker)
        if "dynamodb" in services
        else []
    )
    efs = (
        fetch_efs(session, region, account_id, account_alias, protected_arns, tracker)
        if "efs" in services
        else []
    )
    fsx = (
        fetch_fsx(session, region, account_id, account_alias, protected_arns, tracker)
        if "fsx" in services
        else []
    )
    fsx_volumes = (
        fetch_fsx_volumes(session, region, account_id, account_alias, protected_arns, fsx, tracker)
        if "fsx" in services
        else []
    )
    s3 = (
        fetch_s3(
            session,
            region,
            account_id,
            account_alias,
            protected_arns,
            tracker,
            bucket_locator,
            storage_lens,
        )
        if "s3" in services
        else []
    )
    kms: Any = []
    kms_keys: list = []
    if "kms" in services:
        kms, kms_keys = fetch_kms_inventory(session, region, account_id, account_alias, tracker)
    vpcs = (
        fetch_vpcs(session, region, account_id, account_alias, tracker) if "vpc" in services else []
    )
    load_balancers = (
        fetch_load_balancers(session, region, account_id, account_alias, tracker)
        if "lb" in services
        else []
    )
    eks_clusters, eks_nodegroups = (
        fetch_eks(session, region, account_id, account_alias, tracker)
        if "eks" in services
        else ([], [])
    )
    redshift = (
        fetch_redshift(session, region, account_id, account_alias, tracker)
        if "redshift" in services
        else []
    )
    secrets = (
        fetch_secrets(session, region, account_id, account_alias, tracker)
        if "secrets" in services
        else []
    )
    sqs = (
        fetch_sqs(session, region, account_id, account_alias, tracker) if "sqs" in services else []
    )
    plans = (
        fetch_backup_plans(session, region, account_id, account_alias, tracker)
        if "backup" in services
        else []
    )
    vaults = (
        fetch_backup_vaults(session, region, account_id, account_alias)
        if "backup" in services
        else []
    )
    cfn = fetch_cfn_stacks(session, region, account_id, account_alias) if "iac" in services else []

    s3_tables = (
        fetch_s3_tables(session, region, account_id, account_alias, tracker)
        if "s3tables" in services
        else []
    )
    glue_iceberg = (
        fetch_glue_iceberg(session, region, account_id, account_alias, tracker)
        if "glue" in services
        else []
    )

    native_backups: list = []
    rds_snapshots: list = []
    ebs_ami: list = []
    recovery_points: list = []
    recovery_aggregates: list = []
    truncated_backup_regions: list = []
    if "snapshots" in services:
        # Backup capacity follows the resource services that were asked for: RDS snapshots
        # with "rds", EBS snapshots and AMIs with "ec2", FSx backups with "fsx", DynamoDB
        # backups with "dynamodb", Redshift snapshots with "redshift". AWS Backup recovery
        # points are always listed.
        plan_names = (
            {p.plan_id: p.plan_name for p in plans}
            if "backup" in services
            else list_plan_names(session, region)
        )
        recovered = fetch_recovery_points(
            session, region, account_id, account_alias, plan_names, tracker
        )
        recovery_points, recovery_aggregates = recovered.rows, recovered.aggregates
        if recovered.truncated:
            truncated_backup_regions = [region]
        rds_backups: list = []
        ebs_backups: list = []
        if "rds" in services:
            rds_backups, rds_snapshots = fetch_rds_snapshots(
                session, region, account_id, account_alias, tracker
            )
        if "ec2" in services:
            ebs_backups, ebs_ami = fetch_ebs_and_ami(
                session, region, account_id, account_alias, tracker
            )
        fsx_backups = (
            fetch_fsx_backups(session, region, account_id, tracker) if "fsx" in services else []
        )
        ddb_backups = (
            fetch_dynamodb_backups(session, region, account_id, dynamodb, tracker)
            if "dynamodb" in services
            else []
        )
        redshift_backups = (
            fetch_redshift_snapshots(session, region, account_id, tracker)
            if "redshift" in services
            else []
        )
        native_backups = rds_backups + ebs_backups + fsx_backups + ddb_backups + redshift_backups

    log.info(
        "Region %s: %d instances, %d RDS, %d DynamoDB, %d EFS, %d FSx, %d S3, %d backup plans, %d CFN stacks",
        region,
        len(instances),
        len(rds),
        len(dynamodb),
        len(efs),
        len(fsx),
        len(s3),
        len(plans),
        len(cfn),
    )

    return {
        "instances": instances,
        "attached": attached,
        "unattached": unattached,
        "rds": rds,
        "dynamodb": dynamodb,
        "efs": efs,
        "fsx": fsx,
        "fsx_volumes": fsx_volumes,
        "s3_tables": s3_tables,
        "glue_iceberg": glue_iceberg,
        "recovery_points": recovery_points,
        "recovery_aggregates": recovery_aggregates,
        "truncated_backup_regions": truncated_backup_regions,
        "s3": s3,
        "kms": kms,
        "secrets": secrets,
        "sqs": sqs,
        "plans": plans,
        "vaults": vaults,
        "cfn": cfn,
        "native_backups": native_backups,
        "rds_snapshots": rds_snapshots,
        "ebs_ami": ebs_ami,
        "vpcs": vpcs,
        "load_balancers": load_balancers,
        "eks_clusters": eks_clusters,
        "eks_nodegroups": eks_nodegroups,
        "kms_keys": kms_keys,
        "redshift": redshift,
    }


def _scan_all_regions(
    session,
    regions: list[str],
    account_id: str,
    account_alias: str,
    services: frozenset[str],
    tracker: "DenialTracker | None" = None,
) -> dict[str, list]:
    aggregated: dict[str, list] = {
        "instances": [],
        "attached": [],
        "unattached": [],
        "rds": [],
        "dynamodb": [],
        "efs": [],
        "fsx": [],
        "s3": [],
        "kms": [],
        "secrets": [],
        "sqs": [],
        "plans": [],
        "vaults": [],
        "cfn": [],
        "native_backups": [],
        "rds_snapshots": [],
        "ebs_ami": [],
        "vpcs": [],
        "load_balancers": [],
        "eks_clusters": [],
        "eks_nodegroups": [],
        "kms_keys": [],
        "redshift": [],
        "fsx_volumes": [],
        "s3_tables": [],
        "glue_iceberg": [],
        "recovery_points": [],
        "recovery_aggregates": [],
        "truncated_backup_regions": [],
    }
    max_workers = min(len(regions), 20)
    bucket_locator = BucketLocator()  # one bucket listing per account, shared by all regions
    storage_lens = StorageLensLookup(regions)  # likewise for Storage Lens, loaded on first use
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(
                _scan_region,
                session,
                region,
                account_id,
                account_alias,
                services,
                tracker,
                bucket_locator,
                storage_lens,
            ): region
            for region in regions
        }
        for future in as_completed(futures):
            region = futures[future]
            try:
                result = future.result()
                for key in aggregated:
                    value = result[key]
                    if isinstance(value, list):
                        aggregated[key].extend(value)
                    else:
                        aggregated[key].append(value)
            except Exception as exc:
                log.warning("Region %s scan failed: %s", region, exc)
    return aggregated


# ── Summary computation ───────────────────────────────────────────────────────


def _build_summary(
    agg: dict[str, list], backup_costs, iac_summary=None, service_costs=None
) -> DiscoverySummary:
    s = DiscoverySummary()

    s.total_ec2_instances = len(agg["instances"])
    s.total_ec2_vault_protected = sum(1 for i in agg["instances"] if "AWS Backup" in i.backup_plans)
    s.total_ec2_snapshot_only = sum(
        1
        for i in agg["instances"]
        if "EBS Snapshot" in i.backup_plans and "AWS Backup" not in i.backup_plans
    )
    s.total_ec2_protected = s.total_ec2_vault_protected + s.total_ec2_snapshot_only
    s.total_ec2_unprotected = s.total_ec2_instances - s.total_ec2_protected
    s.ec2_protection_pct = (
        round(s.total_ec2_protected / s.total_ec2_instances * 100, 1)
        if s.total_ec2_instances > 0
        else 0.0
    )

    s.total_attached_disk_tb = round(sum(v.size_tb for v in agg["attached"]), 4)
    s.total_unattached_disk_tb = round(sum(v.size_tb for v in agg["unattached"]), 4)
    s.total_disk_tb = round(s.total_attached_disk_tb + s.total_unattached_disk_tb, 4)

    s.total_rds_instances = len(agg["rds"])
    s.total_rds_protected = sum(1 for r in agg["rds"] if r.in_backup_plan)
    s.total_rds_tb = round(sum(r.size_gib / 1024 for r in agg["rds"]), 4)

    s.total_dynamodb_tables = len(agg["dynamodb"])
    s.total_dynamodb_protected = sum(1 for t in agg["dynamodb"] if t.in_backup_plan)
    s.total_dynamodb_tb = round(sum(t.size_tb for t in agg["dynamodb"]), 6)

    s.total_efs_filesystems = len(agg["efs"])
    s.total_efs_protected = sum(1 for f in agg["efs"] if f.in_backup_plan)
    s.total_efs_tb = round(sum(f.size_tb for f in agg["efs"]), 4)

    s.total_fsx_filesystems = len(agg["fsx"])
    s.total_fsx_protected = sum(1 for f in agg["fsx"] if f.in_backup_plan)
    s.total_fsx_tb = round(sum(f.storage_capacity_tb for f in agg["fsx"]), 4)

    s.total_s3_buckets = len(agg["s3"])
    s.total_s3_gb = round(sum(b.size_gb for b in agg["s3"]), 4)
    s.total_s3_tb = round(s.total_s3_gb / 1024, 4)

    s.total_kms_keys = sum(k.key_count for k in agg["kms"])
    s.total_secrets = sum(x.secret_count for x in agg["secrets"])
    s.total_sqs_queues = sum(q.queue_count for q in agg["sqs"])

    s.total_backup_plans = len(agg["plans"])
    s.total_12mo_backup_spend_usd = round(sum(e.amortized_cost for e in backup_costs), 2)
    s.total_12mo_aws_spend_usd = round(sum(e.amortized_cost for e in (service_costs or [])), 2)

    if iac_summary:
        s.iac_has_iac = iac_summary.has_iac
        s.iac_tools_detected = iac_summary.tools_detected
        s.iac_devops_opportunity = iac_summary.devops_opportunity
        s.iac_cloudformation_stacks = iac_summary.cloudformation_stack_count
        s.iac_cdk_stacks = iac_summary.cdk_stack_count

    return s


# ── JSON serialisation ────────────────────────────────────────────────────────


def _to_dict(obj: Any) -> Any:
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {k: _to_dict(v) for k, v in dataclasses.asdict(obj).items()}
    if isinstance(obj, (list, tuple)):
        return [_to_dict(i) for i in obj]
    return obj


# ── S3 upload ─────────────────────────────────────────────────────────────────


def _upload_to_s3(
    session, local_path: str, bucket_name: str, object_key: str, bucket_region: str
) -> None:
    s3 = session.client("s3", region_name=bucket_region)
    with open(local_path, "rb") as f:
        s3.put_object(Bucket=bucket_name, Key=object_key, Body=f)
    log.info("Uploaded %s → s3://%s/%s", local_path, bucket_name, object_key)


# ── Zip + completion banner ───────────────────────────────────────────────────


def _write_key_file(anonymizer: Anonymizer, directory: str, stamp: str) -> str:
    """The file that maps every anonymized value back to the real one (kept out of the zip)."""
    path = os.path.join(directory, f"{KEY_FILE_PREFIX}-{stamp}.csv")
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(anonymizer.key_file_text())
    return path


def _plans_json_text(plans: list[dict], stamp: str) -> Optional[str]:
    """The backup plans JSON, or None when it could not be built.

    Never raises: a problem with this file must not cost the CSV files or the zip, and neither
    packaging path has a tracker to record it in, so it is only logged.
    """
    try:
        return plans_json.build(plans)
    except Exception as exc:
        log.warning("Could not build %s: %s", plans_json.file_name(stamp), exc)
        return None


def _manifest_text(files: dict[str, Any]) -> Optional[str]:
    """The manifest.json of a results zip, or None when it could not be built.

    ``files`` maps each file name in the zip to its text or bytes. Never raises: a problem with the
    manifest must not cost the zip, so it is only logged.
    """
    try:
        return manifest_core.build(
            files,
            tool="aws",
            tool_version=manifest_core.installed_version("aws-sizing"),
            code_version=runlog.core.code_version(runlog.HERE),
            generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        )
    except Exception as exc:
        log.warning("Could not build %s: %s", manifest_core.FILE_NAME, exc)
        return None


def _access_check_csv(
    discoveries: list[dict],
    stamp: str,
    anonymizer: Optional[Anonymizer],
    extra_rows: Iterable[dict] = (),
) -> dict[str, str]:
    """The pre-flight report of every account as one CSV file, or nothing if none was written.

    ``extra_rows`` are rows for accounts that have no discovery file in the zip: an account the
    scan could not sign in to, one whose scan stopped, one held back by a service control policy,
    and every account of a ``--preflight-only`` run.

    With --anonymize the account id and alias get the labels the other CSV files use; this is
    done after those files are built, so it cannot change their numbering.
    """
    rows = [row for d in discoveries for row in d.get("access_check") or []]
    rows.extend(dict(row) for row in extra_rows)
    if not rows:
        return {}
    if anonymizer is not None:
        for row in rows:
            labelled = anonymizer.anonymize_row(
                {
                    "AwsAccountId": row.get("Owner") or None,
                    "AwsAccountAlias": row.get("OwnerName") or None,
                }
            )
            row["Owner"] = labelled["AwsAccountId"] or ""
            row["OwnerName"] = labelled["AwsAccountAlias"] or ""
    return {preflight_core.file_name(preflight.FILE_PREFIX, stamp): preflight_core.csv_text(rows)}


def _package_results(
    progress_dir: str,
    zip_path: str,
    success: int,
    failed: int,
    elapsed_secs: float = 0.0,
    write_csv: bool = True,
    anonymizer: Optional[Anonymizer] = None,
    stamp: Optional[str] = None,
    title: str = "Org Scan Complete",
    collect_cost: bool = True,
    not_scanned: Optional[list[dict]] = None,
) -> str:
    not_scanned = not_scanned or []
    stamp = stamp or _run_stamp()
    results: list[dict] = []
    scanned: list[dict] = []
    plans: list[dict] = []
    in_zip: dict[str, Any] = {}  # every data file written below, for the manifest
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for acct_id_dir in sorted(os.listdir(progress_dir)):
            json_file = os.path.join(progress_dir, acct_id_dir, "aws_sizing_discovery.json")
            if os.path.exists(json_file):
                # The raw JSON holds every real name, so an anonymized zip leaves it out.
                if anonymizer is None:
                    with open(json_file, "rb") as f:
                        raw = f.read()
                    in_zip[f"{acct_id_dir}/aws_sizing_discovery.json"] = raw
                    zf.writestr(f"{acct_id_dir}/aws_sizing_discovery.json", raw)
                with open(json_file, encoding="utf-8") as f:
                    discovery = json.load(f)
                scanned.append(discovery)
                # The plans come from every account file, resumed ones included, whether or not
                # CSV files are written; an anonymized zip has no plans file either.
                if write_csv or anonymizer is None:
                    if write_csv:
                        results.append(discovery)
                    plans.extend(plans_json.plans_of(discovery))
        if write_csv:
            # One set of CSVs for all accounts, like the PowerShell script's output.
            for name, text in csv_export.build_csv_files(results, stamp, anonymizer).items():
                in_zip[name] = text
                zf.writestr(name, text)
            extra = [row for entry in not_scanned for row in entry["rows"]]
            for name, text in _access_check_csv(results, stamp, anonymizer, extra).items():
                in_zip[name] = text
                zf.writestr(name, text)
        if anonymizer is None:
            plans_text = _plans_json_text(plans, stamp)
            if plans_text is not None:
                in_zip[plans_json.file_name(stamp)] = plans_text
                zf.writestr(plans_json.file_name(stamp), plans_text)
        manifest_text = _manifest_text(in_zip)  # last, so it lists everything above
        if manifest_text is not None:
            zf.writestr(manifest_core.FILE_NAME, manifest_text)
    if anonymizer is not None:
        key_path = _write_key_file(anonymizer, os.path.dirname(os.path.abspath(zip_path)), stamp)
        log.info("Anonymized keys to actual values: %s (not in the zip)", key_path)
    _print_totals(scanned, collect_cost)

    mins, secs = divmod(int(elapsed_secs), 60)
    elapsed_str = f"{mins}m {secs}s" if mins else f"{secs}s"

    status = f"{_C.GREEN}✓{_C.RESET}" if failed == 0 else f"{_C.YELLOW}⚠{_C.RESET}"
    abs_zip = os.path.abspath(zip_path)
    _print_box(
        [
            f"{_C.BOLD}{_C.WHITE}{title} {status}{_C.RESET}",
            "",
            f"{_C.GREEN}✓{_C.RESET}  Accounts scanned   {_C.BOLD}{success}{_C.RESET}",
            f"{_failed_mark(failed)}Failed / skipped   {_C.BOLD}{failed}{_C.RESET}",
            f"   Elapsed time       {_C.BOLD}{elapsed_str}{_C.RESET}",
            *_not_scanned_lines(not_scanned),
            "",
            "Results zip:",
            f"   {_C.BOLD}{_C.CYAN}{abs_zip}{_C.RESET}",
            "",
            "To download from CloudShell:",
            "   Actions → Download file",
            f"   Path: {_C.BOLD}{abs_zip}{_C.RESET}",
        ]
    )
    return zip_path


# The closing box names this many accounts that were not scanned; the CSV has all of them.
_NOT_SCANNED_SHOWN = 20


def _failed_mark(failed: int) -> str:
    """The 3 columns before a closing-box count of failed accounts, as wide as the "✓  " lines."""
    return "   " if failed == 0 else f"{_C.YELLOW}⚠{_C.RESET}  "


def _not_scanned_lines(not_scanned: list[dict], heading: str = "Not scanned:") -> list[str]:
    """Lines for the closing box: each account that was not scanned and why, worst first."""
    if not not_scanned:
        return []
    lines = ["", f"{_C.YELLOW}{heading}{_C.RESET}"]
    for entry in sorted(not_scanned, key=lambda e: (e["why"], e["id"] or "", e["name"] or ""))[
        :_NOT_SCANNED_SHOWN
    ]:
        who = entry["id"] or entry["name"] or "?"
        if entry["name"] and entry["name"] != entry["id"]:
            who = f"{who} ({entry['name']})"
        lines.append(f"   {who}  {entry['why']}")
    if len(not_scanned) > _NOT_SCANNED_SHOWN:
        lines.append(
            f"   ... and {len(not_scanned) - _NOT_SCANNED_SHOWN} more; every one is in "
            f"{preflight.FILE_PREFIX}-<timestamp>.csv"
        )
    return lines


# ── Resume helpers ────────────────────────────────────────────────────────────


def _find_latest_progress_dir(zip_dir: str) -> Optional[str]:
    """Return the most-recent aws-sizing-progress-* directory, or None."""
    dirs = sorted(glob.glob(os.path.join(zip_dir, "aws-sizing-progress-*")))
    return dirs[-1] if dirs else None


def _completed_account_ids(progress_dir: str) -> set:
    """Return set of account IDs that already have a completed JSON in progress_dir."""
    completed = set()
    try:
        for entry in os.listdir(progress_dir):
            if os.path.exists(os.path.join(progress_dir, entry, "aws_sizing_discovery.json")):
                completed.add(entry)
    except FileNotFoundError:
        pass
    return completed


# ── Core orchestration ────────────────────────────────────────────────────────


# ── Optional-scan opt-in ─────────────────────────────────────────────────────
# Each optional scan can be hard-skipped with a --no-<scan> flag. A scan with
# prompt=True also asks yes/no in an interactive terminal (a TTY — preserved by
# the `bash <(curl …)` CloudShell form); prompt=False scans are always on unless
# the flag says otherwise. Non-interactive runs (piped / CI) default to scanning.
# Each entry is (key, flag_attr, question, prompt).
_OPTIONAL_SCANS: tuple[tuple[str, str, str, bool], ...] = (
    ("cost", "no_cost", "Scan cost data (include current backup spend)?", True),
    ("capacity", "no_capacity", "Scan S3 storage sizing (CloudWatch BucketSizeBytes)?", False),
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


def _resolve_scans(args) -> dict[str, bool]:
    """Decide which optional scans run: flag hard-skips, else prompt on a TTY, else on."""
    interactive = sys.stdin.isatty()
    choices: dict[str, bool] = {}
    for key, flag_attr, question, prompt in _OPTIONAL_SCANS:
        if getattr(args, flag_attr, False):
            choices[key] = False
        elif prompt and interactive:
            choices[key] = _ask_yes_no(question)
        else:
            choices[key] = True
    log.info(
        "Optional scans — %s",
        ", ".join(f"{k}={'on' if v else 'off'}" for k, v in choices.items()),
    )
    return choices


def _account_identity(session: Any) -> tuple[str, str]:
    """The account id and its alias (empty when it has none or the alias cannot be read)."""
    sts = session.client("sts", region_name=query_region())
    account_id = sts.get_caller_identity()["Account"]
    iam = session.client("iam", region_name=query_region())
    try:
        aliases = iam.list_account_aliases().get("AccountAliases", [])
        account_alias = aliases[0] if aliases else ""
    except Exception:
        account_alias = ""
    if account_alias:
        log.info("Account: %s (%s)", account_id, account_alias)
    else:
        log.info("Account: %s", account_id)
    return account_id, account_alias


def _resolve_regions(
    session: Any, regions: Optional[list[str]], exclude_regions: Optional[list[str]]
) -> list[str]:
    """The regions to scan: the ones asked for, else every enabled one, minus the excluded."""
    if regions:
        log.info("Scanning %d regions (user-specified)", len(regions))
    else:
        ec2_global = session.client("ec2", region_name=query_region())
        region_resp = ec2_global.describe_regions(
            Filters=[{"Name": "opt-in-status", "Values": ["opt-in-not-required", "opted-in"]}]
        )
        regions = [r["RegionName"] for r in region_resp["Regions"]]
        log.info("Scanning %d regions", len(regions))

    if exclude_regions:
        excluded = set(exclude_regions)
        regions = [r for r in regions if r not in excluded]
        log.info("Excluded regions: %s — scanning %d", ", ".join(sorted(excluded)), len(regions))
    return regions


def check_access(
    session: Optional[Any] = None,
    regions: Optional[list[str]] = None,
    exclude_regions: Optional[list[str]] = None,
    services: Optional[frozenset[str]] = None,
    collect_cost: bool = True,
    access_table: bool = True,
) -> list[dict]:
    """Only the access check of one account (``--preflight-only``): its CSV rows. Nothing is
    collected."""
    if session is None:
        session = boto3.session.Session()
    account_id, account_alias = _account_identity(session)
    regions = _resolve_regions(session, regions, exclude_regions)
    active_services = services if services is not None else DEFAULT_SERVICES
    checks = preflight.run_access_check(
        session, account_id, account_alias, regions, active_services, collect_cost
    )
    preflight.report(checks, account_id, account_alias, access_table)
    return [check.to_row() for check in checks]


def run(
    output_dir: str = "/tmp",
    session: Optional[Any] = None,
    regions: Optional[list[str]] = None,
    exclude_regions: Optional[list[str]] = None,
    services: Optional[frozenset[str]] = None,
    collect_cost: bool = True,
    denial_tracker: "DenialTracker | None" = None,
    access_check: bool = True,
    access_table: bool = True,
) -> str:
    """Run the full discovery + analysis pipeline for a single account."""
    if session is None:
        session = boto3.session.Session()
    if denial_tracker is None:
        denial_tracker = DenialTracker()

    account_id, account_alias = _account_identity(session)
    regions = _resolve_regions(session, regions, exclude_regions)

    active_services = services if services is not None else DEFAULT_SERVICES
    if active_services != DEFAULT_SERVICES:
        log.info("Service filter: %s", ", ".join(sorted(active_services)))

    access_rows: list[dict] = []
    if access_check:
        checks = preflight.run_access_check(
            session, account_id, account_alias, regions, active_services, collect_cost
        )
        preflight.report(checks, account_id, account_alias, access_table)
        access_rows = [check.to_row() for check in checks]

    agg = _scan_all_regions(
        session, regions, account_id, account_alias, active_services, denial_tracker
    )

    if collect_cost and not cost_explorer_available():
        log.info("Skipping cost collection: Cost Explorer is not available in this partition")
        collect_cost = False

    if collect_cost:
        log.info("Fetching 12-month AWS Backup cost history...")
        backup_costs = (
            fetch_backup_costs(session, account_id, account_alias)
            if "backup" in active_services
            else []
        )

        log.info("Fetching 12-month total AWS spend by service...")
        service_costs = fetch_service_costs(session, account_id, account_alias)
        if regions and not any(r.startswith("us-gov") for r in regions):
            log.info("Fetching AWS Backup and snapshot storage cost detail...")
            backup_cost_months = fetch_backup_cost_months(
                session, account_id, account_alias, denial_tracker
            )
            snapshot_storage_costs = fetch_snapshot_storage_costs(
                session, account_id, account_alias, denial_tracker
            )
        else:
            log.info("Skipping AWS Backup and snapshot cost detail (no regions, or GovCloud)")
            backup_cost_months, snapshot_storage_costs = [], []
        if not service_costs:
            # Opted into cost but got nothing — usually missing Cost Explorer access.
            log.warning(
                "Cost data requested but none returned (check Cost Explorer / ce:GetCostAndUsage access)"
            )
    else:
        log.info("Skipping cost collection (opted out)")
        backup_costs = []
        service_costs = []
        backup_cost_months, snapshot_storage_costs = [], []

    apply_glue_iceberg_to_buckets(agg["s3"], agg.get("glue_iceberg", []))

    if "snapshots" in active_services:
        merged = merge_backups(agg.get("native_backups", []), agg.get("recovery_aggregates", []))
        state = dict(
            recovery_keys=recovery_point_keys(agg.get("recovery_aggregates", [])),
            truncated_regions=frozenset(agg.get("truncated_backup_regions", [])),
        )
        apply_backup_summaries(
            agg["instances"],
            merged,
            lambda r: instance_arn(r.region, r.account_id, r.instance_id),
            **state,
        )
        for volumes in (agg["attached"], agg["unattached"]):
            apply_backup_summaries(
                volumes, merged, lambda r: volume_arn(r.region, r.account_id, r.volume_id), **state
            )
        apply_backup_summaries(
            agg["rds"],
            merged,
            lambda r: rds_db_arn(r.region, r.account_id, r.db_instance_identifier),
            **state,
        )
        apply_backup_summaries(
            agg.get("redshift", []),
            merged,
            lambda r: redshift_arn(r.region, r.account_id, r.cluster_identifier),
            **state,
        )
        apply_backup_summaries(
            agg["efs"], merged, lambda r: efs_arn(r.region, r.account_id, r.file_system_id), **state
        )
        apply_backup_summaries(agg["dynamodb"], merged, lambda r: r.table_arn, **state)
        apply_backup_summaries(
            agg["fsx"],
            merged,
            lambda r: fsx_file_system_arn(r.region, r.account_id, r.file_system_id),
            **state,
        )
        apply_backup_summaries(
            agg.get("fsx_volumes", []),
            merged,
            lambda r: fsx_volume_arn(r.region, r.account_id, r.volume_id),
            **state,
        )
        apply_backup_summaries(
            agg["s3"], merged, lambda r: s3_arn(r.region, r.bucket_name), **state
        )

    route53_zones = (
        fetch_route53_zones(session, account_id, account_alias, denial_tracker)
        if "route53" in active_services
        else []
    )
    iam_summary = (
        fetch_iam_summary(session, account_id, account_alias, denial_tracker)
        if "iam" in active_services
        else None
    )

    iac_summary = None
    if "iac" in active_services:
        log.info("Building IaC signal summary...")
        iac_summary = build_iac_summary(
            account_id=account_id,
            account_alias=account_alias,
            cfn_stacks=agg["cfn"],
            s3_bucket_names=[b.bucket_name for b in agg["s3"]],
            dynamodb_table_names=[t.table_name for t in agg["dynamodb"]],
            ec2_tags=[i.tags for i in agg["instances"]],
            rds_tags=[r.tags for r in agg["rds"]],
        )
        if iac_summary.has_iac:
            log.info(
                "IaC detected — tools: %s | DevOps opportunity: %s | %d CFN stacks (%d CDK)",
                ", ".join(iac_summary.tools_detected),
                iac_summary.devops_opportunity,
                iac_summary.cloudformation_stack_count,
                iac_summary.cdk_stack_count,
            )
        else:
            log.info("No IaC signals detected in this account")

    summary = _build_summary(agg, backup_costs, iac_summary, service_costs)
    log.info(
        "Scan complete — %d EC2 (%d protected / %d unprotected), %.2f TB disk, $%.2f backup spend",
        summary.total_ec2_instances,
        summary.total_ec2_protected,
        summary.total_ec2_unprotected,
        summary.total_disk_tb,
        summary.total_12mo_backup_spend_usd,
    )

    scp_restrictions_suspected = bool(denial_tracker)
    perm_errors = denial_tracker.permission_errors() if denial_tracker is not None else []
    if perm_errors:
        log.warning(
            "Account %s: %d IAM permission error(s) prevented full collection — "
            "some resources may be missing. Check 'scan_errors' in the output JSON.",
            account_id,
            len(perm_errors),
        )

    # Risk is intentionally NOT computed here — the customer discovery run is a
    # pure data pull. The Rubrik SE generates the Monte Carlo risk model from
    # this JSON in analyze.py (which recomputes it from the discovery summaries).
    result = DiscoveryResult(
        schema_version="1.0",
        account_id=account_id,
        account_alias=account_alias,
        generated_at=datetime.now(timezone.utc).isoformat(),
        regions_scanned=regions,
        ec2_instances=agg["instances"],
        ec2_attached_volumes=agg["attached"],
        ec2_unattached_volumes=agg["unattached"],
        rds_instances=agg["rds"],
        dynamodb_tables=agg["dynamodb"],
        efs_filesystems=agg["efs"],
        fsx_filesystems=agg["fsx"],
        fsx_volumes=agg.get("fsx_volumes", []),
        s3_tables=agg.get("s3_tables", []),
        glue_iceberg_tables=agg.get("glue_iceberg", []),
        backup_recovery_points=agg.get("recovery_points", []),
        backup_resource_aggregates=agg.get("recovery_aggregates", []),
        truncated_backup_regions=sorted(set(agg.get("truncated_backup_regions", []))),
        s3_buckets=agg["s3"],
        kms_counts=agg["kms"],
        secrets_counts=agg["secrets"],
        sqs_counts=agg["sqs"],
        backup_plans=agg["plans"],
        backup_vaults=agg["vaults"],
        rds_snapshots=agg.get("rds_snapshots", []),
        ebs_and_ami=agg.get("ebs_ami", []),
        backup_cost_months=backup_cost_months,
        snapshot_storage_costs=snapshot_storage_costs,
        vpcs=agg.get("vpcs", []),
        load_balancers=agg.get("load_balancers", []),
        eks_clusters=agg.get("eks_clusters", []),
        eks_nodegroups=agg.get("eks_nodegroups", []),
        kms_keys=agg.get("kms_keys", []),
        route53_zones=route53_zones,
        iam_summaries=[iam_summary] if iam_summary is not None else [],
        redshift_clusters=agg.get("redshift", []),
        backup_costs=backup_costs,
        service_costs=service_costs,
        summary=summary,
        iac_summary=_to_dict(iac_summary) if iac_summary else None,
        scp_restrictions_suspected=scp_restrictions_suspected,
        scan_errors=perm_errors,
        access_check=access_rows,
    )

    out_path = os.path.join(output_dir, "aws_sizing_discovery.json")
    with open(out_path, "w") as f:
        json.dump(_to_dict(result), f, indent=2, default=str)
    log.info("Discovery JSON written to %s", out_path)

    abs_path = os.path.abspath(out_path)
    _print_box(
        [
            f"{_C.BOLD}{_C.WHITE}Scan Complete {_C.GREEN}✓{_C.RESET}",
            "",
            "Discovery file:",
            f"   {_C.BOLD}{_C.CYAN}{abs_path}{_C.RESET}",
            "",
            "To download from CloudShell:",
            "   Actions → Download file",
            f"   Path: {_C.BOLD}{abs_path}{_C.RESET}",
        ],
        color=_C.GREEN,
    )

    return out_path


# ── Org-wide orchestration (sts:AssumeRole) ───────────────────────────────────


def _run_stamp(now: Optional[datetime] = None) -> str:
    """The run's timestamp as PowerShell writes it in file names: ``2026-10-05_140650``."""
    return (now or datetime.now()).strftime(csv_export.TIMESTAMP_FORMAT)


def _zip_name(stamp: str) -> str:
    return f"aws_sizing_results_{stamp}.zip"


# A scan of this many accounts or fewer prints the full permissions table for each; a larger one
# prints the table only for an account with something blocked.
_TABLE_ACCOUNTS = 3


def _scan_accounts(
    targets: list[dict],
    open_session: Callable[[dict], Any],
    *,
    label: str,
    scp_hint: str = "",
    zip_dir: str = ".",
    bucket_name: str = "",
    bucket_region: str = "us-east-1",
    regions: Optional[list[str]] = None,
    exclude_regions: Optional[list[str]] = None,
    services: Optional[frozenset[str]] = None,
    max_workers: int = 8,
    collect_cost: bool = True,
    write_csv: bool = True,
    anonymizer: Optional[Anonymizer] = None,
    stamp: Optional[str] = None,
    access_check: bool = True,
    sign_in_permission: str = "",
    preflight_only: bool = False,
) -> str:
    """Scan every target (account or profile), a few in parallel, and zip the results.

    ``targets`` are ``{"id": account id or None, "name": ...}``; ``open_session`` turns one into
    a boto3 session (and may raise). A target without an id gets it from STS once its session is
    open. Finished accounts are kept in a progress folder, so a rerun resumes where it stopped.

    Every account that is not scanned (no sign-in, a scan that stopped, a service control policy)
    keeps rows in the pre-flight CSV and is listed by name at the end. ``sign_in_permission`` is
    what opening a session needs (``sts:AssumeRole``, ``sso:GetRoleCredentials``), for its row.

    ``preflight_only`` signs in and runs only the access check in each account: no collection,
    no progress folder (so it never affects a later resume), and a zip with the CSV alone.
    """
    abs_zip_dir = os.path.abspath(zip_dir)
    stamp = stamp or _run_stamp()
    completed_ids: set = set()
    progress_dir = ""
    if preflight_only:
        zip_path = os.path.join(abs_zip_dir, _access_zip_name(stamp))
        log.info("Access check only: nothing is collected and no progress folder is used")
    else:
        existing_dir = _find_latest_progress_dir(abs_zip_dir)
        completed_ids = _completed_account_ids(existing_dir) if existing_dir else set()
        if completed_ids:
            progress_dir = existing_dir
            targets = [t for t in targets if not t.get("id") or t["id"] not in completed_ids]
            log.info(
                "Resuming from %s — %d already complete, %d remaining",
                progress_dir,
                len(completed_ids),
                len(targets),
            )
        else:
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
            progress_dir = os.path.join(abs_zip_dir, f"aws-sizing-progress-{timestamp}")
            os.makedirs(progress_dir, exist_ok=True)
            log.info("Progress dir: %s  (kept on disk if interrupted)", progress_dir)
        runlog.set_stop_hint(
            f"Accounts that finished are kept in {progress_dir}; run the same command again to "
            "resume."
        )
        zip_path = os.path.join(abs_zip_dir, _zip_name(stamp))

    total = len(targets) + len(completed_ids)
    log.info("Scanning %d remaining accounts (parallel workers: %d)", len(targets), max_workers)
    counter = {"done": len(completed_ids)}
    started: set[str] = set()
    not_scanned: list[dict] = []
    checked_rows: list[dict] = []
    lock = threading.Lock()
    t0 = time.monotonic()

    def _not_scanned(acct_id: str, name: str, why: str, rows: list[dict]) -> None:
        with lock:
            not_scanned.append({"id": acct_id, "name": name, "why": why, "rows": rows})

    def _scan_one(target: dict) -> str:
        name = target.get("name") or target.get("id") or "?"
        try:
            session = open_session(target)
            acct_id = target.get("id") or (
                session.client("sts", region_name=query_region()).get_caller_identity()["Account"]
            )
        except Exception as exc:
            with lock:
                counter["done"] += 1
                log.warning(
                    "[%d/%d] Cannot sign in to %s: %s — skipping", counter["done"], total, name, exc
                )
            check = preflight.sign_in_check(target.get("id") or "", name, exc, sign_in_permission)
            _not_scanned(target.get("id") or "", name, f"sign in: {check.code}", [check.to_row()])
            return "failed"
        with lock:
            repeated = acct_id in completed_ids or acct_id in started
            started.add(acct_id)
        if repeated:
            log.info("[%s] already scanned or complete — skipping", acct_id)
            return "skipped"

        with lock:
            counter["done"] += 1
            n = counter["done"]
        if preflight_only:
            log.info("[%d/%d] [%s / %s] Checking access...", n, total, acct_id, name)
            try:
                rows = check_access(
                    session,
                    regions=regions,
                    exclude_regions=exclude_regions,
                    services=services,
                    collect_cost=collect_cost,
                    access_table=total <= _TABLE_ACCOUNTS,
                )
            except Exception as exc:
                log.warning(
                    "[%d/%d] Access check failed for %s (%s): %s", n, total, acct_id, name, exc
                )
                check = preflight.scan_failed_check(acct_id, name, exc)
                _not_scanned(acct_id, name, f"access check: {check.code}", [check.to_row()])
                return "failed"
            with lock:
                checked_rows.extend(rows)
            log.info("[%d/%d] [%s] ✓ checked", n, total, acct_id)
            return "ok"

        log.info("[%d/%d] [%s / %s] Starting scan...", n, total, acct_id, name)
        try:
            acct_dir = os.path.join(progress_dir, acct_id)
            os.makedirs(acct_dir, exist_ok=True)
            tracker = DenialTracker()
            json_path = run(
                output_dir=acct_dir,
                session=session,
                regions=regions,
                exclude_regions=exclude_regions,
                services=services,
                collect_cost=collect_cost,
                denial_tracker=tracker,
                access_check=access_check,
                access_table=total <= _TABLE_ACCOUNTS,
            )
            if tracker:
                denied = sorted(tracker.denied_services())
                log.warning(
                    "[%d/%d] [%s / %s] SCP blocked read access for services: %s. "
                    "This account will NOT be counted as complete — it will be retried on resume. %s",
                    n,
                    total,
                    acct_id,
                    name,
                    ", ".join(denied),
                    scp_hint,
                )
                # Its results are dropped so the next run retries it, but what the access check
                # found is exactly what the reader needs to see, so its rows are kept.
                _not_scanned(
                    acct_id,
                    name,
                    f"blocked by a service control policy: {', '.join(denied)}",
                    _access_rows_of(json_path),
                )
                try:
                    os.remove(json_path)
                except OSError:
                    pass
                return "failed"
            if bucket_name:
                _upload_to_s3(
                    session,
                    json_path,
                    bucket_name,
                    f"{acct_id}/aws_sizing_discovery.json",
                    bucket_region,
                )
            log.info("[%d/%d] [%s] ✓ done", n, total, acct_id)
            return "ok"
        except Exception as exc:
            log.warning("[%d/%d] Scan failed for %s (%s): %s", n, total, acct_id, name, exc)
            check = preflight.scan_failed_check(acct_id, name, exc)
            _not_scanned(acct_id, name, f"scan failed: {check.code}", [check.to_row()])
            return "failed"

    success = len(completed_ids)
    failed = 0
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        for result in as_completed(executor.submit(_scan_one, t) for t in targets):
            status = result.result()
            if status == "ok":
                success += 1
            elif status == "failed":
                failed += 1

    if preflight_only:
        log.info(
            "%s access check complete — %d/%d checked, %d could not be checked",
            label,
            success,
            total,
            failed,
        )
        return _package_access_report(
            zip_path,
            checked_rows,
            not_scanned,
            success,
            time.monotonic() - t0,
            anonymizer=anonymizer,
            stamp=stamp,
            title=f"{label} Access Check Complete",
        )

    log.info(
        "%s scan complete — %d/%d succeeded, %d failed / skipped", label, success, total, failed
    )
    return _package_results(
        progress_dir,
        zip_path,
        success,
        failed,
        time.monotonic() - t0,
        write_csv=write_csv,
        anonymizer=anonymizer,
        stamp=stamp,
        title=f"{label} Scan Complete",
        collect_cost=collect_cost,
        not_scanned=not_scanned,
    )


def _access_rows_of(json_path: str) -> list[dict]:
    """The access-check rows of a discovery file, or none if it cannot be read."""
    try:
        with open(json_path, encoding="utf-8") as f:
            return list(json.load(f).get("access_check") or [])
    except (OSError, ValueError, AttributeError):
        return []


def _access_zip_name(stamp: str) -> str:
    return f"aws_access_check_{stamp}.zip"


def _package_access_report(
    zip_path: str,
    rows: list[dict],
    not_scanned: list[dict],
    checked: int,
    elapsed_secs: float = 0.0,
    anonymizer: Optional[Anonymizer] = None,
    stamp: Optional[str] = None,
    title: str = "Access Check Complete",
) -> str:
    """The zip of a ``--preflight-only`` run: the pre-flight CSV of every account, nothing else
    (the run log is added by ``main``)."""
    stamp = stamp or _run_stamp()
    extra = [*rows, *(row for entry in not_scanned for row in entry["rows"])]
    in_zip = dict(_access_check_csv([], stamp, anonymizer, extra))
    manifest_text = _manifest_text(in_zip)
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, text in in_zip.items():
            zf.writestr(name, text)
        if manifest_text is not None:
            zf.writestr(manifest_core.FILE_NAME, manifest_text)
    if anonymizer is not None:
        key_path = _write_key_file(anonymizer, os.path.dirname(os.path.abspath(zip_path)), stamp)
        log.info("Anonymized keys to actual values: %s (not in the zip)", key_path)

    mins, secs = divmod(int(elapsed_secs), 60)
    elapsed_str = f"{mins}m {secs}s" if mins else f"{secs}s"
    failed = len(not_scanned)
    status = f"{_C.GREEN}✓{_C.RESET}" if failed == 0 else f"{_C.YELLOW}⚠{_C.RESET}"
    abs_zip = os.path.abspath(zip_path)
    _print_box(
        [
            f"{_C.BOLD}{_C.WHITE}{title} {status}{_C.RESET}",
            "",
            f"{_C.GREEN}✓{_C.RESET}  Accounts checked   {_C.BOLD}{checked}{_C.RESET}",
            f"{_failed_mark(failed)}Not checked        {_C.BOLD}{failed}{_C.RESET}",
            f"   Elapsed time       {_C.BOLD}{elapsed_str}{_C.RESET}",
            *_not_scanned_lines(not_scanned, "Not checked:"),
            "",
            "Access report (nothing was collected):",
            f"   {_C.BOLD}{_C.CYAN}{abs_zip}{_C.RESET}",
        ]
    )
    return zip_path


def run_org(
    zip_dir: str = ".",
    bucket_name: str = "",
    bucket_region: str = "us-east-1",
    role_name: str = "RubrikDiscoveryRole",
    account_ids: Optional[list[str]] = None,
    regions: Optional[list[str]] = None,
    exclude_regions: Optional[list[str]] = None,
    services: Optional[frozenset[str]] = None,
    max_workers: int = 8,
    collect_cost: bool = True,
    write_csv: bool = True,
    anonymizer: Optional[Anonymizer] = None,
    stamp: Optional[str] = None,
    access_check: bool = True,
    preflight_only: bool = False,
) -> str:
    """Scan accounts via sts:AssumeRole, scanning up to max_workers accounts in parallel.

    If ``account_ids`` is provided, skips organizations:ListAccounts and uses
    that list directly (PowerShell's cross-account mode). Otherwise discovers
    accounts from the Organization.
    """
    mgmt_session = boto3.session.Session(region_name=query_region())
    sts = mgmt_session.client("sts")

    if account_ids:
        accounts = [{"Id": a, "Name": a} for a in account_ids]
        log.info("Using %d explicitly provided account IDs", len(accounts))
    else:
        org = mgmt_session.client("organizations", region_name=query_region())
        try:
            accounts = []
            paginator = org.get_paginator("list_accounts")
            for page in paginator.paginate():
                for acct in page.get("Accounts", []):
                    if acct.get("Status") == "ACTIVE":
                        accounts.append(acct)
        except Exception as exc:
            msg = str(exc)
            log.error("Cannot list organization accounts: %s", msg)
            if "AccessDeniedException" in msg:
                log.error(
                    "Missing permission: organizations:ListAccounts\n"
                    "  Pass --accounts id1,id2,... to provide the list explicitly, or\n"
                    "  attach AWSOrganizationsReadOnlyAccess to this role."
                )
            sys.exit(1)

    def open_session(target: dict) -> Any:
        arn = role_arn(target["id"], role_name)
        try:
            creds = sts.assume_role(
                RoleArn=arn, RoleSessionName="AWSSizingOrgScan", DurationSeconds=3600
            )["Credentials"]
        except Exception as exc:
            raise RuntimeError(f"cannot assume {arn}: {exc}") from exc
        return boto3.session.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
            region_name=query_region(),
        )

    targets = [
        {"id": a.get("Id") or a.get("accountId", ""), "name": a.get("Name") or a.get("Id")}
        for a in accounts
    ]
    return _scan_accounts(
        targets,
        open_session,
        label="Org",
        scp_hint=(
            "Ask your AWS admin to grant RubrikDiscoveryRole an SCP exception for these services, "
            "or re-run with --role-name if an SCP-exempt role already exists."
        ),
        zip_dir=zip_dir,
        bucket_name=bucket_name,
        bucket_region=bucket_region,
        regions=regions,
        exclude_regions=exclude_regions,
        services=services,
        max_workers=max_workers,
        collect_cost=collect_cost,
        write_csv=write_csv,
        anonymizer=anonymizer,
        stamp=stamp,
        access_check=access_check,
        sign_in_permission="sts:AssumeRole",
        preflight_only=preflight_only,
    )


def run_profiles(
    profiles: list[str],
    zip_dir: str = ".",
    bucket_name: str = "",
    bucket_region: str = "us-east-1",
    regions: Optional[list[str]] = None,
    exclude_regions: Optional[list[str]] = None,
    services: Optional[frozenset[str]] = None,
    max_workers: int = 8,
    collect_cost: bool = True,
    write_csv: bool = True,
    anonymizer: Optional[Anonymizer] = None,
    stamp: Optional[str] = None,
    access_check: bool = True,
    preflight_only: bool = False,
) -> str:
    """Scan the account behind each local profile (PowerShell's ``-AllLocalProfiles`` and
    ``-UserSpecifiedProfileNames``). Two profiles that reach the same account give one result."""

    def open_session(target: dict) -> Any:
        return boto3.session.Session(profile_name=target["name"], region_name=query_region())

    return _scan_accounts(
        [{"id": None, "name": p} for p in profiles],
        open_session,
        label="Profile",
        zip_dir=zip_dir,
        bucket_name=bucket_name,
        bucket_region=bucket_region,
        regions=regions,
        exclude_regions=exclude_regions,
        services=services,
        max_workers=max_workers,
        collect_cost=collect_cost,
        write_csv=write_csv,
        anonymizer=anonymizer,
        stamp=stamp,
        access_check=access_check,
        sign_in_permission="sts:GetCallerIdentity",
        preflight_only=preflight_only,
    )


# ── SSO credential vending ────────────────────────────────────────────────────


def _load_sso_token(start_url: str) -> tuple[str, str]:
    """Return (access_token, sso_region) from the local SSO cache.

    Botocore names SSO session token files as SHA1(session_name).json.
    We read ~/.aws/config to find which sso-session matches start_url,
    then load that exact file — avoiding accidental use of a stale token
    from a different session that happens to share the same Identity Center URL.

    Falls back to scanning all cache files for legacy (non-session) tokens,
    or when the start_url doesn't match any configured session exactly.
    The user must have run ``aws sso login`` beforehand.
    """
    import configparser
    import hashlib

    cache_dir = os.path.expanduser("~/.aws/sso/cache")
    if not os.path.isdir(cache_dir):
        raise RuntimeError(
            f"SSO cache directory not found: {cache_dir}\nRun 'aws sso login' first."
        )

    now = datetime.now(timezone.utc)

    # Read all sso-session blocks from ~/.aws/config
    cfg = configparser.ConfigParser()
    cfg.read(os.path.expanduser("~/.aws/config"))
    sessions: list[tuple[str, str, str]] = []  # (name, sso_start_url, sso_region)
    for section in cfg.sections():
        if not section.startswith("sso-session "):
            continue
        name = section[len("sso-session ") :]
        url = cfg.get(section, "sso_start_url", fallback="")
        rgn = cfg.get(section, "sso_region", fallback="")
        sessions.append((name, url, rgn))

    # Sort so exact URL matches come first, then any other session as fallback
    sessions.sort(key=lambda s: s[1] != start_url)

    def _try_session_token(name: str, cfg_region: str) -> Optional[tuple[str, str]]:
        fname = hashlib.sha1(name.encode()).hexdigest() + ".json"
        path = os.path.join(cache_dir, fname)
        if not os.path.exists(path):
            return None
        try:
            with open(path) as fh:
                data = json.load(fh)
        except Exception:
            return None
        token = data.get("accessToken")
        if not token:
            return None
        expires_at = data.get("expiresAt", "")
        try:
            exp_str = expires_at.replace("UTC", "+00:00").replace("Z", "+00:00")
            if datetime.fromisoformat(exp_str) <= now:
                return None
        except Exception:
            pass
        region = data.get("region") or cfg_region or "us-east-1"
        return token, region

    for name, cfg_url, cfg_region in sessions:
        result = _try_session_token(name, cfg_region)
        if result is None:
            continue
        if cfg_url != start_url:
            log.warning(
                "No SSO session configured for '%s' — using session '%s' (%s). "
                "Pass the correct --sso-start-url to suppress this warning.",
                start_url,
                name,
                cfg_url,
            )
        return result

    # Fallback: scan all cache files (handles legacy non-session tokens)
    fallback: Optional[tuple[str, str, str]] = None
    for fname in os.listdir(cache_dir):
        if not fname.endswith(".json"):
            continue
        try:
            with open(os.path.join(cache_dir, fname)) as fh:
                data = json.load(fh)
        except Exception:
            continue
        token = data.get("accessToken")
        if not token:
            continue
        expires_at = data.get("expiresAt", "")
        try:
            exp_str = expires_at.replace("UTC", "+00:00").replace("Z", "+00:00")
            if datetime.fromisoformat(exp_str) <= now:
                continue
        except Exception:
            pass
        cached_url = data.get("startUrl", "")
        region = data.get("region") or "us-east-1"
        if cached_url == start_url:
            return token, region
        if fallback is None:
            fallback = (token, region, cached_url)

    if fallback:
        token, region, cached_url = fallback
        log.warning(
            "No token cached for '%s' — using token for '%s' instead. "
            "If scans fail, run 'aws sso login' and retry.",
            start_url,
            cached_url,
        )
        return token, region

    raise RuntimeError(
        f"No valid SSO token found for {start_url}\nRun 'aws sso login' and try again."
    )


def _bootstrap_assumed_role(role_arn: str) -> None:
    """Assume role_arn via STS and inject the credentials into the process environment.

    All boto3 clients created after this call will automatically use the assumed
    role's credentials, including the SSO portal calls and every per-account scan.
    """
    try:
        sts = boto3.client("sts")
        resp = sts.assume_role(RoleArn=role_arn, RoleSessionName="aws-sizing")
    except Exception as exc:
        log.error("Failed to assume role %s: %s", role_arn, exc)
        sys.exit(1)
    creds = resp["Credentials"]
    os.environ["AWS_ACCESS_KEY_ID"] = creds["AccessKeyId"]
    os.environ["AWS_SECRET_ACCESS_KEY"] = creds["SecretAccessKey"]
    os.environ["AWS_SESSION_TOKEN"] = creds["SessionToken"]
    log.info("Assumed role: %s", resp["AssumedRoleUser"]["Arn"])


def _sso_session(
    sso_client, account_id: str, role_name: str, access_token: str
) -> boto3.session.Session:
    """Vend a boto3 session for account_id via SSO get_role_credentials."""
    resp = sso_client.get_role_credentials(
        accountId=account_id,
        roleName=role_name,
        accessToken=access_token,
    )
    c = resp["roleCredentials"]
    return boto3.session.Session(
        aws_access_key_id=c["accessKeyId"],
        aws_secret_access_key=c["secretAccessKey"],
        aws_session_token=c["sessionToken"],
        region_name=query_region(),
    )


# ── Org-wide orchestration (SSO / Identity Center) ────────────────────────────


def _sso_token(start_url: str, sso_region: str = "") -> tuple[str, str]:
    """An SSO token and its region: the one ``aws sso login`` cached if there is one, otherwise
    a fresh device sign-in. An explicit ``sso_region`` wins over the cached one."""
    try:
        cached, cached_region = _load_sso_token(start_url)
    except RuntimeError:
        if not start_url:
            raise SsoLoginError(
                "No cached SSO login was found. Run 'aws sso login', or pass --sso-start-url "
                "so this tool can sign in itself."
            )
        log.info("No cached SSO token for %s — signing in with the device flow", start_url)
        region = sso_region or SSO_DEFAULT_REGION
        return sso_device_login(start_url, region), region
    return cached, sso_region or cached_region


def run_org_sso(
    sso_start_url: str,
    role_name: str,
    account_ids: Optional[list[str]] = None,
    zip_dir: str = ".",
    bucket_name: str = "",
    bucket_region: str = "us-east-1",
    regions: Optional[list[str]] = None,
    exclude_regions: Optional[list[str]] = None,
    services: Optional[frozenset[str]] = None,
    max_workers: int = 8,
    collect_cost: bool = True,
    write_csv: bool = True,
    sso_region: str = "",
    anonymizer: Optional[Anonymizer] = None,
    stamp: Optional[str] = None,
    access_check: bool = True,
    preflight_only: bool = False,
) -> str:
    """Scan accounts using IAM Identity Center (SSO) credential vending, in parallel.

    No sts:AssumeRole or IAM role creation required. The Permission Set named ``role_name``
    must be assigned to each account being scanned. The sign-in uses the token ``aws sso
    login`` cached, or starts a device sign-in when there is none.

    If ``account_ids`` is provided, uses that list. Otherwise discovers
    accounts via sso.list_accounts (no organizations:ListAccounts needed).
    """
    log.info("SSO mode — signing in to %s", sso_start_url)
    try:
        sso_token, sso_region = _sso_token(sso_start_url, sso_region)
    except SsoLoginError as exc:
        log.error("%s", exc)
        sys.exit(1)

    sso_client = boto3.client("sso", region_name=sso_region)

    if account_ids:
        accounts = [{"accountId": a, "accountName": a} for a in account_ids]
        log.info("Using %d explicitly provided account IDs", len(accounts))
    else:
        log.info("Discovering accounts via SSO...")
        accounts = []
        try:
            paginator = sso_client.get_paginator("list_accounts")
            for page in paginator.paginate(accessToken=sso_token):
                accounts.extend(page.get("accountList", []))
        except Exception as exc:
            log.error("Cannot list SSO accounts: %s", exc)
            log.error("Pass --accounts id1,id2,... to provide the list explicitly.")
            sys.exit(1)
        log.info("Found %d accounts accessible via SSO", len(accounts))

    targets = [
        {"id": a.get("accountId") or a.get("Id", ""), "name": a.get("accountName") or a.get("Name")}
        for a in accounts
    ]
    return _scan_accounts(
        targets,
        lambda target: _sso_session(sso_client, target["id"], role_name, sso_token),
        label="SSO",
        scp_hint="Ask your AWS admin to grant the permission set an SCP exception for these services.",
        zip_dir=zip_dir,
        bucket_name=bucket_name,
        bucket_region=bucket_region,
        regions=regions,
        exclude_regions=exclude_regions,
        services=services,
        max_workers=max_workers,
        collect_cost=collect_cost,
        write_csv=write_csv,
        anonymizer=anonymizer,
        stamp=stamp,
        access_check=access_check,
        sign_in_permission="sso:GetRoleCredentials",
        preflight_only=preflight_only,
    )


# ── Lambda entrypoint ─────────────────────────────────────────────────────────


def lambda_handler(event: dict, context: Any) -> str:
    json_path = run(output_dir="/tmp")

    bucket_name = os.getenv("OUTPUT_BUCKET", "")
    bucket_region = os.getenv("OUTPUT_BUCKET_REGION", "us-east-1")
    lambda_region = os.getenv("AWS_REGION", "us-east-1")

    if bucket_name:
        session = boto3.session.Session()
        sts = session.client("sts")
        account_id = sts.get_caller_identity()["Account"]
        object_key = f"{account_id}/{lambda_region}/aws_sizing_discovery.json"
        _upload_to_s3(session, json_path, bucket_name, object_key, bucket_region)
        return f"Discovery complete. JSON uploaded to s3://{bucket_name}/{object_key}"
    else:
        log.warning("OUTPUT_BUCKET not set — JSON written to /tmp only.")
        return "Discovery complete. OUTPUT_BUCKET not set; JSON at /tmp/aws_sizing_discovery.json"


# ── CLI entrypoint ────────────────────────────────────────────────────────────


def _finish_single_account(
    json_path: str,
    output_dir: str,
    stamp: str,
    write_csv: bool,
    anonymizer: Optional[Anonymizer],
    keep_artifacts: bool = False,
    collect_cost: bool = True,
) -> str:
    """Zip the JSON and the PowerShell-style CSV files, and leave only the zip beside it.

    The CSV files are built straight into the zip, and the loose JSON is removed once the zip is
    written, so the folder holds only what is meant to be shared (as Azure and GCP do).
    ``keep_artifacts`` keeps the loose JSON and also writes the CSV files next to the zip.

    An anonymized zip has no raw JSON (it holds every real name); the key file goes beside it. Its
    loose JSON is removed too unless ``keep_artifacts`` is set, because it would hold the real names.
    """
    csv_files: dict[str, str] = {}
    with open(json_path, encoding="utf-8") as f:
        discovery = json.load(f)
    if write_csv or anonymizer is None:
        if write_csv:
            csv_files = csv_export.build_csv_files([discovery], stamp, anonymizer)
            csv_files.update(_access_check_csv([discovery], stamp, anonymizer))
        if anonymizer is None:  # PowerShell's plans file names every plan, so not when anonymizing
            plans_text = _plans_json_text(plans_json.plans_of(discovery), stamp)
            if plans_text is not None:
                csv_files[plans_json.file_name(stamp)] = plans_text
    in_zip: dict[str, Any] = dict(csv_files)
    if anonymizer is None:
        with open(json_path, "rb") as f:
            in_zip["aws_sizing_discovery.json"] = f.read()
    manifest_text = _manifest_text(in_zip)
    if manifest_text is not None:
        csv_files[manifest_core.FILE_NAME] = manifest_text
    zip_path = os.path.join(output_dir, _zip_name(stamp))
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        if anonymizer is None:
            zf.writestr("aws_sizing_discovery.json", in_zip["aws_sizing_discovery.json"])
        for name, text in csv_files.items():
            zf.writestr(name, text)
    if keep_artifacts:
        for name, text in csv_files.items():
            with open(os.path.join(output_dir, name), "w", encoding="utf-8", newline="") as f:
                f.write(text)
    else:
        try:
            os.remove(json_path)
        except OSError as exc:
            log.warning("Could not remove %s after zipping it: %s", json_path, exc)
    if anonymizer is not None:
        key_path = _write_key_file(anonymizer, output_dir, stamp)
        log.info("Anonymized keys to actual values: %s (not in the zip)", key_path)
    _print_totals([discovery], collect_cost)
    return zip_path


def _check_single_account(
    output_dir: str,
    regions: Optional[list[str]],
    exclude_regions: Optional[list[str]],
    services: Optional[frozenset[str]],
    collect_cost: bool,
    stamp: str,
    anonymizer: Optional[Anonymizer],
) -> str:
    """``--preflight-only`` for the current credentials: the access check, then a zip with its CSV."""
    os.makedirs(output_dir, exist_ok=True)
    t0 = time.monotonic()
    rows = check_access(
        None,
        regions=regions,
        exclude_regions=exclude_regions,
        services=services,
        collect_cost=collect_cost,
        access_table=True,
    )
    return _package_access_report(
        os.path.join(output_dir, _access_zip_name(stamp)),
        rows,
        [],
        1,
        anonymizer=anonymizer,
        stamp=stamp,
        elapsed_secs=time.monotonic() - t0,
    )


def _say_green(line: str) -> None:
    """One line of the totals, in green on the screen as PowerShell prints it. The log keeps the
    plain text, because the run log strips colour codes."""
    runlog.say(f"{_C.GREEN}{line}{_C.RESET}" if line.strip() else line)


def _print_totals(results: list[dict], collect_cost: bool) -> None:
    """The per-resource totals, as the PowerShell script prints them, on the screen and in the log."""
    try:
        totals.print_totals(csv_export.rows_by_file(results), _say_green, collect_cost)
    except Exception as exc:
        log.warning("Could not work out the totals: %s", exc)


def _attach_log(zip_path: str, log_path: str, stamp: str, anonymized: bool) -> None:
    """Add the run log to the zip as ``output_aws_<stamp>.log``.

    When anonymizing, the zip gets a note instead and the real log is kept next to it as
    ``output_aws_not_anonymized_<stamp>.log``, because the log names real accounts and resources.
    """
    with zipfile.ZipFile(zip_path, "a", compression=zipfile.ZIP_DEFLATED) as zf:
        if anonymized:
            zf.writestr(f"output_aws_{stamp}.log", anonymized_log_note())
        else:
            zf.write(log_path, arcname=f"output_aws_{stamp}.log")
    if anonymized:
        target = os.path.join(
            os.path.dirname(os.path.abspath(zip_path)), f"output_aws_not_anonymized_{stamp}.log"
        )
        shutil.copyfile(log_path, target)
        log.info("Run log (not anonymized, not in the zip): %s", target)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="AWS Sizing Tool — discovery + risk analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  # SSO scan (default mode) — signs in with the device flow if 'aws sso login' was not run
  aws-sizing --sso --sso-start-url https://myorg.awsapps.com/start --role-name AdministratorAccess

  # SSO scan, assume a pre-deployed runner role first
  aws-sizing --sso --role-name AdministratorAccess --assume-role arn:aws:iam::123456789012:role/SizingToolRunnerRole

  # SSO scan with an explicit account list read from a file, in another SSO region
  aws-sizing --sso --sso-start-url https://myorg.awsapps.com/start --role-name AdministratorAccess --accounts-file accounts.txt --sso-region eu-west-1

  # Org scan via sts:AssumeRole (requires StackSet role deployed in each account)
  aws-sizing --org

  # Org scan using an existing cross-account role
  aws-sizing --org --role-name OrganizationAccountAccessRole

  # Named accounts through a cross-account role (no Organizations call)
  aws-sizing --cross-account-role OrganizationAccountAccessRole --accounts 123456789012,234567890123

  # Every profile in ~/.aws/credentials, or only some
  aws-sizing --all-profiles
  aws-sizing --profiles prod,staging --profile-location ~/aws-creds

  # GovCloud
  aws-sizing --partition govcloud

  # Anonymize the output files (the key file stays outside the zip)
  aws-sizing --anonymize --not-anonymize-fields Tags

  # Combine the CSVs of several runs into one file per kind
  python -m common.consolidate ./all-my-runs
        """,
    )

    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--org", action="store_true", help="Scan all active accounts via sts:AssumeRole"
    )
    mode.add_argument(
        "--sso",
        action="store_true",
        help="Scan accounts via IAM Identity Center (no role creation needed)",
    )
    mode.add_argument(
        "--cross-account-role",
        default="",
        metavar="ROLE_NAME",
        help="Scan the accounts given with --accounts or --accounts-file through this IAM role "
        "(PowerShell's -CrossAccountRoleName). No Organizations call.",
    )
    mode.add_argument(
        "--all-profiles",
        action="store_true",
        help="Scan the account of every local AWS profile (PowerShell's -AllLocalProfiles)",
    )
    mode.add_argument(
        "--profiles",
        default="",
        metavar="NAMES",
        help="Comma-separated local profiles to scan (PowerShell's -UserSpecifiedProfileNames)",
    )

    parser.add_argument(
        "--sso-start-url",
        default="",
        help="SSO start URL, e.g. https://myorg.awsapps.com/start (required with --sso)",
    )
    parser.add_argument(
        "--sso-region",
        default="",
        help="Region of the IAM Identity Center instance (default: the one in the cached SSO "
        f"login, else {SSO_DEFAULT_REGION})",
    )
    parser.add_argument(
        "--accounts",
        default="",
        help="Comma-separated account IDs to scan (skips organizations:ListAccounts)",
    )
    parser.add_argument(
        "--accounts-file",
        default="",
        metavar="FILE",
        help="File with one account ID per line (alternative to --accounts)",
    )
    parser.add_argument(
        "--role-name",
        "--org-role-name",
        dest="role_name",
        default="",
        help=f"IAM role (--org; default: {DEFAULT_ORG_ROLE}; PowerShell's default for organizations "
        "is OrganizationAccountAccessRole) or IAM Identity Center permission set (--sso; required) "
        "in each account",
    )
    parser.add_argument(
        "--profile-location",
        default="",
        metavar="FILE",
        help="Read profiles from this AWS credentials file (PowerShell's -ProfileLocation)",
    )
    parser.add_argument(
        "--partition",
        type=str.lower,
        choices=["aws", "govcloud"],
        default="aws",
        help="AWS partition to scan (PowerShell's -Partition GovCloud)",
    )
    parser.add_argument(
        "--region-to-query",
        default="",
        metavar="REGION",
        help="Region used for account-wide calls such as STS, IAM and Organizations "
        "(default: us-east-1, or us-gov-east-1 with --partition govcloud)",
    )
    parser.add_argument(
        "--output",
        "-o",
        default="",
        help="Folder for the zip, the run log and, for several accounts, the progress folder "
        "(default: ./outputs for one account, the current folder for several)",
    )
    parser.add_argument(
        "--bucket", default="", help="(Optional) S3 bucket to also upload results to"
    )
    parser.add_argument(
        "--bucket-region", default="us-east-1", help="Region of the S3 bucket (default: us-east-1)"
    )
    parser.add_argument(
        "--regions",
        default="",
        help="Comma-separated list of regions to scan (default: all enabled regions)",
    )
    parser.add_argument(
        "--exclude-regions",
        default="",
        help="Comma-separated list of regions to skip (e.g. ap-east-1,me-south-1)",
    )
    parser.add_argument(
        "--services",
        default="",
        help=(
            "Comma-separated subset of services to collect "
            f"(default: all except iac). Valid values: {', '.join(sorted(ALL_SERVICES))}"
        ),
    )
    # Optional scans — skip flags for scripted/non-interactive runs. In an
    # interactive terminal the tool also asks yes/no for each before scanning;
    # the flag hard-skips (no prompt).
    parser.add_argument(
        "--no-cost",
        action="store_true",
        help="Skip cost collection (12-month Cost Explorer backup + service spend).",
    )
    parser.add_argument(
        "--no-capacity",
        action="store_true",
        help="Skip S3 storage sizing (per-bucket CloudWatch BucketSizeBytes).",
    )
    parser.add_argument(
        "--no-backup-capacity",
        action="store_true",
        help="Skip the native snapshot enumeration (RDS snapshots, EBS snapshots, AMIs), like "
        "PowerShell's -SkipBackupCapacity. The backup columns keep their defaults. Without this "
        "flag it runs for whichever of rds and ec2 are collected.",
    )
    parser.add_argument(
        "--no-csv",
        action="store_true",
        help="Write only the JSON results, not the PowerShell-style CSV files.",
    )
    parser.add_argument(
        "--no-preflight",
        action="store_true",
        help="Skip the pre-flight access check that runs before each account is scanned. The "
        "check makes one read-only call per service and region (plus one billed Cost Explorer "
        "request unless --no-cost) and writes aws_preflight_check-<timestamp>.csv, which lists "
        "what will be captured and what will be dropped.",
    )
    parser.add_argument(
        "--preflight-only",
        action="store_true",
        help="Only run the access check: sign in to each account (every mode works), check what "
        "the scan could read, write aws_preflight_check-<timestamp>.csv into "
        "aws_access_check_<timestamp>.zip and stop. Nothing is collected, and a multi-account run "
        "uses no progress folder. Accounts that cannot be signed in to get a 'sign in' row.",
    )
    parser.add_argument(
        "--keep-artifacts",
        action="store_true",
        help="Single-account mode: also leave the loose JSON and CSV files beside the ZIP. By "
        "default only the ZIP is kept, because they are inside it. With --anonymize the loose "
        "JSON holds the real names. The multi-account modes write only the ZIP.",
    )
    parser.add_argument(
        "--skip-bucket-tags",
        action="store_true",
        help="Do not read S3 bucket tags (PowerShell's -SkipBucketTags).",
    )
    parser.add_argument(
        "--backup-recovery-point-timeout-minutes",
        type=int,
        default=DEFAULT_RECOVERY_POINT_TIMEOUT_MINUTES,
        metavar="N",
        help="Time budget per region for listing AWS Backup recovery points (default: "
        f"{DEFAULT_RECOVERY_POINT_TIMEOUT_MINUTES}). When it runs out the sizes are lower bounds "
        "and the rows are flagged BackupEnumerationTruncated.",
    )
    parser.add_argument(
        "--anonymize",
        action="store_true",
        help="Anonymize names, ids and tags in the CSV files (PowerShell's -Anonymize). The zip "
        "then has no raw JSON; the key file that maps labels back and the real log are written "
        "next to it, not into it.",
    )
    parser.add_argument(
        "--anonymize-fields",
        default="",
        metavar="FIELDS",
        help="Comma-separated extra fields to anonymize (with --anonymize)",
    )
    parser.add_argument(
        "--not-anonymize-fields",
        default="",
        metavar="FIELDS",
        help="Comma-separated fields to leave as they are (with --anonymize); 'Tags' leaves all "
        "tag columns alone",
    )
    parser.add_argument(
        "--workers", type=int, default=8, help="Number of accounts to scan in parallel (default: 8)"
    )
    parser.add_argument(
        "--assume-role",
        default="",
        metavar="ROLE_ARN",
        help="Assume this IAM role before scanning (useful when CloudShell identity lacks permissions)",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable DEBUG logging (default level is INFO)"
    )
    return parser


_open_run_logs: list = []


def _discard_run_log() -> None:
    """Drop the run log of a run that stopped before it could be bundled into a zip.

    Detaches and closes the log handler and deletes the temp file, so a failed run leaves nothing
    behind. A run that finished has already done this, and the entry is then a harmless no-op.
    """
    while _open_run_logs:
        handler, path = _open_run_logs.pop()
        logging.getLogger().removeHandler(handler)
        handler.close()
        try:
            os.remove(path)
        except OSError:
            pass


def _main(argv: Optional[list[str]] = None) -> None:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.cross_account_role and not (args.accounts or args.accounts_file):
        parser.error("--cross-account-role needs --accounts or --accounts-file")
    if (args.anonymize_fields or args.not_anonymize_fields) and not args.anonymize:
        parser.error("--anonymize-fields and --not-anonymize-fields need --anonymize")
    if args.anonymize and args.no_csv:
        parser.error("--anonymize works on the CSV files, so it cannot be used with --no-csv")
    if args.preflight_only and args.no_preflight:
        parser.error("--preflight-only runs only the access check, so it cannot skip it")
    if args.preflight_only and args.no_csv:
        parser.error("--preflight-only writes only the access-check CSV, so it cannot use --no-csv")
    if args.sso and not args.role_name:
        parser.error(
            "--sso needs --role-name: the IAM Identity Center permission set assigned to you in the "
            "accounts (for example --role-name ReadOnlyAccess)"
        )
    try:
        account_ids = resolve_account_ids(args.accounts, args.accounts_file)
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
    if args.profile_location:
        try:
            use_profile_location(args.profile_location)
        except OSError as exc:
            parser.error(str(exc))
    profiles: list[str] = []
    if args.all_profiles or args.profiles:
        try:
            profiles = select_profiles(args.profiles, args.all_profiles)
        except ValueError as exc:
            parser.error(str(exc))
        if not profiles:
            parser.error("No local AWS profiles were found")

    if args.backup_recovery_point_timeout_minutes < 1:
        parser.error("--backup-recovery-point-timeout-minutes must be at least 1")
    configure_partition(
        args.partition == "govcloud",
        args.region_to_query or None,
        recovery_point_timeout_minutes=args.backup_recovery_point_timeout_minutes,
        skip_bucket_tags=args.skip_bucket_tags,
    )

    if args.verbose:
        setup_logging(verbose=True)

    # Stream the run log into the folder the results zip goes to (independent of --verbose, which only
    # gates the console). It is bundled into the zip at the end and then removed, but a run that is
    # stopped, killed or crashes leaves it there, written up to that moment. Attached after any
    # --verbose re-setup so the console handler swap doesn't drop it.
    stamp = _run_stamp()
    several = bool(args.sso or args.org or args.cross_account_role or profiles)
    output_dir = args.output or ("." if several else "./outputs")
    os.makedirs(output_dir, exist_ok=True)
    log_path = os.path.join(output_dir, f"output_aws_{stamp}.log")
    log_handler = add_log_file(log_path)
    _open_run_logs.append((log_handler, log_path))
    runlog.start(argv if argv is not None else sys.argv[1:])
    runlog.install_stop_handlers()
    log.info("Discovery run started.")
    anonymizer = (
        Anonymizer.from_options(args.anonymize_fields, args.not_anonymize_fields)
        if args.anonymize
        else None
    )

    if args.assume_role:
        _bootstrap_assumed_role(args.assume_role)

    if account_ids and not (args.sso or args.org or args.cross_account_role):
        log.warning(
            "--accounts / --accounts-file only apply to --sso, --org and --cross-account-role"
        )
    regions = [r.strip() for r in args.regions.split(",") if r.strip()] if args.regions else None
    exclude_regions = (
        [r.strip() for r in args.exclude_regions.split(",") if r.strip()]
        if args.exclude_regions
        else None
    )

    services: Optional[frozenset[str]] = None
    if args.services:
        requested = frozenset(s.strip() for s in args.services.split(",") if s.strip())
        unknown = requested - ALL_SERVICES
        if unknown:
            parser.error(
                f"Unknown services: {', '.join(sorted(unknown))}. Valid: {', '.join(sorted(ALL_SERVICES))}"
            )
        services = requested

    # Decide optional scans once (prompts on a TTY, flags hard-skip) before scanning.
    scans = _resolve_scans(args)
    if not scans["capacity"]:
        # Declining S3 sizing drops the S3 collector — its whole job is the
        # per-bucket CloudWatch BucketSizeBytes lookup.
        base = services if services is not None else DEFAULT_SERVICES
        services = base - {"s3"}
        log.info("Skipping S3 storage sizing (opted out)")

    # Backup capacity is on unless skipped, whatever --services lists; "snapshots" is the
    # internal switch for it, so an explicit list does not have to name it.
    if args.no_backup_capacity:
        services = (services if services is not None else DEFAULT_SERVICES) - {"snapshots"}
        log.info("Skipping native backup capacity (opted out)")
    elif services is not None:
        services = services | {"snapshots"}

    common = dict(
        bucket_name=args.bucket,
        bucket_region=args.bucket_region,
        regions=regions,
        exclude_regions=exclude_regions,
        services=services,
        max_workers=args.workers,
        collect_cost=scans["cost"],
        write_csv=not args.no_csv,
        anonymizer=anonymizer,
        stamp=stamp,
        access_check=not args.no_preflight,
        preflight_only=args.preflight_only,
    )
    if args.sso:
        zip_path = run_org_sso(
            sso_start_url=args.sso_start_url,
            role_name=args.role_name,
            account_ids=account_ids,
            zip_dir=output_dir,
            sso_region=args.sso_region,
            **common,
        )
    elif args.org or args.cross_account_role:
        zip_path = run_org(
            zip_dir=output_dir,
            role_name=args.cross_account_role or args.role_name or DEFAULT_ORG_ROLE,
            account_ids=account_ids,
            **common,
        )
    elif profiles:
        zip_path = run_profiles(profiles, zip_dir=output_dir, **common)
    elif args.preflight_only:
        zip_path = _check_single_account(
            output_dir, regions, exclude_regions, services, scans["cost"], stamp, anonymizer
        )
        runlog.say(f"\nAccess check complete. Report written to: {zip_path}")
    else:
        json_path = run(
            output_dir=output_dir,
            regions=regions,
            exclude_regions=exclude_regions,
            services=services,
            collect_cost=scans["cost"],
            access_check=not args.no_preflight,
        )
        zip_path = _finish_single_account(
            json_path,
            output_dir,
            stamp,
            not args.no_csv,
            anonymizer,
            args.keep_artifacts,
            scans["cost"],
        )
        runlog.say(f"\nDiscovery complete. Results written to: {os.path.abspath(zip_path)}")

    # Bundle the full DEBUG run log into whichever ZIP the run produced, then
    # drop the temp file. Detach + close the handler first so the file is
    # complete and unlocked.
    log.info("Discovery run complete — bundling run log.")
    runlog.finish()
    logging.getLogger().removeHandler(log_handler)
    log_handler.close()
    if zip_path and os.path.exists(zip_path):
        _attach_log(zip_path, log_path, stamp, anonymizer is not None)
    try:
        os.remove(log_path)
    except OSError:
        pass


def _close_run_logs() -> None:
    """Detach and close the run log of a run that stopped, and leave the file where it is."""
    while _open_run_logs:
        handler, _ = _open_run_logs.pop()
        logging.getLogger().removeHandler(handler)
        handler.close()


def main(argv: Optional[list[str]] = None) -> None:
    try:
        _main(argv)
    except BaseException as exc:
        message = explain_credential_error(exc) if isinstance(exc, Exception) else None
        usage_error = isinstance(exc, SystemExit) and exc.code == 2
        if message is not None or usage_error:
            # A sign-in problem or a bad option is already on the screen in full; nothing is left behind.
            _discard_run_log()
        else:
            runlog.crashed(exc)
            _close_run_logs()
        if message is None:
            raise
        log.debug("Sign-in problem", exc_info=True)
        print(f"\n{message}", file=sys.stderr)
        sys.exit(1)
    finally:
        _open_run_logs.clear()


if __name__ == "__main__":
    main()
