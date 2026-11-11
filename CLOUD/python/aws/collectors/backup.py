"""AWS Backup collector — plans, resource selections, costs, and protection status."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from models.discovery import BackupCostEntry, BackupPlan, BackupRule, BackupSelection, BackupVault

from collectors import BOTO_BACKUP_CFG, DenialTracker, is_scp_denial, record_metric_failures


def fetch_protected_arns(session, region: str, tracker: "DenialTracker | None" = None) -> set[str]:
    """Return the set of all resource ARNs currently protected by AWS Backup in this region."""
    client = session.client("backup", region_name=region)
    protected: set[str] = set()
    try:
        paginator = client.get_paginator("list_protected_resources")
        for page in paginator.paginate():
            for res in page.get("Results", []):
                arn = res.get("ResourceArn", "")
                if arn:
                    protected.add(arn)
    except Exception as exc:
        if is_scp_denial(exc):
            if tracker is not None:
                tracker.record("backup")
            logging.debug("Could not list protected resources in %s (SCP denied)", region)
        else:
            logging.warning("Could not list protected resources in %s: %s", region, exc)
    return protected


def _iso(value) -> str:
    return value.isoformat() if isinstance(value, datetime) else str(value or "")


def _ps_json_datetime(value) -> "str | None":
    """A date as PowerShell's ConvertTo-Json writes it: UTC, the fraction without trailing zeros,
    then ``Z`` (``2022-06-06T23:33:40.022Z``). A date the API did not send is ``None``."""
    if isinstance(value, str) and value:
        return value
    if not isinstance(value, datetime):
        return None
    if value.tzinfo is not None:
        value = value.astimezone(timezone.utc)
    text = value.strftime("%Y-%m-%dT%H:%M:%S")
    fraction = f"{value.microsecond:06d}".rstrip("0")
    return f"{text}.{fraction}Z" if fraction else f"{text}Z"


def _json_safe(value):
    """``value`` with every datetime written the PowerShell way, so it is plain JSON."""
    if isinstance(value, datetime):
        return _ps_json_datetime(value)
    if isinstance(value, dict):
        return {key: _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    return value


# The plan export follows what PowerShell writes with AWS.Tools 5.x, which serializes every
# property of the SDK object: a field the API leaves out is ``null`` (older AWS.Tools wrote
# zeros, false and empty lists instead), and the newer fields are present even when they are null.


def _lifecycle_export(lifecycle) -> "dict | None":
    if lifecycle is None:
        return None
    return {
        "DeleteAfterDays": lifecycle.get("DeleteAfterDays"),
        "DeleteAfterEvent": lifecycle.get("DeleteAfterEvent"),
        "MoveToColdStorageAfterDays": lifecycle.get("MoveToColdStorageAfterDays"),
        "OptInToArchiveForSupportedResources": lifecycle.get("OptInToArchiveForSupportedResources"),
    }


def _copy_actions_export(copy_actions) -> "list | None":
    if copy_actions is None:
        return None
    return [
        {
            "DestinationBackupVaultArn": copy.get("DestinationBackupVaultArn"),
            "Lifecycle": _lifecycle_export(copy.get("Lifecycle")),
        }
        for copy in copy_actions
    ]


def _rule_export(rule: dict) -> dict:
    """A rule with every key AWS.Tools 5.x writes, in its order. Keys boto3 does not return are
    ``None``; anything else boto3 might add is left out on purpose."""
    return {
        "CompletionWindowMinutes": rule.get("CompletionWindowMinutes"),
        "CopyActions": _copy_actions_export(rule.get("CopyActions")),
        "EnableContinuousBackup": rule.get("EnableContinuousBackup"),
        "IndexActions": _json_safe(rule.get("IndexActions")),
        "Lifecycle": _lifecycle_export(rule.get("Lifecycle")),
        "RecoveryPointTags": _json_safe(rule.get("RecoveryPointTags")),
        "RuleId": rule.get("RuleId"),
        "RuleName": rule.get("RuleName"),
        "ScanActions": _json_safe(rule.get("ScanActions")),
        "ScheduleExpression": rule.get("ScheduleExpression"),
        "ScheduleExpressionTimezone": rule.get("ScheduleExpressionTimezone"),
        "StartWindowMinutes": rule.get("StartWindowMinutes"),
        "TargetBackupVaultName": rule.get("TargetBackupVaultName"),
        "TargetLogicallyAirGappedBackupVaultArn": rule.get(
            "TargetLogicallyAirGappedBackupVaultArn"
        ),
    }


def _plan_export(item: dict, desc: dict) -> dict:
    """The plan in the shape of PowerShell's aws-backup-plans-info-*.json element (AWS.Tools 5.x),
    without ``Resources`` and without the SDK transport fields (ResponseMetadata, ContentLength,
    HttpStatusCode). Built from the raw ``list_backup_plans`` item and ``get_backup_plan``
    response, whose datetimes are real ``datetime`` objects. A field the API left out is ``None``.
    """
    raw_plan = desc.get("BackupPlan") or {}
    rules = raw_plan.get("Rules")

    def pick(key: str):
        value = desc.get(key)
        return value if value is not None else item.get(key)

    return {
        "AdvancedBackupSettings": _json_safe(desc.get("AdvancedBackupSettings")),
        "BackupPlan": {
            "AdvancedBackupSettings": _json_safe(raw_plan.get("AdvancedBackupSettings")),
            "BackupPlanName": raw_plan.get("BackupPlanName") or item.get("BackupPlanName"),
            "Rules": None if rules is None else [_rule_export(r) for r in rules],
            "ScanSettings": _json_safe(raw_plan.get("ScanSettings")),
        },
        "BackupPlanArn": pick("BackupPlanArn"),
        "BackupPlanId": pick("BackupPlanId"),
        "CreationDate": _ps_json_datetime(pick("CreationDate")),
        "CreatorRequestId": pick("CreatorRequestId"),
        "DeletionDate": _ps_json_datetime(pick("DeletionDate")),
        "LastExecutionDate": _ps_json_datetime(pick("LastExecutionDate")),
        "ScheduledRunsPreview": _json_safe(desc.get("ScheduledRunsPreview")),
        "VersionId": pick("VersionId"),
    }


def _record_plan_failures(
    tracker: "DenialTracker | None", region: str, errors: list[Exception]
) -> None:
    """One scan error per region for every failed plan or selection read, and a denial for an SCP.

    A failed read must be visible: it leaves the plan (or a selection of it) out, which would
    otherwise read as "this resource is not in a plan". An SCP denial also marks the account
    denied (the account is retried on resume); any other failure only lands in ``scan_errors``.
    """
    if not errors:
        return
    record_metric_failures(
        tracker, region, "AWS Backup plan/selection reads", errors, service="backup"
    )
    if tracker is not None and any(is_scp_denial(exc) for exc in errors):
        tracker.record("backup")


def _selection_from(selection_id: str, selection: dict) -> BackupSelection:
    conditions = selection.get("Conditions") or {}
    return BackupSelection(
        selection_id=selection_id,
        resources=list(selection.get("Resources") or []),
        not_resources=list(selection.get("NotResources") or []),
        list_of_tags=list(selection.get("ListOfTags") or []),
        string_equals=list(conditions.get("StringEquals") or []),
        string_like=list(conditions.get("StringLike") or []),
        string_not_equals=list(conditions.get("StringNotEquals") or []),
        string_not_like=list(conditions.get("StringNotLike") or []),
    )


def fetch_backup_plans(
    session,
    region: str,
    account_id: str,
    account_alias: str,
    tracker: "DenialTracker | None" = None,
) -> list[BackupPlan]:
    """Fetch all active backup plans with their rules and resource selections.

    Every failed read is recorded (see ``_record_plan_failures``). A plan whose details cannot
    be read is still returned, as a placeholder with ``selections_complete=False``, so readers
    know the plan list is incomplete instead of trusting the plans that did load.
    """
    client = session.client("backup", region_name=region, config=BOTO_BACKUP_CFG)
    plans: list[BackupPlan] = []
    errors: list[Exception] = []

    try:
        paginator = client.get_paginator("list_backup_plans")
        plan_list = []
        for page in paginator.paginate(IncludeDeleted=False):
            plan_list.extend(page.get("BackupPlansList", []))
    except Exception as exc:
        errors.append(exc)
        _record_plan_failures(tracker, region, errors)
        return plans

    for item in plan_list:
        plan_id = item.get("BackupPlanId", "")
        try:
            desc = client.get_backup_plan(BackupPlanId=plan_id)
        except Exception as exc:
            errors.append(exc)
            plans.append(
                BackupPlan(
                    account_id=account_id,
                    account_alias=account_alias,
                    region=region,
                    plan_id=plan_id,
                    plan_arn=item.get("BackupPlanArn", ""),
                    plan_name=item.get("BackupPlanName", ""),
                    version_id=item.get("VersionId", ""),
                    creation_date=_iso(item.get("CreationDate")),
                    last_execution_date=_iso(item.get("LastExecutionDate")),
                    rules=[],
                    resources=[],
                    selections_complete=False,
                )
            )
            continue

        raw_plan = desc.get("BackupPlan", {})
        rules: list[BackupRule] = []
        for r in raw_plan.get("Rules", []):
            lifecycle = r.get("Lifecycle") or {}
            rules.append(
                BackupRule(
                    rule_name=r.get("RuleName", ""),
                    vault_name=r.get("TargetBackupVaultName", ""),
                    schedule=r.get("ScheduleExpression", ""),
                    start_window_minutes=int(r.get("StartWindowMinutes") or 0),
                    completion_window_minutes=int(r.get("CompletionWindowMinutes") or 0),
                    delete_after_days=int(lifecycle.get("DeleteAfterDays") or 0),
                    cold_storage_after_days=int(lifecycle.get("MoveToColdStorageAfterDays") or 0),
                )
            )

        resources: list[str] = []
        # AWS Backup assigns resources to a plan by explicit ARN (`Resources`), by tag equality
        # (`ListOfTags`), or by richer `Conditions`. Org policies (BackupPlanId `orgs/…`) almost
        # always select by tag, so `Resources` is empty there — capture the tag/condition criteria
        # too so a resource can be attributed to the plan that protects it (done SE-side).
        selection_tags: list[dict] = []
        selection_conditions: list[dict] = []
        selections: list[BackupSelection] = []
        selections_complete = True

        # A listing that fails half way keeps the selections already read; the plan is then
        # marked incomplete.
        selection_ids: list[str] = []
        try:
            selection_paginator = client.get_paginator("list_backup_selections")
            for page in selection_paginator.paginate(BackupPlanId=plan_id):
                selection_ids.extend(
                    sel.get("SelectionId", "") for sel in page.get("BackupSelectionsList", [])
                )
        except Exception as exc:
            errors.append(exc)
            selections_complete = False

        for sel_id in selection_ids:
            try:
                detail = client.get_backup_selection(BackupPlanId=plan_id, SelectionId=sel_id)
            except Exception as exc:
                # A failed selection contributes nothing (PowerShell would reuse the previous one).
                errors.append(exc)
                selections_complete = False
                continue
            selection = detail.get("BackupSelection") or {}
            resources.extend(selection.get("Resources") or [])
            selection_tags.extend(selection.get("ListOfTags") or [])
            if selection.get("Conditions"):
                selection_conditions.append(selection["Conditions"])
            selections.append(_selection_from(sel_id, selection))

        plans.append(
            BackupPlan(
                account_id=account_id,
                account_alias=account_alias,
                region=region,
                plan_id=plan_id,
                plan_arn=item.get("BackupPlanArn", ""),
                plan_name=item.get("BackupPlanName", ""),
                version_id=item.get("VersionId", ""),
                creation_date=_iso(item.get("CreationDate")),
                last_execution_date=_iso(item.get("LastExecutionDate")),
                rules=rules,
                resources=resources,
                selection_tags=selection_tags,
                selection_conditions=selection_conditions,
                selections=selections,
                selections_complete=selections_complete,
                plan_export=_plan_export(item, desc),
            )
        )

    _record_plan_failures(tracker, region, errors)
    return plans


def fetch_backup_vaults(
    session, region: str, account_id: str, account_alias: str
) -> list[BackupVault]:
    """Fetch AWS Backup vaults with their Vault Lock (WORM immutability) config, recovery-point
    count, and encryption key. `list_backup_vaults` returns these inline, so no per-vault
    describe N+1. Failures are non-fatal (returns what was collected)."""
    client = session.client("backup", region_name=region)
    vaults: list[BackupVault] = []
    try:
        paginator = client.get_paginator("list_backup_vaults")
        for page in paginator.paginate():
            for v in page.get("BackupVaultList", []):
                name = v.get("BackupVaultName", "")
                if not name:
                    continue
                min_ret = v.get("MinRetentionDays")
                max_ret = v.get("MaxRetentionDays")
                vaults.append(
                    BackupVault(
                        account_id=account_id,
                        account_alias=account_alias,
                        region=region,
                        vault_name=name,
                        vault_arn=v.get("BackupVaultArn", ""),
                        encryption_key_arn=v.get("EncryptionKeyArn", "") or "",
                        recovery_point_count=int(v.get("NumberOfRecoveryPoints") or 0),
                        locked=bool(v.get("Locked")),
                        # AWS doesn't return the lock MODE (governance/compliance) on the list call;
                        # a set MinRetentionDays under an active lock means recovery points are
                        # retention-enforced, so surface "compliance" as the best-effort label.
                        lock_state="compliance" if (v.get("Locked") and min_ret) else "",
                        min_retention_days=int(min_ret) if min_ret is not None else None,
                        max_retention_days=int(max_ret) if max_ret is not None else None,
                    )
                )
    except Exception as exc:
        logging.warning("Could not list backup vaults in %s: %s", region, exc)
    return vaults


def _parse_backup_resource_type(usage_type: str) -> str:
    """Map a Cost Explorer USAGE_TYPE string to a normalized resource type label."""
    # Strip region prefix e.g. "USE1-", "USW2-", "APS1-", "EU-" etc.
    core = usage_type.split("-", 1)[-1] if "-" in usage_type else usage_type
    core = core.lower()

    if "backupusage:rds" in core or "rds" in core:
        return "RDS"
    if "backupusage:aurora" in core or "aurora" in core:
        return "Aurora"
    if "backupusage:dynamodb" in core or "dynamodb" in core:
        return "DynamoDB"
    if "backupusage:efs" in core or "efs" in core:
        return "EFS"
    if "backupusage:s3" in core or "s3" in core:
        return "S3"
    if "backupusage:fsx" in core or "fsx" in core:
        return "FSx"
    if "backupusage:ec2" in core or "instancebackup" in core:
        return "EC2"
    if "backupusage:ebs" in core or "snapshot" in core or "ebs" in core:
        return "EBS"
    if "backupusage:documentdb" in core or "docdb" in core:
        return "DocumentDB"
    if "backupusage:neptune" in core:
        return "Neptune"
    if "backupusage:timestream" in core:
        return "Timestream"
    if "backupusage:sap" in core:
        return "SAP HANA"
    if "backupusage:" in core:
        # Extract whatever comes after the colon as-is
        return core.split("backupusage:", 1)[1].split("-")[0].upper()
    return "Other"


def _parse_backup_storage_tier(usage_type: str) -> str:
    """Determine warm vs. cold storage tier from a usage type string."""
    lower = usage_type.lower()
    if "cold" in lower or "archive" in lower or "glacier" in lower:
        return "cold"
    return "warm"


def fetch_backup_costs(session, account_id: str, account_alias: str) -> list[BackupCostEntry]:
    """Fetch 12 months of backup costs from Cost Explorer, broken down by usage type.

    Queries:
    1. AWS Backup service grouped by USAGE_TYPE — gives per-resource-type and warm/cold breakdown.
    2. EBS Snapshots (USAGE_TYPE_GROUP) — direct snapshot costs outside AWS Backup vaults.
    """
    client = session.client("ce", region_name="us-east-1")

    now = datetime.now(timezone.utc)
    start = now.replace(year=now.year - 1).strftime("%Y-%m-%d")
    end = now.strftime("%Y-%m-%d")

    entries: list[BackupCostEntry] = []

    # ── 1. AWS Backup vault costs grouped by usage type ──────────────────────────
    try:
        resp = client.get_cost_and_usage(
            TimePeriod={"Start": start, "End": end},
            Granularity="MONTHLY",
            Metrics=["AmortizedCost", "BlendedCost", "UnblendedCost"],
            Filter={"Dimensions": {"Key": "SERVICE", "Values": ["AWS Backup"]}},
            GroupBy=[{"Type": "DIMENSION", "Key": "USAGE_TYPE"}],
        )
        for period in resp.get("ResultsByTime", []):
            ps = period["TimePeriod"]["Start"]
            pe = period["TimePeriod"]["End"]
            for group in period.get("Groups", []):
                usage_type = group["Keys"][0]
                totals = group.get("Metrics", {})
                cost = float(totals.get("AmortizedCost", {}).get("Amount", 0))
                if cost == 0:
                    continue
                entries.append(
                    BackupCostEntry(
                        account_id=account_id,
                        account_alias=account_alias,
                        period_start=ps,
                        period_end=pe,
                        amortized_cost=cost,
                        blended_cost=float(totals.get("BlendedCost", {}).get("Amount", 0)),
                        unblended_cost=float(totals.get("UnblendedCost", {}).get("Amount", 0)),
                        service="AWS Backup",
                        usage_type=usage_type,
                        resource_type=_parse_backup_resource_type(usage_type),
                        storage_tier=_parse_backup_storage_tier(usage_type),
                    )
                )
    except Exception as exc:
        logging.warning("Could not fetch AWS Backup costs by usage type: %s", exc)

    # ── 2. EBS Snapshots (outside AWS Backup vaults) ─────────────────────────────
    try:
        resp = client.get_cost_and_usage(
            TimePeriod={"Start": start, "End": end},
            Granularity="MONTHLY",
            Metrics=["AmortizedCost", "BlendedCost", "UnblendedCost"],
            Filter={"Dimensions": {"Key": "USAGE_TYPE_GROUP", "Values": ["EC2: EBS - Snapshots"]}},
        )
        for period in resp.get("ResultsByTime", []):
            totals = period.get("Total", {})
            cost = float(totals.get("AmortizedCost", {}).get("Amount", 0))
            if cost == 0:
                continue
            entries.append(
                BackupCostEntry(
                    account_id=account_id,
                    account_alias=account_alias,
                    period_start=period["TimePeriod"]["Start"],
                    period_end=period["TimePeriod"]["End"],
                    amortized_cost=cost,
                    blended_cost=float(totals.get("BlendedCost", {}).get("Amount", 0)),
                    unblended_cost=float(totals.get("UnblendedCost", {}).get("Amount", 0)),
                    service="EBS Snapshots",
                    usage_type="EC2: EBS - Snapshots",
                    resource_type="EBS",
                    storage_tier="warm",
                )
            )
    except Exception as exc:
        logging.warning("Could not fetch EBS Snapshot costs: %s", exc)

    return entries
