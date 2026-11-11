"""DynamoDB table collector."""

from __future__ import annotations

import logging

from models.discovery import DynamoDBTable

from collectors import DenialTracker, is_scp_denial
from collectors.arns import dynamodb_table_arn


def _round4(v: float) -> float:
    return round(v, 4)


def fetch_dynamodb(
    session,
    region: str,
    account_id: str,
    account_alias: str,
    protected_arns: set[str],
    tracker: "DenialTracker | None" = None,
) -> list[DynamoDBTable]:
    """Fetch all DynamoDB tables and their sizing metadata."""
    client = session.client("dynamodb", region_name=region)
    tables: list[DynamoDBTable] = []

    try:
        paginator = client.get_paginator("list_tables")
        table_names: list[str] = []
        for page in paginator.paginate():
            table_names.extend(page.get("TableNames", []))
    except Exception as exc:
        if is_scp_denial(exc):
            if tracker is not None:
                tracker.record("dynamodb")
            logging.debug("Could not list DynamoDB tables in %s (SCP denied)", region)
        else:
            if tracker is not None:
                tracker.record_permission_error("dynamodb", region, exc)
            logging.warning("Could not list DynamoDB tables in %s: %s", region, exc)
        return tables

    for name in table_names:
        try:
            desc = client.describe_table(TableName=name)
            t = desc["Table"]
        except Exception as exc:
            logging.warning("Could not describe DynamoDB table %s in %s: %s", name, region, exc)
            continue

        size_bytes = t.get("TableSizeBytes") or 0
        size_gib = _round4(size_bytes / (1024**3))
        size_tb = _round4(size_gib / 1024)
        # LSI footprint is reported per-index, separate from TableSizeBytes. Rubrik prices the
        # export as table data + LSI, so capture it so the sizing push can fill it 1:1.
        lsi_size_bytes = sum(
            int(idx.get("IndexSizeBytes") or 0) for idx in (t.get("LocalSecondaryIndexes") or [])
        )
        lsi_size_gib = _round4(lsi_size_bytes / (1024**3))
        lsi_size_tb = _round4(lsi_size_gib / 1024)
        table_arn = t.get("TableArn", dynamodb_table_arn(region, account_id, name))
        backup_plans = ["AWS Backup"] if table_arn in protected_arns else []

        pitr_enabled = False
        try:
            cb = client.describe_continuous_backups(TableName=name)
            pitr_desc = cb.get("ContinuousBackupsDescription") or {}
            pitr_status = (pitr_desc.get("PointInTimeRecoveryDescription") or {}).get(
                "PointInTimeRecoveryStatus", "DISABLED"
            )
            pitr_enabled = pitr_status == "ENABLED"
        except Exception as exc:
            logging.debug("Could not get PITR status for %s: %s", name, exc)

        tags: dict[str, str] = {}
        try:
            tag_resp = client.list_tags_of_resource(ResourceArn=table_arn)
            tags = {tag["Key"]: tag["Value"] for tag in tag_resp.get("Tags", [])}
        except Exception as exc:
            logging.debug("Could not fetch tags for DynamoDB table %s: %s", name, exc)

        pt = t.get("ProvisionedThroughput") or {}
        tables.append(
            DynamoDBTable(
                account_id=account_id,
                account_alias=account_alias,
                region=region,
                table_name=t.get("TableName", name),
                table_id=t.get("TableId") or "",
                table_arn=table_arn,
                size_bytes=size_bytes,
                size_gib=size_gib,
                size_tb=size_tb,
                item_count=t.get("ItemCount") or 0,
                status=str(t.get("TableStatus", "")),
                deletion_protection=bool(t.get("DeletionProtectionEnabled")),
                read_capacity_units=int(pt.get("ReadCapacityUnits") or 0),
                write_capacity_units=int(pt.get("WriteCapacityUnits") or 0),
                pitr_enabled=pitr_enabled,
                in_backup_plan=bool(backup_plans) or pitr_enabled,
                backup_plans=backup_plans,
                lsi_size_bytes=lsi_size_bytes,
                lsi_size_gib=lsi_size_gib,
                lsi_size_tb=lsi_size_tb,
                tags=tags,
                number_of_decreases_today=int(pt.get("NumberOfDecreasesToday") or 0),
                global_table_version=str(t.get("GlobalTableVersion") or ""),
            )
        )

    return tables
