"""S3 Tables and Glue Data Catalog Iceberg tables.

Ports ``Get-AWSS3TablesInventory``, ``Get-AWSGlueIcebergInventory``, ``Read-IcebergMetadataJson``
and ``Read-IcebergManifestList``. Table sizes come from the current snapshot of the table's
Iceberg ``metadata.json`` (exact), with CloudWatch as the fallback for S3 Tables.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Optional

from botocore.exceptions import EndpointConnectionError
from models.discovery import GlueIcebergTable, IcebergStats, S3Table

from collectors import BOTO_ADAPTIVE_CFG, DenialTracker, record_metric_failures
from collectors.arns import partition
from collectors.s3 import _maximum
from collectors.snapshots import _iso

log = logging.getLogger(__name__)

_MAX_METADATA_BYTES = 10 * 1024 * 1024
_MAX_MANIFEST_LIST_BYTES = 50 * 1024 * 1024
_DEFAULT_TARGET_MANIFEST_BYTES = 8388608  # Iceberg's default write.manifest-file-size-bytes
_LONG_MAX = 2**63 - 1
_S3_URI = re.compile(r"^s3://([^/]+)/(.+)$")
_S3_BUCKET = re.compile(r"^s3://([^/]+)")
_REDIRECT_CODES = {"PermanentRedirect", "301"}
_LEGACY_LOCATIONS = {"EU": "eu-west-1"}


def _error_code(exc: Exception) -> str:
    response = getattr(exc, "response", None)
    return str(response.get("Error", {}).get("Code", "")) if isinstance(response, dict) else ""


class S3ObjectReader:
    """Reads the S3 objects Iceberg metadata points to, including cross-region buckets.

    Requests are made as requester-pays so buckets that require it still answer. A bucket
    in another region gives a redirect; its region is then looked up once and reused.
    """

    def __init__(self, session, region: str) -> None:
        self._session = session
        self._region = region
        self._clients: dict[str, Any] = {}
        self._bucket_regions: dict[str, str] = {}
        self._no_requester_pays: set[str] = set()

    def _client(self, region: str):
        if region not in self._clients:
            self._clients[region] = self._session.client(
                "s3", region_name=region, config=BOTO_ADAPTIVE_CFG
            )
        return self._clients[region]

    def _bucket_region(self, bucket: str) -> str:
        location = self._client(self._region).get_bucket_location(Bucket=bucket)
        constraint = location.get("LocationConstraint") or "us-east-1"
        return _LEGACY_LOCATIONS.get(constraint, constraint)

    def _call(self, operation: str, bucket: str, key: str) -> dict:
        """One S3 call, retried for a redirect or a 400 (other region, or no requester-pays)."""
        region = self._bucket_regions.get(bucket, self._region)
        payer = {} if bucket in self._no_requester_pays else {"RequestPayer": "requester"}
        try:
            return getattr(self._client(region), operation)(Bucket=bucket, Key=key, **payer)
        except Exception as exc:
            code = _error_code(exc)
            if code in _REDIRECT_CODES:
                self._bucket_regions[bucket] = self._bucket_region(bucket)
                return self._call(operation, bucket, key)
            if code != "400":
                raise
            # A HEAD answer has no body, so a wrong-region request arrives as a bare 400. Try
            # the bucket's own region once, then try without requester-pays.
            if bucket not in self._bucket_regions:
                try:
                    found = self._bucket_region(bucket)
                except Exception:
                    found = region
                self._bucket_regions[bucket] = found
                if found != region:
                    return self._call(operation, bucket, key)
            if payer:
                self._no_requester_pays.add(bucket)
                return self._call(operation, bucket, key)
            raise

    def head(self, bucket: str, key: str) -> dict:
        return self._call("head_object", bucket, key)

    def read(self, bucket: str, key: str) -> bytes:
        return self._call("get_object", bucket, key)["Body"].read()


def _zigzag(data: bytes, pos: int) -> tuple[int, int]:
    """Decode one Avro variable-length zigzag long; returns (value, next position)."""
    number = shift = 0
    while True:
        byte = data[pos]
        pos += 1
        number |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            return (number >> 1) ^ -(number & 1), pos


def count_manifest_list_entries(data: bytes) -> Optional[int]:
    """Number of manifests in an Avro manifest list, from the data block headers only.

    The container is: magic, a metadata map, a 16-byte sync marker, then data blocks of
    ``count | byte size | data | sync``. Adding up the block counts gives the entry count
    without decoding any record. ``None`` if this is not an Avro container.
    """
    if len(data) < 20 or data[:4] != b"Obj\x01":
        return None
    pos = 4
    while True:  # skip the file metadata map
        block_count, pos = _zigzag(data, pos)
        if block_count < 0:
            block_count = -block_count
            _, pos = _zigzag(data, pos)
        for _ in range(block_count):
            key_length, pos = _zigzag(data, pos)
            pos += key_length
            value_length, pos = _zigzag(data, pos)
            pos += value_length
        if block_count == 0:
            break
    pos += 16
    total = 0
    while pos < len(data):
        block_count, pos = _zigzag(data, pos)
        if block_count == 0:
            break
        if block_count < 0:
            block_count = -block_count
            _, pos = _zigzag(data, pos)
        byte_count, pos = _zigzag(data, pos)
        total += block_count
        pos += byte_count + 16
    return total


def _read_manifest_count(
    reader: S3ObjectReader, manifest_list: str, table: str, errors: list[Exception]
) -> Optional[int]:
    match = _S3_URI.match(manifest_list or "")
    if not match:
        return None
    bucket, key = match.groups()
    try:
        if int(reader.head(bucket, key).get("ContentLength") or 0) > _MAX_MANIFEST_LIST_BYTES:
            log.warning("Skipping oversized manifest list of table %s", _safe(table))
            return None
        return count_manifest_list_entries(reader.read(bucket, key))
    except Exception as exc:
        errors.append(exc)
        return None


def _safe(text: str) -> str:
    return re.sub(r"[^\x20-\x7E]", "?", text or "")


def _number(value: Any) -> Optional[int]:
    return int(value) if value not in (None, "") else None


def read_iceberg_stats(
    reader: S3ObjectReader, metadata_location: Optional[str], table: str, errors: list[Exception]
) -> IcebergStats:
    """Stats from the table's metadata.json; whatever could not be read stays None.

    ``errors`` collects failures so one table never stops the run.
    """
    stats = IcebergStats()
    match = _S3_URI.match(metadata_location or "")
    if not match:
        return stats
    bucket, key = match.groups()
    try:
        head = reader.head(bucket, key)
    except Exception as exc:
        errors.append(exc)
        return stats
    stats.metadata_file_storage_class = str(head.get("StorageClass") or "")
    if int(head.get("ContentLength") or 0) > _MAX_METADATA_BYTES:
        log.warning("Skipping oversized metadata.json of table %s", _safe(table))
        return stats

    try:
        meta = json.loads(reader.read(bucket, key))
        stats.format_version = _number(meta.get("format-version"))
        # Snapshot ids are compared as text: they are 64-bit and must not pass through a float.
        current = str(meta.get("current-snapshot-id"))
        snapshots = meta.get("snapshots") or []
        snapshot = next((s for s in snapshots if str(s.get("snapshot-id")) == current), None)
        if snapshot and snapshot.get("summary"):
            summary = snapshot["summary"]
            stats.total_file_size_bytes = _number(summary.get("total-files-size"))
            stats.data_file_count = _number(summary.get("total-data-files"))
            stats.total_delete_file_count = _number(summary.get("total-delete-files"))
            stats.manifest_count = _number(summary.get("total-manifests"))
        if stats.manifest_count is None and snapshot and snapshot.get("manifest-list"):
            stats.manifest_count = _read_manifest_count(
                reader, snapshot["manifest-list"], table, errors
            )
        target = (meta.get("properties") or {}).get("write.manifest-file-size-bytes")
        if target not in (None, ""):
            stats.target_manifest_size_bytes = int(target)
        if stats.manifest_count is not None:
            estimate = stats.manifest_count * (stats.target_manifest_size_bytes or 0)
            stats.manifest_bytes_estimate = estimate if estimate <= _LONG_MAX else None
        stats.compaction_enabled = any(
            (s.get("summary") or {}).get("operation") == "replace" for s in snapshots
        )
    except Exception as exc:
        errors.append(exc)
    return stats


def _record(
    tracker: "DenialTracker | None", region: str, what: str, errors: list[Exception], service: str
) -> None:
    record_metric_failures(tracker, region, what, errors, service=service)


def _tags(items: Any) -> dict[str, str]:
    return {str(k): str(v) for k, v in (items or {}).items()}


def _maintenance_on(status: Any) -> bool:
    """Whether a maintenance setting's status is "enabled", whatever the case ("enabled" from
    the API, "ENABLED" in its documentation)."""
    return str(status or "").casefold() == "enabled"


def fetch_s3_tables(
    session,
    region: str,
    account_id: str,
    account_alias: str,
    tracker: "DenialTracker | None" = None,
) -> list[S3Table]:
    """Every table in every table bucket of the region, with Iceberg stats and tags."""
    client = session.client("s3tables", region_name=region, config=BOTO_ADAPTIVE_CFG)
    cw_client = session.client("cloudwatch", region_name=region, config=BOTO_ADAPTIVE_CFG)
    reader = S3ObjectReader(session, region)
    errors: list[Exception] = []
    maintenance_errors: list[Exception] = []
    tables: list[S3Table] = []

    try:
        buckets = [
            b
            for page in client.get_paginator("list_table_buckets").paginate()
            for b in page.get("tableBuckets", [])
        ]
    except EndpointConnectionError:
        log.debug("S3 Tables is not available in %s", region)
        return tables
    except Exception as exc:
        errors.append(exc)
        _record(tracker, region, "S3 Tables bucket listing", errors, "s3tables")
        return tables

    for bucket in buckets:
        bucket_arn, bucket_name = bucket.get("arn", ""), bucket.get("name", "")
        try:
            summaries = [
                t
                for page in client.get_paginator("list_tables").paginate(tableBucketARN=bucket_arn)
                for t in page.get("tables", [])
            ]
        except Exception as exc:
            errors.append(exc)
            continue
        for summary in summaries:
            namespace = "/".join(summary.get("namespace") or [])
            name = summary.get("name", "")
            arn = summary.get("tableARN", "")
            ids = dict(tableBucketARN=bucket_arn, namespace=namespace, name=name)
            table = S3Table(
                account_id=account_id,
                account_alias=account_alias,
                region=region,
                namespace=namespace,
                table_name=name,
                table_bucket_name=bucket_name,
                table_bucket_arn=bucket_arn,
                table_arn=arn,
                table_type=str(summary.get("type") or ""),
                created_at=_iso(summary.get("createdAt")),
                modified_at=_iso(summary.get("modifiedAt")),
            )
            try:
                detail = client.get_table(**ids)
                table.warehouse_location = detail.get("warehouseLocation")
                table.storage_class = str(detail.get("storageClass") or "STANDARD")
            except Exception as exc:
                errors.append(exc)
            try:
                table.metadata_location = client.get_table_metadata_location(**ids).get(
                    "metadataLocation"
                )
            except Exception as exc:
                errors.append(exc)
                table.metadata_location = ""
            if (table.metadata_location or "").strip():
                table.iceberg = read_iceberg_stats(reader, table.metadata_location, name, errors)
            try:
                config = (
                    client.get_table_maintenance_configuration(**ids).get("configuration") or {}
                )
                # The API writes the status in lower case ("enabled"), and a case-sensitive
                # comparison read every table with maintenance on as off.
                compaction = config.get("icebergCompaction")
                if compaction is not None:
                    table.compaction_enabled = _maintenance_on(compaction.get("status"))
                management = config.get("icebergSnapshotManagement")
                if management is not None:
                    table.snapshot_management_enabled = _maintenance_on(management.get("status"))
            except Exception as exc:
                maintenance_errors.append(exc)
            dimensions = [
                {"Name": "TableBucketName", "Value": bucket_name},
                {"Name": "Namespace", "Value": namespace},
                {"Name": "TableName", "Value": name},
                {"Name": "StorageType", "Value": "TablesStandardStorage"},
            ]
            size = _maximum(cw_client, "AWS/S3/Tables", "TableSizeBytes", dimensions, errors)
            count = _maximum(cw_client, "AWS/S3/Tables", "TableNumberOfObjects", dimensions, errors)
            table.cloudwatch_size_bytes = int(size) if size is not None else None
            table.total_file_count = int(count) if count is not None else None
            try:
                table.tags = _tags(client.list_tags_for_resource(resourceArn=arn).get("tags"))
            except Exception as exc:
                errors.append(exc)
            tables.append(table)

    _record(tracker, region, "S3 Tables", errors, "s3tables")
    _record(
        tracker,
        region,
        "S3 Tables maintenance configuration (CompactionEnabled and SnapshotManagementEnabled left "
        "blank for the tables it failed on)",
        maintenance_errors,
        "s3tables",
    )
    return tables


def fetch_glue_iceberg(
    session,
    region: str,
    account_id: str,
    account_alias: str,
    tracker: "DenialTracker | None" = None,
) -> list[GlueIcebergTable]:
    """Iceberg tables of the Glue Data Catalog, with Iceberg stats and tags.

    Only tables the role may see are listed: with Lake Formation governance a table without a
    SELECT grant for the role is absent from ``GetTables``.
    """
    client = session.client("glue", region_name=region, config=BOTO_ADAPTIVE_CFG)
    reader = S3ObjectReader(session, region)
    errors: list[Exception] = []
    found: list[GlueIcebergTable] = []

    try:
        databases = [
            d["Name"]
            for page in client.get_paginator("get_databases").paginate()
            for d in page.get("DatabaseList", [])
        ]
    except Exception as exc:
        errors.append(exc)
        _record(tracker, region, "Glue database listing", errors, "glue")
        return found

    for database in databases:
        try:
            iceberg = [
                t
                for page in client.get_paginator("get_tables").paginate(DatabaseName=database)
                for t in page.get("TableList", [])
                if str((t.get("Parameters") or {}).get("table_type", "")).lower() == "iceberg"
            ]
        except Exception as exc:
            errors.append(exc)
            continue
        for table in iceberg:
            name = table.get("Name", "")
            location = (table.get("StorageDescriptor") or {}).get("Location") or ""
            metadata_location = (table.get("Parameters") or {}).get("metadata_location")
            bucket = _S3_BUCKET.match(location)
            row = GlueIcebergTable(
                account_id=account_id,
                account_alias=account_alias,
                region=region,
                database_name=database,
                table_name=name,
                s3_bucket_name=bucket.group(1) if bucket else "",
                s3_location=location,
                metadata_location=metadata_location,
                create_time=_iso(table.get("CreateTime")),
                update_time=_iso(table.get("UpdateTime")),
                iceberg=read_iceberg_stats(reader, metadata_location, name, errors),
            )
            arn = f"arn:{partition(region)}:glue:{region}:{account_id}:table/{database}/{name}"
            try:
                row.tags = _tags(client.get_tags(ResourceArn=arn).get("Tags"))
            except Exception as exc:
                errors.append(exc)
            found.append(row)

    _record(tracker, region, "Glue Iceberg tables", errors, "glue")
    return found


def apply_glue_iceberg_to_buckets(buckets: list, tables: list[GlueIcebergTable]) -> None:
    """Mark the buckets that hold Glue Iceberg data and take that data out of their sizes.

    The bytes a bucket holds for Glue Iceberg tables are counted by the Iceberg workload, so
    they are deducted from the bucket's storage classes, largest class first, spilling to the
    next when a class is used up. Buckets are matched case-insensitively, like PowerShell.
    """
    iceberg_bytes: dict[str, float] = {}
    for table in tables:
        match = _S3_BUCKET.match(table.s3_location or "")
        if match:
            name = match.group(1).lower()
            iceberg_bytes[name] = iceberg_bytes.get(name, 0.0) + float(
                table.iceberg.total_file_size_bytes or 0
            )
    for bucket in buckets:
        remaining = iceberg_bytes.get(bucket.bucket_name.lower(), 0.0)
        bucket.has_iceberg_table = bucket.bucket_name.lower() in {
            t.s3_bucket_name.lower() for t in tables if t.s3_bucket_name
        }
        if remaining <= 0:
            continue
        by_size = sorted(
            ((c, v) for c, v in bucket.storage_class_bytes.items() if v is not None),
            key=lambda item: item[1],
            reverse=True,
        )
        for storage_class, current in by_size:
            if remaining <= 0:
                break
            if current <= 0:
                continue
            deducted = min(current, remaining)
            bucket.storage_class_bytes[storage_class] = max(0.0, current - deducted)
            bucket.iceberg_adjusted_classes.append(storage_class)
            remaining -= deducted
        standard = bucket.storage_class_bytes.get("StandardStorage")
        if standard is not None:
            bucket.size_bytes = int(standard)
            bucket.size_gb = round(bucket.size_bytes / (1024**3), 4)
            bucket.size_tb = round(bucket.size_bytes / (1024**4), 4)
