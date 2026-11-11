"""Tests for the S3 Tables and Glue Iceberg collectors and the Iceberg metadata readers."""

import io
import json
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError, EndpointConnectionError
from collectors import DenialTracker
from collectors.iceberg import (
    S3ObjectReader,
    apply_glue_iceberg_to_buckets,
    count_manifest_list_entries,
    fetch_glue_iceberg,
    fetch_s3_tables,
    read_iceberg_stats,
)
from models.discovery import GlueIcebergTable, IcebergStats, S3Bucket

ACCT = "123456789012"
REGION = "us-east-1"
DAY = datetime(2026, 7, 18, 11, 50, 2, tzinfo=timezone.utc)


def _client_error(code, message="boom"):
    return ClientError({"Error": {"Code": code, "Message": message}}, "Op")


# ── Avro manifest list ────────────────────────────────────────────────────────


def _zz(value: int) -> bytes:
    value = (value << 1) ^ (value >> 63)
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _avro(block_counts, metadata=None):
    sync = b"S" * 16
    data = b"Obj\x01"
    pairs = metadata or {b"avro.schema": b'{"type":"record"}', b"avro.codec": b"null"}
    data += _zz(len(pairs))
    for key, value in pairs.items():
        data += _zz(len(key)) + key + _zz(len(value)) + value
    data += _zz(0) + sync
    for count in block_counts:
        payload = b"x" * (count * 3)
        data += _zz(count) + _zz(len(payload)) + payload + sync
    return data


def test_manifest_count_is_the_sum_of_block_counts():
    assert count_manifest_list_entries(_avro([3, 5, 2])) == 10
    assert count_manifest_list_entries(_avro([])) == 0
    assert count_manifest_list_entries(_avro([200, 300])) == 500  # multi-byte varint counts


def test_manifest_count_rejects_a_file_that_is_not_avro():
    assert count_manifest_list_entries(b"not an avro file at all, just text") is None
    assert count_manifest_list_entries(b"Obj") is None


def test_a_truncated_avro_file_raises_so_the_caller_can_record_it():
    with pytest.raises(IndexError):
        count_manifest_list_entries(_avro([3])[:30])


# ── metadata.json stats ───────────────────────────────────────────────────────


class FakeReader:
    def __init__(self, objects, storage_class="", head_error=None, sizes=None):
        self.objects = objects  # (bucket, key) -> bytes
        self.storage_class = storage_class
        self.head_error = head_error
        self.sizes = sizes or {}

    def head(self, bucket, key):
        if self.head_error:
            raise self.head_error
        data = self.objects[(bucket, key)]
        size = self.sizes.get((bucket, key), len(data))
        out = {"ContentLength": size}
        if self.storage_class:
            out["StorageClass"] = self.storage_class
        return out

    def read(self, bucket, key):
        return self.objects[(bucket, key)]


def _meta(**overrides):
    meta = {
        "format-version": 2,
        "current-snapshot-id": 8888888888888888888,
        "snapshots": [
            {"snapshot-id": 1, "summary": {"operation": "append"}},
            {
                "snapshot-id": 8888888888888888888,
                "summary": {
                    "operation": "append",
                    "total-files-size": "1073741824",
                    "total-data-files": "12",
                    "total-delete-files": "3",
                    "total-manifests": "7",
                },
            },
        ],
        "properties": {},
    }
    meta.update(overrides)
    return json.dumps(meta).encode()


LOC = "s3://warehouse/db/tbl/metadata/v1.metadata.json"
KEY = ("warehouse", "db/tbl/metadata/v1.metadata.json")


def _stats(meta, **reader_kwargs):
    errors: list = []
    reader = FakeReader({KEY: meta}, **reader_kwargs)
    return read_iceberg_stats(reader, LOC, "tbl", errors), errors


def test_stats_come_from_the_current_snapshot_summary():
    stats, errors = _stats(_meta(), storage_class="INTELLIGENT_TIERING")
    assert stats.format_version == 2
    assert stats.total_file_size_bytes == 1073741824 and stats.data_file_count == 12
    assert (stats.total_delete_file_count, stats.manifest_count) == (3, 7)
    assert stats.target_manifest_size_bytes == 8388608
    assert stats.manifest_bytes_estimate == 7 * 8388608
    assert stats.metadata_file_storage_class == "INTELLIGENT_TIERING" and errors == []


def test_the_current_snapshot_is_matched_by_text_so_64_bit_ids_survive():
    meta = json.loads(_meta())
    meta["snapshots"][0]["summary"]["total-files-size"] = "5"
    meta["snapshots"][0]["snapshot-id"] = 8888888888888888887  # one less than the current id
    stats, _ = _stats(json.dumps(meta).encode())
    assert stats.total_file_size_bytes == 1073741824


def test_target_manifest_size_property_overrides_the_default():
    stats, _ = _stats(_meta(properties={"write.manifest-file-size-bytes": "1000"}))
    assert stats.target_manifest_size_bytes == 1000 and stats.manifest_bytes_estimate == 7000


def test_compaction_is_true_when_any_snapshot_is_a_replace():
    meta = json.loads(_meta())
    meta["snapshots"][0]["summary"]["operation"] = "replace"
    assert _stats(json.dumps(meta).encode())[0].compaction_enabled is True
    assert _stats(_meta())[0].compaction_enabled is False


def test_missing_manifest_total_falls_back_to_counting_the_manifest_list():
    meta = json.loads(_meta())
    summary = meta["snapshots"][1]["summary"]
    del summary["total-manifests"]
    meta["snapshots"][1]["manifest-list"] = "s3://warehouse/db/tbl/metadata/snap.avro"
    reader = FakeReader(
        {KEY: json.dumps(meta).encode(), ("warehouse", "db/tbl/metadata/snap.avro"): _avro([4, 6])}
    )
    errors: list = []
    stats = read_iceberg_stats(reader, LOC, "tbl", errors)
    assert stats.manifest_count == 10 and errors == []


def test_unreadable_manifest_list_leaves_the_count_unknown_and_records_the_failure():
    meta = json.loads(_meta())
    del meta["snapshots"][1]["summary"]["total-manifests"]
    meta["snapshots"][1]["manifest-list"] = "s3://warehouse/db/tbl/metadata/snap.avro"
    reader = FakeReader(
        {KEY: json.dumps(meta).encode(), ("warehouse", "db/tbl/metadata/snap.avro"): b"Obj\x01"}
    )
    errors: list = []
    stats = read_iceberg_stats(reader, LOC, "tbl", errors)
    assert stats.manifest_count is None and stats.manifest_bytes_estimate is None
    assert stats.total_file_size_bytes == 1073741824  # the rest is kept


def test_manifest_bytes_that_overflow_a_64_bit_long_are_left_unknown():
    stats, _ = _stats(_meta(properties={"write.manifest-file-size-bytes": str(2**62)}))
    assert stats.manifest_count == 7 and stats.manifest_bytes_estimate is None


def test_oversized_metadata_is_skipped_but_keeps_the_storage_class():
    stats, errors = _stats(_meta(), storage_class="STANDARD_IA", sizes={KEY: 11 * 1024 * 1024})
    assert (
        stats.total_file_size_bytes is None and stats.metadata_file_storage_class == "STANDARD_IA"
    )
    assert stats.target_manifest_size_bytes == 8388608 and errors == []


def test_head_failure_returns_the_defaults_and_is_recorded():
    stats, errors = _stats(_meta(), head_error=_client_error("AccessDenied"))
    assert stats == IcebergStats() and len(errors) == 1


def test_invalid_json_keeps_what_was_known_and_is_recorded():
    stats, errors = _stats(b"{not json", storage_class="STANDARD_IA")
    assert (
        stats.total_file_size_bytes is None and stats.metadata_file_storage_class == "STANDARD_IA"
    )
    assert len(errors) == 1


@pytest.mark.parametrize("location", [None, "", "https://example/x", "s3://bucket-only"])
def test_a_location_that_is_not_an_s3_object_gives_the_defaults(location):
    errors: list = []
    assert read_iceberg_stats(FakeReader({}), location, "t", errors) == IcebergStats()
    assert errors == []


# ── reading across regions ────────────────────────────────────────────────────


def _s3_session(regions):
    """Session whose s3 client per region answers a redirect unless it is the bucket's region."""
    created = []

    def client(service, region_name=None, **kw):
        c = MagicMock()
        created.append(region_name)

        def head(Bucket, Key, RequestPayer):
            if region_name != "eu-west-1":
                raise _client_error("PermanentRedirect")
            return {"ContentLength": 5, "StorageClass": "GLACIER_IR"}

        c.head_object.side_effect = head
        c.get_object.side_effect = lambda **kw: {"Body": io.BytesIO(b"hello")}
        c.get_bucket_location.return_value = {"LocationConstraint": "EU"}
        return c

    session = MagicMock()
    session.client.side_effect = client
    return session, created


def test_a_redirect_looks_up_the_bucket_region_once_and_reads_from_there():
    session, created = _s3_session(["us-east-1"])
    reader = S3ObjectReader(session, REGION)
    assert reader.head("b", "k")["StorageClass"] == "GLACIER_IR"
    assert reader.read("b", "k") == b"hello"
    reader.head("b", "k2")
    assert created.count("eu-west-1") == 1  # legacy "EU" maps to eu-west-1; the client is reused
    assert reader._client("eu-west-1").get_bucket_location.call_count == 0  # asked via home region
    for call in reader._client("eu-west-1").head_object.call_args_list:
        assert call.kwargs["RequestPayer"] == "requester"


def test_other_errors_are_not_treated_as_a_redirect():
    session = MagicMock()
    session.client.return_value.head_object.side_effect = _client_error("AccessDenied")
    with pytest.raises(ClientError):
        S3ObjectReader(session, REGION).head("b", "k")


# ── S3 Tables ─────────────────────────────────────────────────────────────────

BUCKET_ARN = f"arn:aws:s3tables:{REGION}:{ACCT}:bucket/tb"
TABLE_ARN = f"arn:aws:s3tables:{REGION}:{ACCT}:bucket/tb/table/uuid"


def _tables_session(
    metadata_location="s3://warehouse/db/tbl/metadata/v1.metadata.json",
    objects=None,
    maintenance=None,
    cw_points=None,
    fail=None,
    list_buckets_error=None,
):
    fail = fail or {}
    tables = MagicMock()

    def paginator(operation):
        p = MagicMock()
        if operation == "list_table_buckets":
            if list_buckets_error:
                p.paginate.side_effect = list_buckets_error
            else:
                p.paginate.return_value = [{"tableBuckets": [{"arn": BUCKET_ARN, "name": "tb"}]}]
        else:
            p.paginate.return_value = [
                {
                    "tables": [
                        {
                            "namespace": ["analytics", "sales"],
                            "name": "customers",
                            "type": "customer",
                            "tableARN": TABLE_ARN,
                            "createdAt": DAY,
                            "modifiedAt": DAY,
                        }
                    ]
                }
            ]
        return p

    tables.get_paginator.side_effect = paginator

    def respond(name, value):
        def call(**kw):
            if name in fail:
                raise fail[name]
            return value

        return call

    tables.get_table.side_effect = respond("get_table", {"warehouseLocation": "s3://wh"})
    tables.get_table_metadata_location.side_effect = respond(
        "get_table_metadata_location",
        {"metadataLocation": metadata_location} if metadata_location else {},
    )
    tables.get_table_maintenance_configuration.side_effect = respond(
        "get_table_maintenance_configuration", {"configuration": maintenance or {}}
    )
    tables.list_tags_for_resource.side_effect = respond(
        "list_tags_for_resource", {"tags": {"Env": "prod"}}
    )

    cw = MagicMock()
    points = cw_points or {}
    cw.get_metric_statistics.side_effect = lambda **kw: {
        "Datapoints": [{"Maximum": v, "Timestamp": DAY} for v in points.get(kw["MetricName"], [])]
    }

    s3 = MagicMock()
    objects = objects if objects is not None else {}
    s3.head_object.side_effect = lambda Bucket, Key, RequestPayer: {
        "ContentLength": len(objects[(Bucket, Key)])
    }
    s3.get_object.side_effect = lambda Bucket, Key, RequestPayer: {
        "Body": io.BytesIO(objects[(Bucket, Key)])
    }
    session = MagicMock()
    session.client.side_effect = lambda service, **kw: {
        "s3tables": tables,
        "cloudwatch": cw,
        "s3": s3,
    }[service]
    return session, cw


def test_s3_table_collects_listing_details_maintenance_metrics_and_tags():
    session, cw = _tables_session(
        objects={KEY: _meta()},
        maintenance={  # the API's own casing, as a real call returns it
            "icebergCompaction": {"status": "disabled"},
            "icebergSnapshotManagement": {"status": "enabled"},
        },
        cw_points={"TableSizeBytes": [100, 900, 300], "TableNumberOfObjects": [4, 8]},
    )
    [table] = fetch_s3_tables(session, REGION, ACCT, "alias")
    assert (table.namespace, table.table_name, table.table_bucket_name) == (
        "analytics/sales",
        "customers",
        "tb",
    )
    assert table.table_type == "customer" and table.created_at == DAY.isoformat()
    assert table.warehouse_location == "s3://wh" and table.storage_class == "STANDARD"
    assert table.iceberg.total_file_size_bytes == 1073741824 and table.iceberg.manifest_count == 7
    assert (table.compaction_enabled, table.snapshot_management_enabled) == (False, True)
    assert (table.cloudwatch_size_bytes, table.total_file_count) == (900, 8)
    assert table.tags == {"Env": "prod"}
    dims = {d["Name"]: d["Value"] for d in cw.get_metric_statistics.call_args.kwargs["Dimensions"]}
    assert dims == {
        "TableBucketName": "tb",
        "Namespace": "analytics/sales",
        "TableName": "customers",
        "StorageType": "TablesStandardStorage",
    }
    assert cw.get_metric_statistics.call_args.kwargs["Namespace"] == "AWS/S3/Tables"


@pytest.mark.parametrize(
    "status, expected",
    [
        ("enabled", True),  # what the API returns (found in a real run: it read as off before)
        ("ENABLED", True),
        ("Enabled", True),
        ("disabled", False),
        ("DISABLED", False),
        ("", False),
        (None, False),
    ],
)
def test_maintenance_status_is_read_without_regard_to_case(status, expected):
    session, _ = _tables_session(
        objects={KEY: _meta()},
        maintenance={
            "icebergCompaction": {"status": status},
            "icebergSnapshotManagement": {"status": status},
        },
    )
    [table] = fetch_s3_tables(session, REGION, ACCT, "alias")
    assert table.compaction_enabled is expected
    assert table.snapshot_management_enabled is expected


def test_a_table_without_metadata_has_no_iceberg_stats_and_a_null_location():
    session, _ = _tables_session(metadata_location=None)
    [table] = fetch_s3_tables(session, REGION, ACCT, "")
    assert table.metadata_location is None and table.iceberg is None
    assert table.cloudwatch_size_bytes is None and table.total_file_count is None
    assert (table.compaction_enabled, table.snapshot_management_enabled) == (None, None)


def test_failed_calls_leave_unknowns_and_are_recorded_once_per_kind_of_call():
    tracker = DenialTracker()
    session, _ = _tables_session(
        fail={
            "get_table": _client_error("AccessDenied"),
            "get_table_metadata_location": _client_error("AccessDenied"),
            "get_table_maintenance_configuration": _client_error("AccessDenied"),
            "list_tags_for_resource": _client_error("AccessDenied"),
        }
    )
    [table] = fetch_s3_tables(session, REGION, ACCT, "", tracker)
    assert table.warehouse_location == "" and table.metadata_location == ""
    assert table.iceberg is None and table.tags == {}
    assert table.compaction_enabled is None
    errors = tracker.permission_errors()
    assert [e["service"] for e in errors] == ["s3tables", "s3tables"]
    assert "3 time(s)" in errors[0]["error"]
    assert "maintenance configuration" in errors[1]["error"] and "1 time(s)" in errors[1]["error"]


def test_a_failed_maintenance_call_is_logged_by_name_and_says_which_flags_are_blank(caplog):
    session, _ = _tables_session(
        objects={KEY: _meta()},
        fail={"get_table_maintenance_configuration": _client_error("AccessDenied")},
    )
    with caplog.at_level("WARNING"):
        [table] = fetch_s3_tables(session, REGION, ACCT, "")
    assert (table.compaction_enabled, table.snapshot_management_enabled) == (None, None)
    [message] = [r.getMessage() for r in caplog.records if "maintenance" in r.getMessage()]
    assert "CompactionEnabled and SnapshotManagementEnabled" in message and REGION in message


def test_a_working_maintenance_call_logs_no_warning(caplog):
    session, _ = _tables_session(
        objects={KEY: _meta()}, maintenance={"icebergCompaction": {"status": "enabled"}}
    )
    with caplog.at_level("WARNING"):
        fetch_s3_tables(session, REGION, ACCT, "")
    assert [r for r in caplog.records if r.levelname == "WARNING"] == []


def test_compaction_falls_back_to_the_metadata_when_the_maintenance_config_is_unknown():
    session, _ = _tables_session(objects={KEY: _meta()})
    session.client("s3tables").get_table_maintenance_configuration.side_effect = _client_error(
        "AccessDenied"
    )
    [table] = fetch_s3_tables(session, REGION, ACCT, "")
    assert table.compaction_enabled is None and table.iceberg.compaction_enabled is False


def test_a_region_without_s3_tables_is_not_an_error():
    tracker = DenialTracker()
    session, _ = _tables_session(
        list_buckets_error=EndpointConnectionError(endpoint_url="https://s3tables.example")
    )
    assert fetch_s3_tables(session, "af-south-1", ACCT, "", tracker) == []
    assert tracker.permission_errors() == []


def test_a_bucket_listing_failure_is_recorded():
    tracker = DenialTracker()
    session, _ = _tables_session(list_buckets_error=_client_error("AccessDenied"))
    assert fetch_s3_tables(session, REGION, ACCT, "", tracker) == []
    assert [e["service"] for e in tracker.permission_errors()] == ["s3tables"]


# ── Glue Iceberg ──────────────────────────────────────────────────────────────


def _glue_session(tables_by_database, objects=None, tags=None, databases_error=None):
    glue = MagicMock()

    def paginator(operation):
        p = MagicMock()
        if operation == "get_databases":
            if databases_error:
                p.paginate.side_effect = databases_error
            else:
                p.paginate.return_value = [
                    {"DatabaseList": [{"Name": d} for d in tables_by_database]}
                ]
        else:
            p.paginate.side_effect = lambda DatabaseName: [
                {"TableList": tables_by_database[DatabaseName]}
            ]
        return p

    glue.get_paginator.side_effect = paginator
    glue.get_tags.side_effect = lambda ResourceArn: {"Tags": tags or {}}
    s3 = MagicMock()
    objects = objects or {}
    s3.head_object.side_effect = lambda Bucket, Key, RequestPayer: {
        "ContentLength": len(objects[(Bucket, Key)])
    }
    s3.get_object.side_effect = lambda Bucket, Key, RequestPayer: {
        "Body": io.BytesIO(objects[(Bucket, Key)])
    }
    session = MagicMock()
    session.client.side_effect = lambda service, **kw: {"glue": glue, "s3": s3}[service]
    return session, glue


def _glue_table(name, table_type="ICEBERG", location="s3://warehouse/db/tbl", metadata=LOC):
    return {
        "Name": name,
        "Parameters": (
            {"table_type": table_type, "metadata_location": metadata}
            if metadata
            else {"table_type": table_type}
        ),
        "StorageDescriptor": {"Location": location},
        "CreateTime": DAY,
        "UpdateTime": DAY,
    }


def test_glue_collects_only_iceberg_tables_matching_case_insensitively():
    session, _ = _glue_session(
        {
            "db": [
                _glue_table("a", "iceberg"),
                _glue_table("b", "ICEBERG"),
                _glue_table("c", "HIVE"),
                {"Name": "d"},
            ]
        },
        objects={KEY: _meta()},
    )
    found = fetch_glue_iceberg(session, REGION, ACCT, "")
    assert [t.table_name for t in found] == ["a", "b"]


def test_glue_table_fields_stats_bucket_and_tags():
    session, glue = _glue_session(
        {"db": [_glue_table("tbl")]}, objects={KEY: _meta()}, tags={"team": "x"}
    )
    [table] = fetch_glue_iceberg(session, REGION, ACCT, "alias")
    assert (table.database_name, table.s3_bucket_name) == ("db", "warehouse")
    assert table.s3_location == "s3://warehouse/db/tbl" and table.metadata_location == LOC
    assert table.create_time == DAY.isoformat()
    assert table.iceberg.total_file_size_bytes == 1073741824 and table.tags == {"team": "x"}
    glue.get_tags.assert_called_once_with(ResourceArn=f"arn:aws:glue:{REGION}:{ACCT}:table/db/tbl")


def test_a_glue_table_without_a_location_or_metadata_keeps_blank_fields():
    table = _glue_table("t", metadata=None)
    del table["StorageDescriptor"]
    session, _ = _glue_session({"db": [table]})
    [found] = fetch_glue_iceberg(session, REGION, ACCT, "")
    assert (found.s3_location, found.s3_bucket_name, found.metadata_location) == ("", "", None)
    assert found.iceberg == IcebergStats()


def test_a_bucket_name_is_taken_from_a_location_without_a_path():
    session, _ = _glue_session(
        {"db": [_glue_table("t", location="s3://just-a-bucket", metadata=None)]}
    )
    assert fetch_glue_iceberg(session, REGION, ACCT, "")[0].s3_bucket_name == "just-a-bucket"


def test_glue_listing_failures_are_recorded():
    tracker = DenialTracker()
    session, _ = _glue_session({}, databases_error=_client_error("AccessDenied"))
    assert fetch_glue_iceberg(session, REGION, ACCT, "", tracker) == []
    assert [e["service"] for e in tracker.permission_errors()] == ["glue"]


# ── deducting Glue Iceberg data from S3 buckets ───────────────────────────────


def _bucket(name, **classes):
    return S3Bucket(
        account_id=ACCT,
        account_alias="",
        bucket_name=name,
        region=REGION,
        size_bytes=int(classes.get("StandardStorage") or 0),
        size_gb=0.0,
        size_tb=0.0,
        object_count=0,
        in_backup_plan=False,
        backup_plans=[],
        storage_class_bytes=dict(classes),
    )


def _glue_row(location, size, bucket=None):
    return GlueIcebergTable(
        account_id=ACCT,
        account_alias="",
        region=REGION,
        database_name="db",
        table_name="t",
        s3_bucket_name=bucket if bucket is not None else location.split("/")[2],
        s3_location=location,
        metadata_location=None,
        iceberg=IcebergStats(total_file_size_bytes=size),
    )


def test_iceberg_bytes_are_deducted_largest_class_first_and_spill_over():
    bucket = _bucket("lake", StandardStorage=100.0, GlacierStorage=500.0, StandardIAStorage=30.0)
    apply_glue_iceberg_to_buckets(
        [bucket], [_glue_row("s3://lake/a", 550), _glue_row("s3://lake/b", 20)]
    )
    assert bucket.storage_class_bytes == {
        "StandardStorage": 30.0,  # 570 total: 500 from Glacier, then 70 of Standard
        "GlacierStorage": 0.0,
        "StandardIAStorage": 30.0,
    }
    assert bucket.size_bytes == 30 and bucket.has_iceberg_table is True
    # The classes deducted from, in order; StandardIA kept its bytes.
    assert bucket.iceberg_adjusted_classes == ["GlacierStorage", "StandardStorage"]


def test_deduction_never_goes_below_zero():
    bucket = _bucket("lake", StandardStorage=10.0)
    apply_glue_iceberg_to_buckets([bucket], [_glue_row("s3://lake/a", 999)])
    assert bucket.storage_class_bytes["StandardStorage"] == 0.0 and bucket.size_bytes == 0


def test_buckets_are_matched_case_insensitively_and_others_are_untouched():
    lake, other = _bucket("Lake", StandardStorage=100.0), _bucket("other", StandardStorage=100.0)
    apply_glue_iceberg_to_buckets([lake, other], [_glue_row("s3://lake/a", 40, bucket="lake")])
    assert lake.storage_class_bytes["StandardStorage"] == 60.0 and lake.has_iceberg_table
    assert other.storage_class_bytes["StandardStorage"] == 100.0 and not other.has_iceberg_table


def test_a_table_of_unknown_size_marks_the_bucket_without_changing_sizes():
    bucket = _bucket("lake", StandardStorage=100.0)
    row = _glue_row("s3://lake/a", None)
    apply_glue_iceberg_to_buckets([bucket], [row])
    assert bucket.has_iceberg_table and bucket.storage_class_bytes["StandardStorage"] == 100.0


def test_no_glue_tables_changes_nothing():
    bucket = _bucket("lake", StandardStorage=100.0)
    apply_glue_iceberg_to_buckets([bucket], [])
    assert not bucket.has_iceberg_table and bucket.storage_class_bytes["StandardStorage"] == 100.0
    assert bucket.iceberg_adjusted_classes == []


def test_a_table_of_unknown_size_adjusts_no_class():
    bucket = _bucket("lake", StandardStorage=100.0)
    apply_glue_iceberg_to_buckets([bucket], [_glue_row("s3://lake/a", None)])
    assert bucket.iceberg_adjusted_classes == []


def test_a_bare_400_is_retried_in_the_bucket_region_then_without_requester_pays():
    session = MagicMock()
    home, other = MagicMock(), MagicMock()
    home.head_object.side_effect = _client_error("400")
    home.get_bucket_location.return_value = {"LocationConstraint": "eu-west-1"}
    other.head_object.side_effect = [_client_error("400"), {"StorageClass": "STANDARD"}]
    session.client.side_effect = lambda _s, region_name, **_k: home if region_name == REGION else other
    reader = S3ObjectReader(session, REGION)
    assert reader.head("b", "k")["StorageClass"] == "STANDARD"
    assert "RequestPayer" not in other.head_object.call_args_list[-1].kwargs
    assert reader._no_requester_pays == {"b"}


def test_a_400_that_persists_is_raised():
    session = MagicMock()
    session.client.return_value.head_object.side_effect = _client_error("400")
    session.client.return_value.get_bucket_location.return_value = {"LocationConstraint": None}
    with pytest.raises(ClientError):
        S3ObjectReader(session, REGION).head("b", "k")
