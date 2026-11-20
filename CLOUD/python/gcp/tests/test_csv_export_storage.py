"""gce_storage_info: one row per bucket, sizes that are blank when unknown, the BigQuery link."""

from __future__ import annotations

import csv
import io

import pytest

import csv_export
from anonymize import Anonymizer
from csv_export import build_csv_files, bigquery_bucket_links

STAMP = "S"
FILE = f"gce_storage_info-{STAMP}.csv"


def _bucket(name, **kw):
    base = {
        "name": name,
        "location": "US-CENTRAL1",
        "location_type": "region",
        "storage_class": "STANDARD",
        "versioning_enabled": False,
        "soft_delete_retention_days": 7,
        "labels": {},
        "size_bytes": None,
        "live_bytes": None,
        "noncurrent_bytes": None,
        "soft_deleted_bytes": None,
        "multipart_bytes": None,
        "object_count": None,
        "size_status": "no datapoint",
    }
    base.update(kw)
    return base


def _measured(name, live, noncurrent=0, soft=0, multipart=0, **kw):
    return _bucket(
        name,
        size_bytes=live + noncurrent,
        live_bytes=live,
        noncurrent_bytes=noncurrent,
        soft_deleted_bytes=soft,
        multipart_bytes=multipart,
        object_count=kw.pop("object_count", 10),
        size_status="measured",
        **kw,
    )


def _table(table_type="EXTERNAL", uri="", biglake="", connection="", dataset="d", table="t"):
    return {
        "dataset_id": dataset,
        "table_id": table,
        "table_type": table_type,
        "external_source_uri": uri,
        "biglake_storage_uri": biglake,
        "connection_id": connection,
    }


def _result(buckets=(), tables=(), project="proj-a"):
    return {
        "projects_scanned": [project],
        "storage": [{"project_id": project, "buckets": list(buckets)}],
        "bigquery": [{"project_id": project, "tables": list(tables)}],
    }


def _rows(result, anonymizer=None):
    text = build_csv_files(result, STAMP, anonymizer)[FILE]
    return list(csv.DictReader(io.StringIO(text))), text


# ── the file ──────────────────────────────────────────────────────────────────


def test_one_row_per_bucket_with_the_columns_declared():
    rows, text = _rows(_result([_measured("b1", 100), _measured("b2", 200)]))
    assert [r["BucketName"] for r in rows] == ["b1", "b2"]
    header = text.splitlines()[0].replace('"', "").split(",")
    assert header[:3] == ["Project", "BucketName", "CreationTime"]
    assert header[: len(csv_export._STORAGE_COLUMNS)] == csv_export._STORAGE_COLUMNS


def _first_size_cell() -> int:
    return csv_export._STORAGE_COLUMNS.index("SizeBytes")


def test_a_measured_bucket_has_its_sizes_in_every_unit():
    (row,), _ = _rows(_result([_measured("b1", 2_000_000_000, noncurrent=1_000_000_000)]))
    assert row["SizeBytes"] == "3000000000"
    assert (row["SizeGb"], row["SizeTb"]) == ("3", "0.003")
    assert row["LiveBytes"] == "2000000000" and row["NoncurrentBytes"] == "1000000000"
    # GB and TB are decimal (10**9, 10**12); GiB and TiB are binary (2**30, 2**40). 3e9 bytes is
    # 2.7939... GiB, written to four decimals, and 0.00272... TiB, written to six.
    assert (row["SizeGiB"], row["SizeTiB"]) == ("2.794", "0.002728")
    assert (row["LiveGiB"], row["NoncurrentGiB"]) == ("1.8626", "0.9313")
    assert row["SizeStatus"] == "measured"


def test_soft_deleted_and_multipart_are_their_own_columns_not_part_of_the_size():
    (row,), _ = _rows(_result([_measured("b1", 1000, soft=400, multipart=30)]))
    assert row["SizeBytes"] == "1000"
    assert row["SoftDeletedBytes"] == "400" and row["MultipartBytes"] == "30"


def test_a_bucket_with_no_reading_is_blank_in_every_size_cell_not_zero():
    (row,), text = _rows(_result([_bucket("empty")]))
    for prefix in csv_export._STORAGE_SIZES:
        for suffix in ("Bytes", "Gb", "Tb", "GiB", "TiB"):
            assert row[f"{prefix}{suffix}"] == "", f"{prefix}{suffix}"
    assert row["ObjectCount"] == "" and row["SizeStatus"] == "no datapoint"
    # In the raw text an unknown is a bare empty field (two commas in a row), never a quoted "0"
    # or "": that is how the file tells "unknown" from a real zero and from an empty string.
    cells = text.splitlines()[1].split(",")
    start = _first_size_cell()
    assert cells[start : start + 25] == [""] * 25


def test_unknown_and_zero_are_different_in_the_raw_text():
    (zero,), zero_text = _rows(_result([_measured("z", 0, object_count=0)]))
    (blank,), blank_text = _rows(_result([_bucket("z")]))
    start = _first_size_cell()
    assert zero_text.splitlines()[1].split(",")[start] == '"0"'
    assert blank_text.splitlines()[1].split(",")[start] == ""


def test_a_real_zero_is_written_as_zero_not_blank():
    # A bucket Monitoring reported with nothing live is 0 bytes, which is not "unknown".
    (row,), _ = _rows(_result([_measured("b1", 0, object_count=0)]))
    assert row["SizeBytes"] == "0" and row["ObjectCount"] == "0"


def test_a_failed_read_says_not_read():
    (row,), _ = _rows(_result([_bucket("b1", size_status="not read")]))
    assert row["SizeStatus"] == "not read" and row["SizeBytes"] == ""


def test_buckets_of_several_projects_keep_the_scan_order():
    result = {
        "projects_scanned": ["p2", "p1"],
        "storage": [
            {"project_id": "p1", "buckets": [_measured("in-p1", 1)]},
            {"project_id": "p2", "buckets": [_measured("in-p2", 1)]},
        ],
    }
    rows, _ = _rows(result)
    assert [(r["Project"], r["BucketName"]) for r in rows] == [("p2", "in-p2"), ("p1", "in-p1")]


def test_a_project_with_no_storage_result_adds_nothing_and_does_not_break():
    result = {"projects_scanned": ["p"], "storage": [None, {"project_id": "p", "buckets": []}]}
    assert build_csv_files(result, STAMP)[FILE] == ""


def test_bucket_labels_become_label_columns_like_the_other_files():
    rows, _ = _rows(_result([_measured("b1", 1, labels={"team-name": "data"})]))
    assert rows[0]["Label/Tag: team_name"] == "data"


def test_the_row_builder_is_registered_and_in_the_files_list():
    assert "gce_storage_info" in [spec.prefix for spec in csv_export.FILES]
    assert csv_export.rows_by_file(_result([_measured("b", 1)]))["gce_storage_info"]


# ── the BigQuery link ─────────────────────────────────────────────────────────


def test_an_external_table_over_a_bucket_is_counted_against_it():
    result = _result(
        [_measured("lake", 10**12), _measured("other", 5)],
        [_table(uri="gs://lake/events/*")],
    )
    rows, _ = _rows(result)
    lake, other = rows
    assert (lake["BigQueryTables"], lake["BigQueryExternalTables"]) == ("1", "1")
    assert (other["BigQueryTables"], other["BigQueryExternalTables"]) == ("0", "0")


def test_a_table_naming_the_same_bucket_twice_counts_once():
    links = bigquery_bucket_links(
        _result(tables=[_table(uri="gs://lake/a/*; gs://lake/b/*; gs://LAKE/c")])
    )
    assert links["lake"]["tables"] == 1


def test_one_table_over_two_buckets_counts_against_both():
    links = bigquery_bucket_links(_result(tables=[_table(uri="gs://one/x; gs://two/y")]))
    assert (links["one"]["tables"], links["two"]["tables"]) == (1, 1)


def test_a_bigquery_iceberg_table_is_linked_through_its_storage_uri():
    links = bigquery_bucket_links(
        _result(
            tables=[_table(table_type="TABLE", biglake="gs://iceberg-data/warehouse/t1/")],
        )
    )
    # Counted as a table that reads the bucket, but not as an EXTERNAL one: BigQuery sizes it.
    assert links["iceberg-data"] == {"tables": 1, "external": 0, "connections": []}


def test_the_bucket_match_ignores_case_and_a_trailing_path():
    rows, _ = _rows(_result([_measured("Mixed-Case", 1)], [_table(uri="gs://mixed-case/")]))
    assert rows[0]["BigQueryTables"] == "1"


def test_connections_are_listed_once_each():
    tables = [
        _table(uri="gs://lake/a", connection="proj.us.conn1", table="t1"),
        _table(uri="gs://lake/b", connection="proj.us.conn1", table="t2"),
        _table(uri="gs://lake/c", connection="proj.us.conn2", table="t3"),
    ]
    rows, _ = _rows(_result([_measured("lake", 1)], tables))
    assert rows[0]["BigQueryConnections"] == "proj.us.conn1; proj.us.conn2"
    assert rows[0]["BigQueryTables"] == "3"


@pytest.mark.parametrize(
    "uri",
    [
        "s3://aws-bucket/data/*",  # BigQuery Omni: the data is in AWS, not in a GCS bucket
        "https://docs.google.com/spreadsheets/d/abc",  # a Google Sheet
        "https://googleapis.com/bigtable/projects/p/instances/i",  # Bigtable
        "",
        None,
    ],
)
def test_sources_that_are_not_a_gcs_bucket_link_to_nothing(uri):
    assert bigquery_bucket_links(_result(tables=[_table(uri=uri)])) == {}


def test_a_bucket_nothing_in_bigquery_reads_has_no_connections_cell():
    (row,), text = _rows(_result([_measured("b", 1)]))
    assert row["BigQueryTables"] == "0" and row["BigQueryConnections"] == ""


def test_a_result_with_no_bigquery_section_still_writes_the_storage_file():
    result = {
        "projects_scanned": ["p"],
        "storage": [{"project_id": "p", "buckets": [_measured("b", 1)]}],
    }
    rows, _ = _rows(result)
    assert rows[0]["BigQueryTables"] == "0"


# ── anonymizing ───────────────────────────────────────────────────────────────


def test_the_bucket_name_and_connection_are_hidden_when_anonymizing():
    tables = [_table(uri="gs://customer-secret-lake/x", connection="secretproj.us.secretconn")]
    rows, text = _rows(_result([_measured("customer-secret-lake", 123)], tables), Anonymizer())
    for real in ("customer-secret-lake", "secretproj", "secretconn", "proj-a"):
        assert real not in text, real
    assert rows[0]["BucketName"] == "BucketName-00000"
    assert rows[0]["BigQueryConnections"] == "BigQueryConnections-00000"
    assert rows[0]["Project"] == "Project-00000"


def test_the_sizes_and_counts_stay_readable_when_anonymizing():
    rows, _ = _rows(_result([_measured("b", 4096, object_count=77)]), Anonymizer())
    assert rows[0]["SizeBytes"] == "4096" and rows[0]["ObjectCount"] == "77"
    assert rows[0]["SizeStatus"] == "measured"


def test_a_project_has_one_label_across_the_storage_and_bigquery_files():
    result = _result(
        [_measured("b", 1)],
        [{**_table(uri="gs://b/x"), "location": "US", "num_rows": 0}],
    )
    texts = build_csv_files(result, STAMP, Anonymizer())
    storage = list(csv.DictReader(io.StringIO(texts[FILE])))
    bigquery = list(csv.DictReader(io.StringIO(texts[f"gce_bigquery_info-{STAMP}.csv"])))
    assert storage[0]["Project"] == bigquery[0]["Project"] == "Project-00000"


def _bq_and_storage(result, anonymizer):
    texts = build_csv_files(result, STAMP, anonymizer)
    bigquery = list(csv.DictReader(io.StringIO(texts[f"gce_bigquery_info-{STAMP}.csv"])))
    storage = list(csv.DictReader(io.StringIO(texts[FILE])))
    return bigquery, storage, "".join(texts.values())


def _bq_table(uri, **kw):
    return {**_table(uri=uri, **kw), "location": "US", "num_rows": 0}


def test_a_bigquery_uri_and_the_storage_row_name_the_same_bucket_when_anonymizing():
    result = _result([_measured("lake", 5)], [_bq_table("gs://lake/raw/2026/*.parquet")])
    bigquery, storage, text = _bq_and_storage(result, Anonymizer())
    label = storage[0]["BucketName"]
    assert label == "BucketName-00000"
    # The bucket in the URI is the storage row's label, and the path is a label of its own.
    assert bigquery[0]["ExternalSourceUri"] == f"gs://{label}/ExternalSourceUri-00000"
    assert "lake" not in text and "parquet" not in text and "2026" not in text


def test_the_join_still_works_in_the_other_order_when_the_bucket_is_met_first_as_a_name():
    anonymizer = Anonymizer()
    anonymizer.anonymize_row({"BucketName": "lake"})
    row = anonymizer.anonymize_row({"ExternalSourceUri": "gs://lake/x"})
    assert row["ExternalSourceUri"].startswith("gs://BucketName-00000/")


def test_two_tables_in_one_bucket_share_its_label_and_keep_their_own_paths():
    tables = [_bq_table("gs://lake/a/*", table="t1"), _bq_table("gs://lake/b/*", table="t2")]
    bigquery, _, _ = _bq_and_storage(_result([_measured("lake", 1)], tables), Anonymizer())
    first, second = (r["ExternalSourceUri"] for r in bigquery)
    assert first.split("/")[2] == second.split("/")[2] == "BucketName-00000"
    assert first != second


def test_every_uri_of_a_table_is_labelled_and_the_buckets_are_kept_apart():
    uri = "gs://one/a/*; gs://two/b/*"
    bigquery, _, text = _bq_and_storage(_result([], [_bq_table(uri)]), Anonymizer())
    assert bigquery[0]["ExternalSourceUri"] == (
        "gs://BucketName-00000/ExternalSourceUri-00000; gs://BucketName-00001/ExternalSourceUri-00001"
    )
    assert "one" not in text and "two" not in text


def test_a_bucket_only_uri_keeps_no_path():
    bigquery, _, _ = _bq_and_storage(_result([], [_bq_table("gs://lake/")]), Anonymizer())
    assert bigquery[0]["ExternalSourceUri"] == "gs://BucketName-00000/"


def test_a_source_that_is_not_a_bucket_is_still_hidden_whole():
    uri = "https://drive.google.com/open?id=SECRETDOC"
    bigquery, _, text = _bq_and_storage(_result([], [_bq_table(uri)]), Anonymizer())
    assert bigquery[0]["ExternalSourceUri"] == "ExternalSourceUri-00000"
    assert "SECRETDOC" not in text and "drive.google" not in text


def test_a_mixed_value_labels_the_bucket_part_and_hides_the_other_part_whole():
    uri = "gs://lake/a/*; https://drive.google.com/open?id=SECRETDOC"
    bigquery, _, text = _bq_and_storage(_result([], [_bq_table(uri)]), Anonymizer())
    assert bigquery[0]["ExternalSourceUri"] == (
        "gs://BucketName-00000/ExternalSourceUri-00000; ExternalSourceUri-00001"
    )
    assert "SECRETDOC" not in text and "lake" not in text


def test_a_blank_uri_is_still_a_value_and_a_missing_one_is_left_alone():
    anonymizer = Anonymizer()
    assert anonymizer.anonymize_row({"ExternalSourceUri": ""})["ExternalSourceUri"] == (
        "ExternalSourceUri-00000"
    )
    assert anonymizer.anonymize_row({"ExternalSourceUri": None})["ExternalSourceUri"] is None


def test_a_bucket_left_readable_by_not_anonymize_fields_stays_readable_in_the_uri():
    anonymizer = Anonymizer.from_options(not_anonymize_fields="BucketName")
    row = anonymizer.anonymize_row({"ExternalSourceUri": "gs://lake/secret/path"})
    assert row["ExternalSourceUri"] == "gs://lake/ExternalSourceUri-00000"


def test_not_anonymize_fields_on_the_uri_leaves_the_uri_alone():
    anonymizer = Anonymizer.from_options(not_anonymize_fields="ExternalSourceUri")
    assert anonymizer.anonymize_row({"ExternalSourceUri": "gs://lake/x"}) == {
        "ExternalSourceUri": "gs://lake/x"
    }


def test_the_key_file_maps_the_bucket_and_the_path_labels_back():
    anonymizer = Anonymizer()
    anonymizer.anonymize_row({"ExternalSourceUri": "gs://lake/raw/*"})
    assert dict(anonymizer.key_rows()) == {
        "BucketName-00000": "lake",
        "ExternalSourceUri-00000": "/raw/*",
    }


def test_the_bucket_match_ignores_case_like_every_other_label():
    anonymizer = Anonymizer()
    anonymizer.anonymize_row({"BucketName": "Lake"})
    row = anonymizer.anonymize_row({"ExternalSourceUri": "GS://LAKE/x"})
    assert row["ExternalSourceUri"].startswith("gs://BucketName-00000/")


def test_adding_the_storage_file_does_not_change_the_numbering_of_the_other_files():
    base = {
        "projects_scanned": ["p"],
        "bigquery": [{"project_id": "p", "tables": [_table(table_type="TABLE", dataset="ds")]}],
    }
    without = build_csv_files(base, STAMP, Anonymizer())[f"gce_bigquery_info-{STAMP}.csv"]
    with_storage = dict(base, storage=[{"project_id": "p", "buckets": [_measured("bucket-x", 1)]}])
    after = build_csv_files(with_storage, STAMP, Anonymizer())[f"gce_bigquery_info-{STAMP}.csv"]
    assert without == after


# ── bucket settings ───────────────────────────────────────────────────────────


def test_the_settings_columns_are_written_for_a_fully_configured_bucket():
    key = "projects/p/locations/us/keyRings/r/cryptoKeys/k"
    bucket = _measured(
        "cfg",
        10,
        creation_time="2026-01-02T03:04:05+00:00",
        location="NAM4",
        location_type="dual-region",
        dual_region_locations=["US-CENTRAL1", "US-EAST1"],
        turbo_replication_enabled=True,
        autoclass_enabled=True,
        autoclass_terminal_storage_class="ARCHIVE",
        hns_enabled=True,
        retention_policy_enabled=True,
        retention_period_days=30,
        bucket_lock_locked=True,
        soft_delete_enabled=True,
        default_kms_key_name=key,
        ubla_enabled=True,
        public_access_prevention="enforced",
    )
    (row,), _ = _rows(_result([bucket]))
    assert row["CreationTime"] == "2026-01-02T03:04:05+00:00"
    assert row["DualRegionLocations"] == "US-CENTRAL1; US-EAST1"
    assert row["TurboReplicationEnabled"] == "True"
    assert (row["AutoclassEnabled"], row["AutoclassTerminalStorageClass"]) == ("True", "ARCHIVE")
    assert row["NamespaceType"] == "HNS"
    assert (row["RetentionPolicyEnabled"], row["RetentionPeriodDays"]) == ("True", "30")
    assert row["BucketLockState"] == "locked" and row["SoftDeleteEnabled"] == "True"
    assert (row["EncryptionType"], row["DefaultKmsKeyName"]) == ("CMEK", key)
    assert row["UniformBucketLevelAccessEnabled"] == "True"
    assert row["PublicAccessPrevention"] == "enforced"


def test_a_bucket_with_default_settings_is_google_managed_flat_and_unlocked():
    (row,), _ = _rows(
        _result(
            [
                _bucket(
                    "plain",
                    hns_enabled=False,
                    bucket_lock_locked=False,
                    retention_policy_enabled=False,
                    soft_delete_enabled=True,
                )
            ]
        )
    )
    assert row["NamespaceType"] == "Standard" and row["BucketLockState"] == "unlocked"
    assert row["EncryptionType"] == "Google-managed" and row["DefaultKmsKeyName"] == ""
    assert row["RetentionPolicyEnabled"] == "False" and row["RetentionPeriodDays"] == ""
    assert row["DualRegionLocations"] == "" and row["TurboReplicationEnabled"] == ""


def test_a_setting_the_bucket_did_not_report_is_blank():
    (row,), _ = _rows(_result([_bucket("sparse")]))
    for column in (
        "CreationTime",
        "AutoclassEnabled",
        "NamespaceType",
        "BucketLockState",
        "UniformBucketLevelAccessEnabled",
        "PublicAccessPrevention",
    ):
        assert row[column] == "", column


def test_the_size_and_object_count_by_class_are_columns():
    bucket = _measured(
        "cls",
        1500,
        class_bytes={"STANDARD": 1000, "NEARLINE": 500, "COLDLINE": 0, "ARCHIVE": 0, "OTHER": 0},
        class_object_counts={"STANDARD": 4, "NEARLINE": 2, "COLDLINE": 0, "ARCHIVE": 0, "OTHER": 0},
    )
    (row,), _ = _rows(_result([bucket]))
    assert (row["SizeBytes_STANDARD"], row["SizeBytes_NEARLINE"]) == ("1000", "500")
    assert (row["ObjectCount_STANDARD"], row["ObjectCount_NEARLINE"]) == ("4", "2")
    assert row["SizeBytes_ARCHIVE"] == "0"


def test_the_class_columns_are_blank_when_the_bucket_has_no_reading():
    (row,), _ = _rows(_result([_bucket("empty")]))
    assert all(row[f"SizeBytes_{c}"] == "" for c in ("STANDARD", "OTHER"))
    assert all(row[f"ObjectCount_{c}"] == "" for c in ("STANDARD", "OTHER"))


def test_the_key_name_is_anonymized_and_the_other_settings_are_not():
    key = "projects/secret-project/locations/us/keyRings/r/cryptoKeys/k"
    bucket = _measured("kms-bucket", 1, default_kms_key_name=key, autoclass_enabled=True)
    (row,), text = _rows(_result([bucket]), Anonymizer())
    assert row["DefaultKmsKeyName"] == "DefaultKmsKeyName-00000"
    assert "secret-project" not in text
    assert row["AutoclassEnabled"] == "True"
