"""BigQuery Omni tables: external tables whose data is in S3 or Azure Blob, not Cloud Storage.

Such a table is not sized by this scan (its data is in another cloud, so it is not in
``gce_storage_info``). The scan marks it in ``ExternalCloud`` and says so in the run summary.

No real Omni table has been seen: these tables are built to look as Google's documentation shows
them (an ``s3://BUCKET/PATH`` source URI in an ``aws-<region>`` dataset). The Azure forms are the
less certain half and are reported as Azure Blob only on a URI or location match.
"""

from __future__ import annotations

import csv
import io

import pytest

import csv_export
import main
from csv_export import (
    EXTERNAL_CLOUD_AZURE,
    EXTERNAL_CLOUD_S3,
    build_csv_files,
    count_other_cloud,
    external_cloud,
    other_cloud_tables,
)
from models.discovery_dataclasses import BigQueryInventory, BigQueryTable, ComputeInventory

STAMP = "S"


def _tbl(kind="EXTERNAL", uri="", location="US", biglake="", table_id="t"):
    return {
        "dataset_id": "d",
        "location": location,
        "table_id": table_id,
        "table_type": kind,
        "external_source_uri": uri,
        "biglake_storage_uri": biglake,
    }


def _rows(tables):
    result = {
        "projects_scanned": ["p"],
        "storage": [],
        "bigquery": [{"project_id": "p", "tables": tables}],
    }
    text = build_csv_files(result, STAMP, None)[f"gce_bigquery_info-{STAMP}.csv"]
    return list(csv.DictReader(io.StringIO(text)))


# ── what counts as another cloud ──────────────────────────────────────────────


@pytest.mark.parametrize(
    "uri",
    ["s3://bucket/path/file.csv", "s3://mybucket/products/*", "S3://Bucket/Path", " s3://b/p "],
)
def test_an_s3_source_uri_is_s3(uri):
    assert external_cloud(_tbl(uri=uri)) == EXTERNAL_CLOUD_S3


def test_an_aws_dataset_location_is_s3_even_without_a_recognised_uri():
    assert external_cloud(_tbl(uri="", location="aws-us-east-1")) == EXTERNAL_CLOUD_S3
    assert external_cloud(_tbl(uri="gs://x/y", location="aws-eu-west-1")) == EXTERNAL_CLOUD_S3


@pytest.mark.parametrize(
    "uri",
    [
        "azure://myaccount.blob.core.windows.net/container/path",
        "https://myaccount.blob.core.windows.net/container/path",
        "AZURE://acct.blob.core.windows.net/c",
    ],
)
def test_an_azure_blob_source_uri_is_azure_blob(uri):
    assert external_cloud(_tbl(uri=uri)) == EXTERNAL_CLOUD_AZURE


def test_an_azure_dataset_location_is_azure_blob():
    assert external_cloud(_tbl(uri="", location="azure-eastus2")) == EXTERNAL_CLOUD_AZURE


def test_several_uris_are_read_one_by_one():
    assert external_cloud(_tbl(uri="gs://a/b; s3://c/d")) == EXTERNAL_CLOUD_S3


def test_a_biglake_storage_uri_is_read_too():
    assert external_cloud(_tbl(kind="TABLE", biglake="s3://iceberg/folder")) == EXTERNAL_CLOUD_S3


# ── what must not be flagged ──────────────────────────────────────────────────


@pytest.mark.parametrize(
    "table",
    [
        _tbl(uri="gs://bucket/path/*"),
        _tbl(uri="gs://bucket/a; gs://bucket/b"),
        _tbl(uri="https://storage.googleapis.com/bucket/x"),
        _tbl(uri="", location="US"),
        _tbl(kind="TABLE", uri="", location="US"),
        _tbl(kind="VIEW", uri="", location="aws-us-east-1"),
        _tbl(kind="TABLE", uri="", location="aws-us-east-1"),
        _tbl(uri="gs://s3://nested"),
        _tbl(uri="drive://x"),
        _tbl(uri="https://example.com/blob.core.windows.net"),
        {},
    ],
)
def test_a_google_cloud_table_or_a_native_or_view_table_is_not_flagged(table):
    assert external_cloud(table) is None


def test_a_native_table_in_an_aws_dataset_is_bigquerys_own_storage_not_another_cloud():
    assert external_cloud(_tbl(kind="TABLE", uri="", location="aws-us-east-1")) is None


def test_a_table_with_no_values_does_not_raise():
    assert external_cloud({"location": None, "table_type": None}) is None
    assert external_cloud(BigQueryTable("d", "US", "t", None)) is None


# ── the csv column ────────────────────────────────────────────────────────────


def test_the_column_comes_after_the_source_uri():
    columns = csv_export._BIGQUERY_COLUMNS
    assert columns.index("ExternalCloud") == columns.index("ExternalSourceUri") + 1


def test_each_table_is_marked_with_its_cloud_or_left_blank():
    rows = _rows(
        [
            _tbl(uri="s3://b/p", table_id="s3"),
            _tbl(uri="azure://a.blob.core.windows.net/c", table_id="az"),
            _tbl(uri="gs://b/p", table_id="gcs"),
            _tbl(kind="TABLE", table_id="native"),
        ]
    )
    assert {r["TableId"]: r["ExternalCloud"] for r in rows} == {
        "s3": "S3",
        "az": "Azure Blob",
        "gcs": "",
        "native": "",
    }


# ── the counts ────────────────────────────────────────────────────────────────


def test_tables_are_counted_by_cloud_across_projects():
    result = {
        "projects_scanned": ["a", "b"],
        "bigquery": [
            {"project_id": "a", "tables": [_tbl(uri="s3://x/y"), _tbl(uri="gs://x/y")]},
            {"project_id": "b", "tables": [_tbl(uri="s3://q/r"), _tbl(location="azure-eastus2")]},
        ],
    }
    assert other_cloud_tables(result) == {"S3": 2, "Azure Blob": 1}


def test_a_project_with_none_counts_nothing():
    assert count_other_cloud([_tbl(uri="gs://a/b")]) == {}
    assert count_other_cloud(None) == {}
    assert count_other_cloud([]) == {}


def test_the_count_reads_table_objects_as_well_as_dicts():
    table = BigQueryTable("d", "aws-us-east-1", "t", "EXTERNAL", external_source_uri="s3://b/p")
    assert count_other_cloud([table]) == {"S3": 1}


# ── the run summary ───────────────────────────────────────────────────────────


def _printed(summaries):
    with main.console.capture() as captured:
        main._print_summary(summaries, None)
    return " ".join(captured.get().split())


def _summary(tables):
    inventory = BigQueryInventory(
        project_id="p", dataset_count=1, tables=tables, table_counts={"EXTERNAL": len(tables)}
    )
    return main._summarise_project(
        "p", {"compute": ComputeInventory(project_id="p"), "bigquery": inventory}
    )


def test_the_project_summary_carries_the_other_cloud_counts():
    s3 = BigQueryTable("d", "aws-us-east-1", "t", "EXTERNAL", external_source_uri="s3://b/p")
    gcs = BigQueryTable("d", "US", "u", "EXTERNAL", external_source_uri="gs://b/p")
    assert _summary([s3, gcs])["bq_other_cloud"] == {"S3": 1}
    skipped = main._summarise_project("p", {"compute": ComputeInventory(project_id="p")})
    assert skipped["bq_other_cloud"] == {}


def test_the_run_summary_warns_when_a_table_reads_another_cloud():
    s3 = BigQueryTable("d", "aws-us-east-1", "t", "EXTERNAL", external_source_uri="s3://b/p")
    text = _printed([_summary([s3])])
    assert "1 BigQuery table(s) read data in S3, not in Google Cloud Storage" in text
    assert "Run the AWS or Azure sizing script" in text
    assert "ExternalCloud" in text


def test_the_warning_names_both_clouds_and_adds_up_across_projects():
    s3 = BigQueryTable("d", "aws-us-east-1", "t", "EXTERNAL", external_source_uri="s3://b/p")
    az = BigQueryTable("d", "azure-eastus2", "u", "EXTERNAL", external_source_uri="")
    text = _printed([_summary([s3, s3]), _summary([az])])
    assert "3 BigQuery table(s) read data in Azure Blob and S3" in text
    assert "2 in S3" in text and "1 in Azure Blob" in text


def test_there_is_no_warning_when_every_table_reads_google_cloud():
    gcs = BigQueryTable("d", "US", "u", "EXTERNAL", external_source_uri="gs://b/p")
    native = BigQueryTable("d", "US", "n", "TABLE")
    text = _printed([_summary([gcs, native])])
    assert "read data in" not in text and "BigQuery Omni" not in text


def test_there_is_no_warning_when_bigquery_was_not_collected():
    skipped = main._summarise_project("p", {"compute": ComputeInventory(project_id="p")})
    assert "BigQuery Omni" not in _printed([skipped])
