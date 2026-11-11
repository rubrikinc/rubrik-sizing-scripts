"""BigQuery through the pipeline: selection, the per-project step, the summary, the files."""

from __future__ import annotations

import csv
import io
import json
import sys
import zipfile
from unittest.mock import MagicMock, patch

import pytest

import main
from anonymize import FILE_ORDER, Anonymizer
from csv_export import build_csv_files
from models.inventory import BigQueryInventory, BigQueryTable, ComputeInventory

# ── selection ─────────────────────────────────────────────────────────────────


def _args(argv):
    return main._build_parser().parse_args(argv)


def test_bigquery_is_a_core_collector_that_runs_by_default():
    assert "bigquery" in main._CORE_COLLECTORS
    assert "bigquery" in main._resolve_collectors(_args([]))


def test_bigquery_can_be_chosen_or_left_out():
    assert main._resolve_collectors(_args(["--collectors", "bigquery"])) == {"bigquery"}
    without = main._resolve_collectors(_args(["--collectors", "compute,storage"]))
    assert "bigquery" not in without
    assert "bigquery" not in main._resolve_collectors(_args(["--inventory-only"]))


def test_the_dry_run_lists_the_bigquery_calls_and_their_role():
    rows = [r for r in main._DRY_RUN_API_CALLS if r[0] == "bigquery"]
    assert len(rows) == 2 and {r[2] for r in rows} == {"roles/bigquery.metadataViewer"}


# ── the per-project step ──────────────────────────────────────────────────────


def test_a_project_runs_the_bigquery_collector_and_keeps_its_errors(mock_credentials):
    inventory = BigQueryInventory(project_id="p", dataset_count=1)
    with patch("collectors.bigquery.BigQueryCollector") as cls:
        cls.return_value.collect.return_value = inventory
        cls.return_value.errors = [
            {"collector": "bigquery", "category": "API_DISABLED", "message": "off"}
        ]
        result = main._collect_project("p", mock_credentials, None, selected={"bigquery"})
    assert result["bigquery"] is inventory
    assert [(e["collector"], e["category"], e["project_id"]) for e in result["errors"]] == [
        ("bigquery", "API_DISABLED", "p")
    ]


def test_a_crashing_bigquery_collector_does_not_stop_the_project(mock_credentials):
    with patch("collectors.bigquery.BigQueryCollector") as cls:
        cls.return_value.collect.side_effect = RuntimeError("boom")
        cls.return_value.errors = []
        result = main._collect_project("p", mock_credentials, None, selected={"bigquery"})
    assert "bigquery" not in result
    assert [e["collector"] for e in result["errors"]] == ["bigquery"]


# ── the JSON ──────────────────────────────────────────────────────────────────


def _table(table_id, kind="TABLE", size=0):
    return BigQueryTable(
        dataset_id="analytics",
        location="US",
        table_id=table_id,
        table_type=kind,
        total_logical_bytes=size,
    )


def _inventory():
    return BigQueryInventory(
        project_id="p",
        dataset_count=1,
        tables=[_table("events", size=5_000_000_000), _table("v", "VIEW")],
        table_counts={"TABLE": 1, "VIEW": 1},
        protectable_logical_bytes=5_000_000_000,
    )


def test_the_bigquery_inventory_is_in_the_discovery_json():
    result = main._build_result(["p"], None, {"p": {"bigquery": _inventory()}})
    data = json.loads(json.dumps(result.to_json_dict(), default=str))
    (entry,) = data["bigquery"]
    assert entry["project_id"] == "p" and entry["dataset_count"] == 1
    assert [t["table_id"] for t in entry["tables"]] == ["events", "v"]
    assert entry["protectable_logical_bytes"] == 5_000_000_000


def test_the_streaming_slice_carries_bigquery_too():
    from streaming_writer import _CATEGORIES, slice_from_result

    assert "bigquery" in _CATEGORIES
    assert slice_from_result("p", {"bigquery": _inventory()})["bigquery"]["dataset_count"] == 1
    assert slice_from_result("p", {})["bigquery"] is None


def test_the_streamed_json_has_a_bigquery_list(tmp_path):
    from streaming_writer import StreamingDiscoveryWriter, slice_from_result

    writer = StreamingDiscoveryWriter(tmp_path, "T")
    writer.add("p", slice_from_result("p", {"bigquery": _inventory()}))
    out = writer.finalize(meta={"projects_scanned": ["p"]}, filename="out.json")
    assert json.loads(out.read_text())["bigquery"][0]["tables"][0]["table_id"] == "events"


# ── the run summary ───────────────────────────────────────────────────────────


def test_the_project_summary_has_the_bigquery_numbers_and_none_when_not_collected():
    done = main._summarise_project(
        "p", {"compute": ComputeInventory(project_id="p"), "bigquery": _inventory()}
    )
    assert done["bq_datasets"] == 1 and done["bq_counts"] == {"TABLE": 1, "VIEW": 1}
    assert done["bq_protectable_bytes"] == 5_000_000_000
    skipped = main._summarise_project("p", {"compute": ComputeInventory(project_id="p")})
    assert skipped["bq_datasets"] is None and skipped["bq_counts"] is None


def _printed(summaries):
    with main.console.capture() as captured:
        main._print_summary(summaries, None)
    return " ".join(captured.get().split())


def test_the_summary_totals_bigquery_across_projects():
    one = main._summarise_project(
        "a", {"compute": ComputeInventory(project_id="a"), "bigquery": _inventory()}
    )
    other = BigQueryInventory(
        project_id="b",
        dataset_count=3,
        table_counts={"TABLE": 2, "MATERIALIZED_VIEW": 1, "EXTERNAL": 4, "SNAPSHOT": 5},
        protectable_logical_bytes=2_500_000_000_000,
    )
    two = main._summarise_project(
        "b", {"compute": ComputeInventory(project_id="b"), "bigquery": other}
    )
    text = _printed([one, two])
    assert (
        "BigQuery: 4 datasets · 3 tables · 1 materialized views · 1 views · 4 external tables · 5 snapshots"
        in text
    )
    assert "2.505 TB, decimal" in text  # (5e9 + 2.5e12) / 1e12, four decimals


def test_the_summary_has_no_bigquery_line_when_it_was_not_collected():
    summary = main._summarise_project("a", {"compute": ComputeInventory(project_id="a")})
    assert "BigQuery:" not in _printed([summary])


# ── the files and the mock run ────────────────────────────────────────────────


def test_a_mock_run_writes_a_bigquery_file_with_rows(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "argv", ["main.py", "--mock", "--output", str(tmp_path)])
    main.main()
    (archive,) = tmp_path.glob("gcp_sizing_results_*.zip")
    with zipfile.ZipFile(archive) as zf:
        (name,) = [n for n in zf.namelist() if n.startswith("gce_bigquery_info-")]
        rows = list(csv.DictReader(io.StringIO(zf.read(name).decode())))
    assert [r["TableId"] for r in rows] == ["events", "events_view"]
    assert rows[0]["TableType"] == "TABLE" and rows[0]["Label/Tag: dataset_team"] == "data"


# ── anonymization ─────────────────────────────────────────────────────────────


def _bq_result():
    return {
        "projects_scanned": ["proj-a"],
        "bigquery": [
            {
                "project_id": "proj-a",
                "tables": [
                    {
                        "dataset_id": "analytics",
                        "location": "US",
                        "table_id": "events",
                        "table_type": "EXTERNAL",
                        "external_source_format": "PARQUET",
                        "external_source_uri": "gs://secret-bucket/x",
                        "dataset_labels": {"team": "data"},
                        "labels": {"env": "prod"},
                    }
                ],
            }
        ],
    }


def test_the_bigquery_file_is_anonymized_last_and_hides_the_new_fields():
    assert FILE_ORDER[-1] == "gce_bigquery_info"
    text = build_csv_files(_bq_result(), "S", Anonymizer())["gce_bigquery_info-S.csv"]
    for real in ("proj-a", "analytics", "events", "secret-bucket", "data", "prod", "dataset_team"):
        assert real not in text, real
    row = next(csv.DictReader(io.StringIO(text)))
    assert (row["Project"], row["DatasetId"], row["TableId"]) == (
        "Project-00000",
        "DatasetId-00000",
        "TableId-00000",
    )
    assert row["ExternalSourceUri"] == "ExternalSourceUri-00000"
    assert row["Location"] == "US" and row["TableType"] == "EXTERNAL"
    assert any(c.startswith("Label/Tag:Label/TagName-") for c in row)


def test_an_empty_external_uri_is_a_value_and_gets_a_label_as_in_powershell():
    result = _bq_result()
    result["bigquery"][0]["tables"][0]["external_source_uri"] = ""
    row = next(
        csv.DictReader(
            io.StringIO(build_csv_files(result, "S", Anonymizer())["gce_bigquery_info-S.csv"])
        )
    )
    assert row["ExternalSourceUri"] == "ExternalSourceUri-00000"


def test_the_key_file_maps_the_new_labels_back():
    anonymizer = Anonymizer()
    build_csv_files(_bq_result(), "S", anonymizer)
    actual = dict(anonymizer.key_rows())
    assert actual["DatasetId-00000"] == "analytics" and actual["TableId-00000"] == "events"
    assert actual["ExternalSourceUri-00000"] == "gs://secret-bucket/x"


@pytest.mark.parametrize("field", ["DatasetId", "TableId", "ExternalSourceUri"])
def test_a_new_field_can_be_left_alone(field):
    text = build_csv_files(_bq_result(), "S", Anonymizer.from_options("", field))[
        "gce_bigquery_info-S.csv"
    ]
    assert f"{field}-0" not in text
