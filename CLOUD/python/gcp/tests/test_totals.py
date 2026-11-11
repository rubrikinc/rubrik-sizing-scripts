"""The totals block: wording and numbers are PowerShell's, and every number comes from the CSV rows."""

import csv
import io
import sys
import zipfile

import csv_export
import main
import pytest
import totals


def _line(lines, start):
    [found] = [line for line in lines if line.startswith(start)]
    return found


def _rows(**files):
    return {f"gce_{name}_info": rows for name, rows in files.items()}


def _table(kind, size=0):
    return {"TableType": kind, "TotalLogicalSizeBytes": size}


def test_the_compute_and_database_lines_use_powershells_wording():
    lines = totals.summary_lines(
        _rows(
            vm=[{}] * 6,
            attached_disk=[{"SizeGb": 10, "SizeTb": 0.01}] * 6,
            unattached_disk=[{"SizeGb": 50, "SizeTb": 0.05}] * 2,
            cloudsql=[{"StorageSizeGb": 150, "StorageSizeTb": 0.15}] * 6,
            spanner=[{}],
        )
    )
    assert lines[:7] == [
        "Total # of GCE VMs: 6",
        "Total # of attached disks: 6",
        "Total # of unattached disks: 2",
        "Total capacity of all disks: 160 GB or 0.16 TB",
        "Total # of Cloud SQL instances: 6",
        "Total Cloud SQL storage: 900 GB or 0.9 TB",
        "Total # of Spanner instances: 1",
    ]


def test_disk_capacity_adds_attached_and_unattached_disks():
    lines = totals.summary_lines(
        _rows(
            attached_disk=[{"SizeGb": 100, "SizeTb": 0.1}],
            unattached_disk=[{"SizeGb": 20.5, "SizeTb": 0.0205}],
        )
    )
    assert "Total capacity of all disks: 120.5 GB or 0.1205 TB" in lines


def test_a_sum_is_printed_with_fifteen_significant_digits_like_powershell():
    assert totals._number(0.1 + 0.2) == "0.3"
    assert totals._number(160.0) == "160"
    assert totals._number(0) == "0"


def test_an_empty_run_prints_zeros_not_blanks():
    lines = totals.summary_lines({}, 0, 0, True)
    assert "Total # of GCE VMs: 0" in lines
    assert "Total capacity of all disks: 0 GB or 0 TB" in lines
    assert "Total Cloud SQL storage: 0 GB or 0 TB" in lines
    assert "Total logical size of protectable BQ data (TABLE + MATERIALIZED_VIEW): 0 TB" in lines


def test_bigquery_tables_are_counted_by_type_and_only_tables_and_matviews_are_sized():
    tables = [
        _table("TABLE", 2 * 10**12),
        _table("TABLE", 5 * 10**11),
        _table("MATERIALIZED_VIEW", 10**12),
        _table("VIEW", 10**13),
        _table("EXTERNAL", 10**13),
        _table("SNAPSHOT", 10**13),
    ]
    lines = totals.summary_lines(_rows(bigquery=tables), 4, 0, True)
    assert "Total # of BigQuery datasets: 4" in lines
    assert "Total # of BigQuery native tables: 2" in lines
    assert "Total # of BigQuery materialized views: 1" in lines
    assert "Total # of BigQuery views (not protected): 1" in lines
    assert "Total # of BigQuery external tables (not protected — data not in BQ): 1" in lines
    assert (
        "Total # of BigQuery table snapshots (not included in the protectable size below): 1"
        in lines
    )
    assert "Total logical size of protectable BQ data (TABLE + MATERIALIZED_VIEW): 3.5 TB" in lines


def test_the_bigquery_size_is_rounded_to_four_places():
    lines = totals.summary_lines(_rows(bigquery=[_table("TABLE", 17_512_345_678)]), 1, 0, True)
    assert _line(lines, "Total logical size of protectable").endswith(": 0.0175 TB")


def test_failed_bigquery_calls_add_powershells_warning():
    lines = totals.summary_lines({}, 0, 3, True)
    assert lines[-1] == (
        "WARNING: 3 BigQuery call(s) failed; the BigQuery totals above may be incomplete. "
        "See the warnings above."
    )
    assert not any(line.startswith("WARNING") for line in totals.summary_lines({}, 0, 0, True))


def test_bigquery_that_was_not_collected_says_so_instead_of_printing_zeros():
    lines = totals.summary_lines({}, 0, 0, False)
    assert lines[-1] == "BigQuery was not collected, so there are no BigQuery totals."
    assert not any("native tables" in line for line in lines)


def test_bigquery_that_failed_everywhere_still_shows_the_totals_and_the_warning():
    lines = totals.summary_lines({}, 0, 2, False)
    assert "Total # of BigQuery native tables: 0" in lines
    assert lines[-1].startswith("WARNING: 2 BigQuery call(s) failed")


def test_the_totals_hold_no_project_names_or_resource_names():
    rows = _rows(
        vm=[{"Project": "secret-project-1", "Name": "payroll-db", "Zone": "us-central1-a"}],
        cloudsql=[{"Project": "secret-project-1", "Name": "billing-sql", "StorageSizeGb": 5}],
    )
    text = "\n".join(totals.summary_lines(rows))
    assert "secret-project-1" not in text and "payroll-db" not in text and "billing-sql" not in text


# ── in a run ──────────────────────────────────────────────────────────────────


def _run(tmp_path, monkeypatch, argv=()):
    monkeypatch.setattr(sys, "argv", ["main.py", "--mock", "--output", str(tmp_path), *argv])
    main.main()
    return zipfile.ZipFile(next(tmp_path.glob("gcp_sizing_results_*.zip")))


def _log(zf):
    name = next(n for n in zf.namelist() if n.startswith("output_gcp_") and n.endswith(".log"))
    return zf.read(name).decode()


def _csv_rows(zf, prefix):
    name = next(n for n in zf.namelist() if n.startswith(prefix + "-"))
    return list(csv.reader(io.StringIO(zf.read(name).decode("utf-8-sig"))))[1:]


def test_the_totals_are_on_the_screen_and_in_the_log_between_the_summary_and_the_run_summary(
    tmp_path, monkeypatch, capsys
):
    zf = _run(tmp_path, monkeypatch)
    screen, log = capsys.readouterr().out, _log(zf)
    for shown in (screen, log):
        assert "Total # of GCE VMs:" in shown and "Total # of Spanner instances:" in shown
        assert shown.index("Discovery Summary") < shown.index("Total # of GCE VMs:")
        assert shown.index("Total # of GCE VMs:") < shown.index("Run summary")


def test_the_totals_agree_with_the_csv_files_in_the_zip(tmp_path, monkeypatch):
    zf = _run(tmp_path, monkeypatch)
    log = _log(zf)
    assert f"Total # of GCE VMs: {len(_csv_rows(zf, 'gce_vm_info'))}" in log
    assert f"Total # of attached disks: {len(_csv_rows(zf, 'gce_attached_disk_info'))}" in log
    assert f"Total # of Cloud SQL instances: {len(_csv_rows(zf, 'gce_cloudsql_info'))}" in log


def test_the_totals_are_printed_even_when_no_csv_files_are_written(tmp_path, monkeypatch):
    zf = _run(tmp_path, monkeypatch, argv=["--no-csv"])
    assert "Total # of GCE VMs:" in _log(zf)


def test_an_anonymized_run_has_the_totals_in_its_real_log(tmp_path, monkeypatch):
    _run(tmp_path, monkeypatch, argv=["--anonymize"])
    kept = next(tmp_path.glob("output_gcp_not_anonymized_*.log"))
    assert "Total # of GCE VMs:" in kept.read_text(encoding="utf-8")


def test_a_failure_in_the_totals_is_a_warning_not_a_crash(tmp_path, monkeypatch):
    monkeypatch.setattr(totals, "summary_lines", lambda *a, **k: 1 / 0)
    zf = _run(tmp_path, monkeypatch)
    log = _log(zf)
    assert "Could not work out the totals" in log and "Run summary" in log


def test_the_new_module_is_packaged():
    assert '"totals"' in open("pyproject.toml", encoding="utf-8").read()


def test_the_datasets_and_the_failed_bigquery_calls_come_from_the_discovery_json(tmp_path, capsys):
    import json

    path = tmp_path / "gcp-sizing-discovery.json"
    path.write_text(
        json.dumps(
            {
                "bigquery": [{"dataset_count": 2}, {"dataset_count": 3}],
                "collection_errors": [
                    {"collector": "bigquery", "message": "x"},
                    {"collector": "bigquery", "message": "y"},
                    {"collector": "compute", "message": "not a BigQuery call"},
                ],
            }
        )
    )
    main._print_totals(path)
    shown = capsys.readouterr().out
    assert "Total # of BigQuery datasets: 5" in shown
    assert "WARNING: 2 BigQuery call(s) failed" in shown


def test_a_json_with_no_bigquery_entries_and_no_failures_says_it_was_not_collected(
    tmp_path, capsys
):
    path = tmp_path / "d.json"
    path.write_text("{}")
    main._print_totals(path)
    assert "BigQuery was not collected" in capsys.readouterr().out
