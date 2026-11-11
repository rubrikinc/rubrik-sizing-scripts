"""Every GCP results zip holds a manifest.json listing the data files in it.

The manifest lists the CSV files and the discovery JSON with a hash that matches the bytes in the zip, and
not the run log. In an anonymized run it holds no real name. Only the zip is left behind, as before.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import sys
import zipfile

import pytest


def _run(monkeypatch, tmp_path, *extra):
    import main

    monkeypatch.setattr(sys, "argv", ["main.py", "--mock", "--output", str(tmp_path), *extra])
    main.main()
    (archive,) = tmp_path.glob("gcp_sizing_results_*.zip")
    return archive


def test_a_run_puts_a_manifest_in_the_zip_and_leaves_only_the_zip(monkeypatch, tmp_path):
    archive = _run(monkeypatch, tmp_path)
    assert "manifest.json" in zipfile.ZipFile(archive).namelist()
    assert sorted(p.name for p in tmp_path.iterdir()) == [archive.name]


def test_the_manifest_says_which_tool_wrote_it(monkeypatch, tmp_path):
    manifest = json.loads(zipfile.ZipFile(_run(monkeypatch, tmp_path)).read("manifest.json"))
    assert manifest["tool"] == "gcp" and manifest["manifest_version"] == 1
    assert manifest["generated_at"].endswith("Z")


def test_it_lists_every_csv_and_json_file_and_not_the_log(monkeypatch, tmp_path):
    zf = zipfile.ZipFile(_run(monkeypatch, tmp_path))
    manifest = json.loads(zf.read("manifest.json"))
    data = {n for n in zf.namelist() if n.endswith((".csv", ".json")) and n != "manifest.json"}
    assert {e["name"] for e in manifest["files"]} == data
    assert not any(e["name"].endswith(".log") for e in manifest["files"])


def test_each_hash_is_the_hash_of_the_bytes_in_the_zip(monkeypatch, tmp_path):
    zf = zipfile.ZipFile(_run(monkeypatch, tmp_path))
    for entry in json.loads(zf.read("manifest.json"))["files"]:
        assert entry["sha256"] == hashlib.sha256(zf.read(entry["name"])).hexdigest(), entry["name"]


def test_a_csv_entry_has_the_columns_and_the_row_count_of_its_file(monkeypatch, tmp_path):
    """The mock run has BigQuery tables but no VMs, so BigQuery is the file with rows to count."""
    zf = zipfile.ZipFile(_run(monkeypatch, tmp_path))
    manifest = json.loads(zf.read("manifest.json"))
    entry = next(e for e in manifest["files"] if e["kind"] == "gce_bigquery_info")
    rows = list(csv.reader(io.StringIO(zf.read(entry["name"]).decode("utf-8"))))
    assert entry["columns"] == rows[0] and entry["rows"] == len(rows) - 1 >= 1


def test_a_file_with_nothing_to_report_is_listed_as_empty_not_left_out(monkeypatch, tmp_path):
    """PowerShell writes a zero-byte file when there are no rows; the manifest says so."""
    zf = zipfile.ZipFile(_run(monkeypatch, tmp_path))
    manifest = json.loads(zf.read("manifest.json"))
    entry = next(e for e in manifest["files"] if e["kind"] == "gce_vm_info")
    assert zf.read(entry["name"]) == b""
    assert entry["rows"] == 0 and entry["columns"] == []


def test_a_run_without_csv_files_lists_only_the_json(monkeypatch, tmp_path):
    manifest = json.loads(zipfile.ZipFile(_run(monkeypatch, tmp_path, "--no-csv")).read("manifest.json"))
    assert manifest["files"] and all(e["name"].endswith(".json") for e in manifest["files"])


def test_an_anonymized_zip_has_a_manifest_that_names_no_resource(monkeypatch, tmp_path):
    zf = zipfile.ZipFile(_run(monkeypatch, tmp_path, "--anonymize"))
    text = zf.read("manifest.json").decode("utf-8")
    manifest = json.loads(text)
    assert not any(e["kind"].startswith("rubrik-discovery") for e in manifest["files"])
    raw = [n for n in zf.namelist() if n.endswith(".json") and n != "manifest.json"]
    assert raw == [], "an anonymized zip has no raw discovery JSON"
    for real in ("mock-project-prod", "mock-project-dev"):
        assert real not in text, real


def test_a_manifest_failure_does_not_cost_the_zip(monkeypatch, tmp_path):
    import manifest_core

    monkeypatch.setattr(manifest_core, "build", lambda *a, **k: 1 / 0)
    zf = zipfile.ZipFile(_run(monkeypatch, tmp_path))
    names = zf.namelist()
    assert "manifest.json" not in names
    assert any(n.startswith("gce_vm_info-") for n in names)
