"""Every Azure results zip holds a manifest.json listing the data files in it.

The manifest lists the CSV and JSON data files with a hash that matches the bytes in the zip, and not the
run log. In an anonymized run it holds no real name. Nothing is left beside the zip unless
--keep-artifacts is given, as before.
"""

from __future__ import annotations

import hashlib
import json
import sys
import zipfile

import pytest

from tests.test_csv_export import _run_mock


def _zip(tmp_path):
    (archive,) = tmp_path.glob("azure_sizing_results_*.zip")
    return zipfile.ZipFile(archive)


def test_a_run_puts_a_manifest_in_the_zip_and_nothing_else_beside_it(monkeypatch, tmp_path):
    _run_mock(monkeypatch, tmp_path)
    zf = _zip(tmp_path)
    assert "manifest.json" in zf.namelist()
    assert [p.name for p in tmp_path.iterdir()] == [zf.filename.rsplit("/", 1)[-1]]


def test_the_manifest_says_which_tool_wrote_it(monkeypatch, tmp_path):
    _run_mock(monkeypatch, tmp_path)
    manifest = json.loads(_zip(tmp_path).read("manifest.json"))
    assert manifest["tool"] == "azure" and manifest["manifest_version"] == 1
    assert manifest["generated_at"].endswith("Z")


def test_it_lists_every_csv_and_json_file_and_not_the_log(monkeypatch, tmp_path):
    _run_mock(monkeypatch, tmp_path)
    zf = _zip(tmp_path)
    manifest = json.loads(zf.read("manifest.json"))
    data = {n for n in zf.namelist() if n.endswith((".csv", ".json")) and n != "manifest.json"}
    assert {e["name"] for e in manifest["files"]} == data
    assert not any(e["name"].endswith(".log") for e in manifest["files"])


def test_each_hash_is_the_hash_of_the_bytes_in_the_zip(monkeypatch, tmp_path):
    _run_mock(monkeypatch, tmp_path)
    zf = _zip(tmp_path)
    for entry in json.loads(zf.read("manifest.json"))["files"]:
        assert entry["sha256"] == hashlib.sha256(zf.read(entry["name"])).hexdigest(), entry["name"]


def test_a_csv_entry_has_the_columns_and_the_row_count_of_its_file(monkeypatch, tmp_path):
    _run_mock(monkeypatch, tmp_path)
    zf = _zip(tmp_path)
    entry = next(
        e for e in json.loads(zf.read("manifest.json"))["files"] if e["kind"] == "azure_vmdisk_info"
    )
    import csv
    import io

    rows = list(csv.reader(io.StringIO(zf.read(entry["name"]).decode("utf-8"))))
    assert entry["columns"] == rows[0] and entry["rows"] == len(rows) - 1 >= 5


def test_a_run_without_csv_files_lists_only_the_json(monkeypatch, tmp_path):
    _run_mock(monkeypatch, tmp_path, "--no-csv")
    manifest = json.loads(_zip(tmp_path).read("manifest.json"))
    assert manifest["files"] and all(e["name"].endswith(".json") for e in manifest["files"])


def test_an_anonymized_zip_has_a_manifest_that_names_no_resource(monkeypatch, tmp_path):
    _run_mock(monkeypatch, tmp_path, "--anonymize")
    zf = _zip(tmp_path)
    text = zf.read("manifest.json").decode("utf-8")
    manifest = json.loads(text)
    assert not any(e["name"].startswith("rubrik-discovery-") for e in manifest["files"])
    # every real name in the unanonymized mock data would show up in a column list or a file name
    for real in ("azdc1", "prod-rg", "Whatlab"):
        assert real not in text


def test_keep_artifacts_leaves_the_manifest_beside_the_zip_too(monkeypatch, tmp_path):
    _run_mock(monkeypatch, tmp_path, "--keep-artifacts")
    assert (tmp_path / "manifest.json").exists()
    zf = _zip(tmp_path)
    assert (tmp_path / "manifest.json").read_bytes() == zf.read("manifest.json")


def test_a_manifest_failure_does_not_cost_the_zip(monkeypatch, tmp_path):
    import manifest_core

    monkeypatch.setattr(manifest_core, "build", lambda *a, **k: 1 / 0)
    _run_mock(monkeypatch, tmp_path)
    names = _zip(tmp_path).namelist()
    assert "manifest.json" not in names
    assert any(n.startswith("azure_vmdisk_info-") for n in names)
