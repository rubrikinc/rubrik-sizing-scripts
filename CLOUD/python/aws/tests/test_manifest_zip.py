"""Every AWS results zip holds a manifest.json listing the data files in it.

The single-account zip and the multi-account (org, SSO, profiles) zip are built in two places, so both are
checked. The manifest lists the CSV and JSON data files with a hash that matches the bytes in the zip, and
not the run log. In an anonymized run it holds no real name.
"""

from __future__ import annotations

import hashlib
import json
import zipfile

import pytest

import main
from anonymize import Anonymizer
from tests.test_csv_export import ACCT, STAMP, _result


def _discovery_json(tmp_path):
    path = tmp_path / "aws_sizing_discovery.json"
    path.write_text(json.dumps(_result()), encoding="utf-8")
    return str(path)


def _manifest(zip_path):
    with zipfile.ZipFile(zip_path) as zf:
        return json.loads(zf.read("manifest.json")), zf


def test_a_single_account_zip_has_a_manifest(tmp_path):
    zip_path = main._finish_single_account(_discovery_json(tmp_path), str(tmp_path), STAMP, True, None)
    manifest, zf = _manifest(zip_path)
    assert manifest["tool"] == "aws" and manifest["manifest_version"] == 1
    assert "manifest.json" in zf.namelist()


def test_the_manifest_lists_every_data_file_and_nothing_else(tmp_path):
    zip_path = main._finish_single_account(_discovery_json(tmp_path), str(tmp_path), STAMP, True, None)
    with zipfile.ZipFile(zip_path) as zf:
        manifest = json.loads(zf.read("manifest.json"))
        data = {n for n in zf.namelist() if n.endswith((".csv", ".json")) and n != "manifest.json"}
    assert {e["name"] for e in manifest["files"]} == data
    assert not any(e["name"].endswith(".log") for e in manifest["files"])


def test_each_hash_is_the_hash_of_the_bytes_in_the_zip(tmp_path):
    zip_path = main._finish_single_account(_discovery_json(tmp_path), str(tmp_path), STAMP, True, None)
    with zipfile.ZipFile(zip_path) as zf:
        manifest = json.loads(zf.read("manifest.json"))
        for entry in manifest["files"]:
            assert entry["sha256"] == hashlib.sha256(zf.read(entry["name"])).hexdigest(), entry["name"]


def test_a_csv_entry_lists_the_columns_the_file_has(tmp_path):
    zip_path = main._finish_single_account(_discovery_json(tmp_path), str(tmp_path), STAMP, True, None)
    with zipfile.ZipFile(zip_path) as zf:
        manifest = json.loads(zf.read("manifest.json"))
        entry = next(e for e in manifest["files"] if e["kind"] == "aws_ec2_instance_info")
        header = zf.read(entry["name"]).decode("utf-8").splitlines()[0]
    assert entry["columns"] == [c.strip('"') for c in header.split(",")]
    assert entry["rows"] == 1


def test_a_run_without_csv_files_still_lists_the_json_files(tmp_path):
    zip_path = main._finish_single_account(_discovery_json(tmp_path), str(tmp_path), STAMP, False, None)
    manifest, _ = _manifest(zip_path)
    kinds = {e["kind"] for e in manifest["files"]}
    assert "aws_sizing_discovery" in kinds and not any(k.startswith("aws_ec2") for k in kinds)


def test_an_anonymized_zip_has_a_manifest_with_no_raw_json_and_no_real_name(tmp_path):
    zip_path = main._finish_single_account(
        _discovery_json(tmp_path), str(tmp_path), STAMP, True, Anonymizer()
    )
    with zipfile.ZipFile(zip_path) as zf:
        text = zf.read("manifest.json").decode("utf-8")
    manifest = json.loads(text)
    assert not any(e["kind"] == "aws_sizing_discovery" for e in manifest["files"])
    for real in (ACCT, "web", "bucket one"):
        assert real not in text, f"{real} is in the manifest"


def test_keep_artifacts_leaves_the_manifest_beside_the_zip_too(tmp_path):
    main._finish_single_account(
        _discovery_json(tmp_path), str(tmp_path), STAMP, True, None, keep_artifacts=True
    )
    assert (tmp_path / "manifest.json").exists()


def _progress(tmp_path, accounts):
    progress = tmp_path / "progress"
    progress.mkdir()
    for account in accounts:
        folder = progress / account
        folder.mkdir()
        (folder / "aws_sizing_discovery.json").write_text(
            json.dumps(_result(account=account)), encoding="utf-8"
        )
    return str(progress)


def test_a_multi_account_zip_has_a_manifest_listing_every_accounts_json(tmp_path):
    zip_path = str(tmp_path / "out.zip")
    accounts = ["111111111111", "222222222222"]
    main._package_results(_progress(tmp_path, accounts), zip_path, 2, 0, stamp=STAMP)
    with zipfile.ZipFile(zip_path) as zf:
        manifest = json.loads(zf.read("manifest.json"))
        listed = {e["name"] for e in manifest["files"]}
        assert {f"{a}/aws_sizing_discovery.json" for a in accounts} <= listed
        for entry in manifest["files"]:
            assert entry["sha256"] == hashlib.sha256(zf.read(entry["name"])).hexdigest()


def test_a_manifest_failure_does_not_cost_the_zip(tmp_path, monkeypatch):
    import manifest_core

    monkeypatch.setattr(manifest_core, "build", lambda *a, **k: 1 / 0)
    zip_path = main._finish_single_account(_discovery_json(tmp_path), str(tmp_path), STAMP, True, None)
    with zipfile.ZipFile(zip_path) as zf:
        names = zf.namelist()
    assert "manifest.json" not in names
    assert any(n.endswith(".csv") for n in names) and "aws_sizing_discovery.json" in names
