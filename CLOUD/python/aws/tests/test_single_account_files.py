"""What a single-account run leaves in its output folder.

Only the ZIP is meant to be shared, so it is all that is left unless --keep-artifacts is given
(as with Azure and GCP). An anonymized run must not leave the raw JSON, which holds the real names.
"""

from __future__ import annotations

import json
import os
import sys
import zipfile

import pytest

import csv_export
import main
from anonymize import Anonymizer
from tests.test_csv_export import ACCT, STAMP, _result


def _json(tmp_path):
    path = tmp_path / "aws_sizing_discovery.json"
    path.write_text(json.dumps(_result()), encoding="utf-8")
    return str(path)


def _beside(tmp_path, zip_path):
    return sorted(p.name for p in tmp_path.iterdir() if p.name != os.path.basename(zip_path))


# ── the default: only the zip ─────────────────────────────────────────────────


def test_a_run_leaves_only_the_zip_which_holds_the_json_and_the_csv_files(tmp_path):
    zip_path = main._finish_single_account(_json(tmp_path), str(tmp_path), STAMP, True, None)
    assert _beside(tmp_path, zip_path) == []
    names = zipfile.ZipFile(zip_path).namelist()
    assert "aws_sizing_discovery.json" in names
    assert len([n for n in names if n.endswith(".csv")]) > 20


def test_no_csv_still_leaves_only_the_zip_with_the_json_the_plans_file_and_the_manifest(tmp_path):
    # PowerShell writes the backup plans file whether or not the CSV files are wanted
    zip_path = main._finish_single_account(_json(tmp_path), str(tmp_path), STAMP, False, None)
    assert _beside(tmp_path, zip_path) == []
    assert sorted(zipfile.ZipFile(zip_path).namelist()) == [
        f"aws-backup-plans-info-{STAMP}.json",
        "aws_sizing_discovery.json",
        "manifest.json",
    ]


def test_the_csv_files_in_the_zip_are_the_ones_the_old_writer_put_on_disk(tmp_path):
    out, old = tmp_path / "new", tmp_path / "old"
    out.mkdir()
    json_path = out / "aws_sizing_discovery.json"
    json_path.write_text(json.dumps(_result()), encoding="utf-8")
    zip_path = main._finish_single_account(str(json_path), str(out), STAMP, True, None)
    written = csv_export.write_csv_files([_result()], str(old), STAMP)
    zf = zipfile.ZipFile(zip_path)
    assert sorted(os.path.basename(p) for p in written) == sorted(
        n for n in zf.namelist() if n.endswith(".csv")
    )
    for path in written:
        with open(path, "rb") as f:
            assert zf.read(os.path.basename(path)) == f.read(), path


# ── an anonymized run ─────────────────────────────────────────────────────────


def test_an_anonymized_run_leaves_no_raw_json_and_no_real_name_beside_the_zip(tmp_path):
    zip_path = main._finish_single_account(
        _json(tmp_path), str(tmp_path), STAMP, True, Anonymizer()
    )
    key = f"aws_anonymized_keys_to_actual_values-{STAMP}.csv"
    assert _beside(tmp_path, zip_path) == [
        key
    ]  # the key file maps labels back; it is meant to stay
    assert "aws_sizing_discovery.json" not in zipfile.ZipFile(zip_path).namelist()
    for name in zipfile.ZipFile(zip_path).namelist():
        assert ACCT not in zipfile.ZipFile(zip_path).read(name).decode(), name
    assert ACCT in (tmp_path / key).read_text()  # and it is the only file that has the real value


# ── --keep-artifacts ──────────────────────────────────────────────────────────


def test_keep_artifacts_leaves_the_json_and_loose_csv_files_identical_to_those_in_the_zip(tmp_path):
    zip_path = main._finish_single_account(
        _json(tmp_path), str(tmp_path), STAMP, True, None, keep_artifacts=True
    )
    loose = _beside(tmp_path, zip_path)
    assert "aws_sizing_discovery.json" in loose
    zf = zipfile.ZipFile(zip_path)
    csvs = [n for n in zf.namelist() if n.endswith(".csv")]
    assert sorted(n for n in loose if n.endswith(".csv")) == sorted(csvs)
    for name in csvs:
        assert (tmp_path / name).read_bytes() == zf.read(name), name


def test_keep_artifacts_with_anonymize_keeps_the_json_on_request_but_the_csv_files_stay_anonymous(
    tmp_path,
):
    zip_path = main._finish_single_account(
        _json(tmp_path), str(tmp_path), STAMP, True, Anonymizer(), keep_artifacts=True
    )
    assert "aws_sizing_discovery.json" in _beside(tmp_path, zip_path)  # asked for, and it is raw
    for path in tmp_path.glob("aws_*-*.csv"):
        if "anonymized_keys" not in path.name:
            assert ACCT not in path.read_text(), path.name


# ── things going wrong ────────────────────────────────────────────────────────


def test_the_json_is_not_removed_if_the_csv_files_cannot_be_built(tmp_path, monkeypatch):
    json_path = _json(tmp_path)

    def boom(*args, **kwargs):
        raise RuntimeError("cannot build")

    monkeypatch.setattr(csv_export, "build_csv_files", boom)
    with pytest.raises(RuntimeError):
        main._finish_single_account(json_path, str(tmp_path), STAMP, True, None)
    assert os.path.exists(json_path)


def test_the_json_is_not_removed_if_writing_the_zip_fails(tmp_path, monkeypatch):
    json_path = _json(tmp_path)

    def boom(self, *args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(zipfile.ZipFile, "writestr", boom)
    with pytest.raises(OSError):
        main._finish_single_account(json_path, str(tmp_path), STAMP, True, None)
    assert os.path.exists(json_path)


def test_a_json_that_cannot_be_removed_is_a_warning_not_a_failure(tmp_path, monkeypatch, caplog):
    json_path = _json(tmp_path)

    def boom(path):
        raise OSError("in use")

    monkeypatch.setattr(main.os, "remove", boom)
    with caplog.at_level("WARNING"):
        zip_path = main._finish_single_account(json_path, str(tmp_path), STAMP, True, None)
    assert os.path.exists(zip_path)
    assert "Could not remove" in caplog.text


# ── the command line ──────────────────────────────────────────────────────────


def _run_cli(tmp_path, monkeypatch, *extra):
    out = tmp_path / "out"
    out.mkdir()
    json_path = out / "aws_sizing_discovery.json"

    def fake_run(**kwargs):
        json_path.write_text(json.dumps(_result()), encoding="utf-8")
        return str(json_path)

    monkeypatch.setattr(main, "run", fake_run)
    monkeypatch.setattr(sys, "argv", ["main.py", "--output", str(out), "--no-cost", *extra])
    main.main()
    return out


def test_the_default_command_line_run_leaves_only_the_zip(tmp_path, monkeypatch):
    out = _run_cli(tmp_path, monkeypatch)
    (zip_path,) = out.glob("aws_sizing_results_*.zip")
    assert sorted(p.name for p in out.iterdir()) == [zip_path.name]


def test_the_command_line_flag_keeps_the_loose_files(tmp_path, monkeypatch):
    out = _run_cli(tmp_path, monkeypatch, "--keep-artifacts")
    names = [p.name for p in out.iterdir()]
    assert "aws_sizing_discovery.json" in names and any(n.endswith(".csv") for n in names)


def test_an_anonymized_command_line_run_leaves_the_zip_the_key_file_and_the_real_log(
    tmp_path, monkeypatch
):
    out = _run_cli(tmp_path, monkeypatch, "--anonymize")
    (zip_path,) = out.glob("aws_sizing_results_*.zip")
    stamp = zip_path.stem[len("aws_sizing_results_") :]
    assert sorted(p.name for p in out.iterdir()) == sorted(
        [
            zip_path.name,
            f"aws_anonymized_keys_to_actual_values-{stamp}.csv",
            f"output_aws_not_anonymized_{stamp}.log",
        ]
    )


def test_the_help_says_what_the_flag_does():
    text = " ".join(main._build_parser().format_help().split())
    assert "--keep-artifacts" in text and "loose JSON and CSV files" in text
