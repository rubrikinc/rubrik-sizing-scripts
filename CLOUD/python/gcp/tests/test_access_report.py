"""What a run of several projects says about each one it could not scan, and --preflight-only.

A project named with --projects that cannot be read, and one whose collection stopped as a whole,
keep rows in the pre-flight CSV and are named at the end. --preflight-only checks access and
collects nothing.
"""

from __future__ import annotations

import csv
import io
import sys
import zipfile
from unittest.mock import MagicMock, patch

import auth
import main
import preflight
import pytest
import runlog_core
from google.api_core import exceptions as gexc
from tests.test_preflight import real_run  # noqa: F401


@pytest.fixture(autouse=True)
def _fresh_digest():
    """The run summary is global: these tests run real main() calls, so each starts and ends clean."""
    runlog_core.ISSUES.reset()
    yield
    runlog_core.ISSUES.reset()


BAD = "no-access-proj-1"
DEAD = "dead-proj-1"


def _zip_file(zip_path, prefix):
    zf = zipfile.ZipFile(zip_path)
    (name,) = [n for n in zf.namelist() if n.startswith(prefix)]
    return zf.read(name).decode("utf-8")


def _rows(zip_path):
    return list(csv.DictReader(io.StringIO(_zip_file(zip_path, "gcp_preflight_check-"))))


def _unreadable(*bad_ids, exc=None):
    failure = exc or gexc.PermissionDenied("The caller does not have permission")

    def resolve(creds, ids, all_projects=True, skipped=None, include_system_projects=False):
        if skipped is not None:
            skipped.extend((bad, failure) for bad in bad_ids)
        return [i for i in ids if i not in bad_ids]

    return resolve


def _run_main(monkeypatch, tmp_path, projects, *flags):
    argv = ["main.py", "--projects", ",".join(projects), "--output", str(tmp_path), *flags]
    monkeypatch.setattr(sys, "argv", argv)
    main.main()


def _good_project():
    return main._run_mock()[0][0]


# ── projects that are not scanned stay in the report ──────────────────────────


def test_a_project_named_with_projects_that_cannot_be_read_has_a_row_and_is_named(
    real_run, monkeypatch, tmp_path
):
    pid = _good_project()
    monkeypatch.setattr(auth, "resolve_projects", _unreadable(BAD))
    _run_main(monkeypatch, tmp_path, [pid, BAD])
    (zip_path,) = tmp_path.glob("gcp_sizing_results_*.zip")
    bad = [r for r in _rows(zip_path) if r["Owner"] == BAD]
    assert [
        (r["Service"], r["Scope"], r["Permission"], r["Access"], r["Detail"], r["Outcome"])
        for r in bad
    ] == [
        (
            preflight.PROJECT,
            BAD,
            preflight.PROJECT_GET,
            "access denied",
            "PermissionDenied",
            "dropped",
        )
    ]
    assert bad[0]["OutputFilesAffected"] == preflight.EVERY_FILE
    log = _zip_file(zip_path, "output_gcp_")
    assert "Not scanned:" in log and f"{BAD}  cannot read the project: PermissionDenied" in log


def test_a_project_whose_collection_stops_gets_a_scan_row(real_run, monkeypatch, tmp_path):
    projects, _regions, per_project = main._run_mock()
    pid = projects[0]

    def collect(project, *args, **kwargs):
        if project == DEAD:
            raise RuntimeError("boom")
        return per_project[pid]

    monkeypatch.setattr(main, "_collect_project", collect)
    _run_main(monkeypatch, tmp_path, [pid, DEAD])
    (zip_path,) = tmp_path.glob("gcp_sizing_results_*.zip")
    dead = [r for r in _rows(zip_path) if r["Owner"] == DEAD]
    services = sorted(r["Service"] for r in dead)
    assert services == sorted(["compute instances", "cloud sql instances", preflight.SCAN])
    (scan,) = [r for r in dead if r["Service"] == preflight.SCAN]
    assert (scan["Access"], scan["Detail"]) == ("could not be checked", "RuntimeError")
    assert f"{DEAD}  collection failed: RuntimeError" in _zip_file(zip_path, "output_gcp_")


def test_a_run_where_everything_was_read_has_no_not_scanned_list(real_run):
    zip_path, _calls, _pid = real_run()
    assert "Not scanned:" not in _zip_file(zip_path, "output_gcp_")
    assert {r["Service"] for r in _rows(zip_path)} == {"compute instances", "cloud sql instances"}


# ── --preflight-only ──────────────────────────────────────────────────────────


def test_preflight_only_writes_only_the_access_report_and_collects_nothing(
    real_run, monkeypatch, tmp_path
):
    pid = _good_project()
    monkeypatch.setattr(auth, "resolve_projects", _unreadable(BAD))
    monkeypatch.setattr(main, "_collect_project", lambda *a, **k: pytest.fail("nothing collected"))
    _run_main(monkeypatch, tmp_path, [pid, BAD], "--preflight-only")
    assert not list(tmp_path.glob("gcp_sizing_results_*.zip"))
    (zip_path,) = tmp_path.glob("gcp_access_check_*.zip")
    names = sorted(zipfile.ZipFile(zip_path).namelist())
    assert len(names) == 3 and names[0].startswith("gcp_preflight_check-")
    assert names[1] == "manifest.json" and names[2].startswith("output_gcp_")
    owners = {(r["Owner"], r["Service"]) for r in _rows(zip_path)}
    assert (BAD, preflight.PROJECT) in owners and (pid, "compute instances") in owners
    log = _zip_file(zip_path, "output_gcp_")
    assert "Not checked:" in log and "Access check complete:" in log
    assert "Run ended: scan finished" in log
    assert sorted(p.name for p in tmp_path.iterdir()) == [zip_path.name]


def test_an_anonymized_preflight_only_run_labels_every_row_and_keeps_the_key_file_outside(
    real_run, monkeypatch, tmp_path
):
    pid = _good_project()
    monkeypatch.setattr(auth, "resolve_projects", _unreadable(BAD))
    _run_main(monkeypatch, tmp_path, [pid, BAD], "--preflight-only", "--anonymize")
    (zip_path,) = tmp_path.glob("gcp_access_check_*.zip")
    rows = _rows(zip_path)
    assert not {pid, BAD} & {r["Owner"] for r in rows} and not {pid, BAD} & {
        r["Scope"] for r in rows
    }
    assert list(tmp_path.glob("gcp_anonymized_keys_to_actual_values-*.csv"))
    assert list(tmp_path.glob("output_gcp_not_anonymized_*.log"))


@pytest.mark.parametrize(
    "flags, message",
    [
        (["--no-preflight"], "cannot skip it"),
        (["--no-csv"], "--no-csv"),
        (["--dry-run"], "--dry-run"),
        (["--mock"], "--mock"),
    ],
)
def test_preflight_only_refuses_options_that_contradict_it(monkeypatch, capsys, flags, message):
    monkeypatch.setattr(sys, "argv", ["main.py", "--preflight-only", *flags])
    with pytest.raises(SystemExit) as exc:
        main.main()
    assert exc.value.code == 2 and message in capsys.readouterr().err


# ── the rows themselves ───────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "exc, access, code",
    [
        (
            gexc.PermissionDenied("The caller does not have permission"),
            "access denied",
            "PermissionDenied",
        ),
        (gexc.NotFound("Project not found"), "access denied", "NotFound"),
        (gexc.TooManyRequests("slow down"), "could not be checked", "TooManyRequests"),
    ],
)
def test_an_unreadable_project_is_classified_by_the_google_error(exc, access, code):
    row = preflight.unreadable_check(BAD, exc).to_row()
    assert (row["Access"], row["Detail"], row["Permission"]) == (
        access,
        code,
        preflight.PROJECT_GET,
    )
    assert "caller" not in str(row)  # the message stays out of the CSV


def test_resolve_projects_reports_each_id_it_could_not_read():
    client = MagicMock()
    good = MagicMock(project_id="good-proj-1")
    failure = gexc.PermissionDenied("denied")
    client.get_project.side_effect = [failure, good]
    skipped: list = []
    with patch("google.cloud.resourcemanager_v3.ProjectsClient", return_value=client):
        result = auth.resolve_projects(
            MagicMock(), [BAD, "good-proj-1"], all_projects=False, skipped=skipped
        )
    assert result == ["good-proj-1"] and skipped == [(BAD, failure)]


def test_the_not_scanned_list_names_twenty_and_points_to_the_csv(capsys):
    entries = [
        {"id": f"proj-{i:02d}", "why": "collection failed: X", "rows": []} for i in range(22)
    ]
    main._print_not_scanned(entries, "Not scanned:")
    out = capsys.readouterr().out
    assert out.count("collection failed: X") == 20 and "2 more" in out
    assert preflight.FILE_PREFIX in out
