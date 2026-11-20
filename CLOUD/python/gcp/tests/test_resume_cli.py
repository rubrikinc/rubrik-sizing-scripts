"""Resuming through the real main(): the CLI options, the progress folder and the zip.

The credential, the project lookup, the access check and the per-project collection are replaced; the
orchestration, the checkpoint store, the merge and the packaging are the real ones.
"""

from __future__ import annotations

import copy
import csv
import glob
import io
import json
import os
import sys
import zipfile
from types import SimpleNamespace

import auth
import checkpoint_core
import main
import preflight
import preflight_core as core
import pytest
import resume
import runlog_core

PROJECTS = ["proj-a", "proj-b", "proj-c"]
BAD = "no-access-proj"


@pytest.fixture(autouse=True)
def _fresh_digest():
    runlog_core.ISSUES.reset()
    yield
    runlog_core.ISSUES.reset()


class Scanner:
    def __init__(self):
        self.scanned: list[str] = []
        self.fail: set[str] = set()
        _, _, per_project = main._run_mock()
        self.template = per_project[next(iter(per_project))]

    def __call__(self, project, credentials, regions, enable_security, pre, selected=None, **kw):
        self.scanned.append(project)
        if project in self.fail:
            raise RuntimeError(f"{project} blew up")
        result = copy.deepcopy(self.template)
        for inventory in result.values():
            if hasattr(inventory, "project_id"):
                inventory.project_id = project
        return result


@pytest.fixture
def run(monkeypatch, tmp_path):
    scanner = Scanner()
    checked: list[list[str]] = []
    unreadable: list[str] = []

    def resolve(credentials, ids, all_projects=True, skipped=None, **k):
        readable = [p for p in ids if p not in unreadable]
        if skipped is not None:
            skipped.extend((p, RuntimeError("PERMISSION_DENIED")) for p in ids if p in unreadable)
        return readable

    def fake_run_all(projects, credentials, selected, workers):
        checked.append(list(projects))
        return [[core.Check(p, "", p, "compute instances", core.OK, None)] for p in projects]

    monkeypatch.setattr(auth, "get_credentials", lambda: "credentials")
    monkeypatch.setattr(auth, "normalise_regions", lambda regions: regions)
    monkeypatch.setattr(auth, "resolve_projects", resolve)
    monkeypatch.setattr(auth, "normalise_scope", lambda *a, **k: None)
    monkeypatch.setattr(auth, "effective_quota_project", lambda creds: ("", ""))
    monkeypatch.setattr(main, "_collect_project", scanner)
    monkeypatch.setattr(preflight, "run_all", fake_run_all)

    def go(*flags, projects=PROJECTS):
        # The zip is named by the second the run started: a zip left by an earlier run in the same
        # test would be overwritten or kept depending on where the second boundary fell. Remove it,
        # so a run leaves exactly the zip it wrote.
        for earlier in glob.glob(str(tmp_path / "gcp_sizing_results_*.zip")):
            os.remove(earlier)
        argv = ["main.py", "--projects", ",".join(projects), "--output", str(tmp_path), *flags]
        monkeypatch.setattr(sys, "argv", argv)
        main.main()
        return sorted(glob.glob(str(tmp_path / "gcp_sizing_results_*.zip")))

    return SimpleNamespace(
        go=go, scanner=scanner, checked=checked, unreadable=unreadable, dir=tmp_path
    )


def _progress(directory):
    return sorted(glob.glob(os.path.join(str(directory), "gcp-sizing-progress-*")))


def _discovery(zip_path):
    zf = zipfile.ZipFile(zip_path)
    (name,) = [n for n in zf.namelist() if n.startswith("gcp-sizing-discovery-")]
    return json.loads(zf.read(name))


def _report_owners(zip_path):
    zf = zipfile.ZipFile(zip_path)
    (name,) = [n for n in zf.namelist() if n.startswith("gcp_preflight_check-")]
    return sorted({r["Owner"] for r in csv.DictReader(io.StringIO(zf.read(name).decode()))})


# ── the progress folder ───────────────────────────────────────────────────────


def test_a_complete_scan_leaves_no_progress_folder(run):
    run.go()
    assert _progress(run.dir) == []


def test_a_project_that_died_keeps_the_folder_and_is_not_saved(run):
    run.scanner.fail = {"proj-b"}
    run.go()
    (folder,) = _progress(run.dir)
    assert set(checkpoint_core.Store(folder, "gcp", "").completed()) == {"proj-a", "proj-c"}


def test_a_named_project_that_could_not_be_read_keeps_the_folder(run):
    """Once access is granted a --resume must be able to pick it up: it has no result yet."""
    run.unreadable.append("proj-c")
    run.go()
    assert len(_progress(run.dir)) == 1


# ── resuming ──────────────────────────────────────────────────────────────────


def test_without_resume_a_run_with_no_terminal_refuses_to_continue(run, capsys):
    run.scanner.fail = {"proj-b"}
    run.go()
    run.scanner.scanned.clear()
    with pytest.raises(SystemExit) as stop:
        run.go()
    assert stop.value.code == 2
    assert run.scanner.scanned == [] and len(_progress(run.dir)) == 1
    assert "--resume" in capsys.readouterr().out


def test_resume_scans_only_the_missing_projects_and_writes_every_project(run):
    run.scanner.fail = {"proj-b"}
    run.go()
    run.scanner.scanned.clear()
    run.scanner.fail = set()
    (zip_path,) = run.go("--resume")
    assert run.scanner.scanned == ["proj-b"]
    assert _discovery(zip_path)["projects_scanned"] == PROJECTS
    assert _progress(run.dir) == []


def test_a_resumed_run_writes_the_same_discovery_as_an_uninterrupted_one(run):
    (reference_zip,) = run.go()
    reference = _discovery(reference_zip)
    for leftover in glob.glob(str(run.dir / "gcp_sizing_results_*.zip")):
        os.remove(leftover)

    run.scanner.fail = {"proj-b"}
    run.go()
    run.scanner.fail = set()
    (resumed_zip,) = run.go("--resume")
    resumed = _discovery(resumed_zip)
    for doc in (reference, resumed):
        doc.pop("generated_at", None)
    assert resumed == reference


def test_fresh_deletes_the_unfinished_run_and_scans_everything(run):
    run.scanner.fail = {"proj-b"}
    run.go()
    run.scanner.scanned.clear()
    run.scanner.fail = set()
    run.go("--fresh")
    assert sorted(run.scanner.scanned) == PROJECTS


def test_a_resumed_run_checks_access_only_for_the_projects_still_to_scan(run):
    run.scanner.fail = {"proj-b"}
    run.go()
    assert run.checked == [PROJECTS]
    run.checked.clear()
    run.scanner.fail = set()
    run.go("--resume")
    assert run.checked == [["proj-b"]]


def test_keep_partial_checks_access_only_for_the_projects_still_missing(run, monkeypatch):
    """A kept partial project is not scanned, so it is not checked again either: it keeps the access
    rows it was saved with."""
    real = run.scanner

    def with_errors(project, *a, **k):
        result = real(project, *a, **k)
        if project == "proj-a":
            result["errors"] = [
                {"project_id": project, "collector": "backup", "category": "OTHER", "message": "x"}
            ]
        return result

    monkeypatch.setattr(main, "_collect_project", with_errors)
    run.scanner.fail = {"proj-b"}
    run.go()
    run.checked.clear()
    real.fail = set()
    run.go("--resume", "--keep-partial")
    assert run.checked == [["proj-b"]]  # proj-a is kept, so it is not checked again
    run.checked.clear()


def test_by_default_a_resume_checks_the_partial_projects_again_too(run, monkeypatch):
    real = run.scanner

    def with_errors(project, *a, **k):
        result = real(project, *a, **k)
        if project == "proj-a":
            result["errors"] = [
                {"project_id": project, "collector": "backup", "category": "OTHER", "message": "x"}
            ]
        return result

    monkeypatch.setattr(main, "_collect_project", with_errors)
    run.scanner.fail = {"proj-b"}
    run.go()
    run.checked.clear()
    real.fail = set()
    run.go("--resume")
    assert sorted(run.checked[0]) == ["proj-a", "proj-b"]  # both are about to be scanned


def test_the_report_of_a_resumed_run_still_has_rows_for_every_project(run):
    run.scanner.fail = {"proj-b"}
    run.go()
    run.scanner.fail = set()
    (zip_path,) = run.go("--resume")
    assert _report_owners(zip_path) == PROJECTS


def test_a_project_that_becomes_readable_is_picked_up_by_a_resume(run):
    run.unreadable.append("proj-c")
    run.go()
    run.scanner.scanned.clear()
    run.unreadable.clear()
    (zip_path,) = run.go("--resume")
    assert run.scanner.scanned == ["proj-c"]
    assert _discovery(zip_path)["projects_scanned"] == PROJECTS


def test_a_run_with_different_options_is_refused_not_mixed(run, capsys):
    run.scanner.fail = {"proj-b"}
    run.go()
    run.scanner.scanned.clear()
    with pytest.raises(SystemExit):
        run.go("--resume", "--collectors", "compute")
    assert run.scanner.scanned == []
    assert "different options" in capsys.readouterr().out


def test_resume_scans_again_by_default_the_projects_that_finished_with_errors(run, monkeypatch):
    errors = {"proj-a"}
    real = run.scanner

    def with_errors(project, *a, **k):
        result = real(project, *a, **k)
        if project in errors:
            result["errors"] = [
                {"project_id": project, "collector": "backup", "category": "OTHER", "message": "x"}
            ]
        return result

    monkeypatch.setattr(main, "_collect_project", with_errors)
    run.scanner.fail = {"proj-b"}
    run.go()
    real.scanned.clear()
    real.fail = set()
    errors.clear()
    run.go("--resume")
    assert sorted(real.scanned) == ["proj-a", "proj-b"]


def test_keep_partial_keeps_the_projects_that_finished_with_errors(run, monkeypatch):
    real = run.scanner

    def with_errors(project, *a, **k):
        result = real(project, *a, **k)
        if project == "proj-a":
            result["errors"] = [
                {"project_id": project, "collector": "backup", "category": "OTHER", "message": "x"}
            ]
        return result

    monkeypatch.setattr(main, "_collect_project", with_errors)
    run.scanner.fail = {"proj-b"}
    run.go()
    real.scanned.clear()
    real.fail = set()
    run.go("--resume", "--keep-partial")
    assert real.scanned == ["proj-b"]  # proj-a is kept with its error


# ── the options ───────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "flags",
    [
        ("--keep-partial",),
        ("--resume", "--fresh"),
        ("--preflight-only", "--resume"),
        ("--mock", "--fresh"),
    ],
    ids=["keep-needs-resume", "resume-and-fresh", "resume-with-preflight-only", "fresh-with-mock"],
)
def test_contradicting_options_are_refused(run, flags):
    with pytest.raises(SystemExit) as stop:
        run.go(*flags)
    assert stop.value.code == 2


def test_the_stop_hint_tells_a_stopped_run_how_to_resume(run):
    run.go()
    assert "--resume" in runlog_core._stop_hint and "gcp-sizing-progress-" in runlog_core._stop_hint


def test_keep_progress_follows_what_is_left(run):
    assert resume.keep_progress([], False) is False
    assert resume.keep_progress([{"id": "p"}], False) is True
    assert resume.keep_progress([], True) is True


# ── what the end of every run says about projects that finished with gaps ─────


def _with_errors(run, monkeypatch, failing_projects):
    """Make the named projects finish with a collector error, as an API that is off does."""
    real = run.scanner

    def scan(project, *a, **k):
        result = real(project, *a, **k)
        if project in failing_projects:
            result["errors"] = [
                {
                    "project_id": project,
                    "collector": "backup",
                    "category": "API_DISABLED",
                    "message": "Backup and DR API is not enabled",
                }
            ]
        return result

    monkeypatch.setattr(main, "_collect_project", scan)


def test_a_clean_run_prints_no_gaps_summary(run, capsys):
    run.go()
    assert "finished with gaps" not in capsys.readouterr().out


def test_a_run_with_a_project_that_finished_with_errors_names_it_and_says_what_to_do(
    run, monkeypatch, capsys
):
    _with_errors(run, monkeypatch, {"proj-b"})
    run.go()
    out = capsys.readouterr().out
    assert "1 of 3 projects finished with gaps" in out
    assert "proj-b" in out and "backup: Backup and DR API is not enabled" in out
    assert "--resume" in out and "--keep-partial" in out  # the folder is kept, so resume is offered


def test_a_project_with_gaps_keeps_the_folder_even_though_every_project_has_a_result(
    run, monkeypatch
):
    """The point of rescanning partial projects by default: it needs a folder to resume from."""
    _with_errors(run, monkeypatch, {"proj-b"})
    run.go()
    (folder,) = _progress(run.dir)
    assert set(checkpoint_core.Store(folder, "gcp", "").completed()) == set(PROJECTS)


def test_the_resume_it_suggests_scans_just_the_project_with_gaps(run, monkeypatch, capsys):
    _with_errors(run, monkeypatch, {"proj-b"})
    run.go()
    capsys.readouterr()
    run.scanner.scanned.clear()
    _with_errors(run, monkeypatch, set())  # the cause is fixed
    (zip_path,) = run.go("--resume")
    assert run.scanner.scanned == ["proj-b"]
    assert _progress(run.dir) == []  # now every project is clean: nothing left to resume
    # not the note at the start of a resume, which also says "finished with gaps"
    assert " of 3 projects finished with gaps" not in capsys.readouterr().out
    assert _discovery(zip_path)["collection_errors"] == []


def test_a_resume_that_still_has_the_gap_keeps_saying_so(run, monkeypatch, capsys):
    _with_errors(run, monkeypatch, {"proj-b"})
    run.go()
    capsys.readouterr()
    (zip_path,) = run.go("--resume")  # nothing fixed
    out = capsys.readouterr().out
    assert "1 of 3 projects finished with gaps" in out and "proj-b" in out
    assert len(_progress(run.dir)) == 1


def test_keep_partial_still_reports_the_gaps_it_kept(run, monkeypatch, capsys):
    _with_errors(run, monkeypatch, {"proj-b"})
    run.go()
    capsys.readouterr()
    run.scanner.scanned.clear()
    run.go("--resume", "--keep-partial")
    out = capsys.readouterr().out
    assert run.scanner.scanned == []  # kept as it was
    assert "1 of 3 projects finished with gaps" in out  # and it still says so


def test_a_run_where_every_project_had_gaps_does_not_say_resume_cannot_help(
    run, monkeypatch, capsys
):
    _with_errors(run, monkeypatch, set(PROJECTS))
    run.go()
    out = capsys.readouterr().out
    assert "3 of 3 projects finished with gaps" in out
    assert "scan the project again by name" not in out  # the folder is kept: resume can help


def test_gaps_of_errors_groups_each_projects_errors_into_one_line():
    errors = [
        {"project_id": "a", "collector": "compute", "message": "boom"},
        {"project_id": "a", "collector": "storage", "message": "bang"},
        {"project_id": "b", "collector": "backup", "category": "OTHER"},
    ]
    assert resume.gaps_of_errors(errors) == [
        ("a", "compute: boom (+1 more)"),
        ("b", "backup: OTHER"),
    ]
    assert resume.gaps_of_errors([]) == []


def test_keep_progress_counts_a_project_with_gaps():
    assert resume.keep_progress([], False, []) is False
    assert resume.keep_progress([], False, [("p", "x")]) is True
    assert resume.keep_progress([], False) is False  # old callers that do not pass gaps
