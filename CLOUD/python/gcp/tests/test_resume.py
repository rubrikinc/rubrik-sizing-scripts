"""Resuming an interrupted scan: finished projects are saved, and a rerun scans only the rest.

All Google SDK calls are mocked. The scan is driven through the real ``_collect_and_write``, with the
per-project collection replaced by a fake that counts how often each project is scanned.
"""

from __future__ import annotations

import json
from unittest.mock import patch

import checkpoint_core as core
import pytest
import resume
from collectors.asset import AssetInventory
from models.inventory import BackupPostureInventory, ComputeInventory, StorageInventory

REQUEST = resume.request_of(
    selected={"asset", "compute"}, regions=None, security=False, scope=None, project_scope="named"
)


def _store(tmp_path, mode=core.RESUME):
    return core.prepare(
        str(tmp_path),
        prefix=resume.PREFIX,
        tool="gcp",
        request=REQUEST,
        mode=mode,
        interactive=False,
    )


class Scanner:
    """A stand-in for ``_collect_project`` that counts scans and can fail chosen projects."""

    def __init__(self, fail=(), with_errors=()):
        self.scanned: list[str] = []
        self.fail = set(fail)
        self.with_errors = set(with_errors)

    def __call__(
        self, pid, credentials, regions, enable_security, precomputed_asset, selected=None, **kw
    ):
        self.scanned.append(pid)
        if pid in self.fail:
            raise RuntimeError(f"{pid} blew up")
        result = {
            "asset": AssetInventory(project_id=pid, total_assets=3, assets_by_type={"t": 3}),
            "compute": ComputeInventory(project_id=pid, total_instances=2, total_disk_tb=0.5),
            "storage": StorageInventory(project_id=pid, total_buckets=1),
            "backup": BackupPostureInventory(project_id=pid, protection_coverage_pct=50.0),
        }
        if pid in self.with_errors:
            result["errors"] = [
                {"project_id": pid, "collector": "backup", "category": "OTHER", "message": "x"}
            ]
        return result


def _run(tmp_path, projects, scanner, store=None, retry_partial=True, access_rows=None, out=None):
    import main

    with patch.object(main, "_collect_project", side_effect=scanner):
        path = main._collect_and_write(
            projects=projects,
            regions=None,
            credentials=object(),
            enable_security=False,
            workers=4,
            org_assets={},
            output_dir=tmp_path,
            access_rows=access_rows,
            failed=[],
            store=store,
            retry_partial=retry_partial,
            access_out=out,
        )
    return json.loads(path.read_text())


def _comparable(doc):
    doc = dict(doc)
    doc.pop("generated_at", None)
    return doc


PROJECTS = ["alpha", "beta", "gamma", "delta"]


# ── what is saved ─────────────────────────────────────────────────────────────


def test_each_finished_project_is_saved(tmp_path):
    store, _ = _store_new(tmp_path)
    _run(tmp_path, PROJECTS, Scanner(), store=store)
    assert set(store.completed()) == set(PROJECTS)
    data, partial = store.load("alpha")
    assert resume.valid(data) and partial is False
    assert data["slice"]["project_id"] == "alpha"
    assert data["line"]["assets"] == 3


def _store_new(tmp_path):
    return core.prepare(
        str(tmp_path),
        prefix=resume.PREFIX,
        tool="gcp",
        request=REQUEST,
        mode=core.AUTO,
        interactive=False,
    )


def test_a_project_with_errors_is_saved_as_partial(tmp_path):
    store, _ = _store_new(tmp_path)
    _run(tmp_path, PROJECTS, Scanner(with_errors={"beta"}), store=store)
    assert store.completed()["beta"] is True
    assert store.completed()["alpha"] is False


def test_a_project_that_died_is_not_saved_so_a_resume_scans_it_again(tmp_path):
    store, _ = _store_new(tmp_path)
    _run(tmp_path, PROJECTS, Scanner(fail={"gamma"}), store=store)
    assert "gamma" not in store.completed()
    assert {"alpha", "beta", "delta"} <= set(store.completed())


def test_a_project_that_ends_after_a_stop_is_not_saved(tmp_path):
    from collectors import utils

    store, _ = _store_new(tmp_path)
    scanner = Scanner()

    def stop_after_alpha(pid, *args, **kwargs):
        result = scanner(pid, *args, **kwargs)
        if pid == "alpha":
            utils.request_stop()
        return result

    utils.reset_stop()
    try:
        import main

        with patch.object(main, "_collect_project", side_effect=stop_after_alpha):
            main._collect_and_write(
                projects=["alpha"],
                regions=None,
                credentials=object(),
                enable_security=False,
                workers=1,
                org_assets={},
                output_dir=tmp_path,
                store=store,
            )
    finally:
        utils.reset_stop()
    # The stop was asked for while alpha ran: its result is cut off, not finished.
    assert store.completed() == {}


# ── resuming ──────────────────────────────────────────────────────────────────


def test_a_resume_does_not_scan_saved_projects_again(tmp_path):
    store, _ = _store_new(tmp_path)
    _run(tmp_path, PROJECTS, Scanner(fail={"gamma", "delta"}), store=store)

    resumed, was_resumed = _store(tmp_path)
    assert was_resumed
    second = Scanner()
    _run(tmp_path, PROJECTS, second, store=resumed)
    assert sorted(second.scanned) == ["delta", "gamma"]
    assert set(resumed.completed()) == set(PROJECTS)


@pytest.mark.parametrize("count", [4, 60], ids=["in-memory", "streaming"])
def test_a_resumed_run_writes_the_same_json_as_an_uninterrupted_one(tmp_path, count):
    projects = [f"proj-{i:03d}" for i in range(count)]
    reference_dir = tmp_path / "reference"
    reference_dir.mkdir()
    resumed_dir = tmp_path / "resumed"
    resumed_dir.mkdir()

    reference = _run(reference_dir, projects, Scanner())

    store, _ = _store_new(resumed_dir)
    _run(resumed_dir, projects, Scanner(fail=set(projects[::3])), store=store)  # a third died
    again, _ = _store(resumed_dir)
    final = _run(resumed_dir, projects, Scanner(), store=again)

    assert _comparable(final) == _comparable(reference)
    assert final["projects_scanned"] == projects  # scan order, not completion order


def test_the_output_lists_projects_in_scan_order_whatever_order_they_finish_in(tmp_path):
    projects = [f"proj-{i:02d}" for i in range(70)]  # streaming path
    store, _ = _store_new(tmp_path)
    doc = _run(tmp_path, projects, Scanner(), store=store)
    assert [c["project_id"] for c in doc["compute"]] == projects


def test_resume_scans_again_by_default_only_the_projects_that_had_errors(tmp_path):
    store, _ = _store_new(tmp_path)
    _run(tmp_path, PROJECTS, Scanner(with_errors={"beta"}), store=store)

    resumed, _ = _store(tmp_path)
    again = Scanner()
    _run(tmp_path, PROJECTS, again, store=resumed)  # no option: the default
    assert again.scanned == ["beta"]  # not the clean ones
    assert resumed.completed()["beta"] is False  # now complete


def test_a_caller_that_does_not_say_gets_the_safe_default(tmp_path):
    """main() always passes retry_partial, so this default is only ever used by a caller that omits it:
    it must be the one that cannot hide a gap."""
    import inspect

    import main

    assert inspect.signature(main._collect_and_write).parameters["retry_partial"].default is True
    assert inspect.signature(resume.split).parameters["retry_partial"].default is True


def test_keep_partial_keeps_a_project_with_errors_as_it_was(tmp_path):
    store, _ = _store_new(tmp_path)
    _run(tmp_path, PROJECTS, Scanner(with_errors={"beta"}), store=store)

    resumed, _ = _store(tmp_path)
    kept = Scanner()
    doc = _run(tmp_path, PROJECTS, kept, store=resumed, retry_partial=False)
    assert kept.scanned == []
    assert [e["project_id"] for e in doc["collection_errors"]] == ["beta"]  # its gap is still there
    assert resumed.completed()["beta"] is True  # still partial


def test_a_corrupt_checkpoint_is_scanned_again_not_dropped_from_the_results(tmp_path):
    store, _ = _store_new(tmp_path)
    _run(tmp_path, PROJECTS, Scanner(), store=store)
    with open(store.unit_path("beta"), "w") as f:
        f.write('{"checkpoint": {"unit": "beta"}, "data": {"slice": {}}}')  # parses, but incomplete

    resumed, _ = _store(tmp_path)
    again = Scanner()
    doc = _run(tmp_path, PROJECTS, again, store=resumed)
    assert again.scanned == ["beta"]
    assert doc["projects_scanned"] == PROJECTS
    assert len(doc["compute"]) == len(PROJECTS)


def test_saved_projects_that_are_not_in_this_run_are_left_out(tmp_path):
    store, _ = _store_new(tmp_path)
    _run(tmp_path, PROJECTS, Scanner(), store=store)
    resumed, _ = _store(tmp_path)
    doc = _run(tmp_path, ["alpha", "beta"], Scanner(), store=resumed)
    assert doc["projects_scanned"] == ["alpha", "beta"]
    assert [c["project_id"] for c in doc["compute"]] == ["alpha", "beta"]


def test_errors_of_a_kept_project_are_still_in_the_output(tmp_path):
    """With --keep-partial a project that finished with errors is reused, and its errors are in the
    results: a gap must not disappear because the project was not scanned again."""
    store, _ = _store_new(tmp_path)
    _run(tmp_path, PROJECTS, Scanner(with_errors={"beta"}), store=store)
    resumed, _ = _store(tmp_path)
    doc = _run(tmp_path, PROJECTS, Scanner(), store=resumed, retry_partial=False)
    assert [e["project_id"] for e in doc["collection_errors"]] == ["beta"]


def test_a_rescanned_projects_old_errors_are_replaced_not_kept_or_doubled(tmp_path):
    store, _ = _store_new(tmp_path)
    _run(tmp_path, PROJECTS, Scanner(with_errors={"beta"}), store=store)
    resumed, _ = _store(tmp_path)
    clean = _run(tmp_path, PROJECTS, Scanner(), store=resumed)  # the default: beta is scanned again
    assert clean["collection_errors"] == []  # it came back clean, so the old error is gone

    other = tmp_path / "second"  # a new folder: the first run above is unfinished and would refuse
    other.mkdir()
    store, _ = _store_new(other)
    _run(other, PROJECTS, Scanner(with_errors={"beta"}), store=store)
    resumed, _ = _store(other)
    still = _run(other, PROJECTS, Scanner(with_errors={"beta"}), store=resumed)
    assert [e["project_id"] for e in still["collection_errors"]] == ["beta"]  # once, not twice


def test_access_rows_of_resumed_projects_are_kept(tmp_path):
    rows = [{"Owner": p, "Service": "compute", "Access": "granted"} for p in PROJECTS]
    store, _ = _store_new(tmp_path)
    _run(tmp_path, PROJECTS, Scanner(fail={"delta"}), store=store, access_rows=rows)

    resumed, _ = _store(tmp_path)
    only_delta = [r for r in rows if r["Owner"] == "delta"]  # the check ran for what was left
    out: list = []
    doc = _run(tmp_path, PROJECTS, Scanner(), store=resumed, access_rows=only_delta, out=out)
    assert sorted(r["Owner"] for r in out) == sorted(PROJECTS)
    assert sorted(r["Owner"] for r in doc["access_check"]) == sorted(PROJECTS)


def test_a_failing_save_does_not_stop_the_scan(tmp_path):
    store, _ = _store_new(tmp_path)

    def broken_save(*args, **kwargs):
        raise OSError("disk full")

    store.save = broken_save
    doc = _run(tmp_path, PROJECTS, Scanner(), store=store)
    assert doc["projects_scanned"] == PROJECTS
    assert len(doc["compute"]) == len(PROJECTS)


def test_without_a_store_nothing_is_saved_and_the_output_is_unchanged(tmp_path):
    doc = _run(tmp_path, PROJECTS, Scanner())
    assert doc["projects_scanned"] == PROJECTS
    assert not list(tmp_path.glob("gcp-sizing-progress-*"))


# ── the options that decide whether a run may be resumed ──────────────────────


def test_the_project_list_is_not_part_of_the_fingerprint():
    a = resume.request_of(
        selected={"asset"}, regions=None, security=False, scope=None, project_scope="all"
    )
    assert "projects" not in a and a["project_scope"] == "all"


def test_options_that_change_what_is_collected_change_the_fingerprint():
    base = dict(
        selected={"asset", "compute"}, regions=None, security=False, scope=None, project_scope="all"
    )
    fp = core.fingerprint(resume.request_of(**base))
    for change in (
        {"selected": {"asset"}},
        {"regions": ["us-central1"]},
        {"security": True},
        {"scope": "organizations/1"},
        {"project_scope": "named"},
    ):
        assert core.fingerprint(resume.request_of(**{**base, **change})) != fp, change


def test_region_order_does_not_change_the_fingerprint():
    one = resume.request_of(
        selected={"asset"}, regions=["b", "a"], security=False, scope=None, project_scope="all"
    )
    two = resume.request_of(
        selected={"asset"}, regions=["a", "b"], security=False, scope=None, project_scope="all"
    )
    assert core.fingerprint(one) == core.fingerprint(two)


def test_mode_follows_the_options():
    class Args:
        resume = False
        fresh = False

    args = Args()
    assert resume.mode_of(args) == core.AUTO
    args.resume = True
    assert resume.mode_of(args) == core.RESUME
    args.resume, args.fresh = False, True
    assert resume.mode_of(args) == core.FRESH


def test_split_reports_what_it_leaves_out(tmp_path):
    store, _ = _store_new(tmp_path)
    _run(tmp_path, PROJECTS, Scanner(with_errors={"beta"}), store=store)
    todo, reuse, notes = resume.split(store, ["alpha", "beta"], retry_partial=False)
    assert todo == [] and reuse == ["alpha", "beta"]
    assert any("2 saved project(s) are not in this run" in n for n in notes)
    assert any("kept as they were because of --keep-partial" in n for n in notes)

    todo, reuse, notes = resume.split(store, ["alpha", "beta"])  # the default
    assert todo == ["beta"] and reuse == ["alpha"]
    assert any("scanned again" in n and "--keep-partial" in n for n in notes)
