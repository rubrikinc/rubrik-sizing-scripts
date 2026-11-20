"""Resuming an interrupted Azure scan, through the real main() with only the collectors replaced.

``_collect_subscription`` is swapped for a fake that counts how often each subscription is scanned and
returns the populated inventories of ``main._run_mock``, so ``_collect_all``, the save callback, the
merge of saved and fresh results and the progress folder are the real ones.
"""

from __future__ import annotations

import copy
import glob
import json
import os
import sys
import zipfile
from types import SimpleNamespace
from unittest.mock import MagicMock

import auth
import checkpoint_core
import main
import preflight
import preflight_core as core
import pytest
import resume
import runlog_core
from collectors.utils import _warned as warn_once_memory
from tests.test_preflight import SUB, real_run  # noqa: F401 - the fixture

SUB2 = "33333333-3333-3333-3333-333333333333"
SUB3 = "44444444-4444-4444-4444-444444444444"
ALL = [SUB, SUB2, SUB3]


@pytest.fixture(autouse=True)
def _fresh_digest():
    runlog_core.ISSUES.reset()
    warn_once_memory.clear()
    yield
    runlog_core.ISSUES.reset()
    warn_once_memory.clear()


class Scanner:
    """Stands in for _collect_subscription: counts scans, fails chosen subscriptions."""

    def __init__(self, fail=()):
        self.scanned: list[str] = []
        self.fail = set(fail)
        comp, bp, stor, db, jobs, cost, _ = main._run_mock(frozenset())
        self.template = (comp[0], bp[0], stor[0], db[0], jobs[0], cost[0])

    def __call__(self, sub_id, credential, regions, cloud=None, scans=None, out=None, skips=None):
        self.scanned.append(sub_id)
        if sub_id in self.fail:
            raise ValueError(f"{sub_id} blew up")
        result = copy.deepcopy(self.template)
        for part in result:
            part.subscription_id = sub_id
        return result


# Captured at import, before the real_run fixture replaces main._collect_all with a canned result.
_REAL_COLLECT_ALL = main._collect_all


@pytest.fixture
def scan(real_run, monkeypatch, tmp_path):
    """A real main() over three subscriptions with only the scan replaced; run(*flags) runs it.

    real_run stubs the credential, the subscription lookups and the extras collectors; here the scan
    itself is replaced one level lower than it does, so the real _collect_all (and with it the save
    callback and the progress folder) runs.
    """
    import collectors.aks_cosmos as aks_cosmos

    scanner = Scanner()
    monkeypatch.setattr(main, "_collect_subscription", scanner)
    monkeypatch.setattr(main, "_collect_all", _REAL_COLLECT_ALL)
    monkeypatch.setattr(auth, "resolve_subscriptions", lambda *a, **k: list(ALL))
    monkeypatch.setattr(auth, "resolve_subscription_names", lambda *a, **k: {})
    checked: list[list[str]] = []
    blocked: set[str] = set()  # subscriptions whose access check denies a service (see tests)
    fake_run_all = preflight.run_all  # real_run's: one OK and one DENIED row per subscription

    def spy(subs, names, *args, **kwargs):
        checked.append(list(subs))
        rows = fake_run_all(subs, names, *args, **kwargs)
        # real_run's fake denies a service everywhere. Keep only its readable row, except for the
        # subscriptions a test asked to be blocked.
        return [
            checks if sub in blocked else [c for c in checks if c.status == core.OK]
            for sub, checks in zip(subs, rows)
        ]

    monkeypatch.setattr(preflight, "run_all", spy)
    for collector, inventory in (
        ("AksCollector", aks_cosmos.AksInventory),
        ("CosmosCollector", aks_cosmos.CosmosInventory),
    ):
        fake = MagicMock()
        fake.side_effect = lambda sub_id, *a, _inv=inventory, **k: SimpleNamespace(
            collect=lambda: _inv(subscription_id=sub_id)
        )
        monkeypatch.setattr(f"collectors.aks_cosmos.{collector}", fake)

    def run(*flags, subs=",".join(ALL)):
        # The zip is named by the minute the run started: a zip left by an earlier run in the same
        # test would be overwritten or kept depending on where the minute boundary fell. Remove it,
        # so a run leaves exactly the zip it wrote.
        for earlier in glob.glob(str(tmp_path / "azure_sizing_results_*.zip")):
            os.remove(earlier)
        argv = ["main.py", "--output", str(tmp_path), "--no-devops"]
        if subs is not None:  # None: leave the scope to the flags the test passes
            argv += ["--subs", subs]
        argv += list(flags)
        monkeypatch.setattr(sys, "argv", argv)
        main.main()
        return sorted(glob.glob(str(tmp_path / "azure_sizing_results_*.zip")))

    return SimpleNamespace(
        run=run, scanner=scanner, dir=tmp_path, checked=checked, blocked=blocked
    )


def _progress(directory):
    return sorted(glob.glob(os.path.join(str(directory), "azure-sizing-progress-*")))


def _json_of(zip_path):
    zf = zipfile.ZipFile(zip_path)
    (name,) = [n for n in zf.namelist() if n.startswith("rubrik-discovery-")]
    return json.loads(zf.read(name))


# ── the progress folder ───────────────────────────────────────────────────────


def test_a_complete_scan_leaves_no_progress_folder(scan):
    scan.run()
    assert _progress(scan.dir) == []
    assert sorted(scan.scanner.scanned) == sorted(ALL)


def test_each_scanned_subscription_is_saved_as_it_finishes(scan):
    scan.scanner.fail = {SUB3}
    scan.run()
    (folder,) = _progress(scan.dir)  # kept: a subscription has no result
    store = checkpoint_core.Store(folder, "azure", "", envelope=True)
    assert set(store.completed()) == {SUB, SUB2}
    data, _ = store.load(SUB)
    assert resume.valid(data) and set(data["parts"]) == set(resume.SCAN_PARTS)


def test_a_subscription_whose_scan_failed_is_not_saved(scan):
    scan.scanner.fail = {SUB2}
    scan.run()
    (folder,) = _progress(scan.dir)
    assert SUB2 not in checkpoint_core.Store(folder, "azure", "").completed()


# ── resuming ──────────────────────────────────────────────────────────────────


def test_without_resume_a_run_with_no_terminal_refuses_to_continue(scan, capsys):
    scan.scanner.fail = {SUB3}
    scan.run()
    scan.scanner.scanned.clear()
    with pytest.raises(SystemExit) as stop:
        scan.run()
    assert stop.value.code == 2
    assert scan.scanner.scanned == []  # nothing scanned, nothing deleted
    assert len(_progress(scan.dir)) == 1
    assert "--resume" in capsys.readouterr().out


def test_resume_scans_only_the_subscriptions_that_are_missing(scan):
    scan.scanner.fail = {SUB3}
    scan.run()
    scan.scanner.scanned.clear()
    scan.scanner.fail = set()
    (zip_path,) = scan.run("--resume")
    assert scan.scanner.scanned == [SUB3]
    assert sorted(_json_of(zip_path)["subscriptions"]) == sorted(ALL)
    assert _progress(scan.dir) == []  # complete now: the folder is gone


def test_fresh_deletes_the_unfinished_run_and_scans_everything(scan):
    scan.scanner.fail = {SUB3}
    scan.run()
    scan.scanner.scanned.clear()
    scan.scanner.fail = set()
    scan.run("--fresh")
    assert sorted(scan.scanner.scanned) == sorted(ALL)


def test_a_resumed_run_writes_the_same_result_as_an_uninterrupted_one(scan, tmp_path):
    (reference_zip,) = scan.run()
    reference = _json_of(reference_zip)
    for leftover in glob.glob(str(scan.dir / "azure_sizing_results_*.zip")):
        os.remove(leftover)

    scan.scanner.fail = {SUB2}
    scan.run()
    scan.scanner.fail = set()
    (resumed_zip,) = scan.run("--resume")
    resumed = _json_of(resumed_zip)

    for doc in (reference, resumed):
        doc.pop("generated_at", None)
    assert (
        resumed["subscriptions"] == reference["subscriptions"]
    )  # scan order, not completion order
    assert resumed == reference


def test_the_totals_of_a_resumed_run_are_not_trivially_zero(scan):
    scan.scanner.fail = {SUB3}
    scan.run()
    scan.scanner.fail = set()
    (zip_path,) = scan.run("--resume")
    assert _json_of(zip_path)["total_vms"] > 0


def test_a_run_with_different_options_is_refused_not_mixed(scan, capsys):
    scan.scanner.fail = {SUB3}
    scan.run()
    scan.scanner.scanned.clear()
    with pytest.raises(SystemExit):
        scan.run("--resume", "--skip-aks")  # a different set of collectors
    assert scan.scanner.scanned == []
    assert "different options" in capsys.readouterr().out


def test_a_truncated_checkpoint_is_scanned_again_not_trusted(scan):
    scan.scanner.fail = {SUB3}
    scan.run()
    (folder,) = _progress(scan.dir)
    store = checkpoint_core.Store(folder, "azure", "")
    with open(store.unit_path(SUB), "w") as f:
        f.write('{"checkpoint": {"unit": "' + SUB + '"}, "da')
    scan.scanner.scanned.clear()
    scan.scanner.fail = set()
    scan.run("--resume")
    assert sorted(scan.scanner.scanned) == sorted([SUB, SUB3])


def test_a_checkpoint_missing_a_part_is_scanned_again_not_dropped(scan):
    scan.scanner.fail = {SUB3}
    scan.run()
    (folder,) = _progress(scan.dir)
    store = checkpoint_core.Store(folder, "azure", "")
    store.save(SUB, {"parts": {"compute": {}}, "access": []})  # parses, but is incomplete
    scan.scanner.scanned.clear()
    scan.scanner.fail = set()
    (zip_path,) = scan.run("--resume")
    assert sorted(scan.scanner.scanned) == sorted([SUB, SUB3])
    assert len(_json_of(zip_path)["compute"]) == len(ALL)


# ── the options ───────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "flags",
    [("--keep-partial",), ("--resume", "--fresh"), ("--preflight-only", "--resume")],
    ids=["keep-needs-resume", "resume-and-fresh", "resume-with-preflight-only"],
)
def test_contradicting_options_are_refused(scan, flags):
    with pytest.raises(SystemExit) as stop:
        scan.run(*flags)
    assert stop.value.code == 2


# ── merging ───────────────────────────────────────────────────────────────────


def test_merge_keeps_scan_order_and_aligns_errors_with_the_subscription_list(tmp_path):
    store, _ = checkpoint_core.prepare(
        str(tmp_path), prefix=resume.PREFIX, tool="azure", request={}, interactive=False
    )
    comp, bp, stor, db, jobs, cost, _ = main._run_mock(frozenset())
    template = (comp[0], bp[0], stor[0], db[0], jobs[0], cost[0])
    store.save("b", resume.scan_checkpoint(template, []))
    boom = ValueError("boom")
    scanned, errors = main._merge_scans(
        ["a", "b", "c"], ["a", "c"], ["A-result", None], {1: boom}, store
    )
    assert scanned[0] == "A-result" and scanned[2] is None
    assert len(scanned[1]) == 6 and isinstance(scanned[1][0], resume.Saved)  # from the saved run
    assert errors == {2: boom}  # index 1 of the todo list is subscription "c", which is index 2


def test_is_partial_follows_the_access_check():
    ok = {"Access": "readable"}
    assert resume._REQUIRED  # module imports
    assert main._is_partial([ok]) is False
    assert main._is_partial([ok, {"Access": "access denied"}]) is True
    assert main._is_partial([{"Access": "not enabled"}]) is True
    assert main._is_partial([{"Access": "could not be checked"}]) is False


# ── what the access check covers, and what the zip reports ────────────────────


def _report_owners(zip_path):
    import csv
    import io

    zf = zipfile.ZipFile(zip_path)
    (name,) = [n for n in zf.namelist() if n.startswith("azure_preflight_check-")]
    return sorted({row["Owner"] for row in csv.DictReader(io.StringIO(zf.read(name).decode()))})


def test_a_resumed_run_checks_access_only_for_the_subscriptions_still_to_scan(scan):
    scan.scanner.fail = {SUB3}
    scan.run()
    assert scan.checked == [ALL]  # the first run checked everything
    scan.checked.clear()
    scan.scanner.fail = set()
    scan.run("--resume")
    assert scan.checked == [[SUB3]]


def test_the_report_of_a_resumed_run_still_has_rows_for_the_subscriptions_it_did_not_rescan(scan):
    scan.scanner.fail = {SUB3}
    scan.run()
    scan.scanner.fail = set()
    (zip_path,) = scan.run("--resume")
    assert _report_owners(zip_path) == sorted(ALL)


def test_a_run_with_different_regions_is_refused_not_mixed(scan, capsys):
    scan.scanner.fail = {SUB3}
    scan.run("--regions", "eastus")
    scan.scanner.scanned.clear()
    with pytest.raises(SystemExit):
        scan.run("--resume", "--regions", "westus2")
    assert scan.scanner.scanned == []
    assert "different options" in capsys.readouterr().out


@pytest.mark.parametrize(
    "first, second",
    [
        ((), ("--current-subscription",)),  # no scope flag means all now, not the current login
        (("--subscriptions", "prod"), ("--current-subscription",)),
        (("--management-groups", "mg1"), ("--subscriptions", "mg1")),
        (("--subscriptions", "prod"), ("--management-groups", "prod")),
    ],
)
def test_a_run_that_asked_for_its_subscriptions_another_way_is_refused_not_mixed(
    scan, capsys, first, second
):
    # The scan scope and the resume fingerprint read the same main._scope_kind. Before AZ-1 no flag
    # meant the current subscription, so a bare run and --current-subscription shared a fingerprint.
    scan.scanner.fail = {SUB3}
    scan.run(*first, subs=None)
    scan.scanner.scanned.clear()
    with pytest.raises(SystemExit):
        scan.run("--resume", *second, subs=None)
    assert scan.scanner.scanned == []
    assert "different options" in capsys.readouterr().out


def test_a_subscription_with_a_blocked_service_is_saved_as_partial(scan):
    scan.blocked.add(SUB2)
    scan.scanner.fail = {SUB3}
    scan.run()
    (folder,) = _progress(scan.dir)
    done = checkpoint_core.Store(folder, "azure", "").completed()
    assert done == {SUB: False, SUB2: True}  # only the one whose access check denied a service


def test_resume_scans_again_a_subscription_that_had_a_blocked_service_by_default(scan):
    scan.blocked.add(SUB2)
    scan.scanner.fail = {SUB3}
    scan.run()
    scan.scanner.scanned.clear()
    scan.scanner.fail = set()
    scan.run("--resume")
    assert sorted(scan.scanner.scanned) == sorted([SUB2, SUB3])  # the partial one and the missing one


def test_a_caller_that_does_not_say_gets_the_safe_default():
    import inspect

    assert inspect.signature(resume.split).parameters["retry_partial"].default is True


def test_keep_partial_checks_access_only_for_the_subscriptions_still_missing(scan):
    scan.blocked.add(SUB2)
    scan.scanner.fail = {SUB3}
    scan.run()
    scan.checked.clear()
    scan.scanner.fail = set()
    scan.run("--resume", "--keep-partial")
    assert scan.checked == [[SUB3]]  # SUB2 is kept, so it is not checked again


def test_by_default_a_resume_checks_the_partial_subscriptions_again_too(scan):
    scan.blocked.add(SUB2)
    scan.scanner.fail = {SUB3}
    scan.run()
    scan.checked.clear()
    scan.scanner.fail = set()
    scan.run("--resume")
    assert sorted(scan.checked[0]) == sorted([SUB2, SUB3])  # both are about to be scanned


def test_keep_partial_keeps_a_subscription_that_had_a_blocked_service_as_it_was(scan):
    scan.blocked.add(SUB2)
    scan.scanner.fail = {SUB3}
    scan.run()
    scan.scanner.scanned.clear()
    scan.scanner.fail = set()
    (zip_path,) = scan.run("--resume", "--keep-partial")
    assert scan.scanner.scanned == [SUB3]  # SUB2 is kept, gaps and all
    assert sorted(_json_of(zip_path)["subscriptions"]) == sorted(ALL)
