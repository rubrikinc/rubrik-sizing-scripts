"""Which subscriptions had something go wrong during their scan, and what that does to a resume.

Every warning in the Azure scan collectors is a failure that left something out, and begins with
``[<subscription id>]``; gaps.py counts them per subscription so a subscription that finished with
gaps is saved as partial, whatever the access check predicted.
"""

from __future__ import annotations

import logging

import checkpoint_core
import gaps
import main
import pytest
import resume
from collectors import utils
from tests.test_preflight import real_run  # noqa: F401 - the scan fixture builds on it
from tests.test_resume import ALL, SUB, SUB2, SUB3, _progress, scan  # noqa: F401 - fixtures

logger = logging.getLogger("collectors.test")


@pytest.fixture(autouse=True)
def _clean():
    utils._warned.clear()
    yield
    utils._warned.clear()


@pytest.fixture
def recorder():
    rec = gaps.GapRecorder([SUB, SUB2, SUB3]).install()
    yield rec
    rec.uninstall()


# ── attribution ───────────────────────────────────────────────────────────────


def test_a_warning_is_counted_for_the_subscription_it_names_and_no_other(recorder):
    logger.warning("[%s] Failed to list VMs: boom", SUB)
    assert recorder.count(SUB) == 1 and recorder.count(SUB2) == 0 and recorder.count(SUB3) == 0
    assert recorder.has_gaps(SUB) and not recorder.has_gaps(SUB2)
    assert recorder.gaps() == {SUB: 1}


def test_errors_count_and_lower_levels_do_not(recorder):
    logger.error("[%s] Cost query error: x", SUB)
    logger.info("[%s] Storage: 3 accounts", SUB)
    logger.debug("[%s] noise", SUB)
    assert recorder.count(SUB) == 1


def test_a_message_without_a_known_subscription_is_not_attributed(recorder):
    logger.warning("Failed to do something with no subscription")
    logger.warning("[not-a-subscription-of-this-run] Failed to list VMs")
    logger.warning("[%s] but the id is not in brackets first", SUB.upper() + "x")
    assert recorder.gaps() == {}


def test_a_few_examples_are_kept_and_repeats_are_not_listed_twice(recorder):
    for i in range(6):
        logger.warning("[%s] Skipping disk d%d: boom", SUB, i)
    logger.warning("[%s] Skipping disk d0: boom", SUB)
    assert recorder.count(SUB) == 7
    assert len(recorder.examples(SUB)) == 3


# ── warn_once ─────────────────────────────────────────────────────────────────


def test_a_cause_shown_once_is_still_counted_for_the_next_subscription(recorder):
    """warn_once shows a repeated cause once on the screen, but a second subscription with the same
    failure has a gap too."""
    for sub in (SUB, SUB2, SUB3):
        utils.warn_once(
            "[%s] Azure Monitor metrics query failed (the same failure is not repeated): x", sub
        )
    assert recorder.gaps() == {SUB: 1, SUB2: 1, SUB3: 1}


def test_a_warning_warn_once_does_show_is_not_counted_twice(recorder):
    utils.warn_once(
        "[%s] Azure Monitor metrics query failed (the same failure is not repeated): y", SUB
    )
    assert recorder.count(SUB) == 1  # once through note(), and the handler skips the record shown


def test_warn_once_still_logs_each_cause_once(recorder, caplog):
    with caplog.at_level(logging.WARNING):
        for sub in (SUB, SUB2):
            utils.warn_once("[%s] same cause: z", sub)
    assert len([r for r in caplog.records if "same cause" in r.getMessage()]) == 1


# ── lifecycle ─────────────────────────────────────────────────────────────────


def test_the_handler_is_removed_even_when_the_scan_raises():
    rec = gaps.GapRecorder([SUB]).install()
    assert rec in logging.getLogger().handlers
    try:
        raise RuntimeError("scan blew up")
    except RuntimeError:
        pass
    finally:
        rec.uninstall()
    assert rec not in logging.getLogger().handlers
    gaps.note("[%s] after uninstall" % SUB)  # no recorder: must be a no-op, not an error
    assert rec.count(SUB) == 0


def test_a_second_recorder_replaces_the_first_for_note_and_uninstalling_the_old_one_keeps_it():
    first = gaps.GapRecorder([SUB]).install()
    second = gaps.GapRecorder([SUB]).install()
    first.uninstall()  # must not clear the second's registration
    gaps.note("[%s] Failed to list VMs" % SUB)
    second.uninstall()
    assert second.count(SUB) == 1 and first.count(SUB) == 0


def test_counting_never_raises_into_the_scan(recorder):
    logger.warning("[%s] message with a %%s that has no argument", SUB)  # formats fine
    logger.warning("%s", object())  # an odd record must not break logging
    assert recorder.count(SUB) >= 1


# ── through the real main() ───────────────────────────────────────────────────


def _warning_scanner(scan, warn_for):
    """Make the fake scan log a warning for the named subscriptions, as a real collector would."""
    real = scan.scanner

    def scanner(sub_id, *args, **kwargs):
        result = real(sub_id, *args, **kwargs)
        if sub_id in warn_for:
            logging.getLogger("collectors.compute").warning("[%s] Failed to list VMs: boom", sub_id)
        return result

    return scanner


def test_a_subscription_whose_scan_logged_a_warning_is_saved_as_partial(scan, monkeypatch):
    monkeypatch.setattr(main, "_collect_subscription", _warning_scanner(scan, {SUB2}))
    scan.scanner.fail = {SUB3}  # keeps the folder so it can be read
    scan.run()
    (folder,) = _progress(scan.dir)
    store = checkpoint_core.Store(folder, "azure", "")
    # The shared fixture's access check denies a service in every subscription, so "partial" is true
    # for all of them whatever the scan did. What isolates the warning is the saved count, and
    # test_is_partial_counts_warnings_and_blocked_services pins that a count alone makes it partial.
    data, _ = store.load(SUB2)
    assert data["gaps"]["count"] == 1 and "Failed to list VMs" in data["gaps"]["examples"][0]
    assert store.load(SUB)[0]["gaps"]["count"] == 0
    assert set(store.completed()) == {SUB, SUB2}


def test_a_warning_in_one_subscription_is_not_counted_for_the_others_in_a_serial_scan(
    scan, monkeypatch
):
    monkeypatch.setattr(main, "_collect_subscription", _warning_scanner(scan, {SUB}))
    scan.scanner.fail = {SUB3}
    scan.run("--workers", "1")
    (folder,) = _progress(scan.dir)
    store = checkpoint_core.Store(folder, "azure", "")
    assert store.load(SUB)[0]["gaps"]["count"] == 1
    assert store.load(SUB2)[0]["gaps"]["count"] == 0


def test_is_partial_counts_warnings_and_blocked_services():
    clean = [{"Access": "readable"}]
    assert main._is_partial(clean) is False
    assert main._is_partial(clean, 0) is False
    assert (
        main._is_partial(clean, 2) is True
    )  # a scan-time failure the access check did not predict
    assert main._is_partial([{"Access": "access denied"}], 0) is True
    assert main._is_partial([{"Access": "not enabled"}]) is True
    assert main._is_partial([{"Access": "could not be checked"}]) is False


def test_an_old_checkpoint_without_gaps_is_still_valid_and_reads_as_no_gaps():
    old = {"parts": {n: {} for n in resume.SCAN_PARTS}, "access": []}
    assert resume.valid(old)
    assert resume.gaps_of(old) == {"count": 0, "examples": []}


# ── what the end of every run says about subscriptions that finished with gaps ─


def test_a_clean_run_prints_no_gaps_summary(scan, capsys):
    scan.run()
    assert "finished with gaps" not in capsys.readouterr().out


def test_a_subscription_whose_scan_logged_a_failure_is_named_with_the_failure(
    scan, monkeypatch, capsys
):
    monkeypatch.setattr(main, "_collect_subscription", _warning_scanner(scan, {SUB2}))
    scan.run()
    out = capsys.readouterr().out
    assert "1 of 3 subscriptions finished with gaps" in out
    assert SUB2 in out and "Failed to list VMs: boom" in out
    assert "[" + SUB2 + "]" not in out.split("finished with gaps", 1)[1]  # named once, not twice


def test_a_subscription_the_access_check_blocked_is_named_even_if_its_scan_logged_nothing(
    scan, capsys
):
    scan.blocked.add(SUB3)
    scan.run()
    out = capsys.readouterr().out
    assert "1 of 3 subscriptions finished with gaps" in out
    assert f"{SUB3}  the access check found a service it could not read" in out


def test_a_subscription_with_gaps_keeps_the_folder_though_every_subscription_has_a_result(
    scan, monkeypatch, capsys
):
    """Rescanning partial subscriptions by default needs a folder to resume from."""
    monkeypatch.setattr(main, "_collect_subscription", _warning_scanner(scan, {SUB2}))
    scan.run()
    (folder,) = _progress(scan.dir)
    assert set(checkpoint_core.Store(folder, "azure", "").completed()) == set(ALL)
    out = capsys.readouterr().out
    assert "same command with --resume" in out and "--keep-partial" in out


def test_the_resume_it_offers_scans_just_that_subscription_and_ends_clean(
    scan, monkeypatch, capsys
):
    monkeypatch.setattr(main, "_collect_subscription", _warning_scanner(scan, {SUB2}))
    scan.run()
    capsys.readouterr()
    scan.scanner.scanned.clear()
    monkeypatch.setattr(main, "_collect_subscription", scan.scanner)  # the cause is fixed
    scan.run("--resume")
    assert scan.scanner.scanned == [SUB2]
    assert _progress(scan.dir) == []
    out = capsys.readouterr().out
    # The note at the start of a resume also says "finished with gaps in the earlier run": the end
    # summary is the one that reads "N of M subscriptions finished with gaps".
    assert " of 3 subscriptions finished with gaps" not in out
    assert "scanned again" in out  # and the start of the resume did say what it was doing


def test_a_resume_that_still_has_the_gap_keeps_saying_so(scan, monkeypatch, capsys):
    monkeypatch.setattr(main, "_collect_subscription", _warning_scanner(scan, {SUB2}))
    scan.run()
    capsys.readouterr()
    scan.run("--resume")  # nothing fixed
    out = capsys.readouterr().out
    assert "1 of 3 subscriptions finished with gaps" in out and SUB2 in out
    assert len(_progress(scan.dir)) == 1


def test_keep_partial_still_reports_the_gaps_it_kept(scan, monkeypatch, capsys):
    monkeypatch.setattr(main, "_collect_subscription", _warning_scanner(scan, {SUB2}))
    scan.run()
    capsys.readouterr()
    scan.scanner.scanned.clear()
    scan.run("--resume", "--keep-partial")
    out = capsys.readouterr().out
    assert scan.scanner.scanned == []  # kept as it was
    assert "1 of 3 subscriptions finished with gaps" in out and SUB2 in out


def test_the_total_counts_a_subscription_whose_scan_failed(scan, monkeypatch, capsys):
    monkeypatch.setattr(main, "_collect_subscription", _warning_scanner(scan, {SUB2}))
    scan.scanner.fail = {SUB3}
    scan.run()
    assert "1 of 3 subscriptions finished with gaps" in capsys.readouterr().out


def test_several_failures_in_one_subscription_are_one_line_with_a_count(scan, monkeypatch, capsys):
    real = scan.scanner

    def scanner(sub_id, *args, **kwargs):
        result = real(sub_id, *args, **kwargs)
        if sub_id == SUB:
            for what in ("VMs", "disks", "vaults"):
                logging.getLogger("collectors.compute").warning(
                    "[%s] Failed to list %s: x", sub_id, what
                )
        return result

    monkeypatch.setattr(main, "_collect_subscription", scanner)
    scan.run()
    out = capsys.readouterr().out
    assert "Failed to list VMs: x (+2 more)" in out


def test_keep_progress_counts_a_subscription_with_gaps():
    assert resume.keep_progress([], []) is False
    assert resume.keep_progress([], [("s", "x")]) is True
    assert resume.keep_progress([{"id": "s"}], []) is True
    assert resume.keep_progress([]) is False  # callers that do not pass gaps


def test_subscription_gaps_names_a_subscription_by_its_display_name_when_it_has_one(tmp_path):
    store, _ = checkpoint_core.prepare(
        str(tmp_path), prefix=resume.PREFIX, tool="azure", request={}, interactive=False
    )
    parts = {name: {} for name in resume.SCAN_PARTS}
    store.save(
        "sub-a",
        {
            "parts": parts,
            "access": [],
            "gaps": {"count": 2, "examples": ["[sub-a] Failed to list VMs: boom"]},
        },
        partial=True,
    )
    store.save("sub-b", {"parts": parts, "access": [], "gaps": {"count": 0, "examples": []}})
    got = main._subscription_gaps(store, ["sub-a", "sub-b", "sub-c"], {"sub-a": "Prod"})
    assert got == [
        ("sub-a (Prod)", "Failed to list VMs: boom (+1 more)")
    ]  # sub-c has no checkpoint
    assert main._subscription_gaps(None, ["sub-a"], {}) == []
