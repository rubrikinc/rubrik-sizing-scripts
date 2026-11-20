"""Resuming an interrupted multi-account scan: what a progress folder is, and when it may be reused.

The scans run through the real ``run_org`` / ``run_profiles`` with ``run`` replaced by a fake that
writes one account file, so the progress folder, the guard and the zip are the real ones.
"""

from __future__ import annotations

import glob
import json
import os
import zipfile

import checkpoint_core
import pytest
from tests.test_modes import (  # noqa: F401 - fixtures
    _EMPTY_KEYS,
    ACCT_A,
    ACCT_B,
    _result_for,
    cli,
    runner,
)

ACCT_SCP = "333333333333"  # the runner fixture's fake run() reports this one as SCP-blocked
RESUME = checkpoint_core.RESUME
FRESH = checkpoint_core.FRESH


def _progress_dirs(directory):
    return sorted(glob.glob(os.path.join(str(directory), "aws-sizing-progress-*")))


def _org(runner, accounts, **kwargs):
    options = {"role_name": "R", "max_workers": 1, **kwargs}
    return runner.main.run_org(zip_dir=str(runner.dir), account_ids=accounts, **options)


def _account_files(zip_path):
    return sorted(n for n in zipfile.ZipFile(zip_path).namelist() if n.endswith("discovery.json"))


# ── the progress folder ───────────────────────────────────────────────────────


def test_a_scan_that_finishes_every_account_leaves_no_progress_folder(runner):
    _org(runner, [ACCT_A, ACCT_B])
    assert _progress_dirs(runner.dir) == []


def test_a_scan_with_an_unfinished_account_keeps_the_progress_folder(runner):
    _org(runner, [ACCT_A, ACCT_SCP])
    (folder,) = _progress_dirs(runner.dir)
    manifest = checkpoint_core.read_manifest(folder)
    assert manifest["status"] == checkpoint_core.IN_PROGRESS
    assert os.path.exists(os.path.join(folder, ACCT_A, "aws_sizing_discovery.json"))
    assert not os.path.exists(os.path.join(folder, ACCT_SCP, "aws_sizing_discovery.json"))


def test_a_failure_while_writing_an_account_file_keeps_the_old_one_intact(tmp_path):
    """The account file is what a resume counts as finished, so a failed write must not damage it."""
    path = str(tmp_path / "aws_sizing_discovery.json")
    checkpoint_core.write_json_atomic(path, {"account": "old"})

    class Unwritable:
        def __repr__(self):
            raise RuntimeError("killed while writing")

    with pytest.raises(RuntimeError):
        checkpoint_core.write_json_atomic(path, {"account": Unwritable()})
    assert json.load(open(path)) == {"account": "old"}
    assert os.listdir(tmp_path) == ["aws_sizing_discovery.json"]  # no temp file left behind


def test_run_writes_the_account_file_through_the_atomic_writer(tmp_path, monkeypatch):
    """run() must not write the account file in place (a kill would leave a truncated file)."""
    import main

    seen = []
    real = checkpoint_core.write_json_atomic

    def spy(path, obj, **kwargs):
        seen.append(os.path.basename(path))
        return real(path, obj, **kwargs)

    monkeypatch.setattr(checkpoint_core, "write_json_atomic", spy)
    monkeypatch.setattr(main, "_account_identity", lambda session: (ACCT_A, ""))
    monkeypatch.setattr(main, "_resolve_regions", lambda *a, **k: [])
    monkeypatch.setattr(main, "_scan_all_regions", lambda *a, **k: {k2: [] for k2 in _EMPTY_KEYS})
    monkeypatch.setattr(main, "_print_box", lambda *a, **k: None)
    import contextlib

    with contextlib.suppress(Exception):
        main.run(
            output_dir=str(tmp_path), session=object(), services=frozenset(), collect_cost=False
        )
    assert "aws_sizing_discovery.json" in seen


# ── resuming ──────────────────────────────────────────────────────────────────


def test_without_resume_a_run_with_no_terminal_refuses_to_continue(runner, capsys):
    _org(runner, [ACCT_A, ACCT_SCP])
    runner.scanned.clear()
    with pytest.raises(SystemExit) as stop:
        _org(runner, [ACCT_A, ACCT_SCP])
    assert stop.value.code == 2
    assert runner.scanned == []  # nothing was scanned, nothing deleted
    assert len(_progress_dirs(runner.dir)) == 1
    assert "--resume" in capsys.readouterr().err


def test_resume_scans_only_the_accounts_that_are_missing(runner):
    _org(runner, [ACCT_A, ACCT_SCP])
    runner.scanned.clear()
    zip_path = _org(runner, [ACCT_A, ACCT_SCP], resume_mode=RESUME)
    assert [a for a, _ in runner.scanned] == [ACCT_SCP]
    assert _account_files(zip_path) == [f"{ACCT_A}/aws_sizing_discovery.json"]


def test_fresh_deletes_the_unfinished_run_and_scans_everything(runner):
    _org(runner, [ACCT_A, ACCT_SCP])
    runner.scanned.clear()
    _org(runner, [ACCT_A, ACCT_SCP], resume_mode=FRESH)
    assert sorted(a for a, _ in runner.scanned) == [ACCT_A, ACCT_SCP]


def test_a_run_with_different_options_does_not_pick_up_another_runs_accounts(runner, capsys):
    """An org scan followed by a different one in the same folder must not mix their accounts."""
    _org(runner, [ACCT_A, ACCT_SCP])
    runner.scanned.clear()
    with pytest.raises(SystemExit):
        runner.main.run_org(
            zip_dir=str(runner.dir),
            role_name="R",
            account_ids=[ACCT_B],  # a different list
            resume_mode=RESUME,
        )
    assert runner.scanned == []
    assert "different options" in capsys.readouterr().err


@pytest.mark.parametrize(
    "change",
    [
        {"regions": ["us-east-1"]},
        {"exclude_regions": ["eu-west-1"]},
        {"services": frozenset({"ec2"})},
        {"collect_cost": False},
        {"role_name": "OtherRole"},
    ],
    ids=["regions", "exclude-regions", "services", "cost", "role"],
)
def test_each_option_that_changes_what_an_account_holds_blocks_a_resume(runner, change):
    _org(runner, [ACCT_A, ACCT_SCP])
    kwargs = {"role_name": "R", **change}
    with pytest.raises(SystemExit):
        runner.main.run_org(
            zip_dir=str(runner.dir), account_ids=[ACCT_A, ACCT_SCP], resume_mode=RESUME, **kwargs
        )


def test_options_that_only_change_the_packaging_do_not_block_a_resume(runner):
    _org(runner, [ACCT_A, ACCT_SCP])
    runner.scanned.clear()
    zip_path = _org(runner, [ACCT_A, ACCT_SCP], resume_mode=RESUME, write_csv=False, max_workers=2)
    assert [a for a, _ in runner.scanned] == [ACCT_SCP]
    assert zip_path


def test_only_the_accounts_this_run_asked_for_are_zipped(runner):
    """A progress folder can hold an account the current list dropped: it must not leak in."""
    import main

    progress = runner.dir / "progress"
    for account in (ACCT_A, ACCT_B):
        (progress / account).mkdir(parents=True)
        (progress / account / "aws_sizing_discovery.json").write_text(
            json.dumps(_result_for(account))
        )
    zip_path = str(runner.dir / "out.zip")
    main._package_results(str(progress), zip_path, 1, 0, stamp="2026-10-05_140650", only={ACCT_A})
    assert _account_files(zip_path) == [f"{ACCT_A}/aws_sizing_discovery.json"]


def test_a_narrower_account_list_is_refused_rather_than_silently_narrowed(runner):
    _org(runner, [ACCT_A, ACCT_B, ACCT_SCP])
    with pytest.raises(SystemExit):
        _org(runner, [ACCT_A], resume_mode=RESUME)


def test_a_truncated_account_file_is_scanned_again_not_trusted(runner):
    _org(runner, [ACCT_A, ACCT_SCP])
    (folder,) = _progress_dirs(runner.dir)
    path = os.path.join(folder, ACCT_A, "aws_sizing_discovery.json")
    with open(path, "w") as f:
        f.write('{"account_id": "1111')  # what a killed, non-atomic write left behind
    runner.scanned.clear()
    zip_path = _org(runner, [ACCT_A, ACCT_SCP], resume_mode=RESUME)
    assert ACCT_A in [a for a, _ in runner.scanned]
    assert f"{ACCT_A}/aws_sizing_discovery.json" in _account_files(zip_path)


def test_a_file_that_goes_bad_after_the_scan_is_left_out_not_fatal(runner, caplog):
    """A file unreadable at packaging time must not lose the whole zip after a long scan."""
    import main

    progress = runner.dir / "progress"
    for account, text in ((ACCT_A, json.dumps(_result_for(ACCT_A))), (ACCT_B, '{"broken')):
        (progress / account).mkdir(parents=True)
        (progress / account / "aws_sizing_discovery.json").write_text(text)
    zip_path = str(runner.dir / "out.zip")
    main._package_results(str(progress), zip_path, 1, 1, stamp="2026-10-05_140650")
    assert _account_files(zip_path) == [f"{ACCT_A}/aws_sizing_discovery.json"]
    assert "Leaving out 222222222222" in caplog.text


# ── partial accounts: rescanned by default, kept with --keep-partial ──────────


def _mark_partial(folder, account):
    path = os.path.join(folder, account, "aws_sizing_discovery.json")
    data = json.load(open(path))
    data["scan_errors"] = [{"service": "rds", "error": "AccessDenied"}]
    json.dump(data, open(path, "w"))


def test_resume_scans_again_by_default_only_the_accounts_with_errors(runner):
    _org(runner, [ACCT_A, ACCT_B, ACCT_SCP])
    (folder,) = _progress_dirs(runner.dir)
    _mark_partial(folder, ACCT_B)
    runner.scanned.clear()
    _org(runner, [ACCT_A, ACCT_B, ACCT_SCP], resume_mode=RESUME)  # no option: the default
    assert sorted(a for a, _ in runner.scanned) == [ACCT_B, ACCT_SCP]  # not ACCT_A: it was clean


def test_keep_partial_keeps_an_account_with_errors_as_it_was(runner):
    _org(runner, [ACCT_A, ACCT_B, ACCT_SCP])
    (folder,) = _progress_dirs(runner.dir)
    _mark_partial(folder, ACCT_B)
    runner.scanned.clear()
    zip_path = _org(
        runner, [ACCT_A, ACCT_B, ACCT_SCP], resume_mode=RESUME, retry_partial=False
    )
    assert [a for a, _ in runner.scanned] == [ACCT_SCP]
    assert f"{ACCT_B}/aws_sizing_discovery.json" in _account_files(zip_path)  # kept, gaps and all


def test_a_caller_that_does_not_say_gets_the_safe_default():
    """main() always passes retry_partial, so every runner's default is only used by a caller that
    omits it: it must be the one that cannot hide a gap."""
    import inspect

    import main

    for name in ("_scan_accounts", "run_org", "run_org_sso", "run_profiles"):
        default = inspect.signature(getattr(main, name)).parameters["retry_partial"].default
        assert default is True, name


def test_a_resume_says_what_it_decided_about_partial_accounts(runner, caplog):
    _org(runner, [ACCT_A, ACCT_B, ACCT_SCP])
    (folder,) = _progress_dirs(runner.dir)
    _mark_partial(folder, ACCT_B)
    with caplog.at_level("INFO"):
        _org(runner, [ACCT_A, ACCT_B, ACCT_SCP], resume_mode=RESUME)
    assert any("scanned again" in r.getMessage() and "--keep-partial" in r.getMessage() for r in caplog.records)
    caplog.clear()
    (folder,) = _progress_dirs(runner.dir)
    _mark_partial(folder, ACCT_A)
    with caplog.at_level("INFO"):
        _org(runner, [ACCT_A, ACCT_B, ACCT_SCP], resume_mode=RESUME, retry_partial=False)
    kept = [r.getMessage() for r in caplog.records if "kept as they were" in r.getMessage()]
    assert kept and "because of --keep-partial" in kept[0] and "gaps are still in the results" in kept[0]


def test_a_retry_that_fails_leaves_the_account_out_instead_of_zipping_its_old_file(
    runner, monkeypatch
):
    # Two things keep the old partial file out: the retry deletes it, and the zip is built only
    # from accounts that ended with a file in this run. The second is what this test exercises.
    _org(runner, [ACCT_A, ACCT_B, ACCT_SCP])
    (folder,) = _progress_dirs(runner.dir)
    _mark_partial(folder, ACCT_B)

    def failing_run(output_dir, session, **kwargs):
        if os.path.basename(output_dir) == ACCT_B:
            raise ValueError("boom")
        return os.path.join(output_dir, "aws_sizing_discovery.json")

    monkeypatch.setattr(runner.main, "run", failing_run)
    zip_path = _org(runner, [ACCT_A, ACCT_B, ACCT_SCP], resume_mode=RESUME)
    assert f"{ACCT_B}/aws_sizing_discovery.json" not in _account_files(zip_path)


# ── the options ───────────────────────────────────────────────────────────────


def test_the_options_reach_the_multi_account_runners(cli):
    cli.main.main(["--org", "--resume"])
    kwargs = cli.calls["run_org"][1]
    assert kwargs["resume_mode"] == RESUME and kwargs["retry_partial"] is True  # the default
    cli.main.main(["--org", "--resume", "--keep-partial"])
    assert cli.calls["run_org"][1]["retry_partial"] is False
    cli.main.main(["--org", "--fresh"])
    assert cli.calls["run_org"][1]["resume_mode"] == FRESH
    cli.main.main(["--org"])
    assert cli.calls["run_org"][1]["resume_mode"] == checkpoint_core.AUTO


@pytest.mark.parametrize(
    "argv",
    [
        ["--org", "--keep-partial"],
        ["--org", "--resume", "--fresh"],
        ["--preflight-only", "--resume"],
    ],
    ids=["keep-needs-resume", "resume-and-fresh", "resume-with-preflight-only"],
)
def test_contradicting_options_are_refused(argv, capsys):
    import main

    with pytest.raises(SystemExit) as stop:
        main._main(argv)
    assert stop.value.code == 2


# ── what the end of every run says about accounts that finished with gaps ─────


@pytest.fixture
def gappy(runner, monkeypatch):
    """The runner's fake scan, with scan errors recorded for the accounts in ``.accounts``."""
    real = runner.main.run
    accounts: dict = {}

    def run_with_gaps(output_dir, session, **kwargs):
        path = real(output_dir=output_dir, session=session, **kwargs)
        account = os.path.basename(output_dir)
        if account in accounts:
            data = json.load(open(path))
            data["scan_errors"] = accounts[account]
            json.dump(data, open(path, "w"))
        return path

    monkeypatch.setattr(runner.main, "run", run_with_gaps)
    runner.gaps = accounts
    return runner


def _gap(service="rds", region="us-east-1", error="AccessDenied"):
    return [{"service": service, "region": region, "error": error}]


def test_a_clean_run_prints_no_gaps_summary(runner, capsys):
    _org(runner, [ACCT_A, ACCT_B])
    assert "finished with gaps" not in capsys.readouterr().out


def test_an_account_with_scan_errors_is_named_with_its_first_error(gappy, capsys):
    gappy.gaps[ACCT_B] = _gap("rds", "eu-west-1", "AccessDenied") + _gap("efs", "eu-west-1", "x")
    _org(gappy, [ACCT_A, ACCT_B])
    out = capsys.readouterr().out
    assert "1 of 2 accounts finished with gaps" in out
    assert f"{ACCT_B}  rds (eu-west-1): AccessDenied (+1 more)" in out
    assert ACCT_A + "  " not in out.split("finished with gaps", 1)[1]  # the clean one is not listed


def test_a_region_that_could_not_be_scanned_shows_up_as_a_gap(gappy, capsys):
    gappy.gaps[ACCT_A] = _gap(gappy.main.REGION_SERVICE, "af-south-1", "endpoint unreachable")
    _org(gappy, [ACCT_A, ACCT_B])
    assert f"{ACCT_A}  region (af-south-1): endpoint unreachable" in capsys.readouterr().out


def test_an_account_with_gaps_keeps_the_folder_so_the_resume_it_offers_can_work(gappy, capsys):
    """Rescanning partial accounts by default needs a folder to resume from, so a run whose every
    account finished (with gaps) must still keep it."""
    gappy.gaps[ACCT_B] = _gap()
    _org(gappy, [ACCT_A, ACCT_B])
    out = capsys.readouterr().out
    assert len(_progress_dirs(gappy.dir)) == 1
    assert "same command with --resume" in out and "--keep-partial" in out


def test_the_resume_it_offers_scans_just_the_account_with_gaps_and_ends_clean(gappy, capsys):
    gappy.gaps[ACCT_B] = _gap()
    _org(gappy, [ACCT_A, ACCT_B])
    capsys.readouterr()
    gappy.scanned.clear()
    gappy.gaps.clear()  # the cause is fixed
    _org(gappy, [ACCT_A, ACCT_B], resume_mode=RESUME)
    assert [a for a, _ in gappy.scanned] == [ACCT_B]
    assert _progress_dirs(gappy.dir) == []  # every account is clean now: nothing left to resume
    # not the note at the start of a resume, which also says "finished with gaps"
    assert " of 2 accounts finished with gaps" not in capsys.readouterr().out


def test_a_resume_that_still_has_the_gap_keeps_saying_so(gappy, capsys):
    gappy.gaps[ACCT_B] = _gap()
    _org(gappy, [ACCT_A, ACCT_B])
    capsys.readouterr()
    _org(gappy, [ACCT_A, ACCT_B], resume_mode=RESUME)  # nothing fixed
    out = capsys.readouterr().out
    assert "1 of 2 accounts finished with gaps" in out and ACCT_B in out
    assert len(_progress_dirs(gappy.dir)) == 1


def test_keep_partial_still_reports_the_gaps_it_kept(gappy, capsys):
    gappy.gaps[ACCT_B] = _gap()
    _org(gappy, [ACCT_A, ACCT_B])
    capsys.readouterr()
    gappy.scanned.clear()
    _org(gappy, [ACCT_A, ACCT_B], resume_mode=RESUME, retry_partial=False)
    out = capsys.readouterr().out
    assert gappy.scanned == []  # kept as it was
    assert "1 of 2 accounts finished with gaps" in out and ACCT_B in out


def test_the_summary_counts_an_account_that_was_not_scanned_in_the_total(gappy, capsys):
    gappy.gaps[ACCT_A] = _gap()
    _org(gappy, [ACCT_A, ACCT_B, ACCT_SCP])  # ACCT_SCP is blocked by an SCP: not scanned
    assert "1 of 3 accounts finished with gaps" in capsys.readouterr().out


def test_the_summary_is_written_to_the_run_log_not_only_the_screen(monkeypatch):
    """It goes through runlog.say, which prints and also writes the same text to the log, so a log
    read later says which accounts had gaps."""
    import main

    written = []
    monkeypatch.setattr(main.runlog, "say", written.append)
    main._print_gaps([("111122223333", "rds (us-east-1): AccessDenied")], 4, True)
    assert len(written) == 1
    assert "1 of 4 accounts finished with gaps" in written[0]
    assert "111122223333  rds (us-east-1): AccessDenied" in written[0]


def test_nothing_is_written_when_no_account_has_gaps(monkeypatch):
    import main

    written = []
    monkeypatch.setattr(main.runlog, "say", written.append)
    main._print_gaps([], 4, False)
    assert written == []


def test_account_gaps_reads_the_first_error_and_counts_the_rest(tmp_path):
    import main

    folder = tmp_path / "111122223333"
    folder.mkdir()
    (folder / "aws_sizing_discovery.json").write_text(
        json.dumps({"scan_errors": _gap("rds", "us-east-1", "A") + _gap("efs", "", "B")})
    )
    (tmp_path / "999999999999").mkdir()  # no file: not counted
    (tmp_path / "999999999999" / "aws_sizing_discovery.json").write_text('{"scan_errors": [')
    got = main._account_gaps(str(tmp_path), {"111122223333", "999999999999", "000000000000"})
    assert got == {"111122223333": "rds (us-east-1): A (+1 more)"}
