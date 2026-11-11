"""How an AWS run ends in its log: finished, crashed, stopped by a signal, or sent away at the start.

The log is streamed into the folder the results go to, so a run that does not finish leaves it there.
"""

from __future__ import annotations

import glob
import json
import logging
import signal
import subprocess
import sys
import textwrap
import zipfile
from pathlib import Path

import main
import pytest
import runlog_core as core
from tests.test_modes import ACCT_A, _result_for, runner  # noqa: F401 - the runner fixture

AWS = Path(__file__).resolve().parents[1]
PY = AWS.parent
POSIX = sys.platform != "win32"


@pytest.fixture(autouse=True)
def _restore():
    yield
    core.restore_stop_handlers()
    core.set_stop_hint("")
    for handler in [
        h for h in logging.getLogger().handlers if isinstance(h, core.TranscriptHandler)
    ]:
        logging.getLogger().removeHandler(handler)
        handler.close()


def _fake_run(monkeypatch, out, during=lambda: None):
    json_path = out / "aws_sizing_discovery.json"
    json_path.write_text(json.dumps(_result_for(ACCT_A)))

    def fake_run(**kwargs):
        during()
        return str(json_path)

    monkeypatch.setattr(main, "run", fake_run)
    monkeypatch.setattr(main, "_resolve_scans", lambda args: {"cost": False, "capacity": True})
    monkeypatch.setattr(main.csv_export.log, "warning", lambda *a, **k: None)


def _logs(folder) -> list:
    return sorted(glob.glob(str(folder / "output_aws_*.log")))


def test_the_log_is_streamed_into_the_output_folder_from_the_start(tmp_path, monkeypatch):
    out = tmp_path / "out"
    out.mkdir()
    seen = {}

    def look():
        (path,) = _logs(out)
        seen["text"] = Path(path).read_text(encoding="utf-8")

    _fake_run(monkeypatch, out, during=look)
    main.main(["--output", str(out)])
    assert seen["text"].startswith("# Run log: AWS sizing tool")
    assert "Discovery run started." in seen["text"] and "Run ended" not in seen["text"]


def test_a_run_that_finishes_ends_its_log_with_the_scan_finished_line_and_removes_the_loose_file(
    tmp_path, monkeypatch
):
    out = tmp_path / "out"
    out.mkdir()
    _fake_run(monkeypatch, out)
    main.main(["--output", str(out)])
    zf = zipfile.ZipFile(next(out.glob("aws_sizing_results_*.zip")))
    log = zf.read(next(n for n in zf.namelist() if n.endswith(".log"))).decode()
    assert log.splitlines()[-1].startswith("Run ended: scan finished at ")
    assert _logs(out) == []


def test_a_crash_leaves_the_log_in_the_output_folder_with_the_error_and_the_traceback(
    tmp_path, monkeypatch
):
    out = tmp_path / "out"
    out.mkdir()

    def boom():
        raise RuntimeError("the collector fell over")

    _fake_run(monkeypatch, out, during=boom)
    with pytest.raises(RuntimeError):
        main.main(["--output", str(out)])
    (path,) = _logs(out)
    text = Path(path).read_text(encoding="utf-8")
    assert text.startswith("# Run log: AWS sizing tool") and "Discovery run started." in text
    assert "Run ended: failed with RuntimeError: the collector fell over at " in text
    assert "The results zip was not written." in text and "in boom" in text
    assert not list(out.glob("aws_sizing_results_*.zip"))
    assert not [h for h in logging.getLogger().handlers if isinstance(h, core.TranscriptHandler)]
    assert main._open_run_logs == []


def test_a_sign_in_problem_still_leaves_nothing_behind(tmp_path, monkeypatch, capsys):
    out = tmp_path / "out"
    out.mkdir()

    def no_credentials():
        from botocore.exceptions import NoCredentialsError

        raise NoCredentialsError()

    _fake_run(monkeypatch, out, during=no_credentials)
    with pytest.raises(SystemExit) as stop:
        main.main(["--output", str(out)])
    assert stop.value.code == 1
    assert _logs(out) == [] and "credentials" in capsys.readouterr().err.lower()


def test_a_bad_option_found_after_the_log_opened_leaves_nothing_behind(tmp_path, monkeypatch):
    out = tmp_path / "out"
    out.mkdir()
    _fake_run(monkeypatch, out)
    with pytest.raises(SystemExit) as stop:
        main.main(["--output", str(out), "--services", "not-a-service"])
    assert stop.value.code == 2 and _logs(out) == []


def test_a_multi_account_run_streams_its_log_to_the_folder_the_zip_goes_to(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(main, "select_profiles", lambda profiles, every: ["p1"])

    def boom(profiles, **kwargs):
        raise RuntimeError("an account failed hard")

    monkeypatch.setattr(main, "run_profiles", boom)
    monkeypatch.setattr(main, "_resolve_scans", lambda args: {"cost": False, "capacity": True})
    with pytest.raises(RuntimeError):
        main.main(["--profiles", "p1", "--output", str(tmp_path / "elsewhere")])
    assert len(_logs(tmp_path / "elsewhere")) == 1 and _logs(tmp_path) == []


def test_a_multi_account_run_tells_a_stopped_run_where_finished_accounts_are_kept(runner):
    runner.main.run_org(zip_dir=str(runner.dir), role_name="R", account_ids=[ACCT_A])
    hint = core._stop_hint
    assert "aws-sizing-progress-" in hint and "run the same command again to resume." in hint
    assert str(runner.dir) in hint


CHILD = textwrap.dedent("""
    import sys, time
    sys.path[:0] = [{aws!r}, {py!r}]
    import main
    main.run = lambda **kwargs: (print("scanning", flush=True), time.sleep(120))
    main._resolve_scans = lambda args: {{"cost": False, "capacity": True}}
    main.main(["--output", sys.argv[1]])
    """).format(aws=str(AWS), py=str(PY))


@pytest.mark.skipif(not POSIX, reason="needs POSIX signals")
@pytest.mark.parametrize(
    ("number", "words"),
    [(15, "SIGTERM"), (1, "the terminal closing (SIGHUP)"), (2, "Ctrl-C (SIGINT)")],
)
def test_a_real_run_stopped_by_a_signal_leaves_a_partial_log_that_says_why(tmp_path, number, words):
    out = tmp_path / "out"
    out.mkdir()
    child = subprocess.Popen(
        [sys.executable, "-c", CHILD, str(out)], stdout=subprocess.PIPE, text=True, cwd=str(AWS)
    )
    for line in child.stdout:
        if line.strip() == "scanning":
            break
    child.send_signal(number)
    assert child.wait(timeout=20) == 128 + number
    (path,) = _logs(out)
    text = Path(path).read_text(encoding="utf-8")
    assert text.startswith("# Run log: AWS sizing tool") and "Discovery run started." in text
    assert f"Run ended: stopped by {words} at " in text
    assert not list(out.glob("aws_sizing_results_*.zip"))
