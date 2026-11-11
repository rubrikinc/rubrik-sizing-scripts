"""How an Azure run ends in its log: finished, failed, or stopped by a signal.

The log is streamed into the output folder, so whatever ends the run leaves it there.
"""

import glob
import signal
import subprocess
import sys
import textwrap
import zipfile
from pathlib import Path

import pytest

import main
import runlog_core as core

AZURE = Path(__file__).resolve().parents[1]
PY = AZURE.parent
POSIX = sys.platform != "win32"


@pytest.fixture(autouse=True)
def _restore_signals():
    yield
    core.restore_stop_handlers()
    core.set_stop_hint("")


def _run(tmp_path, monkeypatch, during):
    monkeypatch.setattr("collectors.pricing.fetch_vm_prices", lambda pairs: {})
    monkeypatch.setattr("collectors.utils.warn_once", lambda *a, **k: None)
    monkeypatch.setattr("collectors.storage.warn_once", lambda *a, **k: None)
    monkeypatch.setattr(main, "_run_mock", during)
    monkeypatch.setattr(sys, "argv", ["main.py", "--mock", "--output", str(tmp_path)])
    return main.main()


def _partial_log(tmp_path) -> str:
    (path,) = glob.glob(str(tmp_path / "output_azure_*.log"))
    return Path(path).read_text(encoding="utf-8")


def test_a_run_that_fails_leaves_its_log_in_the_output_folder_with_the_error(tmp_path, monkeypatch):
    def boom(skips):
        raise RuntimeError("the subscription list could not be read")

    with pytest.raises(RuntimeError):
        _run(tmp_path, monkeypatch, boom)
    text = _partial_log(tmp_path)
    assert text.startswith("# Run log: Azure sizing tool")
    assert "Rubrik Discovery — Azure Edition" in text
    assert (
        "Run ended: failed with RuntimeError: the subscription list could not be read at " in text
    )
    assert "The results zip was not written." in text and "in boom" in text
    assert not list(tmp_path.glob("azure_sizing_results_*.zip"))


def test_a_run_that_exits_with_an_error_code_says_so(tmp_path, monkeypatch):
    def give_up(skips):
        raise SystemExit(1)

    with pytest.raises(SystemExit):
        _run(tmp_path, monkeypatch, give_up)
    assert "Run ended: exited with code 1 at " in _partial_log(tmp_path)


def test_a_run_that_finishes_ends_its_log_with_the_scan_finished_line_inside_the_zip(
    tmp_path, monkeypatch
):
    _run(tmp_path, monkeypatch, main._run_mock)
    zf = zipfile.ZipFile(next(tmp_path.glob("azure_sizing_results_*.zip")))
    log = zf.read(next(n for n in zf.namelist() if n.endswith(".log"))).decode()
    assert log.splitlines()[-1].startswith("Run ended: scan finished at ")
    assert not glob.glob(str(tmp_path / "output_azure_*.log"))


def test_the_stop_handlers_are_installed_once_the_log_is_open(tmp_path, monkeypatch):
    seen = {}

    def look(skips):
        seen["sigterm"] = signal.getsignal(signal.SIGTERM)
        seen["log"] = glob.glob(str(tmp_path / "output_azure_*.log"))
        raise SystemExit(1)

    with pytest.raises(SystemExit):
        _run(tmp_path, monkeypatch, look)
    assert callable(seen["sigterm"]) and seen["sigterm"] not in (signal.SIG_DFL, signal.SIG_IGN)
    assert len(seen["log"]) == 1


CHILD = textwrap.dedent("""
    import sys, time
    sys.path[:0] = [{azure!r}, {py!r}]
    import main
    main._run_mock = lambda skips: (print("scanning", flush=True), time.sleep(120))
    sys.argv = ["main.py", "--mock", "--output", sys.argv[1]]
    main.main()
    """).format(azure=str(AZURE), py=str(PY))


@pytest.mark.skipif(not POSIX, reason="needs POSIX signals")
@pytest.mark.parametrize(
    ("number", "words"),
    [(15, "SIGTERM"), (1, "the terminal closing (SIGHUP)"), (2, "Ctrl-C (SIGINT)")],
)
def test_a_real_run_stopped_by_a_signal_leaves_a_partial_log_that_says_why(tmp_path, number, words):
    child = subprocess.Popen(
        [sys.executable, "-c", CHILD, str(tmp_path)],
        stdout=subprocess.PIPE,
        text=True,
        cwd=str(AZURE),
    )
    for line in child.stdout:
        if line.strip() == "scanning":
            break
    child.send_signal(number)
    assert child.wait(timeout=20) == 128 + number
    text = _partial_log(tmp_path)
    assert text.startswith("# Run log: Azure sizing tool") and "Rubrik Discovery" in text
    assert f"Run ended: stopped by {words} at " in text
    assert not list(tmp_path.glob("azure_sizing_results_*.zip"))
