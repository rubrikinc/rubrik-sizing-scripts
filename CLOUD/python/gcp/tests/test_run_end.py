"""How a GCP run ends in its log: finished, crashed, stopped by a signal, or a dry run.

The log starts in a temp file, because the output folder can come from the config file, and moves
into the output folder as soon as that is known. From then on a run that does not finish leaves it
there, written up to that moment.
"""

import glob
import signal
import subprocess
import sys
import textwrap
import zipfile
from pathlib import Path

import main
import pytest
import runlog_core as core

GCP = Path(__file__).resolve().parents[1]
PY = GCP.parent
POSIX = sys.platform != "win32"


@pytest.fixture(autouse=True)
def _restore():
    yield
    core.restore_stop_handlers()
    core.set_stop_hint("")


def _argv(monkeypatch, tmp_path, *extra):
    monkeypatch.setattr(sys, "argv", ["main.py", "--mock", "--output", str(tmp_path), *extra])


def _logs(folder) -> list:
    return sorted(glob.glob(str(Path(folder) / "output_gcp_*.log")))


def test_the_log_moves_into_the_output_folder_before_the_scan_starts(tmp_path, monkeypatch):
    seen = {}
    original = main._run_mock

    def look():
        (path,) = _logs(tmp_path)
        seen["text"] = Path(path).read_text(encoding="utf-8")
        return original()

    monkeypatch.setattr(main, "_run_mock", look)
    _argv(monkeypatch, tmp_path)
    main.main()
    assert seen["text"].startswith("# Run log: GCP sizing tool")
    assert "# Command line: --mock" in seen["text"] and "Run ended" not in seen["text"]


def test_a_run_that_finishes_ends_its_log_with_the_scan_finished_line_and_removes_the_loose_file(
    tmp_path, monkeypatch
):
    _argv(monkeypatch, tmp_path)
    main.main()
    zf = zipfile.ZipFile(next(tmp_path.glob("gcp_sizing_results_*.zip")))
    log = zf.read(next(n for n in zf.namelist() if n.endswith(".log"))).decode()
    assert log.splitlines()[-1].startswith("Run ended: scan finished at ")
    assert _logs(tmp_path) == []


def test_a_crash_leaves_the_log_in_the_output_folder_with_the_error_and_the_traceback(
    tmp_path, monkeypatch
):
    def boom():
        raise RuntimeError("the project list could not be read")

    monkeypatch.setattr(main, "_run_mock", boom)
    _argv(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError):
        main.main()
    (path,) = _logs(tmp_path)
    text = Path(path).read_text(encoding="utf-8")
    assert text.startswith("# Run log: GCP sizing tool") and "# Command line: --mock" in text
    assert "Run ended: failed with RuntimeError: the project list could not be read at " in text
    assert "The results zip was not written." in text and "in boom" in text
    assert not list(tmp_path.glob("gcp_sizing_results_*.zip"))


def test_a_run_that_exits_with_an_error_code_says_so(tmp_path, monkeypatch):
    def give_up():
        raise SystemExit(1)

    monkeypatch.setattr(main, "_run_mock", give_up)
    _argv(monkeypatch, tmp_path)
    with pytest.raises(SystemExit):
        main.main()
    assert "Run ended: exited with code 1 at " in Path(_logs(tmp_path)[0]).read_text(
        encoding="utf-8"
    )


def test_a_dry_run_leaves_no_log_and_creates_no_output_folder(tmp_path, monkeypatch):
    import auth

    out = tmp_path / "not-created"
    monkeypatch.setattr(auth, "get_credentials", lambda: "credentials")
    monkeypatch.setattr(auth, "resolve_projects", lambda c, ids, all_projects, **k: ["p1"])
    monkeypatch.setattr(sys, "argv", ["main.py", "--dry-run", "--output", str(out)])
    monkeypatch.chdir(tmp_path)
    main.main()
    assert not out.exists() and _logs(tmp_path) == []


def test_the_stop_handlers_are_installed_once_the_log_is_open(tmp_path, monkeypatch):
    seen = {}

    def look():
        seen["sigterm"] = signal.getsignal(signal.SIGTERM)
        raise SystemExit(1)

    monkeypatch.setattr(main, "_run_mock", look)
    _argv(monkeypatch, tmp_path)
    with pytest.raises(SystemExit):
        main.main()
    assert callable(seen["sigterm"]) and seen["sigterm"] not in (signal.SIG_DFL, signal.SIG_IGN)


CHILD = textwrap.dedent("""
    import sys, time
    sys.path[:0] = [{gcp!r}, {py!r}]
    import main
    main._run_mock = lambda: (print("scanning", flush=True), time.sleep(120))
    sys.argv = ["main.py", "--mock", "--output", sys.argv[1]]
    main.main()
    """).format(gcp=str(GCP), py=str(PY))


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
        cwd=str(GCP),
    )
    for line in child.stdout:
        if line.strip() == "scanning":
            break
    child.send_signal(number)
    assert child.wait(timeout=20) == 128 + number
    (path,) = _logs(tmp_path)
    text = Path(path).read_text(encoding="utf-8")
    assert text.startswith("# Run log: GCP sizing tool") and "# Command line: --mock" in text
    assert f"Run ended: stopped by {words} at " in text
    assert not list(tmp_path.glob("gcp_sizing_results_*.zip"))
