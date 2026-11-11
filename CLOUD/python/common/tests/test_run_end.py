"""How a run ends in its log: the last line, the crash footer, moving the log, and the signals.

A log must say how the run ended or be visibly cut off. These tests send real signals to a child
process, because a handler that is never triggered proves nothing.
"""

import logging
import subprocess
import sys
import textwrap
import threading
import time
from pathlib import Path

import pytest

from common import runlog as r

PY = Path(__file__).resolve().parents[2]
POSIX = sys.platform != "win32"


@pytest.fixture(autouse=True)
def _clean():
    r.ISSUES.reset()
    r.set_stop_hint("")
    yield
    r.set_stop_hint("")
    r.restore_stop_handlers()
    r.ISSUES.reset()


@pytest.fixture
def handler(tmp_path):
    h = r.TranscriptHandler(str(tmp_path / "run.log"), logging.INFO)
    yield h
    h.close()


def _text(h) -> str:
    return Path(h.transcript.path).read_text(encoding="utf-8")


# ── the last line ─────────────────────────────────────────────────────────────


def test_the_last_line_says_how_the_run_ended_and_when(handler):
    r.screen("scanning")
    assert r.end_run("scan finished") is True
    lines = _text(handler).splitlines()
    assert lines[0] == "scanning"
    assert (
        lines[-1].startswith("Run ended: scan finished at ")
        and len(lines[-1].split(" at ")[1]) == 8
    )


def test_only_the_first_ending_is_written(handler):
    assert r.end_run("scan finished") is True
    assert r.end_run("failed with ValueError: late") is False
    assert r.crashed(ValueError("later still")) is False
    assert _text(handler).count("Run ended:") == 1 and "late" not in _text(handler)


def test_two_threads_ending_the_run_at_once_write_one_line(handler):
    threads = [threading.Thread(target=r.end_run, args=("scan finished",)) for _ in range(8)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert _text(handler).count("Run ended:") == 1


def test_with_no_log_open_nothing_happens():
    assert r.end_run("scan finished") is False and r.crashed(ValueError("x")) is False


def test_the_scan_finished_line_follows_the_digest_helper(handler):
    assert r.finished() is True
    assert "Run ended: scan finished at" in _text(handler)


def test_the_last_line_is_on_disk_before_the_log_is_closed(handler):
    r.end_run("scan finished")
    assert "Run ended:" in _text(handler)


# ── a run that raised ─────────────────────────────────────────────────────────


def _raise() -> None:
    raise ValueError("the account list was empty")


def test_a_crash_writes_the_error_the_traceback_and_that_no_zip_was_written(handler):
    try:
        _raise()
    except ValueError as exc:
        r.crashed(exc)
    text = _text(handler)
    assert "Run ended: failed with ValueError: the account list was empty at " in text
    assert "The results zip was not written. This log holds what was done up to now." in text
    assert "The traceback:" in text and "in _raise" in text and "the account list was empty" in text


def test_the_stop_hint_is_added_to_a_crash_and_can_be_changed(handler):
    r.set_stop_hint(
        "Finished accounts are kept in ./progress; run the same command again to resume."
    )
    r.set_stop_hint(
        "Finished accounts are kept in ./progress-2; run the same command again to resume."
    )
    r.crashed(RuntimeError("boom"))
    text = _text(handler)
    assert "./progress-2" in text and "./progress;" not in text


def test_a_clean_exit_writes_nothing_and_a_failing_one_writes_its_code(handler):
    assert r.crashed(SystemExit()) is False and r.crashed(SystemExit(0)) is False
    assert "Run ended" not in _text(handler)
    assert r.crashed(SystemExit(2)) is True
    assert "Run ended: exited with code 2 at " in _text(handler)


def test_an_exit_with_a_message_says_the_message(handler):
    r.crashed(SystemExit("No credentials were found"))
    assert "Run ended: exited with code No credentials were found at " in _text(handler)


def test_a_keyboard_interrupt_that_reaches_the_wrapper_is_recorded(handler):
    r.crashed(KeyboardInterrupt())
    assert "Run ended: stopped by Ctrl-C (KeyboardInterrupt) at " in _text(handler)


# ── moving the log ────────────────────────────────────────────────────────────


def test_moving_the_log_keeps_what_was_written_and_what_follows(tmp_path):
    h = r.TranscriptHandler(str(tmp_path / "temp.log"), logging.INFO)
    try:
        r.screen("before")
        target = tmp_path / "out"
        target.mkdir()
        new = h.move(str(target / "run.log"))
        r.screen("after")
        assert new == str(target / "run.log") and not (tmp_path / "temp.log").exists()
        assert (target / "run.log").read_text(encoding="utf-8").splitlines() == ["before", "after"]
        assert h.transcript.path == new
    finally:
        h.close()


def test_moving_it_to_where_it_already_is_changes_nothing(handler):
    r.screen("one")
    assert handler.move(handler.transcript.path) == handler.transcript.path
    r.screen("two")
    assert _text(handler).splitlines() == ["one", "two"]


def test_a_move_that_fails_keeps_logging_where_it_was_and_says_so(handler, tmp_path):
    r.screen("before")
    old = handler.transcript.path
    assert handler.move(str(tmp_path / "missing" / "run.log")) == old
    r.screen("after")
    lines = _text(handler).splitlines()
    assert lines[0] == "before" and lines[-1] == "after"
    assert any(line.startswith("Could not move the run log to ") for line in lines)


def test_ending_a_moved_log_writes_the_last_line_in_the_new_place(tmp_path):
    h = r.TranscriptHandler(str(tmp_path / "temp.log"), logging.INFO)
    try:
        (tmp_path / "out").mkdir()
        moved = h.move(str(tmp_path / "out" / "run.log"))
        r.end_run("scan finished")
        assert "Run ended:" in Path(moved).read_text(encoding="utf-8")
    finally:
        h.close()


# ── the lock ──────────────────────────────────────────────────────────────────


def test_ending_the_run_from_a_thread_that_holds_the_lock_does_not_deadlock(handler):
    done = []

    def holder() -> None:
        with handler.transcript.lock:
            done.append(r.end_run("stopped by SIGTERM"))

    thread = threading.Thread(target=holder)
    thread.start()
    thread.join(5)
    assert not thread.is_alive() and done == [True]


def test_handlers_are_installed_on_the_main_thread_only():
    assert "SIGINT" in r.install_stop_handlers()
    result = []
    worker = threading.Thread(target=lambda: result.append(r.install_stop_handlers()))
    worker.start()
    worker.join()
    assert result == [[]]


# ── real signals, sent to a child process ─────────────────────────────────────

CHILD = textwrap.dedent("""
    import logging, sys, threading, time
    sys.path.insert(0, {py!r})
    from common import runlog as r
    handler = r.TranscriptHandler(sys.argv[1], logging.INFO)
    r.set_stop_hint(sys.argv[2])
    if sys.argv[3] == "handlers":
        r.install_stop_handlers()
    if sys.argv[4] == "busy":
        threading.Thread(target=time.sleep, args=(120,)).start()
    r.screen("line one")
    r.screen("line two")
    print("ready", flush=True)
    time.sleep(120)
    """).format(py=str(PY))


def _run_child(tmp_path, hint="", handlers="handlers", busy="idle"):
    log = tmp_path / "child.log"
    child = subprocess.Popen(
        [sys.executable, "-c", CHILD, str(log), hint, handlers, busy],
        stdout=subprocess.PIPE,
        text=True,
    )
    assert child.stdout.readline().strip() == "ready"
    return child, log


@pytest.mark.skipif(not POSIX, reason="needs POSIX signals")
@pytest.mark.parametrize(
    ("name", "number", "words"),
    [
        ("SIGINT", 2, "Ctrl-C (SIGINT)"),
        ("SIGTERM", 15, "SIGTERM"),
        ("SIGHUP", 1, "the terminal closing (SIGHUP)"),
    ],
)
def test_a_stop_signal_writes_the_last_line_and_exits_with_the_usual_code(
    tmp_path, name, number, words
):
    child, log = _run_child(tmp_path, hint="Resume with the same command.")
    child.send_signal(number)
    assert child.wait(timeout=10) == 128 + number
    text = log.read_text(encoding="utf-8")
    assert text.splitlines()[:2] == ["line one", "line two"]
    assert f"Run ended: stopped by {words} at " in text
    assert "The results zip was not written." in text and "Resume with the same command." in text


@pytest.mark.skipif(not POSIX, reason="needs POSIX signals")
def test_the_run_stops_at_once_even_with_a_worker_thread_still_running(tmp_path):
    child, log = _run_child(tmp_path, busy="busy")
    started = time.monotonic()
    child.send_signal(15)
    assert child.wait(timeout=10) == 143
    assert time.monotonic() - started < 5
    assert "stopped by SIGTERM" in log.read_text(encoding="utf-8")


@pytest.mark.skipif(not POSIX, reason="needs POSIX signals")
def test_a_kill_leaves_what_was_written_and_no_last_line(tmp_path):
    child, log = _run_child(tmp_path)
    child.kill()
    child.wait(timeout=10)
    text = log.read_text(encoding="utf-8")
    assert text.splitlines() == ["line one", "line two"] and "Run ended" not in text


@pytest.mark.skipif(not POSIX, reason="needs POSIX signals")
def test_without_the_handlers_a_termination_leaves_the_log_cut_off(tmp_path):
    child, log = _run_child(tmp_path, handlers="none")
    child.terminate()
    child.wait(timeout=10)
    assert "Run ended" not in log.read_text(encoding="utf-8")
