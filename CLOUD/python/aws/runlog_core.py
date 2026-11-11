"""Run log shared by the AWS, Azure and GCP tools.

The log is a transcript of the screen: what a person watching the run saw, in the same order, as plain
text. Console output and the log records that reach the screen are written to the log file; colour
codes, spinner frames and library debug noise are not. Every warning and error is also recorded in
an issue registry, which prints a digest at the end of the run: each distinct problem once, with how
often it happened, one example, and what to do about it.

This module imports only the standard library, because an installed tool cannot import ``common``;
each tool carries a byte-identical copy named ``runlog_core.py``.
"""

from __future__ import annotations

import logging
import os
import platform
import re
import shutil
import signal
import subprocess
import sys
import textwrap
import threading
import traceback
from collections import OrderedDict
from datetime import datetime
from importlib import metadata
from typing import Callable, Iterable, NamedTuple, Optional

ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")

# Libraries whose records are kept out of the log below WARNING, however verbose the screen is.
NOISY_PREFIXES = (
    "botocore",
    "boto3",
    "s3transfer",
    "urllib3",
    "requests",
    "azure",
    "msal",
    "msrest",
    "google",
    "googleapiclient",
    "grpc",
    "httplib2",
    "oauthlib",
    "asyncio",
    "charset_normalizer",
)

LOG_FORMAT = "%(asctime)s %(levelname)-7s %(name)s — %(message)s"
LOG_DATE_FORMAT = "%H:%M:%S"

GUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
ISO_TIME = re.compile(r"\d{4}-\d\d-\d\dT[\d:.]+(?:\s*[+-]\d\d:?\d\d|Z)?")
LONG_NUMBER = re.compile(r"\b\d{5,}\b")


def plain(text: str) -> str:
    """Text as a person read it on the screen.

    No colour codes. A carriage return keeps only what was written last on that line (a spinner
    redraws itself), and lines carry no trailing spaces.
    """
    lines = []
    for line in ANSI.sub("", text).split("\n"):
        if "\r" in line:
            segments = [part for part in line.split("\r") if part.strip()]
            line = segments[-1] if segments else ""
        lines.append(line.rstrip())
    return "\n".join(lines)


def one_line(text: str, limit: int = 300) -> str:
    """Collapse whitespace so a message fits on one line, and cut it at ``limit`` characters."""
    collapsed = " ".join(str(text).split())
    return collapsed if len(collapsed) <= limit else collapsed[: limit - 3] + "..."


# ── the transcript ───────────────────────────────────────────────────────────


class Transcript:
    """The log file. Console output and log records are written through one lock, so the order on
    the screen is the order in the file."""

    def __init__(self, path: str) -> None:
        self.path = str(path)
        # Re-entrant: a signal handler runs in the main thread, which may be in the middle of a write.
        self.lock = threading.RLock()
        self._file = open(self.path, "w", encoding="utf-8", newline="\n")
        # How the run ended, once ``end_run`` has written the last line.
        self.ended: Optional[str] = None

    def write(self, text: str) -> None:
        cleaned = plain(text)
        with self.lock:
            if not self._file.closed:
                self._file.write(cleaned + "\n")
                self._file.flush()

    def write_durable(self, text: str) -> None:
        """Write and force the bytes to disk, for the last line of a run."""
        self.write(text)
        with self.lock:
            if not self._file.closed:
                try:
                    os.fsync(self._file.fileno())
                except OSError:
                    pass

    def move(self, path: str) -> str:
        """Continue the log in ``path``, which must be in an existing folder. Nothing already written
        is lost. When the move fails the log stays where it was, says so, and that path is returned.
        """
        target = str(path)
        with self.lock:
            if self._file.closed or os.path.abspath(target) == os.path.abspath(self.path):
                return self.path
            self._file.flush()
            self._file.close()
            moved, error = target, ""
            try:
                try:
                    os.replace(self.path, target)
                except OSError:
                    shutil.move(self.path, target)
            except OSError as exc:
                moved, error = self.path, str(exc)
            self.path = moved
            self._file = open(self.path, "a", encoding="utf-8", newline="\n")
            if error:
                self._file.write(f"Could not move the run log to {target}: {one_line(error)}\n")
                self._file.flush()
            return self.path

    def close(self) -> None:
        with self.lock:
            if not self._file.closed:
                self._file.close()


_current: Optional[Transcript] = None


def current() -> Optional[Transcript]:
    """The transcript of the run in progress, or None."""
    return _current


def screen(text: str) -> None:
    """Write text that was shown on the screen to the log. Does nothing when no log is open."""
    transcript = _current
    if transcript is not None:
        transcript.write(text)


def is_noisy(logger_name: str) -> bool:
    return any(logger_name == p or logger_name.startswith(p + ".") for p in NOISY_PREFIXES)


class TranscriptHandler(logging.Handler):
    """Writes the log records that reach the screen to the transcript, and records every warning
    and error for the digest. Library records below WARNING are left out."""

    def __init__(self, path: str, level: int = logging.INFO) -> None:
        super().__init__(level)
        global _current
        self.transcript = Transcript(path)
        _current = self.transcript
        self._formatter = logging.Formatter(LOG_FORMAT, datefmt=LOG_DATE_FORMAT)

    def emit(self, record: logging.LogRecord) -> None:
        try:
            if record.levelno >= logging.WARNING:
                ISSUES.add(record.levelno, record.name, record.getMessage())
            if record.levelno < logging.WARNING and is_noisy(record.name):
                return
            copy = logging.makeLogRecord(record.__dict__)
            copy.levelname = logging.getLevelName(record.levelno)
            self.transcript.write(self._formatter.format(copy))
        except Exception:  # noqa: BLE001 - logging must never stop a run
            self.handleError(record)

    def move(self, path: str) -> str:
        """Continue the log in ``path`` (see ``Transcript.move``)."""
        return self.transcript.move(path)

    def close(self) -> None:
        global _current
        self.transcript.close()
        if _current is self.transcript:
            _current = None
        super().close()


# ── how the run ended ────────────────────────────────────────────────────────
#
# A log that stops without a last line means the process was killed (``kill -9``, a power cut): nothing
# can write anything then. Every other way a run can end writes one line, "Run ended: ...", so a log
# either says how the run ended or is visibly cut off.

_stop_hint = ""


def set_stop_hint(text: str) -> None:
    """What to tell the reader when the run stops before it wrote its results (for example where
    finished work was kept and how to resume). Replaces any earlier hint."""
    global _stop_hint
    _stop_hint = text


def _clock() -> str:
    return datetime.now().strftime("%H:%M:%S")


def _not_written_lines() -> list:
    lines = ["The results zip was not written. This log holds what was done up to now."]
    if _stop_hint:
        lines.append(_stop_hint)
    return lines


def end_run(outcome: str, detail: Iterable[str] = ()) -> bool:
    """Write the last lines of the log: ``Run ended: <outcome> at HH:MM:SS`` and any ``detail``.

    Only the first call writes; a run that was already closed (or has no log open) is left alone.
    The line is forced to disk, so it survives whatever ends the process next. Returns True when
    this call wrote it.
    """
    transcript = _current
    if transcript is None:
        return False
    with transcript.lock:
        if transcript.ended is not None:
            return False
        transcript.ended = outcome
        transcript.write_durable("\n".join([f"Run ended: {outcome} at {_clock()}", *detail]))
    return True


def finished() -> bool:
    """The scan is done and the digest is written; the results are being packaged."""
    return end_run("scan finished")


def crashed(exc: BaseException) -> bool:
    """Write how a run that raised ended: the error and its traceback, or the exit code.

    A clean exit (``sys.exit()`` or code 0) writes nothing, because the code that exits cleanly
    either finished the run or deliberately leaves no log.
    """
    if isinstance(exc, SystemExit):
        if exc.code in (None, 0):
            return False
        return end_run(f"exited with code {one_line(str(exc.code), 120)}", _not_written_lines())
    if isinstance(exc, KeyboardInterrupt):
        return end_run("stopped by Ctrl-C (KeyboardInterrupt)", _not_written_lines())
    trace = plain("".join(traceback.format_exception(type(exc), exc, exc.__traceback__)))
    detail = [*_not_written_lines(), "The traceback:", *("  " + line for line in trace.split("\n"))]
    return end_run(f"failed with {type(exc).__name__}: {one_line(str(exc), 200)}", detail)


# (name, how the log words it). SIGHUP is what closing the terminal sends.
STOP_SIGNALS = (
    ("SIGINT", "Ctrl-C (SIGINT)"),
    ("SIGTERM", "SIGTERM"),
    ("SIGHUP", "the terminal closing (SIGHUP)"),
    ("SIGBREAK", "Ctrl-Break (SIGBREAK)"),
)


def _show_cursor() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            if stream.isatty():
                stream.write("\x1b[?25h")
        except Exception:  # noqa: BLE001 - the terminal may already be gone
            pass


def _stop_handler(label: str) -> Callable:
    def handle(signum, frame) -> None:  # noqa: ARG001
        end_run(f"stopped by {label}", _not_written_lines())
        _show_cursor()
        for stream in (sys.stdout, sys.stderr):
            try:
                stream.flush()
            except Exception:  # noqa: BLE001 - the terminal may already be gone
                pass
        # Not sys.exit: that waits for worker threads, which can be minutes into a scan.
        os._exit(128 + int(signum))

    return handle


def install_stop_handlers() -> list:
    """On Ctrl-C, SIGTERM and a closing terminal: write the last line of the log, flush it to disk and
    exit with the usual code (128 plus the signal number). Returns the names it installed. Does
    nothing off the main thread. The default for each of these is to die without a word."""
    installed: list = []
    if threading.current_thread() is not threading.main_thread():
        return installed
    for name, label in STOP_SIGNALS:
        number = getattr(signal, name, None)
        if number is None:
            continue
        try:
            signal.signal(number, _stop_handler(label))
        except (ValueError, OSError):
            continue
        installed.append(name)
    return installed


def restore_stop_handlers() -> None:
    """Put the default handlers back (for tests and for code that runs after the scan)."""
    for name, _ in STOP_SIGNALS:
        number = getattr(signal, name, None)
        if number is None:
            continue
        try:
            signal.signal(
                number, signal.default_int_handler if name == "SIGINT" else signal.SIG_DFL
            )
        except (ValueError, OSError):
            pass


# ── the header ───────────────────────────────────────────────────────────────


def package_versions(names: Iterable[str]) -> str:
    found = []
    for name in names:
        try:
            found.append(f"{name} {metadata.version(name)}")
        except Exception:  # noqa: BLE001 - not installed
            found.append(f"{name} not installed")
    return ", ".join(found)


def code_version(directory: str) -> str:
    """The commit of the checkout the tool runs from (hash and date), or ``unknown``."""
    try:
        out = subprocess.run(
            ["git", "-C", directory, "log", "-n1", "--format=%h %ad", "--date=short"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return out.stdout.strip() if out.returncode == 0 and out.stdout.strip() else "unknown"
    except Exception:  # noqa: BLE001
        return "unknown"


def write_header(tool: str, facts: Iterable[tuple], argv: Optional[list] = None) -> None:
    """The first lines of the log: what ran, with what, so a log read later explains itself."""
    lines = [
        f"# Run log: {tool}",
        "# This file is a transcript of the screen, plus this header and a final digest.",
    ]
    lines += [f"# {key}: {value}" for key, value in facts]
    lines.append(f"# Python: {platform.python_version()} on {platform.platform()}")
    if argv is not None:
        lines.append(f"# Command line: {' '.join(argv) if argv else '(no options)'}")
    lines.append("")
    screen("\n".join(lines))


# ── issues and their fixes ───────────────────────────────────────────────────


class Solution(NamedTuple):
    """What to do about a problem. ``pattern`` is matched against the text of the error;
    ``fix`` may use the pattern's named groups, for example ``{project}``."""

    id: str
    pattern: "re.Pattern[str]"
    fix: str


class _Blank(dict):
    def __missing__(self, key: str) -> str:
        return "<" + key + ">"


_solutions: list = []
_masks: list = []
_cause: list = []
_noun: list = ["scope"]
DOC = "docs/troubleshooting.md"


def configure(
    solutions: Iterable[Solution] = (),
    masks: Iterable["re.Pattern[str]"] = (),
    cause: Optional[Callable[[str], Optional[tuple]]] = None,
    noun: str = "scope",
) -> None:
    """Set the tool's solutions (first match wins) and the patterns that make two messages the
    same problem, for example the name of a project or a region.

    ``cause`` (optional) names what a message is really about: it returns ``(key, scope)`` or None.
    Messages with the same key are one problem however they are worded, for example the access
    check and the collector both reporting the same API as off, and ``scope`` (a project, say) is
    collected so the digest can say where it happened. ``noun`` is what a scope is called.
    """
    _solutions[:] = list(solutions)
    _masks[:] = list(masks)
    _cause[:] = [cause] if cause else []
    _noun[0] = noun


def solve(text: str, service: str = "", code: str = "") -> Optional[tuple]:
    """``(id, fix)`` for the first solution that matches, else None."""
    target = f"{service} | {code} | {text}"
    for solution in _solutions:
        match = solution.pattern.search(target)
        if match:
            groups = {k: (v or "") for k, v in match.groupdict().items()}
            return solution.id, solution.fix.format_map(_Blank(groups))
    return None


def fix_lines(text: str, service: str = "", code: str = "", width: int = 96) -> list:
    """The fix for a problem as lines: ``Fix:`` and a short wrapped explanation, each command on a
    line of its own that is never wrapped (a command split over two lines cannot be copied), and
    the troubleshooting anchor. When nothing matches, a generic pointer.

    In a solution's text a line starting with ``Run: `` is a command; other lines are sentences.
    """
    found = solve(text, service, code)
    if found is None:
        return [f"Fix: no specific advice for this one; see {DOC}"]
    solution_id, fix = found
    lines: list = []
    for paragraph in fix.split("\n"):
        if paragraph.startswith("Run: "):
            lines.append("     " + paragraph)
            continue
        lead = "Fix: " if not lines else "     "
        for wrapped in textwrap.wrap(paragraph, width=width - 5) or [""]:
            lines.append((lead if not lines else "     ") + wrapped)
    lines.append(f"     ({DOC}#{solution_id})")
    return lines


def normalize(message: str) -> str:
    """The message with the parts that vary (ids, times, long numbers, names) masked, so the same
    problem on many accounts, projects or regions counts as one."""
    text = GUID.sub("<id>", message)
    text = ISO_TIME.sub("<time>", text)
    for mask in _masks:
        text = mask.sub("<name>", text)
    return LONG_NUMBER.sub("<n>", " ".join(text.split()))


class Issues:
    """Every warning and error of the run, grouped by what they say once the variable parts are
    masked."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._groups: "OrderedDict[str, dict]" = OrderedDict()
        self.total = 0

    def add(self, level: int, source: str, message: str, scope: str = "") -> None:
        found = None
        if _cause:
            try:
                found = _cause[0](message)
            except Exception:  # noqa: BLE001 - grouping must never stop a run
                found = None
        key = found[0] if found else normalize(message)
        scope = scope or (found[1] if found else "")
        with self._lock:
            group = self._groups.setdefault(
                key,
                {"count": 0, "level": level, "source": source, "examples": [], "scopes": []},
            )
            if scope and scope not in group["scopes"]:
                group["scopes"].append(scope)
            group["count"] += 1
            group["level"] = max(group["level"], level)
            if len(group["examples"]) < 3 and message not in group["examples"]:
                group["examples"].append(message)
            self.total += 1

    def groups(self) -> list:
        with self._lock:
            items = [dict(group, scopes=list(group["scopes"])) for group in self._groups.values()]
        return sorted(items, key=lambda g: (-g["level"], -len(g["scopes"]), -g["count"]))

    def reset(self) -> None:
        with self._lock:
            self._groups.clear()
            self.total = 0


ISSUES = Issues()


def digest_lines(max_groups: int = 12, limit: int = 300) -> list:
    """The end-of-run digest: each distinct problem once, how often, one example, and the fix."""
    groups = ISSUES.groups()
    if not groups:
        return ["No warnings or errors were recorded."]
    word = "problem" if len(groups) == 1 else "problems"
    lines = [f"{len(groups)} distinct {word} ({ISSUES.total} warnings and errors in all):"]
    for number, group in enumerate(groups[:max_groups], 1):
        example = group["examples"][0]
        level = "ERROR" if group["level"] >= logging.ERROR else "WARNING"
        scopes = group.get("scopes") or []
        where = f"{len(scopes)} {_noun[0]}{'' if len(scopes) == 1 else 's'}:"
        if not scopes:
            how_many = f"{group['count']}x"
        elif group["count"] > len(scopes):
            how_many = f"{group['count']}x in {where}"
        else:
            how_many = where
        lines.append(f"  {number}. [{level}] {how_many} {one_line(example, limit)}")
        if scopes:
            shown = ", ".join(scopes[:5]) + (f" +{len(scopes) - 5} more" if len(scopes) > 5 else "")
            lines.append(f"     {_noun[0].capitalize()}s: {shown}")
        lines += [f"     {line}" for line in fix_lines(example)]
    if len(groups) > max_groups:
        lines.append(f"  ... and {len(groups) - max_groups} more distinct problems")
    return lines


def problem_lines(groups: list, solve_group: Callable[[dict], list], limit: int = 300) -> list:
    """Lines describing blocked pre-flight groups: the error as the cloud worded it, and the fix.

    ``groups`` come from ``preflight_core.blocked_groups`` with a ``message`` added;
    ``solve_group`` returns the lines of the fix for one of them.
    """
    lines = []
    for group in groups:
        scopes = [scope for scope in (group.get("scopes") or []) if scope]
        shown = ", ".join(scopes[:3]) + (f" +{len(scopes) - 3} more" if len(scopes) > 3 else "")
        where = f" ({shown})" if scopes else ""
        lines.append(f"  {group['service']}{where}: {group.get('code') or group['status']}")
        if group.get("message"):
            lines.append(f"      Error: {one_line(group['message'], limit)}")
        lines += [f"      {line}" for line in solve_group(group)]
    return lines
