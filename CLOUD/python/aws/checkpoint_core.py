"""Checkpoints shared by the AWS, Azure and GCP tools, so an interrupted run can be resumed.

A scan is a list of units (AWS accounts, Azure subscriptions, GCP projects). Each unit that finishes is
saved as one file, written whole or not at all. A later run in the same folder reads those files back,
scans only the units that are missing, and builds the results from both.

Three things keep a resume honest:

* **Atomic writes.** A file is written beside its final name, flushed to disk and renamed, so a run that
  is killed while writing leaves no half-written checkpoint that counts as finished.
* **A scope record.** The progress folder holds a manifest with a fingerprint of the options that choose
  what is scanned (scope, regions, services, cost). A run with different options does not pick up another
  run's units: it is refused, or the old folder is replaced when the person says so.
* **An explicit decision.** An unfinished run is resumed only when the person says so (a question on a
  terminal, ``--resume`` otherwise), so old results are never mixed into a new scan by surprise.
* **A finished marker.** A folder whose results were built is removed (or marked finished and never
  resumed), so a later run cannot mix its units into a scan they did not belong to.

This module imports only the standard library, because an installed tool cannot import ``common``; each
tool carries a byte-identical copy named ``checkpoint_core.py``.
"""

from __future__ import annotations

import glob
import hashlib
import json
import logging
import os
import re
import shutil
import sys
import tempfile
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

log = logging.getLogger(__name__)

SCHEMA = 1
MANIFEST_NAME = "checkpoint-manifest.json"
UNIT_FILE = "checkpoint.json"

IN_PROGRESS = "in_progress"
FINISHED = "finished"

AUTO = "auto"  # ask on a terminal; resume a matching run when there is no one to ask
RESUME = "resume"  # --resume: carry on with the previous run, or fail if it does not match
FRESH = "fresh"  # --fresh: delete the previous run and start over

_SAFE_UNIT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")


class ResumeRefused(Exception):
    """The previous run cannot be resumed and the person did not say to start over."""


# ── Files ─────────────────────────────────────────────────────────────────────


def write_json_atomic(path: str, obj: Any, *, indent: Optional[int] = None) -> None:
    """Write ``obj`` as JSON to ``path`` so that ``path`` is either the old file or the whole new one."""
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".checkpoint-", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(obj, f, indent=indent, default=str)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    _fsync_dir(directory)


def _fsync_dir(directory: str) -> None:
    """Make the rename itself durable. Not possible on every platform, and not worth failing for."""
    try:
        fd = os.open(directory, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def safe_unit_name(unit: str) -> str:
    """A folder name for a unit id: the id itself when it is plain, else a cleaned name plus a hash."""
    if _SAFE_UNIT.fullmatch(unit) and unit not in (".", ".."):
        return unit
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", unit).strip("._") or "unit"
    return f"{cleaned[:100]}-{hashlib.sha1(unit.encode('utf-8')).hexdigest()[:8]}"


def fingerprint(request: Dict[str, Any]) -> str:
    """A short digest of the options that choose what a run scans."""
    text = json.dumps(request, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def _read_json(path: str) -> Optional[Any]:
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


# ── The store ─────────────────────────────────────────────────────────────────


class Store:
    """The checkpoint files of one run: one folder per unit under ``root``.

    ``envelope=True`` wraps each unit's data with its id and a ``partial`` flag (Azure and GCP).
    ``envelope=False`` keeps the unit's own document as the file, which the caller writes with
    :func:`write_json_atomic` at :meth:`unit_path` (AWS, whose per-account JSON is also an output).
    """

    def __init__(
        self,
        root: str,
        tool: str,
        fingerprint_: str,
        *,
        envelope: bool = True,
        filename: str = UNIT_FILE,
    ) -> None:
        self.root = root
        self.tool = tool
        self.fingerprint = fingerprint_
        self.envelope = envelope
        self.filename = filename
        self.discarded: List[str] = []  # unit files found unreadable and removed

    # paths
    def unit_dir(self, unit: str) -> str:
        return os.path.join(self.root, safe_unit_name(unit))

    def unit_path(self, unit: str) -> str:
        return os.path.join(self.unit_dir(unit), self.filename)

    # writing
    def save(self, unit: str, data: Any, *, partial: bool = False) -> str:
        """Save a finished unit. ``partial`` marks one that finished with gaps (errors, a time limit)."""
        path = self.unit_path(unit)
        write_json_atomic(
            path,
            {
                "checkpoint": {
                    "schema": SCHEMA,
                    "tool": self.tool,
                    "unit": unit,
                    "partial": bool(partial),
                    "completed_at": datetime.now(timezone.utc).isoformat(),
                },
                "data": data,
            },
        )
        return path

    # reading
    def load(self, unit: str) -> Optional[Tuple[Any, bool]]:
        """``(data, partial)`` for a saved unit, or None when it is missing or unreadable."""
        return self._read_unit(self.unit_path(unit))

    def completed(self) -> Dict[str, bool]:
        """Every unit with a readable checkpoint, as ``{unit: partial}``.

        An unreadable file (a run killed by something that bypassed the atomic write, a disk that
        filled up) is removed and listed in ``discarded``, so the unit is scanned again instead of
        counted as done.
        """
        done: Dict[str, bool] = {}
        try:
            entries = sorted(os.listdir(self.root))
        except OSError:
            return done
        for entry in entries:
            path = os.path.join(self.root, entry, self.filename)
            if not os.path.isfile(path):
                continue
            if self.envelope:
                doc = _read_json(path)
                unit = _envelope_unit(doc)
                if unit is None:
                    self._drop(path)
                    continue
                done[unit] = bool(doc["checkpoint"].get("partial"))
            else:
                if not isinstance(_read_json(path), dict):
                    self._drop(path)
                    continue
                done[entry] = False
        return done

    def _read_unit(self, path: str) -> Optional[Tuple[Any, bool]]:
        doc = _read_json(path)
        if self.envelope:
            if _envelope_unit(doc) is None:
                return None
            return doc["data"], bool(doc["checkpoint"].get("partial"))
        return (doc, False) if isinstance(doc, dict) else None

    def _drop(self, path: str) -> None:
        log.warning("Ignoring an unreadable checkpoint and scanning it again: %s", path)
        self.discarded.append(path)
        try:
            os.unlink(path)
        except OSError:
            pass

    # lifecycle
    def finish(self, *, keep: bool = False) -> None:
        """The results are built: remove the folder, or keep it marked so it is never resumed."""
        if keep:
            manifest = read_manifest(self.root) or {}
            manifest["status"] = FINISHED
            manifest["finished_at"] = datetime.now(timezone.utc).isoformat()
            write_json_atomic(os.path.join(self.root, MANIFEST_NAME), manifest, indent=2)
            return
        self.discard()

    def discard(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)


def _envelope_unit(doc: Any) -> Optional[str]:
    if not isinstance(doc, dict) or "data" not in doc:
        return None
    ck = doc.get("checkpoint")
    if not isinstance(ck, dict) or not isinstance(ck.get("unit"), str):
        return None
    return ck["unit"]


def read_manifest(root: str) -> Optional[Dict[str, Any]]:
    doc = _read_json(os.path.join(root, MANIFEST_NAME))
    return doc if isinstance(doc, dict) else None


# ── Starting or resuming a run ────────────────────────────────────────────────


def _find_unfinished(parent: str, prefix: str) -> Tuple[Optional[str], List[str]]:
    """The newest folder that holds an unfinished run, and the older-format folders it ignored."""
    unfinished: Optional[str] = None
    ignored: List[str] = []
    for path in sorted(glob.glob(os.path.join(parent, prefix + "-*")), reverse=True):
        if not os.path.isdir(path):
            continue
        manifest = read_manifest(path)
        if manifest is None:
            ignored.append(path)  # made before manifests existed: nothing says what it was for
        elif manifest.get("status") == IN_PROGRESS and unfinished is None:
            unfinished = path
    return unfinished, ignored


def _new_run(
    parent: str,
    prefix: str,
    tool: str,
    request: Dict[str, Any],
    fp: str,
    code_version: str,
    **store_options: Any,
) -> Store:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    root = os.path.join(parent, f"{prefix}-{stamp}")
    suffix = 1
    while os.path.exists(root):  # two runs in one second
        suffix += 1
        root = os.path.join(parent, f"{prefix}-{stamp}-{suffix}")
    os.makedirs(root)
    write_json_atomic(
        os.path.join(root, MANIFEST_NAME),
        {
            "schema": SCHEMA,
            "tool": tool,
            "fingerprint": fp,
            "request": request,
            "status": IN_PROGRESS,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "code_version": code_version,
        },
        indent=2,
    )
    return Store(root, tool, fp, **store_options)


def _ask_default(question: str, default: bool) -> bool:
    suffix = "[Y/n]" if default else "[y/N]"
    try:
        answer = input(f"  {question} {suffix} ").strip().lower()
    except EOFError:
        return default
    return default if not answer else answer in ("y", "yes")


def _age(started_at: Optional[str]) -> str:
    """How long ago a run started, for the question and the messages: "3 hours ago"."""
    try:
        started = datetime.fromisoformat(str(started_at))
        seconds = max(0, int((datetime.now(timezone.utc) - started).total_seconds()))
    except (TypeError, ValueError):
        return "at an unknown time"
    for unit, size in (("day", 86400), ("hour", 3600), ("minute", 60)):
        if seconds >= size:
            n = seconds // size
            return f"{n} {unit}{'' if n == 1 else 's'} ago"
    return "just now"


def prepare(
    parent: str,
    *,
    prefix: str,
    tool: str,
    request: Dict[str, Any],
    mode: str = AUTO,
    code_version: str = "",
    envelope: bool = True,
    filename: str = UNIT_FILE,
    interactive: Optional[bool] = None,
    ask: Optional[Callable[[str, bool], bool]] = None,
    say: Optional[Callable[[str], None]] = None,
) -> Tuple[Store, bool]:
    """Open this run's progress folder: resume the previous unfinished run, or start a new one.

    ``request`` holds the options that choose what is scanned; two runs with the same request are the
    same scan. ``mode`` is :data:`AUTO`, :data:`RESUME` or :data:`FRESH` (the ``--resume`` and ``--fresh``
    options). In :data:`AUTO` an unfinished run is never continued silently: on a terminal the person is
    asked, and without one the run is refused until ``--resume`` or ``--fresh`` says what to do. Returns
    ``(store, resumed)``. Raises :class:`ResumeRefused` when the previous run does not
    match and nobody agreed to replace it.
    """
    interactive = sys.stdin.isatty() if interactive is None else interactive
    ask = ask or _ask_default
    say = say or log.info
    fp = fingerprint(request)
    options = {"envelope": envelope, "filename": filename}

    found, ignored = _find_unfinished(parent, prefix)
    for path in ignored:
        say(
            f"Ignoring {path}: it was made by an older version and records no scope, so it is not resumed."
        )

    if found is None:
        if mode == RESUME:
            raise ResumeRefused(
                "--resume was given, but there is no unfinished run in this folder."
            )
        return _new_run(parent, prefix, tool, request, fp, code_version, **options), False

    old = Store(found, tool, (read_manifest(found) or {}).get("fingerprint", ""), **options)
    done = len(old.completed())

    if mode == FRESH:
        say(
            f"--fresh: deleting the unfinished run in {found} ({done} units done) and starting over."
        )
        old.discard()
        return _new_run(parent, prefix, tool, request, fp, code_version, **options), False

    if old.fingerprint == fp:
        if mode == AUTO:
            when = _age((read_manifest(found) or {}).get("started_at"))
            what = f"An unfinished run is in {found} ({done} units done, started {when})."
            if not interactive:
                # Nobody to ask, and a silent resume could mix old results into a new scan.
                raise ResumeRefused(
                    f"{what} Add --resume to continue it, or --fresh to delete it and start over."
                )
            if not ask(f"{what} Resume it? (No deletes it and starts over.)", True):
                say(f"Deleting {found} and starting over.")
                old.discard()
                return _new_run(parent, prefix, tool, request, fp, code_version, **options), False
        previous = (read_manifest(found) or {}).get("code_version", "")
        if previous and code_version and previous != code_version:
            say(f"Note: the unfinished run was made by code {previous}; this is {code_version}.")
        say(f"Resuming {found}: {done} units already done.")
        return old, True

    explain = (
        f"The unfinished run in {found} was started with different options, so its results "
        "would not belong to this scan."
    )
    if mode == AUTO and interactive:
        if ask(f"{explain} Delete it and start over?", False):
            old.discard()
            return _new_run(parent, prefix, tool, request, fp, code_version, **options), False
    raise ResumeRefused(
        f"{explain} Run it again with the same options to resume it, or add --fresh to delete it "
        "and start over."
    )


# ── What a run says about the units it finished with gaps ─────────────────────

SUMMARY_SHOWN = 10  # units named on the screen; the zip and the checkpoints hold every one


def gaps_summary(
    noun: str,
    gaps: List[Tuple[str, str]],
    total: int,
    *,
    kept: bool,
    resume_hint: str = "--resume",
) -> List[str]:
    """The lines that end a run: how many units finished with gaps, which, and what to do.

    ``noun`` is "account", "subscription" or "project". ``gaps`` is ``(unit, why)`` for each unit that
    finished with gaps, and ``total`` how many units the run covers. A unit with gaps is complete as
    far as the scan got, not as far as the environment goes: a listing that failed or a service that
    was denied leaves something out of it, and nothing else in the results says so.

    ``kept`` says whether the progress folder is still there. If it is, ``--resume`` scans just these
    again. If it is not, there is nothing to resume, so the advice is to fix the cause and scan them
    by name. Nothing is returned when there are no gaps, so a clean run says nothing.
    """
    if not gaps:
        return []
    many = len(gaps) > 1
    plural = noun + "s" if many else noun
    are = "are" if many else "is"
    of = noun + "s" if total != 1 else noun
    lines = [
        f"{len(gaps)} of {total} {of} finished with gaps "
        f"(something in {'them' if many else 'it'} was not read):"
    ]
    for unit, why in gaps[:SUMMARY_SHOWN]:
        lines.append(f"  {unit}  {why}")
    if len(gaps) > SUMMARY_SHOWN:
        lines.append(f"  ... and {len(gaps) - SUMMARY_SHOWN} more")
    if kept:
        lines.append(
            f"Fix the cause, then run the same command with {resume_hint}: only the {plural} with "
            f"gaps {are} scanned again. Add --keep-partial to keep {'them' if many else 'it'} as "
            f"{'they are' if many else 'it is'}."
        )
    else:
        lines.append(
            f"The results above include {'these' if many else 'this'} {plural} with what was "
            f"read. To read more, fix the cause and scan the {plural} again by name."
        )
    return lines
