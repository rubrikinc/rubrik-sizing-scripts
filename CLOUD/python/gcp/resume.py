"""Resuming an interrupted GCP scan: what one project's checkpoint holds, and which projects to scan.

A finished project is saved as one checkpoint (see ``checkpoint_core``). It holds the slice the
output writers already use (``streaming_writer.slice_from_result``), plus what the screen, the
summary and the access-check CSV need, so a resumed project is never rebuilt into inventory
objects: everything is plain JSON, read back as it was written.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

import checkpoint_core as core

logger = logging.getLogger(__name__)

PREFIX = "gcp-sizing-progress"

# What every checkpoint must hold to be used. A file without them (an older layout, a hand edit)
# is scanned again instead of dropping the project from the results.
_REQUIRED = ("slice", "summary", "errors", "access", "line")


def request_of(
    *,
    selected: set,
    regions: Optional[list],
    security: bool,
    scope: Optional[str],
    project_scope: str,
) -> dict:
    """The options that change what is collected inside a project, and so what a resume may reuse.

    The list of projects is deliberately not part of it: a scan of "all projects" run again an
    hour later may see a few more or fewer, and a project that is already done is done whichever
    way the list came about. ``project_scope`` says how the list was asked for ("all", "current" or
    "named"), so a run that scans everything does not resume one that scanned a single project.
    """
    return {
        "tool": "gcp",
        "collectors": sorted(selected),
        "regions": sorted(regions) if regions else None,
        "security": bool(security),
        "org_scope": scope,
        "project_scope": project_scope,
    }


def project_checkpoint(
    project_id: str,
    result: dict,
    summary: dict,
    slice_dict: dict,
    off: Optional[set],
    access: list,
) -> dict:
    """What is saved for a finished project: its slice (already built for the output), the summary
    row, the errors, its access-check rows and what its screen line showed."""
    asset = result.get("asset")
    return {
        "slice": slice_dict,
        "summary": summary,
        "errors": list(result.get("errors", [])),
        "access": list(access),
        "line": {
            "assets": asset.total_assets if asset is not None else None,
            "asset_types": len(asset.assets_by_type) if asset is not None else None,
            "switched_off": sorted(off) if off else None,
        },
    }


def is_partial(result: dict) -> bool:
    """A project that finished with gaps: a collector recorded an error.

    An empty result is not partial: it means every service was switched off, so there was nothing
    to read.
    """
    return bool(result.get("errors"))


def should_save(*, stopped: bool, died: bool) -> bool:
    """Whether a project's result is a finished one worth keeping.

    A project that died as a whole is not saved, so a resume scans it again. Neither is one that
    ends after a stop was asked for: BigQuery then records "the run was stopped" as an error and
    returns what it has, which is a cut-off result, not a finished one.
    """
    return not stopped and not died


def valid(data: Any) -> bool:
    """Whether a loaded checkpoint holds everything a resume needs."""
    return isinstance(data, dict) and all(key in data for key in _REQUIRED)


def access_by_project(rows: list) -> dict:
    """The access-check rows of each project, keyed by project id (the row's Owner)."""
    grouped: dict = {}
    for row in rows:
        grouped.setdefault(row.get("Owner"), []).append(row)
    return grouped


def split(store: Any, projects: list, retry_partial: bool = True) -> tuple:
    """Which projects to scan and which to take from the saved run: ``(todo, reuse, notes)``.

    A project is reused when it has a readable checkpoint. One that finished with errors is scanned
    again (``retry_partial``, the default) so a gap cannot hide behind "saved"; ``--keep-partial``
    keeps it as it was. Saved projects that are not in ``projects`` are left out of the results,
    and ``notes`` says how many.
    """
    done = store.completed()
    todo: list = []
    reuse: list = []
    notes: list = []
    unreadable = 0
    for pid in projects:
        if pid not in done or (retry_partial and done[pid]):
            todo.append(pid)
            continue
        loaded = store.load(pid)
        if loaded is None or not valid(loaded[0]):
            unreadable += 1
            todo.append(pid)
        else:
            reuse.append(pid)
    outside = len(set(done) - set(projects))
    if outside:
        notes.append(
            f"{outside} saved project(s) are not in this run's project list and are left out of "
            "the results."
        )
    if unreadable:
        notes.append(f"{unreadable} saved project(s) could not be read and are scanned again.")
    partial = [pid for pid in reuse if done[pid]]
    if partial:
        notes.append(
            f"{len(partial)} project(s) finished with errors in the earlier run and are kept as "
            "they were because of --keep-partial; their gaps are still in the results."
        )
    again = [pid for pid in todo if done.get(pid)]
    if again:
        notes.append(
            f"{len(again)} project(s) finished with errors in the earlier run and are scanned "
            "again (add --keep-partial to keep them as they were)."
        )
    return todo, reuse, notes


def keep_progress(not_scanned: list, stopped_early: bool, gaps: Optional[list] = None) -> bool:
    """Whether the progress folder is kept after the results are written.

    It is kept when any project has no saved result: one that could not be read (a named project the
    sign-in cannot see yet), one that died, and one not reached after a stop. It is also kept when a
    project finished with gaps (``gaps``), so a later --resume can scan it again once the cause is
    fixed: that is what makes rescanning partial projects by default mean anything. A later --resume
    then scans just those. When every project has a full result there is nothing to resume, so it
    is removed.
    """
    return bool(not_scanned) or stopped_early or bool(gaps)


def gaps_of_errors(errors: list) -> list:
    """``(project, why)`` for each project with collector errors, one line each, in the order seen.

    A project's errors are grouped: the first reason is shown, and how many more follow it.
    """
    by_project: dict = {}
    for error in errors:
        by_project.setdefault(error.get("project_id") or "?", []).append(error)
    gaps = []
    for pid, items in by_project.items():
        first = items[0]
        why = f"{first.get('collector', '?')}: {first.get('message', first.get('category', ''))}"
        if len(items) > 1:
            why += f" (+{len(items) - 1} more)"
        gaps.append((pid, why[:160]))
    return gaps


def mode_of(args: Any) -> str:
    if getattr(args, "fresh", False):
        return core.FRESH
    if getattr(args, "resume", False):
        return core.RESUME
    return core.AUTO
