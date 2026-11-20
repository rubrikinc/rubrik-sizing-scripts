"""Resuming an interrupted Azure scan: what one subscription's checkpoint holds, and how it is read back.

A finished subscription is saved as one checkpoint (see ``checkpoint_core``): everything collected for it,
as the plain JSON ``DiscoveryResult.build`` would write. A resumed subscription is read back as ``Saved``
objects, which answer the attribute reads the rest of the run makes on the collectors' dataclasses
(``comp.vms``, ``bp.vaults``, ``cost.total_6mo_spend``), so a fresh and a resumed subscription produce the
same JSON and are never rebuilt into the 48 collector types.
"""

from __future__ import annotations

import dataclasses
import inspect
import typing
from typing import Any, Optional

import checkpoint_core as core

PREFIX = "azure-sizing-progress"

# What each saved piece of a subscription's scan is called in its checkpoint, in the order
# _collect_subscription returns them. Only the scan is saved: it is the long, parallel stage. What is
# collected after it (tag names, AKS, Cosmos DB, Backup Vaults, containers, Key Vaults, Defender, Purview
# and Site Recovery) is a few small calls per subscription, and runs again for every subscription on a
# resume, so a resumed run never mixes saved and fresh values of the same collector.
SCAN_PARTS = ("compute", "backup_posture", "storage", "database", "backup_jobs", "cost")

_REQUIRED = ("parts", "access")


def _nested_types(cls: Optional[type]) -> dict:
    """For a dataclass: ``{field: nested dataclass}`` for each field that holds a dataclass (or a list of
    them), from its type hints. Empty when there is no class or its hints cannot be resolved."""
    if cls is None or not dataclasses.is_dataclass(cls):
        return {}
    try:
        hints = typing.get_type_hints(cls)
    except Exception:  # noqa: BLE001 - hints can fail to resolve across Python versions
        return {}
    nested: dict = {}
    for field in dataclasses.fields(cls):
        hint = hints.get(field.name)
        parts = (
            [a for a in typing.get_args(hint) if a is not type(None)]
            if typing.get_origin(hint) is typing.Union
            else [hint]
        )
        for part in parts:
            if typing.get_origin(part) is list:
                args = typing.get_args(part)
                part = args[0] if args else None
            if inspect.isclass(part) and dataclasses.is_dataclass(part):
                nested[field.name] = part
    return nested


class Saved:
    """A saved inventory read back: attribute access to its fields, and nothing else.

    It is deliberately not a dict. Two collector dataclasses have a field named like a dict method
    (``DataProtectionInventory.items``, ``KeyVault.keys``), which a dict subclass would answer with the
    method instead of the saved list. A field that was not saved raises ``AttributeError``, as it would
    on the dataclass, so ``getattr(x, name, default)`` still falls back the way the code expects.

    ``cls`` is the dataclass the data came from. With it a field is wrapped exactly when its declared
    type is a dataclass or a list of them, so a plain map such as ``tags`` is never wrapped by accident
    and a nested ``tag_summary`` reads back as an object. Without it (or if its hints cannot be
    resolved) a dict inside a list is taken to be a record.
    """

    __slots__ = ("_data", "_cls", "_nested")

    # Read by models.inventory._asdict_safe, which cannot import this module, to serialise the data
    # of a saved inventory as it is. Looked up on the class, so it never reaches __getattr__.
    SAVED_DATA_ATTR = "_data"

    def __init__(self, data: dict, cls: Optional[type] = None) -> None:
        object.__setattr__(self, "_data", data)
        object.__setattr__(self, "_cls", cls)
        object.__setattr__(self, "_nested", _nested_types(cls))

    def __getattr__(self, name: str) -> Any:
        data = object.__getattribute__(self, "_data")
        if name in data:
            nested = object.__getattribute__(self, "_nested")
            return _wrap(data[name], nested.get(name), typed=bool(nested) or None)
        # The two properties the collectors' dataclasses compute from a list.
        if name == "total_vaults" and "vaults" in data:
            return len(data["vaults"])
        if name == "database_count" and "databases" in data:
            return len(data["databases"])
        raise AttributeError(name)

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError("a saved inventory is read-only")

    def __repr__(self) -> str:
        return f"Saved({object.__getattribute__(self, '_data')!r})"

    def as_dict(self) -> dict:
        return object.__getattribute__(self, "_data")


def _wrap(value: Any, cls: Optional[type] = None, typed: Optional[bool] = None) -> Any:
    """A saved value as the run reads it.

    With ``cls`` (the field's declared dataclass) a dict, or each dict of a list, becomes a Saved of that
    class. Without it, a dict inside a list is a record and anything else stays as it is, so maps such as
    ``tags`` keep ``.get()`` and ``.items()``; ``typed`` is True when the class's hints were read and said
    this field holds no dataclass, in which case nothing is wrapped.
    """
    if cls is not None:
        if isinstance(value, list):
            return [Saved(v, cls) if isinstance(v, dict) else v for v in value]
        return Saved(value, cls) if isinstance(value, dict) else value
    if typed:
        return value
    if isinstance(value, list):
        return [Saved(v) if isinstance(v, dict) else _wrap(v) for v in value]
    return value


def unwrap(obj: Any) -> Any:
    """The plain data of a saved inventory, for serialising it again."""
    return obj.as_dict() if isinstance(obj, Saved) else obj


def request_of(
    *,
    scope: str,
    regions: Optional[list],
    cloud: str,
    scans: dict,
    skips: frozenset,
    devops: bool,
    devops_orgs: Optional[str],
) -> dict:
    """The options that change what is collected inside a subscription, and so what a resume may reuse.

    The resolved subscription list is deliberately not part of it: ``--all`` run again an hour later
    may see a few more or fewer, and a subscription that is done is done whichever way the list came
    about. How the list was asked for is: a run for one subscription does not resume a run for all.
    ``scope`` is ``main._scope_kind``'s answer, the same one that picks the list.
    """
    return {
        "tool": "azure",
        "cloud": cloud,
        "scope": scope,
        "regions": sorted(regions) if regions else None,
        "scans": {key: bool(value) for key, value in sorted(scans.items())},
        "skips": sorted(skips),
        "devops": bool(devops),
        "devops_orgs": devops_orgs or "",
    }


def scan_checkpoint(scan: tuple, access: list, gaps: Optional[dict] = None) -> dict:
    """What is saved for a subscription whose scan finished: the six results, as the plain JSON they
    serialise to, its access-check rows, and the gaps its scan logged (a count and a few examples),
    so a later run can say which subscriptions had gaps and why without scanning them again."""
    from models.inventory import _asdict_safe

    return {
        "parts": {name: _asdict_safe(obj) for name, obj in zip(SCAN_PARTS, scan)},
        "access": list(access),
        "gaps": dict(gaps) if gaps else {"count": 0, "examples": []},
    }


def gaps_of(data: dict) -> dict:
    """The gaps a saved subscription's scan logged: ``{"count", "examples"}``.

    A checkpoint saved before gaps were recorded has none, and reads as none: it was not rescanned
    only because nothing then said it should be.
    """
    found = data.get("gaps") if isinstance(data, dict) else None
    if not isinstance(found, dict):
        return {"count": 0, "examples": []}
    return {"count": int(found.get("count") or 0), "examples": list(found.get("examples") or [])}


def valid(data: Any) -> bool:
    """Whether a loaded checkpoint holds everything a resume needs."""
    if not isinstance(data, dict) or not all(key in data for key in _REQUIRED):
        return False
    parts = data["parts"]
    return isinstance(parts, dict) and all(isinstance(parts.get(name), dict) for name in SCAN_PARTS)


def part_classes() -> dict:
    """The dataclass each saved part was serialised from, by part name."""
    from collectors.backup_jobs import BackupJobsInventory
    from collectors.backup_posture import BackupPostureInventory
    from collectors.compute import ComputeInventory
    from collectors.cost import CostSummary
    from collectors.database import DatabaseInventory
    from collectors.storage import StorageInventory

    return {
        "compute": ComputeInventory,
        "backup_posture": BackupPostureInventory,
        "storage": StorageInventory,
        "database": DatabaseInventory,
        "backup_jobs": BackupJobsInventory,
        "cost": CostSummary,
    }


def restore(data: dict) -> tuple:
    """A saved subscription's scan as the six objects _collect_subscription returns (Saved inventories)."""
    classes = part_classes()
    return tuple(Saved(data["parts"][name], classes[name]) for name in SCAN_PARTS)


def split(store: Any, subscriptions: list, retry_partial: bool = True) -> tuple:
    """Which subscriptions to scan and which to take from the saved run: (todo, reuse, notes).

    One that finished with gaps is scanned again (``retry_partial``, the default) so a gap cannot
    hide behind "saved"; ``--keep-partial`` keeps it as it was.
    """
    done = store.completed()
    todo: list = []
    reuse: list = []
    notes: list = []
    unreadable = 0
    for sub in subscriptions:
        if sub not in done or (retry_partial and done[sub]):
            todo.append(sub)
            continue
        loaded = store.load(sub)
        if loaded is None or not valid(loaded[0]):
            unreadable += 1
            todo.append(sub)
        else:
            reuse.append(sub)
    outside = len(set(done) - set(subscriptions))
    if outside:
        notes.append(
            f"{outside} saved subscription(s) are not in this run's list and are left out of the results."
        )
    if unreadable:
        notes.append(f"{unreadable} saved subscription(s) could not be read and are scanned again.")
    partial = [sub for sub in reuse if done[sub]]
    if partial:
        notes.append(
            f"{len(partial)} subscription(s) finished with gaps in the earlier run and are kept as "
            "they were because of --keep-partial; their gaps are still in the results."
        )
    again = [sub for sub in todo if done.get(sub)]
    if again:
        notes.append(
            f"{len(again)} subscription(s) finished with gaps in the earlier run and are scanned "
            "again (add --keep-partial to keep them as they were)."
        )
    return todo, reuse, notes


def keep_progress(not_scanned: list, gaps: Optional[list] = None) -> bool:
    """Whether the progress folder is kept after the results are written.

    It is kept when any subscription has no saved result (it could not be read, or its scan failed)
    or finished with gaps, so a later --resume can scan just those again once the cause is fixed:
    that is what makes rescanning partial subscriptions by default mean anything. When every
    subscription has a full result there is nothing to resume, so it is removed.
    """
    return bool(not_scanned) or bool(gaps)


def mode_of(args: Any) -> str:
    if getattr(args, "fresh", False):
        return core.FRESH
    if getattr(args, "resume", False):
        return core.RESUME
    return core.AUTO
