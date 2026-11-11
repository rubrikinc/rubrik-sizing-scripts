"""Output contract for the discovery CSV files (task B2).

Built from ``columns.json`` (extracted from the PowerShell scripts, see build_columns.py)
plus the file-name and value-format rules below. Emitters and tests use it to check that a
file name and header match what the PowerShell scripts produce.

Header rules (``FileSpec.check_header``):
  * no duplicate columns;
  * every column is a known static column or matches a dynamic pattern (``Tag: {key}``);
  * every required (non-optional) static column is present;
  * the static columns that are present keep the contract's relative order.
Dynamic columns may appear anywhere. Files with status ``partial`` skip the order check and
accept columns outside the list (some columns are computed at run time); files with status
``unresolved`` accept any header. Both are reported by ``strict_gaps``.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

COLUMNS_JSON = Path(__file__).resolve().parent / "columns.json"

# Timestamp written into file names, per cloud (PowerShell date format -> regex).
TIMESTAMPS = {
    "aws": ("yyyy-MM-dd_HHmmss", r"\d{4}-\d{2}-\d{2}_\d{6}"),
    "azure": ("yyyy-MM-dd_HHmm", r"\d{4}-\d{2}-\d{2}_\d{4}"),
    "gcp": ("yyyy-MM-dd_HHmmss", r"\d{4}-\d{2}-\d{2}_\d{6}"),
}

# How every CSV cell is written. Matches Export-Csv -NoTypeInformation under the invariant
# culture, and common/csv_writer.py.
VALUE_FORMAT = {
    "quote_all_fields": True,
    "header_row": True,
    "empty_collection": "header only",
    "null": "empty string",
    "boolean": ["True", "False"],
    "decimal_separator": ".",
    "thousands_separator": None,
    "line_terminator": "\n",
    "encoding": "utf-8",
    "bom": False,
}


@dataclass(frozen=True)
class FileSpec:
    cloud: str
    prefix: str
    separator: str
    extension: str
    status: str
    static: tuple[str, ...]
    optional: frozenset[str]
    dynamic: tuple[str, ...]
    notes: str = ""
    # Open decision (task list id) that the file's name or layout waits on.
    decision: Optional[str] = None
    _dyn_re: tuple[re.Pattern, ...] = field(default=(), repr=False, compare=False)

    @property
    def required(self) -> tuple[str, ...]:
        return tuple(c for c in self.static if c not in self.optional)

    def file_name_regex(self) -> re.Pattern:
        ts = TIMESTAMPS[self.cloud][1]
        stem = re.escape(self.prefix) + re.escape(self.separator)
        return re.compile(rf"^{stem}{ts}\.{re.escape(self.extension)}$")

    def file_name(self, timestamp: str) -> str:
        if not re.fullmatch(TIMESTAMPS[self.cloud][1], timestamp):
            raise ValueError(f"timestamp {timestamp!r} does not match {TIMESTAMPS[self.cloud][0]}")
        return f"{self.prefix}{self.separator}{timestamp}.{self.extension}"

    def is_dynamic(self, column: str) -> bool:
        return any(r.fullmatch(column) for r in self._dyn_re)

    def check_header(self, header: Iterable[str]) -> list[str]:
        """Problems found in ``header``; an empty list means it conforms."""
        cols = list(header)
        if self.status == "unresolved":
            return []
        problems = []
        dupes = sorted({c for c in cols if cols.count(c) > 1})
        if dupes:
            problems.append(f"duplicate columns: {dupes}")
        known = set(self.static)
        unknown = [c for c in cols if c not in known and not self.is_dynamic(c)]
        if unknown and self.status != "partial":
            problems.append(f"columns not in contract: {unknown}")
        missing = [c for c in self.required if c not in cols]
        if missing:
            problems.append(f"required columns missing: {missing}")
        if self.status != "partial":
            present = [c for c in cols if c in known]
            expected = [c for c in self.static if c in set(present)]
            if present != expected:
                problems.append(f"column order differs from contract: {present} != {expected}")
        return problems


def _dynamic_regex(pattern: str) -> Optional[re.Pattern]:
    if pattern.startswith("expr:"):
        return None
    parts = re.split(r"(\{\w+\})", pattern)
    body = "".join(".+" if p.startswith("{") else re.escape(p) for p in parts)
    return re.compile(body)


def _spec(cloud: str, entry: dict) -> FileSpec:
    dyn = tuple(entry.get("dynamic") or [])
    regs = tuple(r for r in (_dynamic_regex(d) for d in dyn) if r is not None)
    cols = entry.get("columns") or []
    return FileSpec(
        cloud=cloud,
        prefix=entry["prefix"],
        separator=entry["separator"],
        extension=entry["extension"],
        status=entry["status"],
        static=tuple(c["name"] for c in cols),
        optional=frozenset(c["name"] for c in cols if c["optional"]),
        dynamic=dyn,
        notes=entry.get("notes", ""),
        decision=entry.get("decision"),
        _dyn_re=regs,
    )


class Contract:
    def __init__(self, data: dict) -> None:
        self.files: dict[str, FileSpec] = {}
        for cloud, entries in data["clouds"].items():
            for entry in entries:
                spec = _spec(cloud, entry)
                if spec.prefix in self.files:
                    raise ValueError(f"duplicate file prefix {spec.prefix}")
                self.files[spec.prefix] = spec

    @classmethod
    def load(cls, path: Path = COLUMNS_JSON) -> "Contract":
        return cls(json.loads(Path(path).read_text(encoding="utf-8")))

    def spec(self, prefix: str) -> FileSpec:
        return self.files[prefix]

    def for_cloud(self, cloud: str) -> list[FileSpec]:
        return [s for s in self.files.values() if s.cloud == cloud]

    def match_file_name(self, name: str) -> Optional[FileSpec]:
        for spec in self.files.values():
            if spec.file_name_regex().match(name):
                return spec
        return None

    def check_csv(self, name: str, header: Iterable[str]) -> list[str]:
        """Check a produced file by name and header row."""
        spec = self.match_file_name(name)
        if spec is None:
            return [f"file name {name!r} matches no contract file"]
        return spec.check_header(header)

    def strict_gaps(self) -> list[str]:
        """Files the contract cannot fully pin down yet."""
        return [f"{s.prefix}: {s.status}" for s in self.files.values() if s.status != "resolved"]


def assert_conforms(contract: Contract, name: str, header: Iterable[str]) -> None:
    """Test helper for emitters: raises AssertionError listing every problem."""
    problems = contract.check_csv(name, header)
    assert not problems, f"{name}: " + "; ".join(problems)
