"""Combine the CSV files of several sizing runs into one file per kind.

Port of ``consolidate.ps1``. CSV files are grouped by the part of their name before the first
dash (``aws_ec2_instance_info-2026-10-05_140650.csv`` belongs to ``aws_ec2_instance_info``) and
each group is written to ``<prefix>_combined.csv`` with one header: every column any file in the
group has.

Rules kept from the PowerShell script:
  * every ``*.csv`` below the directory is read, subdirectories included;
  * a file whose name has no dash is ignored, and so is an empty one;
  * blank lines are skipped; a group without any row writes nothing;
  * a cell that exists but is empty is written as ``""``, a column a file does not have is left
    bare (null), and every other value is quoted;
  * a data cell that starts with ``= + - @``, a tab, a CR or an LF gets a single quote in front, so
    a spreadsheet does not read it as a formula (SPARK-957429). The header row is not changed.

The columns appear in the order they are first seen. PowerShell takes the columns that a later
file adds from a hashtable, so their order there changes from run to run.

Usage: ``python -m common.consolidate [DIRECTORY] [--output-dir DIR]``
"""

from __future__ import annotations

import argparse
import csv
import io
import os
import sys
from typing import Any, Iterator, Optional


def _quote(text: str) -> str:
    return '"' + text.replace('"', '""') + '"'


# The same set as ``Protect-CsvValue`` in consolidate.ps1 (SPARK-957429): '^[=+\-@\t\r\n]'.
_FORMULA_START = ("=", "+", "-", "@", "\t", "\r", "\n")


def _protect(text: str) -> str:
    """``text`` with a single quote in front if a spreadsheet would read it as a formula."""
    return "'" + text if text.startswith(_FORMULA_START) else text


def _csv_files(directory: str) -> Iterator[str]:
    """The folder's own CSV files, then each subfolder's, depth first, by name."""
    entries = sorted(os.listdir(directory), key=str.lower)
    paths = [os.path.join(directory, name) for name in entries]
    for path in paths:
        if os.path.isfile(path) and path.lower().endswith(".csv"):
            yield path
    for path in paths:
        if os.path.isdir(path):
            yield from _csv_files(path)


def _prefix(path: str) -> Optional[str]:
    """The name before the first dash, or None for a file the PowerShell script skips."""
    stem = os.path.splitext(os.path.basename(path))[0]
    return stem.split("-", 1)[0] if "-" in stem else None


def _read_rows(path: str) -> list[dict[str, Optional[str]]]:
    with open(path, encoding="utf-8-sig", newline="") as handle:
        text = handle.read()
    if not text.strip():
        return []
    lines = [row for row in csv.reader(io.StringIO(text)) if row]
    if not lines:
        return []
    header, rows = lines[0], lines[1:]
    return [
        {column: (row[i] if i < len(row) else None) for i, column in enumerate(header)}
        for row in rows
    ]


def _render(columns: list[str], rows: list[dict[str, Any]]) -> str:
    lines = [",".join(_quote(c) for c in columns)]
    for row in rows:
        lines.append(
            ",".join("" if row.get(c) is None else _quote(_protect(str(row[c]))) for c in columns)
        )
    return "\n".join(lines) + "\n"


def consolidate(directory: str = ".", output_dir: str = ".") -> list[str]:
    """Write ``<prefix>_combined.csv`` into ``output_dir`` for every group that has rows.

    Returns the paths written, in prefix order.
    """
    groups: dict[str, list[str]] = {}
    for path in _csv_files(directory):
        prefix = _prefix(path)
        if prefix is not None:
            groups.setdefault(prefix, []).append(path)

    written: list[str] = []
    for prefix in sorted(groups, key=str.lower):
        rows: list[dict[str, Optional[str]]] = []
        columns: list[str] = []
        for path in groups[prefix]:
            for row in _read_rows(path):
                rows.append(row)
                columns.extend(c for c in row if c not in columns)
        if not rows:
            continue
        os.makedirs(output_dir, exist_ok=True)
        target = os.path.join(output_dir, f"{prefix}_combined.csv")
        with open(target, "w", encoding="utf-8", newline="") as handle:
            handle.write(_render(columns, rows))
        written.append(target)
    return written


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Combine CSV files with the same prefix (the name before the first dash)."
    )
    parser.add_argument("directory", nargs="?", default=".", help="Folder with the CSV files")
    parser.add_argument(
        "--output-dir", default=".", help="Where to write the combined files (default: here)"
    )
    args = parser.parse_args(argv)
    if not os.path.isdir(args.directory):
        print(f"Not a directory: {args.directory}", file=sys.stderr)
        return 2
    for path in consolidate(args.directory, args.output_dir):
        print(f"Wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
