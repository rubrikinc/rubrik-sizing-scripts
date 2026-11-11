"""The manifest written into every results zip: what the tool produced, in a form CI and an importer can check.

``manifest.json`` lists the CSV and JSON data files in the zip (not the run log) with, for each, a
SHA-256 and, for a CSV file, its row count and its columns. It records the tool, its version and the
commit it ran from. It holds no names, tags or values, only file names, counts, hashes and column
names, so it is safe in an anonymized run.

Why: nothing in a zip said which tool or which column set produced a file, so a change in a column was
found only when something downstream broke. With the columns in the manifest, CI can compare them with
``contract/columns.json`` and an importer can see a change between two runs.

The importer reads only ``.csv``, ``.xlsx`` and ``.xls`` from a zip, so this file is ignored by it today,
as the run log and the JSON files are. Its name has no ``aws`` / ``azure`` / ``gce`` prefix, which the
importer uses to route a file to a cloud.

This module is shared as a byte-identical copy in each tool (``common/manifest.py`` is the original),
so it uses only the standard library and syntax that Python 3.9 accepts.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import re
from importlib import metadata
from typing import Dict, List, Mapping, Optional, Union

FILE_NAME = "manifest.json"
MANIFEST_VERSION = 1

Content = Union[str, bytes]

# The timestamp the tools put in a file name: 2026-10-05_140650 (AWS, GCP) or 2026-10-05_1406 (Azure).
_STAMP = re.compile(r"[-_]\d{4}-\d{2}-\d{2}_\d{4,6}$")
_DATA_SUFFIXES = (".csv", ".json")


def kind_of(name: str) -> str:
    """The kind of file: its name without the folder, the timestamp and the extension."""
    base = name.replace("\\", "/").rsplit("/", 1)[-1]
    stem = base.rsplit(".", 1)[0] if "." in base else base
    return _STAMP.sub("", stem)


def is_data_file(name: str) -> bool:
    """True for a CSV or JSON data file; false for the run log and for the manifest itself."""
    base = name.replace("\\", "/").rsplit("/", 1)[-1].lower()
    return base != FILE_NAME and base.endswith(_DATA_SUFFIXES)


def _as_bytes(content: Content) -> bytes:
    if isinstance(content, bytes):
        return content
    if isinstance(content, str):
        return content.encode("utf-8")
    raise TypeError("a file's content must be text or bytes, not %s" % type(content).__name__)


def _table(content: Content):
    """(columns, row count) of a CSV file's text; ([], 0) for an empty file.

    A leading byte order mark and the ``#TYPE`` line of PowerShell's Export-Csv are skipped. Rows are
    counted with a CSV parser, so a quoted comma or newline does not split one.
    """
    text = _as_bytes(content).decode("utf-8-sig", errors="replace")
    rows = [row for row in csv.reader(io.StringIO(text, newline="")) if row]
    if rows and len(rows[0]) == 1 and rows[0][0].startswith("#TYPE "):
        rows = rows[1:]
    if not rows:
        return [], 0
    return list(rows[0]), len(rows) - 1


def entry(name: str, content: Content) -> Dict[str, object]:
    """The manifest entry for one file."""
    data = _as_bytes(content)
    item = {
        "name": name,
        "kind": kind_of(name),
        "sha256": hashlib.sha256(data).hexdigest(),
    }  # type: Dict[str, object]
    if name.lower().endswith(".csv"):
        columns, rows = _table(data)
        item["rows"] = rows
        item["columns"] = columns
    else:
        item["rows"] = None
    return item


def build(
    files: Mapping[str, Content],
    tool: str,
    tool_version: Optional[str] = None,
    code_version: Optional[str] = None,
    generated_at: Optional[str] = None,
    scope: Optional[Mapping[str, object]] = None,
) -> str:
    """The text of ``manifest.json`` for ``files`` (name -> content), listed in name order.

    Only data files are listed: the run log, and the manifest itself, are left out. The same input
    always gives the same bytes, so two runs can be compared.

    ``scope`` says how much of the estate the run covered (a mode and counts, never names), so
    whoever reads the zip can tell a partial scan from a full one without the log. It is left out
    of the document when not given, so a tool that does not pass it writes the same bytes as before.
    """
    listed = [entry(name, files[name]) for name in sorted(files) if is_data_file(name)]
    document = {
        "manifest_version": MANIFEST_VERSION,
        "tool": tool,
        "tool_version": tool_version,
        "code_version": code_version,
        "generated_at": generated_at,
    }  # type: Dict[str, object]
    if scope is not None:
        document["scope"] = dict(scope)
    document["files"] = listed
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"


def installed_version(distribution: str) -> Optional[str]:
    """The installed version of ``distribution``, or None when the tool runs from a checkout."""
    try:
        return metadata.version(distribution)
    except Exception:  # noqa: BLE001 - not installed
        return None


def names(manifest_text: str) -> List[str]:
    """The file names a manifest lists."""
    return [item["name"] for item in json.loads(manifest_text)["files"]]
