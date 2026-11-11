"""CSV output matching PowerShell ``Export-Csv -NoTypeInformation``."""

from __future__ import annotations

import csv
import re
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


def format_value(value: Any) -> str:
    """Render a cell the way PowerShell does under the invariant culture."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "True" if value else "False"
    if isinstance(value, float):
        if value.is_integer() and abs(value) < 1e15:
            return str(int(value))
        text = repr(value)
        if "e" not in text and abs(value) >= 1e15:
            mantissa, exponent = f"{value:.14e}".split("e")
            text = f"{mantissa.rstrip('0').rstrip('.')}e{int(exponent):+03d}"
        return text.replace("e", "E")  # PowerShell writes 1E-05 where Python writes 1e-05
    return str(value)


def csv_file_name(prefix: str, timestamp: str) -> str:
    """Underscores inside the prefix, a hyphen before the timestamp."""
    clean = re.sub(r"[^A-Za-z0-9]+", "_", prefix).strip("_")
    return f"{clean}-{timestamp}.csv"


def write_csv(
    path: str | Path,
    columns: Sequence[str],
    rows: Iterable[Mapping[str, Any]],
) -> int:
    """Write ``rows`` with ``columns`` as the fixed header order.

    Every field is quoted. An empty collection yields a header-only file.
    A row key outside ``columns`` raises ValueError so contract drift fails loudly.
    Returns the number of data rows written.
    """
    allowed = set(columns)
    count = 0
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f, quoting=csv.QUOTE_ALL, lineterminator="\n")
        writer.writerow(columns)
        for row in rows:
            extra = set(row) - allowed
            if extra:
                raise ValueError(f"Columns not in contract: {sorted(extra)}")
            writer.writerow([format_value(row.get(c)) for c in columns])
            count += 1
    return count
