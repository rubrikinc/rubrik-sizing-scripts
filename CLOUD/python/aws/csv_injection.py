"""CSV formula injection (SPARK-957429), as ``Protect-CsvValue`` in ``Get-AWSSizingInfo.ps1``.

A cell that begins with ``=``, ``+``, ``-``, ``@``, a tab, a CR or an LF is read by a spreadsheet as a
formula (``=WEBSERVICE(...)``, DDE). Anyone with tag-write access in a customer account controls those
values, so they get a single quote in front, which makes the spreadsheet treat the cell as text.

The PowerShell function applies this to tag values, to the Name tag of EC2 instances, volumes and FSx
file systems, and to the Description of AMIs and snapshots, and nowhere else. The Python exporter uses
it in the same places. Only text is changed: numbers and booleans are not text and are returned as they
are, so a negative number stays a number.
"""

from __future__ import annotations

from typing import Any

# The same set as the PowerShell regex '^[=+\-@\t\r\n]'.
_FORMULA_START = ("=", "+", "-", "@", "\t", "\r", "\n")


def protect_csv_value(value: Any) -> Any:
    """``value`` with a single quote in front if it is text that starts like a formula."""
    if isinstance(value, str) and value.startswith(_FORMULA_START):
        return "'" + value
    return value
