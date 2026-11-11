"""The pre-flight core is shipped as a copy inside each tool.

An installed tool carries only its own modules (see each ``pyproject.toml``), so it cannot import
``common``. ``common/preflight.py`` is the tested original; each tool holds a byte-identical copy
named ``preflight_core.py``. Edit the original, then copy it over the three.
"""

import ast
import csv
import io
import re
from pathlib import Path

import pytest

from common import preflight as core
from common.consolidate import consolidate

PY = Path(__file__).resolve().parents[2]
ORIGINAL = PY / "common" / "preflight.py"
TOOLS = ("aws", "azure", "gcp")
COPIES = [PY / tool / "preflight_core.py" for tool in TOOLS]
STANDARD_LIBRARY = {"__future__", "concurrent", "csv", "dataclasses", "io", "re", "typing"}
IMPORT_OF_COMMON = re.compile(r"^\s*(from|import)\s+common\b", re.MULTILINE)


@pytest.mark.parametrize("copy", COPIES, ids=TOOLS)
def test_each_tools_copy_is_identical_to_the_original(copy):
    assert copy.read_bytes() == ORIGINAL.read_bytes(), (
        f"{copy.relative_to(PY)} differs from common/preflight.py; "
        "edit the original and copy it over all three"
    )


def test_the_core_imports_only_the_standard_library():
    imported = set()
    for node in ast.walk(ast.parse(ORIGINAL.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert imported <= STANDARD_LIBRARY, sorted(imported - STANDARD_LIBRARY)


def _shipped_sources(tool):
    for path in sorted((PY / tool).rglob("*.py")):
        relative = path.relative_to(PY / tool).parts
        if "tests" not in relative and "live" not in relative:
            yield path


@pytest.mark.parametrize("tool", TOOLS)
def test_no_shipped_module_imports_common(tool):
    offenders = [
        str(path.relative_to(PY))
        for path in _shipped_sources(tool)
        if IMPORT_OF_COMMON.search(path.read_text(encoding="utf-8"))
    ]
    assert offenders == [], "an installed tool has no `common` package to import"


@pytest.mark.parametrize(
    "path",
    [ORIGINAL, *COPIES, *[PY / tool / "preflight.py" for tool in TOOLS]],
    ids=lambda p: str(p.relative_to(PY)),
)
def test_the_new_modules_parse_as_python_3_9(path):
    ast.parse(path.read_text(encoding="utf-8"), feature_version=(3, 9))


def _report(owner):
    check = core.Check(
        owner, "", "us-east-1", "rds instances", core.DENIED, None, "AccessDenied", ("f",)
    )
    return core.csv_text([check.to_row()])


def test_the_reports_of_several_runs_combine_into_one_file(tmp_path):
    for stamp, owner in (
        ("2026-10-05_140650", "111111111111"),
        ("2026-10-06_090000", "222222222222"),
    ):
        name = core.file_name("aws_preflight_check", stamp)
        (tmp_path / name).write_text(_report(owner), encoding="utf-8", newline="")
    (written,) = consolidate(str(tmp_path), str(tmp_path / "out"))
    assert written.endswith("aws_preflight_check_combined.csv")
    rows = list(csv.DictReader(io.StringIO(Path(written).read_text(encoding="utf-8"))))
    assert [r["Owner"] for r in rows] == ["111111111111", "222222222222"]
    assert list(rows[0]) == list(core.CSV_COLUMNS)
