"""The run-log core is shipped as a copy inside each tool, like the pre-flight core.

``common/runlog.py`` is the tested original; each tool holds a byte-identical ``runlog_core.py``.
Edit the original, then copy it over the three.
"""

import ast
from pathlib import Path

import pytest

PY = Path(__file__).resolve().parents[2]
ORIGINAL = PY / "common" / "runlog.py"
TOOLS = ("aws", "azure", "gcp")
COPIES = [PY / tool / "runlog_core.py" for tool in TOOLS]
STANDARD_LIBRARY = {
    "__future__",
    "collections",
    "datetime",
    "importlib",
    "logging",
    "os",
    "platform",
    "re",
    "shutil",
    "signal",
    "subprocess",
    "sys",
    "textwrap",
    "threading",
    "traceback",
    "typing",
}


@pytest.mark.parametrize("copy", COPIES, ids=TOOLS)
def test_each_tools_copy_is_identical_to_the_original(copy):
    assert copy.read_bytes() == ORIGINAL.read_bytes(), (
        f"{copy.relative_to(PY)} differs from common/runlog.py; "
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


@pytest.mark.parametrize("path", [ORIGINAL, *COPIES], ids=lambda p: str(p.relative_to(PY)))
def test_the_core_parses_as_python_3_9(path):
    ast.parse(path.read_text(encoding="utf-8"), feature_version=(3, 9))
