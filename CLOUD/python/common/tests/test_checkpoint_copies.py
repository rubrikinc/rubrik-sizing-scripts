"""The checkpoint core is shipped as a copy inside each tool, like the pre-flight, run-log and manifest cores.

``common/checkpoint.py`` is the tested original; each tool holds a byte-identical ``checkpoint_core.py``.
Edit the original, then copy it over the three.
"""

import ast
from pathlib import Path

import pytest

PY = Path(__file__).resolve().parents[2]
ORIGINAL = PY / "common" / "checkpoint.py"
TOOLS = ("aws", "azure", "gcp")
COPIES = [PY / tool / "checkpoint_core.py" for tool in TOOLS]
STANDARD_LIBRARY = {
    "__future__",
    "datetime",
    "glob",
    "hashlib",
    "json",
    "logging",
    "os",
    "re",
    "shutil",
    "sys",
    "tempfile",
    "typing",
}


@pytest.mark.parametrize("copy", COPIES, ids=TOOLS)
def test_each_tools_copy_is_identical_to_the_original(copy):
    assert copy.read_bytes() == ORIGINAL.read_bytes(), (
        f"{copy.relative_to(PY)} differs from common/checkpoint.py; "
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


@pytest.mark.parametrize("tool", TOOLS)
def test_each_tool_lists_its_copy_for_packaging(tool):
    pyproject = (PY / tool / "pyproject.toml").read_text(encoding="utf-8")
    assert '"checkpoint_core"' in pyproject
