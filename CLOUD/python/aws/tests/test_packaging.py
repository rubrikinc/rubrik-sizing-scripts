"""The installed package must contain every top-level module the tool imports.

Tests run from the source folder, where every module is importable, so a module missing from
``py-modules`` in pyproject.toml only shows up after ``pip install`` as an ImportError.
"""

import re
from pathlib import Path

AWS = Path(__file__).resolve().parents[1]


def _declared(key: str) -> set[str]:
    text = (AWS / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(rf"^{key}\s*=\s*\[(.*?)\]", text, re.S | re.M)
    assert match, f"{key} not found in pyproject.toml"
    return set(re.findall(r'"([^"]+)"', match.group(1)))


def test_every_top_level_module_is_packaged():
    modules = {p.stem for p in AWS.glob("*.py")}
    assert modules == _declared("py-modules")


def test_every_package_folder_is_packaged():
    folders = {p.parent.name for p in AWS.glob("*/__init__.py") if p.parent.name != "tests"}
    assert folders == _declared("packages")
