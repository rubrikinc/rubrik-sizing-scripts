"""The installed package must contain every top-level module the tool imports.

Tests run from the source folder, where every module is importable, so a module missing from
``py-modules`` in pyproject.toml only shows up after ``pip install`` as an ImportError. Azure's
``main.py`` imports ``csv_export`` and ``anonymize``; with neither listed, a wheel built from this
folder failed on its first import. The folders (``collectors``, ``models``) are found by a pattern
under ``[tool.setuptools.packages.find]`` rather than listed, so they are checked against that.
"""

import re
from pathlib import Path

AZURE = Path(__file__).resolve().parents[1]
PYPROJECT = (AZURE / "pyproject.toml").read_text(encoding="utf-8")


def _py_modules() -> set[str]:
    match = re.search(r"^py-modules\s*=\s*\[(.*?)\]", PYPROJECT, re.S | re.M)
    assert match, "py-modules not found in pyproject.toml"
    return set(re.findall(r'"([^"]+)"', match.group(1)))


def _package_patterns() -> list[str]:
    match = re.search(r"^include\s*=\s*\[(.*?)\]", PYPROJECT, re.S | re.M)
    assert match, "packages.find include not found in pyproject.toml"
    return re.findall(r'"([^"]+)"', match.group(1))


def test_every_top_level_module_is_packaged():
    modules = {p.stem for p in AZURE.glob("*.py")}
    assert modules == _py_modules()


def test_every_package_folder_is_found_by_the_include_patterns():
    folders = {p.parent.name for p in AZURE.glob("*/__init__.py") if p.parent.name != "tests"}
    patterns = _package_patterns()
    unmatched = {f for f in folders if not any(re.fullmatch(p.replace("*", ".*"), f) for p in patterns)}
    assert unmatched == set(), f"not packaged: {sorted(unmatched)}"


def test_tests_are_not_packaged():
    assert '"tests*"' in PYPROJECT.split("exclude", 1)[-1]


def test_the_entry_point_names_a_packaged_module():
    entry = re.search(r'^rubrik-discovery\s*=\s*"([^":]+):', PYPROJECT, re.M)
    assert entry, "console entry point not found"
    assert entry.group(1) in _py_modules()
