"""The pinned requirements: every package at an exact version, every declared dependency covered,
and the tools' pins the same as the set the test suites install, so tests run on what users get."""

import re

import pytest
from bootstrap_support import PY_DIR
from packaging.markers import default_environment
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

TOOLS = ("aws", "azure", "gcp")
# The Python versions each tool supports, as the locks are resolved for.
PYTHONS = {"aws": ("3.9", "3.10"), "azure": ("3.10",), "gcp": ("3.10",)}
TEST_LOCK = PY_DIR / "requirements-test.txt"
DEV_TOOLS = {"pytest", "build", "playwright"}


def _requirements(path):
    """The requirement lines of a requirements file, without comments or -r/-c lines."""
    lines = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split(" #", 1)[0].strip()
        if line and not line.startswith(("#", "-")):
            lines.append(Requirement(line))
    return lines


def _environment(python):
    env = default_environment()
    env.update(python_version=python, python_full_version=f"{python}.0")
    return env


def _pins(path, python):
    """name -> version for the pins of a lock that apply to ``python``."""
    pins = {}
    for req in _requirements(path):
        if req.marker is None or req.marker.evaluate(_environment(python)):
            pins[canonicalize_name(req.name)] = next(iter(req.specifier)).version
    return pins


@pytest.mark.parametrize("path", [PY_DIR / t / "requirements.txt" for t in TOOLS] + [TEST_LOCK])
def test_every_package_is_pinned_to_one_exact_version(path):
    loose = [str(r) for r in _requirements(path) if [s.operator for s in r.specifier] != ["=="]]
    assert not loose, f"{path.name} has requirements that are not exact pins: {loose}"
    assert "./update_requirements.sh" in path.read_text(encoding="utf-8")[:300]


@pytest.mark.parametrize("tool", TOOLS)
def test_every_declared_dependency_is_pinned_within_its_range(tool):
    declared = _requirements(PY_DIR / tool / "requirements.in")
    for python in PYTHONS[tool]:
        pins = _pins(PY_DIR / tool / "requirements.txt", python)
        for req in declared:
            if req.marker is not None and not req.marker.evaluate(_environment(python)):
                continue
            version = pins.get(canonicalize_name(req.name))
            assert version, f"{tool}: {req.name} is not pinned for Python {python}"
            assert req.specifier.contains(
                version, prereleases=True
            ), f"{tool}: {req.name}=={version} is outside {req.specifier} (Python {python})"


@pytest.mark.parametrize("tool", TOOLS)
def test_the_tools_pins_are_the_versions_the_tests_run_on(tool):
    tested = _pins(TEST_LOCK, "3.10")
    pins = _pins(PY_DIR / tool / "requirements.txt", "3.10")
    differ = {
        name: (version, tested.get(name))
        for name, version in pins.items()
        if tested.get(name) != version
    }
    assert not differ, f"{tool} pins differ from requirements-test.txt: {differ}"


@pytest.mark.parametrize("tool", TOOLS)
def test_no_development_tool_is_installed_with_a_tool(tool):
    names = {canonicalize_name(r.name) for r in _requirements(PY_DIR / tool / "requirements.txt")}
    assert not names & DEV_TOOLS


@pytest.mark.parametrize("tool", TOOLS)
def test_the_packaged_dependencies_are_all_declared(tool):
    # Read with a pattern, as the CI image's Python 3.10 has no tomllib.
    text = (PY_DIR / tool / "pyproject.toml").read_text(encoding="utf-8")
    block = re.search(r"^dependencies\s*=\s*\[(.*?)^\]", text, re.S | re.M).group(1)
    packaged = {canonicalize_name(Requirement(d).name) for d in re.findall(r'"([^"]+)"', block)}
    declared = {canonicalize_name(r.name) for r in _requirements(PY_DIR / tool / "requirements.in")}
    assert packaged <= declared, f"{tool}: in pyproject.toml only: {sorted(packaged - declared)}"


def test_the_test_set_covers_every_tool():
    text = (PY_DIR / "requirements-test.in").read_text(encoding="utf-8")
    assert all(re.search(rf"^-r {tool}/requirements\.in$", text, re.M) for tool in TOOLS)
