"""Each tool's real output conforms to the contract extracted from the PowerShell scripts.

The contract (``columns.json``) is built from the PowerShell code. These tests run each tool, read the
manifest that goes into its zip (file name, kind and columns, as written), and check every CSV file's name
and header against it. A column the tool adds, drops or reorders, or a file it writes that PowerShell does
not, fails here instead of surfacing when something downstream reads the file.

Two kinds of difference are allowed, and only by name, so each one is visible and has to be removed on
purpose:
  * ``NOT_YET_IN_THE_CONTRACT``: a file the Python tool writes whose PowerShell source is not on this
    branch yet, so the contract cannot list it;
  * an empty file (a zero-byte file is what PowerShell writes when there is nothing to report).
"""

from __future__ import annotations

import json
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from contract.contract import Contract

PY = Path(__file__).resolve().parents[2]

# Files the Python tools write that the contract does not list yet. Remove an entry when the PowerShell
# change that adds the file reaches this branch and columns.json is regenerated.
NOT_YET_IN_THE_CONTRACT = {
    "gcp": set(),
    "aws": set(),
    "azure": set(),
}

_RUN = (
    "import sys; sys.path[:0]=[{tool_dir!r}, {py!r}]; import main; "
    "sys.argv=['main.py','--mock','--output',{out!r}]; main.main()"
)


def _mock_manifest(tool: str, out: Path) -> dict:
    code = _RUN.format(tool_dir=str(PY / tool), py=str(PY), out=str(out))
    done = subprocess.run(
        [sys.executable, "-I", "-c", code], cwd=PY / tool, capture_output=True, text=True
    )
    assert done.returncode == 0, done.stderr[-800:]
    (archive,) = out.glob("*_sizing_results_*.zip")
    return json.loads(zipfile.ZipFile(archive).read("manifest.json"))


@pytest.fixture(scope="module")
def contract():
    return Contract.load()


@pytest.mark.parametrize("tool", ["azure", "gcp"])
def test_every_csv_file_a_mock_run_writes_conforms_to_the_contract(tool, contract, tmp_path):
    manifest = _mock_manifest(tool, tmp_path)
    csv_files = [e for e in manifest["files"] if e["name"].endswith(".csv")]
    assert csv_files, f"the {tool} mock run wrote no CSV files"
    problems = []
    for entry in csv_files:
        if entry["kind"] in NOT_YET_IN_THE_CONTRACT[tool]:
            continue
        spec = contract.spec(entry["kind"])  # a file the contract does not list raises KeyError
        if not entry["columns"]:
            continue  # a zero-byte file: nothing to report
        issues = spec.check_header(entry["columns"])
        if issues:
            problems.append(f"{entry['kind']}: {issues[:3]}")
    assert problems == []


@pytest.mark.parametrize("tool", ["azure", "gcp"])
def test_every_file_name_a_mock_run_writes_follows_the_contracts_rules(tool, contract, tmp_path):
    manifest = _mock_manifest(tool, tmp_path)
    for entry in manifest["files"]:
        if not entry["name"].endswith(".csv") or entry["kind"] in NOT_YET_IN_THE_CONTRACT[tool]:
            continue
        spec = contract.spec(entry["kind"])
        stamp = entry["name"][len(entry["kind"]) + len(spec.separator) : -len(".csv")]
        assert entry["name"] == spec.file_name(stamp), entry["name"]


def _load_tool_module(tool: str, name: str):
    """Load ``<tool>/<name>.py`` under a name of its own.

    Each tool has a module called ``csv_export`` (and so on), and Python caches a module by name, so a
    plain ``import csv_export`` returns whichever tool's was imported first in the process. Loading by
    path under ``<tool>_<name>`` keeps the three apart, whatever order the tests run in. The tool's own
    folder is on the path while it loads, because its modules import each other by name.
    """
    import importlib.util

    key = f"_conformance_{tool}_{name}"
    if key in sys.modules:
        return sys.modules[key]
    path = PY / tool / f"{name}.py"
    spec = importlib.util.spec_from_file_location(key, path)
    module = importlib.util.module_from_spec(spec)
    saved = {n: sys.modules.pop(n) for n in list(sys.modules) if _is_tool_local(n, tool)}
    sys.path[:0] = [str(PY / tool), str(PY)]
    try:
        sys.modules[key] = module
        spec.loader.exec_module(module)
    finally:
        del sys.path[:2]
        for n in [m for m in list(sys.modules) if _is_tool_local(m, tool)]:
            if n not in saved:
                del sys.modules[n]
        sys.modules.update(saved)
    return module


def _is_tool_local(module_name: str, tool: str) -> bool:
    """True for a top-level module that exists as a file in ``<tool>/`` (so it may be shadowed)."""
    top = module_name.split(".")[0]
    return (PY / tool / f"{top}.py").exists() or (PY / tool / top).is_dir()


def _aws_manifest(**extra_records) -> dict:
    """The manifest of the AWS exporter's files for its test fixture (AWS has no mock run), with any
    extra record collections added. The same files go into the zip."""
    csv_export = _load_tool_module("aws", "csv_export")
    manifest_core = _load_tool_module("aws", "manifest_core")
    result = _aws_fixture()
    result.update(extra_records)
    files = csv_export.build_csv_files([result], _AWS_STAMP)
    return json.loads(manifest_core.build(files, tool="aws"))


_AWS_STAMP = "2026-10-05_140650"


def _aws_fixture() -> dict:
    """The AWS exporter's test fixture, loaded from its own tests without importing ``tests`` by name
    (every tool has a ``tests`` package)."""
    import importlib.util

    key = "_conformance_aws_fixture"
    if key not in sys.modules:
        path = PY / "aws" / "tests" / "test_csv_export.py"
        spec = importlib.util.spec_from_file_location(key, path)
        module = importlib.util.module_from_spec(spec)
        saved = {n: sys.modules.pop(n) for n in list(sys.modules) if _is_tool_local(n, "aws")}
        sys.path[:0] = [str(PY / "aws"), str(PY)]
        try:
            sys.modules[key] = module
            spec.loader.exec_module(module)
        finally:
            del sys.path[:2]
            for n in [m for m in list(sys.modules) if _is_tool_local(m, "aws")]:
                if n not in saved:
                    del sys.modules[n]
            sys.modules.update(saved)
    return sys.modules[key]._result()


# A header-only file (nothing to report) is written from a hand-made header in the PowerShell script, and
# for aws_redshift_info that header puts ResourceArn 13th while the rows put it 5th. Python reproduces both.
# So a header-only file may carry the fallback header, by name; a populated file never may.
POWERSHELL_FALLBACK_HEADER_ORDER = {"aws_redshift_info"}

_REDSHIFT_CLUSTER = dict(
    account_id="057149785675",
    account_alias="",
    region="us-west-2",
    cluster_identifier="rs-1",
    node_type="ra3.xlplus",
    number_of_nodes=2,
    cluster_status="available",
    master_username="admin",
    db_name="dev",
    cluster_create_time="2026-10-03T00:30:00+00:00",
    automated_snapshot_retention_period=1,
    manual_snapshot_retention_period=-1,
)


def _aws_problems(manifest: dict, contract) -> list:
    problems = []
    for entry in manifest["files"]:
        if not entry["name"].endswith(".csv") or entry["kind"] in NOT_YET_IN_THE_CONTRACT["aws"]:
            continue
        spec = contract.spec(entry["kind"])
        if not entry["columns"]:
            continue
        if entry["rows"] == 0 and entry["kind"] in POWERSHELL_FALLBACK_HEADER_ORDER:
            continue  # the fallback header: same columns, PowerShell's own order (checked below)
        issues = spec.check_header(entry["columns"])
        if issues:
            problems.append(f"{entry['kind']}: {issues[:3]}")
    return problems


def test_the_aws_exporter_output_conforms_to_the_contract(contract):
    assert _aws_problems(_aws_manifest(), contract) == []


def test_a_populated_redshift_file_follows_the_contract_order(contract):
    """The fixture has no clusters, so the file above is header-only; this checks the rows' order."""
    manifest = _aws_manifest(redshift_clusters=[_REDSHIFT_CLUSTER])
    entry = next(e for e in manifest["files"] if e["kind"] == "aws_redshift_info")
    assert entry["rows"] == 1
    assert contract.spec("aws_redshift_info").check_header(entry["columns"]) == []
    assert entry["columns"].index("ResourceArn") == 4


def test_the_redshift_fallback_header_has_the_same_columns_as_the_contract(contract):
    """Only the order may differ (PowerShell's hand-made header); a missing or extra column is a bug."""
    manifest = _aws_manifest()
    entry = next(e for e in manifest["files"] if e["kind"] == "aws_redshift_info")
    assert entry["rows"] == 0
    spec = contract.spec("aws_redshift_info")
    assert sorted(entry["columns"]) == sorted(spec.static)


def test_a_populated_file_never_gets_the_fallback_exception():
    """The exception covers header-only files; a populated one with the wrong order must still fail."""
    assert POWERSHELL_FALLBACK_HEADER_ORDER == {"aws_redshift_info"}


def _master_gcp_script() -> str:
    """master's Get-GCPSizingInfo.ps1, or a skip when git or origin/master is not available."""
    import shutil

    git = shutil.which("git")
    if not git:
        pytest.skip("git is not installed")
    shown = subprocess.run(
        [git, "show", "origin/master:sizing_scripts/cloud/Get-GCPSizingInfo.ps1"],
        cwd=PY,
        capture_output=True,
        text=True,
    )
    if shown.returncode != 0:
        pytest.skip("origin/master is not available")
    return shown.stdout


def test_the_bigquery_file_matches_masters_powershell_while_the_contract_lacks_it():
    """gce_bigquery_info is in NOT_YET_IN_THE_CONTRACT, so the contract cannot check it. Until it can, check
    the static columns against the row master's PowerShell builds, in order (the case of Gb/GB differs
    and the importer ignores it)."""
    import re

    text = _master_gcp_script()
    start = text.index("Get-GCPBigQueryInventory {")
    block = text[start : start + 12000]
    body = block[block.index("$tableObj = [PSCustomObject]@{") :]
    body = body[: body.index("\n                    }")]
    powershell = re.findall(r'^\s*"?([A-Za-z]+)"?\s*=', body, re.M)
    assert len(powershell) >= 20, "could not read the BigQuery row from master's script"

    gcp_csv_export = _load_tool_module("gcp", "csv_export")
    python = [
        c for c in gcp_csv_export._BIGQUERY_COLUMNS if not c.startswith(("Label/Tag", "Tag"))
    ]
    assert [c.lower() for c in python] == [c.lower() for c in powershell]


# The pre-flight report exists only in the Python tools (PowerShell has no such file), so columns.json
# cannot list it. Its columns are defined once, in common/preflight.py, and every tool copies that module.
PREFLIGHT_COLUMNS = [
    "Owner",
    "OwnerName",
    "Scope",
    "Service",
    "Permission",
    "Access",
    "Outcome",
    "ResourcesFound",
    "Detail",
    "OutputFilesAffected",
]


def test_the_preflight_columns_here_are_the_ones_the_shared_module_defines():
    """Guards the list above against drifting from common/preflight.py."""
    sys.path.insert(0, str(PY))
    try:
        from common import preflight
    finally:
        sys.path.remove(str(PY))
    assert list(preflight.CSV_COLUMNS) == PREFLIGHT_COLUMNS


@pytest.mark.parametrize("tool", ["aws", "azure", "gcp"])
def test_each_tools_preflight_report_has_the_shared_columns_and_name(tool):
    """A --mock run skips the check (it needs credentials), so this builds each tool's report from a
    sample row with the same code a real run uses, and checks the header and the file name rule."""
    import csv
    import io

    core = _load_tool_module(tool, "preflight_core")
    preflight = _load_tool_module(tool, "preflight")
    row = {
        "Owner": "1",
        "OwnerName": "n",
        "Scope": "s",
        "Service": "x",
        "Permission": "p",
        "Access": "readable",
        "Outcome": "captured",
        "ResourcesFound": "yes",
        "Detail": "",
        "OutputFilesAffected": "",
    }
    text = core.csv_text([row])
    parsed = list(csv.reader(io.StringIO(text)))
    assert parsed[0] == PREFLIGHT_COLUMNS
    assert len(parsed) == 2 and len(parsed[1]) == len(PREFLIGHT_COLUMNS)
    assert preflight.FILE_PREFIX == f"{tool}_preflight_check"
    assert core.file_name(preflight.FILE_PREFIX, "2026-10-20_230504") == (
        f"{tool}_preflight_check-2026-10-20_230504.csv"
    )


# Columns master's PowerShell writes that this branch's copy of the script (and so columns.json) does not
# have yet, by file. Empty while the copy is up to date. Remove an entry when the contract has the column;
# a test below fails if one is left behind.
COLUMNS_NOT_YET_IN_THE_CONTRACT: dict = {}


def _gcp_declared_columns() -> dict:
    gcp_csv_export = _load_tool_module("gcp", "csv_export")
    return {spec.prefix: list(spec.columns) for spec in gcp_csv_export.FILES}


def test_every_gcp_files_declared_columns_conform_to_the_contract(contract):
    """A --mock run has no VM or disk rows, so it cannot check those files' columns. The exporter declares
    them in FILES, so check that: this is what would have caught the base-2 columns the contract lacks."""
    problems = []
    for prefix, columns in _gcp_declared_columns().items():
        if prefix in NOT_YET_IN_THE_CONTRACT["gcp"]:
            continue
        allowed = COLUMNS_NOT_YET_IN_THE_CONTRACT.get(prefix, set())
        checked = [c for c in columns if c not in allowed]
        issues = contract.spec(prefix).check_header(checked)
        if issues:
            problems.append(f"{prefix}: {issues[:3]}")
    assert problems == []


def test_an_allowed_column_is_really_missing_from_the_contract(contract):
    """An entry in COLUMNS_NOT_YET_IN_THE_CONTRACT must go when the contract gains the column."""
    stale = []
    for prefix, columns in COLUMNS_NOT_YET_IN_THE_CONTRACT.items():
        known = set(contract.spec(prefix).static)
        stale += [f"{prefix}.{c}" for c in columns if c in known]
    assert stale == [], f"the contract has these now, remove them from the allowance: {stale}"


def test_the_allowed_columns_are_ones_masters_powershell_writes():
    """The allowance is for columns master's script has and this branch's copy lacks. Check master's script
    really has each one, so the list cannot name a column that exists nowhere in PowerShell."""
    text = _master_gcp_script()
    absent = [
        f"{prefix}.{column}"
        for prefix, columns in COLUMNS_NOT_YET_IN_THE_CONTRACT.items()
        for column in columns
        if f'"{column}"' not in text
    ]
    assert absent == [], f"not in master's Get-GCPSizingInfo.ps1: {absent}"


def test_the_allowed_columns_are_ones_the_python_tool_really_writes():
    """The allowance must not be a place to hide a column the tool does not write."""
    declared = _gcp_declared_columns()
    missing = [
        f"{prefix}.{c}"
        for prefix, columns in COLUMNS_NOT_YET_IN_THE_CONTRACT.items()
        for c in columns
        if c not in declared.get(prefix, [])
    ]
    assert missing == []


def test_an_allowed_exception_is_really_missing_from_the_contract(contract):
    """An entry in NOT_YET_IN_THE_CONTRACT must go when the contract gains the file, so it cannot linger."""
    stale = []
    for names in NOT_YET_IN_THE_CONTRACT.values():
        for kind in names:
            try:
                contract.spec(kind)
            except KeyError:
                continue
            stale.append(kind)
    assert stale == [], f"remove from NOT_YET_IN_THE_CONTRACT, the contract has them now: {stale}"
