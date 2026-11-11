"""packaging/make_cloud_zips.sh: each zip holds the tool as committed, its docs and a quickstart whose
commands the tool accepts, and nothing else."""

import re
import shutil
import subprocess
import zipfile

import pytest
from bootstrap_support import PY_DIR

SCRIPT = PY_DIR / "packaging" / "make_cloud_zips.sh"
CLOUDS = ("aws", "azure", "gcp")
DOCS = (
    "user-guide.md",
    "permissions.md",
    "troubleshooting.md",
    "logging.md",
    "powershell-parameter-mapping.md",
)
# Lines of the quickstart that run another program, whose options are not the tool's.
OTHER_COMMANDS = ("aws ", "az ", "gcloud ", "export ", "unset ", "python3 -m venv", ".venv/bin/pip")


def _git(*args):
    return subprocess.run(
        ["git", "-C", str(PY_DIR), *args], capture_output=True, text=True, check=False
    )


pytestmark = pytest.mark.skipif(
    shutil.which("bash") is None
    or shutil.which("tar") is None
    or _git("rev-parse", "HEAD").returncode != 0,
    reason="needs bash, tar and a git checkout",
)


@pytest.fixture(scope="module")
def zips(tmp_path_factory):
    out = tmp_path_factory.mktemp("zips")
    run = subprocess.run(
        ["bash", str(SCRIPT), "", "HEAD", str(out)], capture_output=True, text=True, check=False
    )
    assert run.returncode == 0, run.stderr
    commit = _git("rev-parse", "--short", "HEAD").stdout.strip()
    built = {cloud: out / f"rubrik-cloud-sizing-{cloud}-{commit}.zip" for cloud in CLOUDS}
    assert all(path.is_file() for path in built.values()), sorted(p.name for p in out.iterdir())
    return built


def _names(path):
    return zipfile.ZipFile(path).namelist()


def _read(path, member):
    return zipfile.ZipFile(path).read(member)


@pytest.mark.parametrize("cloud", CLOUDS)
def test_a_zip_holds_the_tool_its_docs_and_a_quickstart(zips, cloud):
    root = f"rubrik-cloud-sizing-{cloud}/"
    names = set(_names(zips[cloud]))
    expected = {"main.py", "requirements.txt", "QUICKSTART.md"}
    expected |= {f"docs/{doc}" for doc in DOCS + (f"{cloud}-vs-powershell.md",)}
    assert {root + name for name in expected} <= names


@pytest.mark.parametrize("cloud", CLOUDS)
def test_a_zip_holds_nothing_else(zips, cloud):
    names = _names(zips[cloud])
    assert not [n for n in names if "/tests/" in n or "__pycache__" in n or n.endswith(".pyc")]
    assert all(n.startswith(f"rubrik-cloud-sizing-{cloud}/") for n in names)


@pytest.mark.parametrize("cloud", CLOUDS)
def test_the_code_is_the_committed_code(zips, cloud):
    committed = _git("show", f"HEAD:sizing_scripts/cloud/python/{cloud}/main.py").stdout
    zipped = _read(zips[cloud], f"rubrik-cloud-sizing-{cloud}/main.py").decode()
    assert zipped == committed


@pytest.mark.parametrize("cloud", CLOUDS)
def test_every_option_the_quickstart_names_is_one_the_tool_has(zips, cloud):
    quickstart = _read(zips[cloud], f"rubrik-cloud-sizing-{cloud}/QUICKSTART.md").decode()
    lines = [
        line for line in quickstart.splitlines() if not line.strip().startswith(OTHER_COMMANDS)
    ]
    named = set(re.findall(r"(?<![\w-])(--[a-z][a-z-]+)", "\n".join(lines))) - {"--help"}
    source = (PY_DIR / cloud / "main.py").read_text(encoding="utf-8")
    missing = sorted(option for option in named if f'"{option}"' not in source)
    assert named and not missing, f"{cloud} QUICKSTART names options the tool lacks: {missing}"


@pytest.mark.parametrize("cloud", CLOUDS)
def test_the_quickstart_uses_commands_that_work_in_bash_and_powershell(zips, cloud):
    quickstart = _read(zips[cloud], f"rubrik-cloud-sizing-{cloud}/QUICKSTART.md").decode()
    assert "source .venv" not in quickstart
    assert ".venv/bin/pip install -r requirements.txt" in quickstart
    assert ".venv/bin/python main.py" in quickstart
