"""The run guides and example scripts: complete, free of real identifiers, valid, and pointing at the public repository."""

import re
import shutil
import subprocess

import pytest
import test_deny_list
from bootstrap_support import PY_DIR

GUIDES = PY_DIR / "docs" / "run-guides"
CLOUDS = ("aws", "azure", "gcp")
ZERO_GUID = "00000000-0000-0000-0000-000000000000"
GUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
TWELVE_DIGITS = re.compile(r"(?<![\d-])\d{12}(?![\d-])")
DOCUMENTED_NUMBERS = {"123456789012", "234567890123"}  # the usual example account and org ids
EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+")
FILES = [GUIDES / f"{c}-run-guide.html" for c in CLOUDS] + [
    GUIDES / "examples" / f"run-{c}-sizing.sh" for c in CLOUDS
]


@pytest.mark.parametrize(
    "path",
    FILES
    + [GUIDES / "README.md", GUIDES / "check_guides.js", GUIDES / "examples" / "make_examples.js"],
    ids=lambda p: p.name,
)
def test_every_file_is_there(path):
    assert path.is_file() and path.stat().st_size > 200


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_no_real_identifier_is_in_a_guide_or_an_example(path):
    text = path.read_text(encoding="utf-8")
    assert set(GUID.findall(text)) <= {ZERO_GUID}, "a subscription or tenant id"
    assert not set(TWELVE_DIGITS.findall(text)) - DOCUMENTED_NUMBERS, "an AWS account id"
    assert set(EMAIL.findall(text)) <= {"git@github.com"}, "a person's address"
    assert "/Users/" not in text, "a personal path"
    assert set(re.findall(r"/home/(\w+)", text)) <= {
        "me"
    }, "a personal path (/home/me is the placeholder)"


@pytest.mark.parametrize(
    "cloud, placeholders",
    [
        (
            "aws",
            [
                "--sso-start-url 'https://YOUR-ORG.awsapps.com/start'",
                "--role-name 'YOUR_PERMISSION_SET'",
                "--accounts 'ACCOUNT_ID_1,ACCOUNT_ID_2'",
            ],
        ),
        ("azure", ["--subs 'SUBSCRIPTION_ID_1,SUBSCRIPTION_ID_2'"]),
        ("gcp", ["--projects 'PROJECT_ID_1,PROJECT_ID_2'"]),
    ],
)
def test_each_example_scans_placeholder_ids_and_says_to_replace_them(cloud, placeholders):
    text = (GUIDES / "examples" / f"run-{cloud}-sizing.sh").read_text(encoding="utf-8")
    command = next(line for line in text.splitlines() if line.startswith("python main.py"))
    assert all(p in command for p in placeholders), command
    assert text.splitlines()[2].startswith("# EXAMPLE: replace ")


@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
@pytest.mark.parametrize("cloud", CLOUDS)
def test_each_example_is_valid_bash(cloud):
    script = GUIDES / "examples" / f"run-{cloud}-sizing.sh"
    assert subprocess.run(["bash", "-n", str(script)], capture_output=True).returncode == 0


@pytest.mark.parametrize("cloud", CLOUDS)
def test_each_example_runs_its_own_tool_and_is_not_verbose(cloud):
    text = (GUIDES / "examples" / f"run-{cloud}-sizing.sh").read_text(encoding="utf-8")
    tool = re.search(r'TOOL_REL="CLOUD/python/(\w+)"', text).group(1)
    assert tool == cloud and (PY_DIR / tool / "main.py").is_file()
    assert "set -euo pipefail" in text and "python main.py" in text
    assert "--verbose" not in text


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_the_files_clone_the_public_repository_and_name_no_private_one(path):
    text = path.read_text(encoding="utf-8")
    assert "https://github.com/rubrikinc/rubrik-sizing-scripts.git" in text
    assert "--branch master" in text
    assert not test_deny_list.DENY.search(text)
    assert not re.search(r"scaledata|sizing_apps|cloud_sizing_script_python|git@github\.com", text)


def test_the_readme_describes_every_guide_and_example():
    text = (GUIDES / "README.md").read_text(encoding="utf-8")
    for cloud in CLOUDS:
        assert f"{cloud}-run-guide.html" in text and f"run-{cloud}-sizing.sh" in text


@pytest.mark.skipif(
    shutil.which("node") is None or shutil.which("bash") is None, reason="needs node and bash"
)
def test_each_guide_still_generates_valid_scripts_with_the_options_in_the_right_place():
    result = subprocess.run(["node", "check_guides.js"], cwd=GUIDES, capture_output=True, text=True)
    lines = result.stdout.strip().splitlines()
    assert result.returncode == 0, "\n".join(line for line in lines if line.startswith("FAIL"))
    assert len(lines) >= 24 and not [line for line in lines if line.startswith("FAIL")]


# ── the guides against the tools ──────────────────────────────────────────────

FILE_SPEC = re.compile(r"FileSpec\(\s*(?:prefix=)?\"([a-z0-9_]+)\"")


def _guide(cloud):
    return (GUIDES / f"{cloud}-run-guide.html").read_text(encoding="utf-8")


@pytest.mark.parametrize("cloud", CLOUDS)
def test_each_guide_names_every_file_its_tool_writes(cloud):
    exporter = (PY_DIR / cloud / "csv_export.py").read_text(encoding="utf-8")
    files = FILE_SPEC.findall(exporter)
    assert files, "no output file found in the exporter; has FileSpec changed shape?"
    missing = [name for name in files if name not in _guide(cloud)]
    assert not missing, f"{cloud}-run-guide.html does not name these files: {missing}"


def test_the_azure_guide_offers_every_skip_switch_of_the_tool():
    source = (PY_DIR / "azure" / "main.py").read_text(encoding="utf-8")
    tool = set(re.findall(r"\(\s*\(\"(--skip-[a-z-]+)\"", source))
    guide_text = _guide("azure")
    offered = set(re.findall(r"\[\"skip\w+\", \"(--skip-[a-z-]+)\"", guide_text))
    assert tool, "no skip switch found in main.py; has SKIP_SWITCHES changed shape?"
    assert (
        offered == tool
    ), f"in the tool only: {tool - offered}; in the guide only: {offered - tool}"
    for flag in tool:
        assert f"<code>{flag}</code>" in guide_text, f"the flags table does not list {flag}"


def test_the_azure_guide_needs_no_install_beyond_requirements_txt():
    guide_text = _guide("azure")
    assert "requirements-parity.txt" not in guide_text and 'id="parity"' not in guide_text
    assert "pip install -q -r requirements.txt" in guide_text
