"""End-to-end runs of the REAL bootstrap scripts against PATH shims (no cloud, no PyPI)."""

import os
import shutil
import sys
from pathlib import Path

import pytest
from bootstrap_support import BASHES, PY_DIR, git_archive, make_cloud_shims, run_script

pytestmark = pytest.mark.skipif(
    shutil.which("curl") is None or shutil.which("git") is None,
    reason="e2e tests need curl and git",
)

REAL_TEMPLATE = (PY_DIR / "aws" / "iac" / "2-sizing-tool-spokes.yaml").read_text()
SPOKES = "iac/2-sizing-tool-spokes.yaml"


@pytest.fixture(params=BASHES)
def bash(request):
    return request.param


@pytest.fixture
def shim():
    d = make_cloud_shims("aws-sizing")
    yield d
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
def aws_archive(tmp_path):
    files = {
        "CLOUD/python/aws/pyproject.toml": '[project]\nname = "aws-sizing"\nversion = "4.5.6"\n',
        "CLOUD/python/aws/main.py": "print('hi')\n",
        "CLOUD/python/aws/" + SPOKES: REAL_TEMPLATE,
    }
    path, commit = git_archive(tmp_path, files)
    return path, commit


# An SSO run needs a permission set; without a terminal the installer cannot ask for one.
SSO = ["--sso", "--role-name", "Sizing-Ps"]


def calls(log, prefix):
    return [line for line in log if line.startswith(prefix)]


def run(tmp_path, shim, archive, args, **kw):
    path, _ = archive
    return run_script(tmp_path, "aws", args, shim=shim, url=path.as_uri(), **kw)


def assert_clean_run(res):
    text = res.stdout + res.stderr
    assert "unbound variable" not in text, text
    assert "Traceback" not in text, text
    assert "YOUR-ARTIFACTS-BUCKET" not in text
    assert res.leftovers == [], "temp dir must be removed on exit"


# --------------------------------------------------------------------------- SSO (default)


def test_sso_happy_path(tmp_path, shim, bash, aws_archive):
    _, commit = aws_archive
    res, log = run(tmp_path, shim, aws_archive, SSO, bash=bash)
    assert res.rc == 0, res.stdout + res.stderr
    assert_clean_run(res)
    # the discovery source (not a wheel) is what gets installed, and it existed when pip ran
    (pip,) = calls(log, "python3 -m pip install")
    assert "--ignore-installed" in pip and pip.rstrip().endswith("CLOUD/python/aws")
    assert any(line.startswith("PIP_SRC_HAS_PYPROJECT") for line in log)
    # version/ref/commit are reported from the fetched source
    assert "aws-sizing 4.5.6" in res.stdout and "master @ " + commit in res.stdout
    assert "(pinned" not in res.stdout
    # the tool is launched in SSO mode, and nothing touches S3 or CloudFormation
    (scan,) = calls(log, "aws-sizing --sso")
    assert "--role-name Sizing-Ps" in scan, scan
    assert not calls(log, "aws-sizing --org")
    assert not [line for line in log if line.startswith("aws ") and (" s3" in line or "cloudformation" in line)]
    assert not calls(log, "UNEXPECTED")
    # static box title (no version slot, no VERSION reference)
    assert "AWS Sizing Tool" in res.stdout and "AWS Sizing Tool  v" not in res.stdout


@pytest.mark.parametrize("args", [["--sso"], []])
def test_sso_without_a_permission_set_stops_before_anything_runs(tmp_path, shim, aws_archive, args):
    """No terminal to ask on (stdin is /dev/null): stop and say how to pass the permission set."""
    res, log = run(tmp_path, shim, aws_archive, args)
    text = res.stdout + res.stderr
    assert res.rc == 1, text
    assert "An SSO scan needs the permission set" in text and "--role-name" in text
    assert not [line for line in log if line.startswith(("aws ", "python3 -m pip", "aws-sizing"))], log
    assert "Traceback" not in text and res.leftovers == []


def test_sso_uses_user_install_outside_a_venv(tmp_path, shim, aws_archive):
    res, log = run(tmp_path, shim, aws_archive, SSO, in_venv=False)
    assert res.rc == 0, res.stdout + res.stderr
    (pip,) = calls(log, "python3 -m pip install")
    assert "--user" in pip


def test_flags_are_passed_through_to_the_tool(tmp_path, shim, aws_archive):
    res, log = run(tmp_path, shim, aws_archive,
                   ["--sso", "--regions", "us-east-1,us-west-2", "--exclude-regions", "eu-west-1",
                    "--services", "ec2,rds", "--accounts", "111122223333", "--role-name", "Admin"])
    assert res.rc == 0, res.stdout + res.stderr
    (scan,) = calls(log, "aws-sizing")
    for piece in ("--sso", "--regions us-east-1,us-west-2", "--exclude-regions eu-west-1",
                  "--services ec2,rds", "--accounts 111122223333", "--role-name Admin"):
        assert piece in scan, scan


def test_debug_flag_shows_source_dir(tmp_path, shim, aws_archive):
    res, _ = run(tmp_path, shim, aws_archive, [*SSO, "--debug"])
    assert res.rc == 0, res.stdout + res.stderr
    assert "Source dir: " in res.stdout


# --------------------------------------------------------------------------- single account (bug fix)


def test_single_account_never_enters_the_stackset_branch(tmp_path, shim, bash, aws_archive):
    """Regression: --single-account used to fall into the StackSet branch (SSO_MODE=false)."""
    res, log = run(tmp_path, shim, aws_archive, ["--single-account"], bash=bash)
    assert res.rc == 0, res.stdout + res.stderr
    assert_clean_run(res)
    assert not [line for line in log if line.startswith("aws ")], "single-account must not call any aws API: %s" % log
    (scan,) = calls(log, "aws-sizing")
    assert "--output ./output" in scan and "--org" not in scan and "--sso" not in scan
    assert "[1/3]" in res.stdout and "Starting single-account scan" in res.stdout


# --------------------------------------------------------------------------- org / StackSet


def test_org_creates_stackset_from_a_local_file_not_a_url(tmp_path, shim, bash, aws_archive):
    res, log = run(tmp_path, shim, aws_archive, ["--org"], bash=bash)
    assert res.rc == 0, res.stdout + res.stderr
    assert_clean_run(res)
    (create,) = calls(log, "aws cloudformation create-stack-set")
    assert "--template-body file://" in create and create.count(SPOKES) == 1
    assert "--template-url" not in create and "s3://" not in create and ".s3.amazonaws.com" not in create
    (exists,) = calls(log, "TEMPLATE_BODY_EXISTS")
    assert exists.startswith("TEMPLATE_BODY_EXISTS=yes"), "the template file must exist when CloudFormation reads it"
    assert "BYTES=%d" % len(REAL_TEMPLATE.encode()) in exists and len(REAL_TEMPLATE.encode()) < 51200
    assert "https://github.com/rubrikinc/rubrik-sizing-scripts/blob/master/CLOUD/python/aws/" + SPOKES in res.stdout
    assert calls(log, "aws-sizing --org")
    assert calls(log, "aws cloudformation delete-stack-set"), "cleanup still runs after the scan"


def test_org_updates_an_existing_stackset_from_a_local_file(tmp_path, shim, aws_archive):
    res, log = run(tmp_path, shim, aws_archive, ["--org"], stackset_exists=True)
    assert res.rc == 0, res.stdout + res.stderr
    assert not calls(log, "aws cloudformation create-stack-set")
    (update,) = calls(log, "aws cloudformation update-stack-set")
    assert "--template-body file://" in update and "--template-url" not in update
    assert calls(log, "TEMPLATE_BODY_EXISTS=yes")


def test_org_skip_stackset_does_not_touch_cloudformation(tmp_path, shim, aws_archive):
    res, log = run(tmp_path, shim, aws_archive, ["--org", "--skip-stackset"])
    assert res.rc == 0, res.stdout + res.stderr
    assert not [line for line in log if "cloudformation" in line]
    assert calls(log, "aws-sizing --org")


def test_deploy_role_only_prints_the_bootstrap_command(tmp_path, shim, bash, aws_archive):
    res, log = run(tmp_path, shim, aws_archive, ["--org", "--deploy-role-only"], bash=bash)
    assert res.rc == 0, res.stdout + res.stderr
    assert_clean_run(res)
    assert not calls(log, "aws-sizing")
    want = "bash <(curl -fsSL https://raw.githubusercontent.com/rubrikinc/rubrik-sizing-scripts/master/CLOUD/python/aws/install.sh) --skip-stackset"
    assert want in res.stdout
    assert "RUBRIK_DISCOVERY_REF=" not in res.stdout


def test_deploy_role_only_hint_preserves_a_pin(tmp_path, shim, aws_archive):
    _, commit = aws_archive
    ref = commit[:12]
    res, log = run(tmp_path, shim, aws_archive, ["--org", "--deploy-role-only"], ref=ref)
    assert res.rc == 0, res.stdout + res.stderr
    want = ("RUBRIK_DISCOVERY_REF=%s bash <(curl -fsSL https://raw.githubusercontent.com/rubrikinc/"
            "rubrik-sizing-scripts/%s/CLOUD/python/aws/install.sh) --skip-stackset" % (ref, ref))
    assert want in res.stdout
    assert "(pinned, verified)" in res.stdout


def test_org_with_a_missing_template_skips_the_stackset_but_still_scans(tmp_path, shim):
    files = {"CLOUD/python/aws/pyproject.toml": '[project]\nversion = "1.0.0"\n', "CLOUD/python/aws/main.py": "x\n"}
    archive = git_archive(tmp_path, files)
    res, log = run(tmp_path, shim, archive, ["--org"])
    text = res.stdout + res.stderr
    assert "IAM role template not found in the downloaded source" in text
    assert not calls(log, "aws cloudformation create-stack-set")
    assert calls(log, "aws-sizing --org") and res.rc == 0


def test_deploy_role_only_with_a_missing_template_fails(tmp_path, shim):
    files = {"CLOUD/python/aws/pyproject.toml": '[project]\nversion = "1.0.0"\n', "CLOUD/python/aws/main.py": "x\n"}
    archive = git_archive(tmp_path, files)
    res, log = run(tmp_path, shim, archive, ["--org", "--deploy-role-only"])
    assert res.rc == 1
    assert not calls(log, "aws-sizing")


# --------------------------------------------------------------------------- failures


def test_fetch_failure_stops_before_install(tmp_path, shim, bash):
    missing = tmp_path / "nope.tgz"
    res, log = run_script(tmp_path, "aws", SSO, shim=shim, url=missing.as_uri(), bash=bash)
    text = res.stdout + res.stderr
    assert res.rc == 1, text
    assert "Could not fetch the discovery tool from GitHub" in text
    assert "github.com and codeload.github.com" in text
    assert not calls(log, "python3 -m pip"), "nothing may be installed after a failed fetch"
    assert not calls(log, "aws-sizing")
    assert "Traceback" not in text and res.leftovers == []


def test_pin_mismatch_aborts_before_install(tmp_path, shim, aws_archive):
    res, log = run(tmp_path, shim, aws_archive, SSO, ref="0" * 40)
    text = res.stdout + res.stderr
    assert res.rc == 1
    assert "requested commit" in text
    assert not calls(log, "python3 -m pip") and not calls(log, "aws-sizing")


def test_pip_failure_is_reported(tmp_path, shim, aws_archive):
    res, log = run(tmp_path, shim, aws_archive, SSO, pip_exit=1)
    assert res.rc == 1
    assert "pip install failed" in res.stdout + res.stderr
    assert not calls(log, "aws-sizing")


# =========================================================================== Azure and GCP
# The same flow for azure/install.sh and gcp/install.sh: preflight, login check, fetch, uninstall, pip install
# of the extracted dir, then the tool is launched. These scripts run with set -euo pipefail and need
# Python >= 3.10 (their own preflight).

needs_py310 = pytest.mark.skipif(sys.version_info < (3, 10), reason="azure/gcp scripts require Python >= 3.10")

CLOUDS = {
    "azure": dict(entry="rubrik-discovery", pkg="rubrik-discovery-azure", edition="Azure",
                  extra_args=["--subs", "aaaa-1111,bbbb-2222"], login_fail=dict(az_logged_in=False),
                  login_msg="Not logged in to Azure CLI"),
    "gcp": dict(entry="rubrik-gcp-discovery", pkg="rubrik-discovery-gcp", edition="GCP",
                extra_args=["--projects", "p1,p2"], login_fail=dict(adc_ok=False),
                login_msg="Application Default Credentials not configured"),
}


@pytest.fixture(params=sorted(CLOUDS))
def cloud(request):
    return request.param


@pytest.fixture
def cshim(cloud):
    d = make_cloud_shims(CLOUDS[cloud]["entry"])
    yield d
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
def carchive(tmp_path, cloud):
    files = {
        "CLOUD/python/%s/pyproject.toml" % cloud: '[project]\nname = "x"\nversion = "7.8.9"\n',
        "CLOUD/python/%s/main.py" % cloud: "print('hi')\n",
    }
    return git_archive(tmp_path, files)


def crun(tmp_path, cloud, shim, archive, args, **kw):
    path, _ = archive
    return run_script(tmp_path, cloud, args, shim=shim, url=path.as_uri(), **kw)


def pip_calls(log):
    return [line for line in log if line.startswith("pip3 ")]


@needs_py310
def test_cloud_happy_path(tmp_path, cloud, cshim, carchive, bash):
    cfg = CLOUDS[cloud]
    _, commit = carchive
    res, log = crun(tmp_path, cloud, cshim, carchive, ["--all"], bash=bash)
    assert res.rc == 0, res.stdout + res.stderr
    assert_clean_run(res)
    # fetch, then uninstall the old copy, then install the EXTRACTED directory (it existed when pip ran)
    uninstall = [line for line in log if line.startswith("pip3 uninstall")]
    install = [line for line in log if line.startswith("pip3 install")]
    assert uninstall == ["pip3 uninstall --yes %s" % cfg["pkg"]]
    assert len(install) == 1 and install[0].rstrip().endswith("CLOUD/python/" + cloud)
    assert log.index(uninstall[0]) < log.index(install[0])
    assert any(line.startswith("PIP_SRC_HAS_PYPROJECT") for line in log)
    # version / ref / commit come from the fetched source
    assert "Rubrik Discovery %s 7.8.9" % cfg["edition"] in res.stdout and "master @ " + commit in res.stdout
    assert "(pinned" not in res.stdout
    # the tool runs with the forwarded flags and the default output dir
    out = str(tmp_path / "home" / "rubrik-output")
    assert "%s --output %s --all" % (cfg["entry"], out) in log
    # static box title, no version slot
    assert "Rubrik Discovery — %s Edition" % cfg["edition"] in res.stdout
    assert "Edition  v" not in res.stdout and "Edition    v" not in res.stdout
    # user install unless root; no wheel language anywhere
    assert ("--user" in install[0]) == (os.getuid() != 0)
    assert "WHEEL_URL" not in res.stdout + res.stderr


@needs_py310
def test_cloud_no_user_flag_inside_a_virtualenv(tmp_path, cloud, cshim, carchive):
    res, log = crun(tmp_path, cloud, cshim, carchive, ["--all"], virtual_env="/some/venv")
    assert res.rc == 0, res.stdout + res.stderr
    (install,) = [line for line in log if line.startswith("pip3 install")]
    assert "--user" not in install


@needs_py310
def test_cloud_flags_are_forwarded(tmp_path, cloud, cshim, carchive):
    cfg = CLOUDS[cloud]
    res, log = crun(tmp_path, cloud, cshim, carchive, cfg["extra_args"])
    assert res.rc == 0, res.stdout + res.stderr
    (run_line,) = [line for line in log if line.startswith(cfg["entry"])]
    assert " ".join(cfg["extra_args"]) in run_line


@needs_py310
def test_azure_writes_to_clouddrive_when_present(tmp_path):
    shim = make_cloud_shims("rubrik-discovery")
    try:
        archive = git_archive(tmp_path, {"CLOUD/python/azure/pyproject.toml": '[project]\nversion = "1.0.0"\n',
                                         "CLOUD/python/azure/main.py": "x\n"})
        res, log = run_script(tmp_path, "azure", ["--all"], shim=shim, url=archive[0].as_uri(), make_clouddrive=True)
    finally:
        shutil.rmtree(shim, ignore_errors=True)
    assert res.rc == 0, res.stdout + res.stderr
    assert "rubrik-discovery --output %s --all" % (tmp_path / "home" / "clouddrive") in log


@needs_py310
def test_gcp_writes_to_home_inside_cloud_shell(tmp_path):
    shim = make_cloud_shims("rubrik-gcp-discovery")
    try:
        archive = git_archive(tmp_path, {"CLOUD/python/gcp/pyproject.toml": '[project]\nversion = "1.0.0"\n',
                                         "CLOUD/python/gcp/main.py": "x\n"})
        res, log = run_script(tmp_path, "gcp", ["--all"], shim=shim, url=archive[0].as_uri(), cloud_shell=True)
    finally:
        shutil.rmtree(shim, ignore_errors=True)
    assert res.rc == 0, res.stdout + res.stderr
    assert "rubrik-gcp-discovery --output %s --all" % (tmp_path / "home") in log


@needs_py310
def test_cloud_pinned_run_reports_verification(tmp_path, cloud, cshim, carchive):
    _, commit = carchive
    res, _ = crun(tmp_path, cloud, cshim, carchive, ["--all"], ref=commit[:12])
    assert res.rc == 0, res.stdout + res.stderr
    assert "(pinned, verified)" in res.stdout


# --- failures: a failed fetch must never remove a working install -------------------------------


@needs_py310
def test_cloud_fetch_failure_leaves_the_existing_install_alone(tmp_path, cloud, cshim, bash):
    missing = tmp_path / "nope.tgz"
    res, log = run_script(tmp_path, cloud, ["--all"], shim=cshim, url=missing.as_uri(), bash=bash)
    text = res.stdout + res.stderr
    assert res.rc == 1, text
    assert "Could not fetch the discovery tool from GitHub" in text
    assert "github.com and codeload.github.com" in text and "RUBRIK_DISCOVERY_REF" in text
    assert not pip_calls(log), "neither uninstall nor install may run after a failed fetch: %s" % log
    assert not [line for line in log if line.startswith(CLOUDS[cloud]["entry"])]
    assert "Traceback" not in text and res.leftovers == []


@needs_py310
def test_cloud_pin_mismatch_leaves_the_existing_install_alone(tmp_path, cloud, cshim, carchive):
    res, log = crun(tmp_path, cloud, cshim, carchive, ["--all"], ref="0" * 40)
    assert res.rc == 1
    assert "requested commit" in res.stdout + res.stderr
    assert not pip_calls(log)


@needs_py310
def test_cloud_pip_failure_is_reported(tmp_path, cloud, cshim, carchive):
    res, log = crun(tmp_path, cloud, cshim, carchive, ["--all"], pip_exit=1)
    text = res.stdout + res.stderr
    assert res.rc == 1
    assert "Installation failed" in text
    assert not [line for line in log if line.startswith(CLOUDS[cloud]["entry"])]


@needs_py310
def test_cloud_login_check_runs_before_any_download_or_install(tmp_path, cloud, cshim, carchive):
    cfg = CLOUDS[cloud]
    res, log = crun(tmp_path, cloud, cshim, carchive, ["--all"], **cfg["login_fail"])
    assert res.rc == 1
    assert cfg["login_msg"] in res.stdout + res.stderr
    assert not pip_calls(log)
    assert res.leftovers == [], "fetch must not have run (no temp dir was ever created)"
