"""Every collector's package is in the base install, and the packages fit the code.

requirements.txt and the dependencies in pyproject.toml carry the Backup Vault, Defender and Purview
packages. requirements-parity.txt and the ``parity`` extra stay, empty, so older scripts still work.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parents[1]
REQUIREMENTS = HERE / "requirements.txt"
PARITY_FILE = HERE / "requirements-parity.txt"
PYPROJECT = (HERE / "pyproject.toml").read_text(encoding="utf-8")
COLLECTOR_PACKAGES = {"azure-mgmt-dataprotection", "azure-mgmt-security", "azure-mgmt-purview"}


def _name(requirement: str) -> str:
    return (
        re.split(r"[<>=!~\[ ;]", requirement.strip().strip('"').strip("',"))[0]
        .lower()
        .replace("_", "-")
    )


def _file_packages(path: Path) -> list:
    lines = path.read_text(encoding="utf-8").splitlines()
    return [
        _name(line) for line in lines if line.strip() and not line.strip().startswith(("#", "-r"))
    ]


def _pyproject_list(header: str) -> list:
    match = re.search(rf"^{header} = \[(.*?)\]", PYPROJECT, re.DOTALL | re.MULTILINE)
    assert match, header
    return [_name(line) for line in match.group(1).splitlines() if line.strip().startswith('"')]


def test_the_base_install_has_every_collectors_package():
    assert COLLECTOR_PACKAGES <= set(_file_packages(REQUIREMENTS))
    assert COLLECTOR_PACKAGES <= set(_pyproject_list("dependencies"))


@pytest.mark.parametrize("collector", ["defender", "purview", "data_protection"])
def test_the_packages_are_the_ones_each_collector_imports(collector):
    source = (HERE / "collectors" / f"{collector}.py").read_text(encoding="utf-8")
    imported = re.findall(r"from azure\.mgmt\.(\w+)(?:\.\w+)* import", source)
    assert imported, collector
    assert {f"azure-mgmt-{name}" for name in imported} <= COLLECTOR_PACKAGES


def test_the_parity_file_and_extra_add_nothing_and_still_work():
    assert _file_packages(PARITY_FILE) == []
    assert "-r requirements.txt" in PARITY_FILE.read_text(encoding="utf-8").splitlines()
    assert _pyproject_list("parity") == []


def test_no_code_points_at_the_parity_file():
    mentions = [
        path.relative_to(HERE)
        for path in HERE.rglob("*.py")
        if "tests" not in path.parts and ".venv" not in path.parts
        if "requirements-parity.txt" in path.read_text(encoding="utf-8")
    ]
    assert mentions == []


def test_site_recovery_is_left_out_and_requirements_in_says_why():
    assert "azure-mgmt-recoveryservicessiterecovery" not in _file_packages(REQUIREMENTS)
    assert "azure-mgmt-recoveryservicessiterecovery" not in _pyproject_list("dependencies")
    # The reason is a comment in requirements.in; the generated requirements.txt keeps none.
    text = (HERE / "requirements.in").read_text(encoding="utf-8")
    assert "recoveryservicessiterecovery" in text and "2.x" in text


class _Credential:
    def get_token(self, *args, **kwargs):
        from azure.core.credentials import AccessToken

        return AccessToken("not-a-token", 9999999999)


SUB = "00000000-0000-0000-0000-000000000000"


def test_the_defender_client_has_the_call_the_collector_and_the_check_make():
    pytest.importorskip("azure.mgmt.security")
    from azure.mgmt.security import SecurityCenter

    assert callable(SecurityCenter(_Credential(), SUB).pricings.list)


def test_the_purview_client_has_the_call_the_collector_and_the_check_make():
    pytest.importorskip("azure.mgmt.purview")
    from azure.mgmt.purview import PurviewManagementClient

    assert callable(PurviewManagementClient(_Credential(), SUB).accounts.list_by_subscription)
