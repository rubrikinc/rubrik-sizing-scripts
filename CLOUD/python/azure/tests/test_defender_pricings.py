"""Defender pricings: the call must work with the azure-mgmt-security versions we install."""

import inspect
import os
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from collectors import defender  # noqa: E402

SUB = "00000000-0000-0000-0000-000000000000"
PLANS = [
    SimpleNamespace(name="VirtualMachines", pricing_tier="Standard", sub_plan="P2"),
    SimpleNamespace(name="StorageAccounts", pricing_tier="Free", sub_plan=None),
]


class _ScopedPricings:
    """azure-mgmt-security 7.x: the scope is a required argument."""

    def __init__(self):
        self.scopes = []

    def list(self, scope_id, filter=None, **kwargs):  # noqa: A002 - the SDK's own name
        self.scopes.append(scope_id)
        return SimpleNamespace(value=PLANS)


class _OldPricings:
    """azure-mgmt-security before 7.0: no arguments."""

    def list(self, **kwargs):
        return SimpleNamespace(value=PLANS)


def _collector(pricings):
    collector = defender.DefenderCollector(SUB, credential=object())
    collector._has_sdk = True
    collector._client = SimpleNamespace(pricings=pricings)
    return collector


def test_the_scope_is_passed_to_an_sdk_that_requires_it():
    pricings = _ScopedPricings()
    inv = _collector(pricings).collect()
    assert inv.error is None
    assert pricings.scopes == [f"subscriptions/{SUB}"]
    assert [p.name for p in inv.plans] == ["VirtualMachines", "StorageAccounts"]
    assert (inv.total_plans_standard, inv.total_plans_free) == (1, 1)
    assert inv.defender_servers_tier == "P2"


def test_an_older_sdk_without_the_scope_still_works():
    inv = _collector(_OldPricings()).collect()
    assert inv.error is None
    assert len(inv.plans) == 2


def test_the_installed_sdk_accepts_the_call_the_tool_makes():
    pytest.importorskip("azure.mgmt.security")
    from azure.mgmt.security import SecurityCenter

    call = SecurityCenter(object(), SUB).pricings.list
    parameters = inspect.signature(call).parameters
    if "scope_id" in parameters:
        inspect.signature(call).bind(scope_id=f"subscriptions/{SUB}")
    else:
        inspect.signature(call).bind()


def test_the_access_check_uses_the_same_call():
    import preflight

    source = inspect.getsource(preflight._defender)
    assert "list_pricings(" in source
    assert "pricings.list()" not in source
