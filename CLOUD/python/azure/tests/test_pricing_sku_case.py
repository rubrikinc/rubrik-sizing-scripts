"""The retail price list filters on armSkuName case-sensitively, so the SKU must go out as the VM reports it.

The collector used to lowercase every size and rebuild it with ``str.capitalize()`` on each ``_``-separated
part, which turned ``Standard_D16s_v5`` into ``Standard_D16s_V5`` and ``Standard_DS1_v2`` into
``Standard_Ds1_V2``. The service found nothing for those, so the VM price estimate was empty for almost
every current VM size (checked against the live price list: the real name returns prices, the rebuilt one
returns none). Only sizes without a version suffix, such as ``Standard_B2ms``, worked.
"""

from __future__ import annotations

import pytest

from collectors import pricing

REAL_SKUS = [
    "Standard_D16s_v5",
    "Standard_B2ls_v2",
    "Standard_B2pts_v2",
    "Standard_DS1_v2",
    "Standard_B2ms",
    "Standard_E16as_v5",
    "Standard_NC24ads_A100_v4",
]


@pytest.fixture
def filters(monkeypatch):
    """Record the OData filter of every price request; answer with no items."""
    seen: list[str] = []

    def fake(filter_str, timeout):
        seen.append(filter_str)
        return []

    monkeypatch.setattr(pricing, "_get_all_pages", fake)
    return seen


@pytest.mark.parametrize("sku", REAL_SKUS)
def test_the_filter_carries_the_sku_as_the_vm_reported_it(sku, filters):
    pricing.fetch_vm_prices([(sku, "centralus")], _delay_between_calls=0)
    assert len(filters) == 1
    assert f"armSkuName eq '{sku}'" in filters[0]


def test_the_result_is_still_keyed_by_the_lowercase_pair(monkeypatch):
    price = pricing.VmPriceInfo(
        vm_size="Standard_D16s_v5", region="centralus", linux_hourly_usd=1.0, windows_hourly_usd=2.0
    )
    monkeypatch.setattr(pricing, "_fetch_one", lambda *a, **k: price)
    result = pricing.fetch_vm_prices([("Standard_D16s_v5", "CentralUS")], _delay_between_calls=0)
    assert list(result) == [("standard_d16s_v5", "centralus")]


def test_two_spellings_of_one_size_make_one_request_with_the_first_spelling(filters):
    pricing.fetch_vm_prices(
        [("Standard_D16s_v5", "centralus"), ("STANDARD_D16S_V5", "centralus")],
        _delay_between_calls=0,
    )
    assert len(filters) == 1
    assert "armSkuName eq 'Standard_D16s_v5'" in filters[0]


def test_a_size_given_in_lowercase_is_asked_for_as_given_not_rebuilt(filters):
    """Lowercase input (older callers, the unit tests) has no better spelling to offer, but it must
    not be 'repaired' into the wrong one: the old code produced ``Standard_D4s_V3`` here."""
    pricing.fetch_vm_prices([("standard_d4s_v3", "eastus")], _delay_between_calls=0)
    assert "armSkuName eq 'Standard_D4s_V3'" not in filters[0]


def test_a_quote_in_a_size_cannot_break_out_of_the_filter(filters):
    pricing.fetch_vm_prices(
        [("Standard_D2s_v3' or 1 eq 1 or armSkuName eq 'x", "eastus")], _delay_between_calls=0
    )
    value = filters[0].split("armSkuName eq '", 1)[1].split("' and armRegionName", 1)[0]
    # inside an OData string every quote is doubled, so none is left alone to end the string
    assert value == "Standard_D2s_v3'' or 1 eq 1 or armSkuName eq ''x"
    assert value.replace("''", "").count("'") == 0
