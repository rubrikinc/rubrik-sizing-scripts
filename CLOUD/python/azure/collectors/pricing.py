"""Azure Retail Prices API client for VM on-demand pricing.

Uses the public Azure Retail Prices API — no authentication required.
Fetches on-demand (pay-as-you-go) Linux and Windows hourly rates for
each unique (vm_size, region) pair in the discovered environment.

Prices are used to report the monthly on-demand cost of the discovered workload
rather than generic $/TB industry estimates.

API reference: https://learn.microsoft.com/en-us/rest/api/cost-management/retail-prices/azure-retail-prices
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from typing import Optional
from urllib.error import URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

import tls

logger = logging.getLogger(__name__)

_PRICES_API = "https://prices.azure.com/api/retail/prices"
_HOURS_PER_MONTH = 730.0


@dataclass
class VmPriceInfo:
    """On-demand hourly pricing for one VM size in one region."""

    vm_size: str  # e.g. "Standard_D4s_v3"
    region: str  # e.g. "eastus"
    linux_hourly_usd: Optional[float]  # None if not found
    windows_hourly_usd: Optional[float]  # None if not found or Linux-only SKU

    @property
    def linux_monthly_usd(self) -> Optional[float]:
        return round(self.linux_hourly_usd * _HOURS_PER_MONTH, 2) if self.linux_hourly_usd else None

    @property
    def windows_monthly_usd(self) -> Optional[float]:
        return (
            round(self.windows_hourly_usd * _HOURS_PER_MONTH, 2)
            if self.windows_hourly_usd
            else None
        )

    def monthly_for_os(self, os_type: str) -> Optional[float]:
        """Return monthly cost for the given OS type ('Windows' or other)."""
        if os_type.lower() == "windows" and self.windows_monthly_usd is not None:
            return self.windows_monthly_usd
        return self.linux_monthly_usd


# Type alias: key is (vm_size.lower(), region.lower())
PriceMap = dict[tuple[str, str], VmPriceInfo]


# Why price requests failed, so a run that finds no prices can say why instead of "no SKUs found".
_request_errors: list = []


def fetch_vm_prices(
    vm_size_region_pairs: list[tuple[str, str]],
    timeout: int = 10,
    _delay_between_calls: float = 0.05,
) -> PriceMap:
    """Fetch on-demand retail pricing for a set of (vm_size, region) pairs.

    Deduplicates pairs before fetching.  Failures for individual SKUs are
    logged and skipped — the returned dict simply won't contain that key.

    Args:
        vm_size_region_pairs: List of (vm_size, region) tuples from the
            compute collector (values already lowercased).
        timeout: HTTP request timeout in seconds per call.
        _delay_between_calls: Pause between API calls (rate limiting).

    Returns:
        Dict keyed by (vm_size.lower(), region.lower()) → VmPriceInfo.
        Missing entries mean pricing was unavailable for that combination.
    """
    # The price list matches armSkuName case-sensitively, so the size is asked for as the VM reported
    # it. The result is still keyed by the lowercase pair, so one size is one request however it is
    # spelled; the first spelling seen is the one sent.
    spelling: dict[tuple[str, str], str] = {}
    for sz, rg in vm_size_region_pairs:
        if sz and sz.lower() != "unknown" and rg:
            spelling.setdefault((sz.lower(), rg.lower()), sz)
    unique_pairs = set(spelling)

    if not unique_pairs:
        return {}

    logger.info("Fetching Azure retail prices for %d unique VM SKUs…", len(unique_pairs))

    result: PriceMap = {}
    _request_errors.clear()
    for i, (vm_size, region) in enumerate(sorted(unique_pairs)):
        try:
            info = _fetch_one(spelling[(vm_size, region)], region, timeout)
            if info is not None:
                result[(vm_size, region)] = info
                logger.debug(
                    "  %s in %s → Linux $%.4f/h  Windows %s/h",
                    vm_size,
                    region,
                    info.linux_hourly_usd or 0,
                    f"${info.windows_hourly_usd:.4f}" if info.windows_hourly_usd else "N/A",
                )
            else:
                logger.debug("  %s in %s → not found in pricing API", vm_size, region)
        except Exception as exc:
            logger.debug("  %s in %s → pricing lookup failed: %s", vm_size, region, exc)

        if i < len(unique_pairs) - 1:
            time.sleep(_delay_between_calls)

    found = len(result)
    if found == 0 or _request_errors:
        detail = (
            f"first error: {_request_errors[0]}"
            if _request_errors
            else "the prices service answered but had nothing for these SKUs and regions"
        )
        logger.warning(
            "VM pricing: found %d of %d SKUs; %d price request(s) failed (%s)",
            found,
            len(unique_pairs),
            len(_request_errors),
            detail,
        )
    logger.info(
        "Pricing: found %d/%d SKUs (%.0f%%)",
        found,
        len(unique_pairs),
        found / len(unique_pairs) * 100 if unique_pairs else 0,
    )
    return result


def compute_workload_costs(
    vms: list[dict],
    price_map: PriceMap,
) -> tuple[float, float]:
    """Return (total_monthly_usd, unprotected_monthly_usd) for a VM list.

    Args:
        vms: List of VM dicts from DiscoveryResult.compute[].vms.
            Each must have: vm_size, location, os_type, resource_id, is_unprotected.
        price_map: Output of ``fetch_vm_prices()``.

    Returns:
        Tuple of (total_monthly_usd, unprotected_monthly_usd).
        Both are 0.0 if pricing data is unavailable.
    """
    total = 0.0
    unprotected = 0.0

    for vm in vms:
        key = (
            (vm.get("vm_size") or "").lower(),
            (vm.get("location") or "").lower(),
        )
        info = price_map.get(key)
        if info is None:
            continue

        os_type = vm.get("os_type") or "Linux"
        monthly = info.monthly_for_os(os_type)
        if monthly is None:
            continue

        total += monthly
        if vm.get("is_unprotected"):
            unprotected += monthly

    return round(total, 2), round(unprotected, 2)


def _fetch_one(vm_size: str, region: str, timeout: int) -> Optional[VmPriceInfo]:
    """Fetch pricing for one (vm_size, region) pair from the API.

    Returns None if no matching items are found.
    """
    # armSkuName is matched case-sensitively, so vm_size must be the spelling the VM reported
    # (Standard_D4s_v3). Values are quoted as OData strings: a quote is doubled.
    filter_str = (
        f"serviceName eq 'Virtual Machines' "
        f"and armSkuName eq '{_odata_quote(vm_size)}' "
        f"and armRegionName eq '{_odata_quote(region)}' "
        f"and priceType eq 'Consumption'"
    )

    items = _get_all_pages(filter_str, timeout)
    if not items:
        return None

    linux_price: Optional[float] = None
    windows_price: Optional[float] = None

    for item in items:
        # Skip spot prices
        if "spot" in (item.get("skuName") or "").lower():
            continue
        # Skip low-priority
        if "low priority" in (item.get("skuName") or "").lower():
            continue
        # Only hourly "1 Hour" billing
        if item.get("unitOfMeasure") != "1 Hour":
            continue

        price = item.get("retailPrice")
        if price is None or price <= 0:
            continue

        sku_name = (item.get("skuName") or "").lower()
        if "windows" in sku_name:
            if windows_price is None or price < windows_price:
                windows_price = float(price)
        else:
            if linux_price is None or price < linux_price:
                linux_price = float(price)

    if linux_price is None and windows_price is None:
        return None

    return VmPriceInfo(
        vm_size=vm_size,
        region=region,
        linux_hourly_usd=linux_price,
        windows_hourly_usd=windows_price,
    )


def _get_all_pages(filter_str: str, timeout: int) -> list[dict]:
    """Fetch all pages for a filter query, returning combined items."""
    items: list[dict] = []
    url: Optional[str] = (
        f"{_PRICES_API}?{urlencode({'$filter': filter_str, 'api-version': '2023-01-01-preview'})}"
    )

    while url:
        req = Request(url, headers={"User-Agent": "RubrikDiscovery/1.0"})
        try:
            with urlopen(req, timeout=timeout, context=tls.ssl_context()) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except (URLError, OSError) as exc:
            logger.debug("Pricing API request failed: %s", exc)
            _request_errors.append(f"{type(exc).__name__}: {' '.join(str(exc).split())[:200]}")
            break

        items.extend(data.get("Items") or [])
        url = data.get("NextPageLink")

    return items


def _odata_quote(value: str) -> str:
    """Escape ``value`` for use inside a single-quoted OData string: a quote is doubled."""
    return value.replace("'", "''")
