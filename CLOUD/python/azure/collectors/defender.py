"""Microsoft Defender for Cloud detection (optional collector).

Lists the Defender pricing plans (Defender for Servers, Storage, SQL,
Key Vault, etc.) on the subscription and reports which are at the
"Standard" tier (paid, active) vs. "Free" (disabled).  The parity
matrix reads ``total_defender_plans_standard`` on DiscoveryResult to
determine whether ransomware-detection coverage is already in place.

Requires ``azure-mgmt-security`` (in ``requirements.txt``).
Without it, the collector gracefully returns zeros and the parity
matrix treats this capability as "not detected."

RBAC: "Security Reader" at subscription scope.  On 403 we return empty
rather than failing the discovery run.
"""

from __future__ import annotations

import inspect
import logging
from dataclasses import dataclass, field
from typing import Any, Optional

from azure.core.exceptions import HttpResponseError
from azure.identity import DefaultAzureCredential
from cloud import DEFAULT_CLOUD, CloudEnvironment

from collectors.utils import enum_text

logger = logging.getLogger(__name__)

#: Conditional import — azure-mgmt-security is an optional extra.  We
#: detect its availability at import time so callers can decide whether
#: to instantiate the collector at all (avoids noisy warnings in the
#: customer's default path).
try:
    from azure.mgmt.security import SecurityCenter as _SecurityCenter  # type: ignore[import]

    HAS_SDK = True
except ImportError:
    _SecurityCenter = None  # type: ignore[assignment]
    HAS_SDK = False


@dataclass
class DefenderPlan:
    """One Defender-for-Cloud pricing entry."""

    name: str  # e.g. "VirtualMachines", "StorageAccounts"
    pricing_tier: str  # "Standard" | "Free" | unknown
    sub_plan: Optional[str] = None


@dataclass
class DefenderInventory:
    """Defender-for-Cloud coverage for one subscription."""

    subscription_id: str
    sdk_available: bool = True
    plans: list[DefenderPlan] = field(default_factory=list)
    total_plans_standard: int = 0
    total_plans_free: int = 0

    #: Highest Defender-for-Servers sub-plan tier observed on this
    #: subscription.  One of ``"P2" | "P1" | "Standard" | "Free" | "None"``.
    #: Determines ransomware-detection capability in the parity matrix:
    #:   P2 → full enterprise coverage (ransomware, threat hunting, EDR)
    #:   P1 → baseline server protection + Defender for Servers basic
    #:   Standard → generic Standard tier without explicit sub-plan
    #:   Free → Defender installed but not paid
    #:   None → Defender for Servers not enabled at all
    defender_servers_tier: str = "None"

    error: Optional[str] = None


def list_pricings(client: Any, subscription_id: str) -> Any:
    """The subscription's Defender pricings, for every supported azure-mgmt-security version.

    From 7.0.0, ``pricings.list`` takes the scope (``subscriptions/<id>``) as a required argument;
    earlier versions take none and use the client's subscription.
    """
    call = client.pricings.list
    try:
        wants_scope = "scope_id" in inspect.signature(call).parameters
    except (TypeError, ValueError):
        wants_scope = False
    if wants_scope:
        return call(scope_id=f"subscriptions/{subscription_id}")
    return call()


class DefenderCollector:
    """Lists Defender-for-Cloud plans for a subscription."""

    def __init__(
        self,
        subscription_id: str,
        credential: DefaultAzureCredential,
        cloud: CloudEnvironment = DEFAULT_CLOUD,
    ) -> None:
        self._sub_id = subscription_id
        self._credential = credential
        # Capture HAS_SDK at construction time so patching it later (in
        # tests) doesn't confuse collect().  The instance flag is the
        # source of truth for this collector after construction.
        self._has_sdk = HAS_SDK
        self._client = None
        if self._has_sdk:
            try:
                self._client = _SecurityCenter(credential, subscription_id, **cloud.client_kwargs())  # type: ignore[misc]
            except Exception as exc:
                logger.debug("[%s] SecurityCenter instantiation failed: %s", subscription_id, exc)

    def collect(self) -> DefenderInventory:
        """Return a populated ``DefenderInventory`` — never raises."""
        inv = DefenderInventory(subscription_id=self._sub_id, sdk_available=self._has_sdk)
        if not self._has_sdk or self._client is None:
            inv.error = "azure-mgmt-security not installed"
            return inv

        try:
            result = list_pricings(self._client, self._sub_id)
        except HttpResponseError as exc:
            status = getattr(exc, "status_code", "?")
            msg = (
                "Security Reader role missing"
                if status in (401, 403)
                else getattr(exc, "message", str(exc))
            )
            logger.warning(
                "[%s] Defender pricings.list() failed (HTTP %s): %s", self._sub_id, status, msg
            )
            inv.error = f"HTTP {status}: {msg}"
            return inv
        except Exception as exc:
            logger.warning("[%s] Defender pricings.list() failed: %s", self._sub_id, exc)
            inv.error = str(exc)
            return inv

        try:
            items = getattr(result, "value", None) or list(result or [])
        except Exception as exc:
            logger.warning("[%s] Could not enumerate Defender pricings: %s", self._sub_id, exc)
            inv.error = str(exc)
            return inv

        for p in items:
            try:
                name = getattr(p, "name", None) or ""
                tier = enum_text(getattr(p, "pricing_tier", None)) or "Unknown"
                sub_plan = getattr(p, "sub_plan", None)
                plan = DefenderPlan(
                    name=str(name),
                    pricing_tier=tier,
                    sub_plan=str(sub_plan) if sub_plan else None,
                )
                inv.plans.append(plan)
                if tier.lower() == "standard":
                    inv.total_plans_standard += 1
                elif tier.lower() == "free":
                    inv.total_plans_free += 1
            except Exception as exc:
                logger.debug("[%s] Skipping Defender plan %r: %s", self._sub_id, p, exc)

        inv.defender_servers_tier = _servers_tier_from_plans(inv.plans)
        logger.debug(
            "[%s] Defender: %d standard / %d free plans; servers tier=%s",
            self._sub_id,
            inv.total_plans_standard,
            inv.total_plans_free,
            inv.defender_servers_tier,
        )
        return inv


#: Azure Defender "resource_type" values that map to Defender for Servers.
#: Microsoft has used both ``VirtualMachines`` and the legacy ``Servers``
#: label in different API versions — we accept either.
_SERVERS_PLAN_NAMES: frozenset[str] = frozenset({"virtualmachines", "servers"})

#: Rank the Defender-for-Servers sub-plans so we can pick the highest tier
#: observed on a subscription for the parity matrix.
_SERVERS_TIER_RANK: dict[str, int] = {
    "None": 0,
    "Free": 1,
    "Standard": 2,
    "P1": 3,
    "P2": 4,
}


def _servers_tier_from_plans(plans: list[DefenderPlan]) -> str:
    """Return the highest-ranked Defender-for-Servers tier across *plans*.

    ``Defender for Servers`` is represented in the pricings API as a plan
    whose ``name`` is ``VirtualMachines`` (sometimes ``Servers``).  Its
    ``sub_plan`` field — when present — is either ``P1`` or ``P2``;
    otherwise the overall ``pricing_tier`` ("Standard" / "Free") is the
    best signal.  Returns ``"None"`` if no Defender-for-Servers plan is
    present at all.
    """
    best = "None"
    best_rank = 0
    for p in plans:
        if p.name.lower() not in _SERVERS_PLAN_NAMES:
            continue
        # Prefer sub_plan when present; fall back to pricing_tier.
        candidate: str
        if p.sub_plan and p.sub_plan.upper() in {"P1", "P2"}:
            candidate = p.sub_plan.upper()
        elif p.pricing_tier.lower() == "standard":
            candidate = "Standard"
        elif p.pricing_tier.lower() == "free":
            candidate = "Free"
        else:
            continue
        rank = _SERVERS_TIER_RANK.get(candidate, 0)
        if rank > best_rank:
            best = candidate
            best_rank = rank
    return best
