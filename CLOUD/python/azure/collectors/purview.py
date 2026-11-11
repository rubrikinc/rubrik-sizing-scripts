"""Microsoft Purview account detection (optional collector).

Lists Purview accounts in the subscription.  Presence of at least one
account indicates the customer has data-classification infrastructure
in place — the parity matrix reads ``total_purview_accounts`` on
DiscoveryResult to decide whether the "sensitive data classification"
capability is covered.

Requires ``azure-mgmt-purview`` (in ``requirements.txt``).
Without it, the collector returns zeros and the parity matrix reports
this capability as "not detected."

RBAC: "Reader" at subscription scope + list permissions on Purview
accounts.  Graceful degrade on 403.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

from azure.core.exceptions import HttpResponseError
from azure.identity import DefaultAzureCredential
from cloud import DEFAULT_CLOUD, CloudEnvironment

logger = logging.getLogger(__name__)

try:
    from azure.mgmt.purview import PurviewManagementClient as _PurviewClient  # type: ignore[import]

    HAS_SDK = True
except ImportError:
    _PurviewClient = None  # type: ignore[assignment]
    HAS_SDK = False


@dataclass
class PurviewAccountInfo:
    """One Purview account in the subscription."""

    name: str
    resource_group: str
    location: str


@dataclass
class PurviewInventory:
    """Purview coverage for one subscription."""

    subscription_id: str
    sdk_available: bool = True
    accounts: list[PurviewAccountInfo] = field(default_factory=list)
    total_accounts: int = 0
    error: Optional[str] = None


class PurviewCollector:
    """Lists Purview accounts for a subscription."""

    def __init__(
        self,
        subscription_id: str,
        credential: DefaultAzureCredential,
        cloud: CloudEnvironment = DEFAULT_CLOUD,
    ) -> None:
        self._sub_id = subscription_id
        self._credential = credential
        self._has_sdk = HAS_SDK
        self._client = None
        if self._has_sdk:
            try:
                self._client = _PurviewClient(credential, subscription_id, **cloud.client_kwargs())  # type: ignore[misc]
            except Exception as exc:
                logger.debug(
                    "[%s] PurviewManagementClient instantiation failed: %s", subscription_id, exc
                )

    def collect(self) -> PurviewInventory:
        inv = PurviewInventory(subscription_id=self._sub_id, sdk_available=self._has_sdk)
        if not self._has_sdk or self._client is None:
            inv.error = "azure-mgmt-purview not installed"
            return inv

        try:
            for acc in self._client.accounts.list_by_subscription():
                try:
                    rg = _parse_rg(getattr(acc, "id", "") or "")
                    inv.accounts.append(
                        PurviewAccountInfo(
                            name=str(getattr(acc, "name", "") or ""),
                            resource_group=rg,
                            location=str(getattr(acc, "location", "") or ""),
                        )
                    )
                except Exception as exc:
                    logger.debug("[%s] Skipping Purview account: %s", self._sub_id, exc)

            inv.total_accounts = len(inv.accounts)
            logger.debug("[%s] Purview: %d account(s)", self._sub_id, inv.total_accounts)
        except HttpResponseError as exc:
            status = getattr(exc, "status_code", "?")
            msg = (
                "Purview read permission missing"
                if status in (401, 403)
                else getattr(exc, "message", str(exc))
            )
            logger.warning(
                "[%s] Purview list_by_subscription failed (HTTP %s): %s", self._sub_id, status, msg
            )
            inv.error = f"HTTP {status}: {msg}"
        except Exception as exc:
            logger.warning("[%s] Purview listing failed: %s", self._sub_id, exc)
            inv.error = str(exc)

        return inv


def _parse_rg(resource_id: str) -> str:
    """Extract resource group from an ARM resource ID."""
    parts = resource_id.split("/")
    try:
        i = parts.index("resourceGroups")
        return parts[i + 1]
    except (ValueError, IndexError):
        return ""
