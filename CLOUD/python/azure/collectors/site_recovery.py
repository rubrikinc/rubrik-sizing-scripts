"""Azure Site Recovery detection (optional collector).

Counts replicated items in each Recovery Services vault — a non-zero
count indicates Site Recovery (ASR) is orchestrating DR for at least
some workloads.  The parity matrix reads
``total_asr_protected_items`` on DiscoveryResult to cover the
"orchestrated DR" capability.

Requires ``azure-mgmt-recoveryservicessiterecovery``, which ``requirements.txt`` leaves out (see the
note there).  Without it, the collector returns zero
and the parity matrix reports this capability as "not detected."

Uses the existing vault list from the backup_posture collector so we
don't re-enumerate — pass ``vault_refs`` (list of
``(resource_group, vault_name)`` tuples) at construction.  On 403 we
skip that vault silently.
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
    from azure.mgmt.recoveryservicessiterecovery import (  # type: ignore[import]
        SiteRecoveryManagementClient as _SiteRecoveryClient,
    )

    HAS_SDK = True
except ImportError:
    _SiteRecoveryClient = None  # type: ignore[assignment]
    HAS_SDK = False


@dataclass
class AsrVaultSummary:
    """Replicated-items count for a single vault."""

    vault_name: str
    resource_group: str
    replicated_items_count: int = 0
    error: Optional[str] = None


@dataclass
class SiteRecoveryInventory:
    """ASR coverage for one subscription."""

    subscription_id: str
    sdk_available: bool = True
    vaults: list[AsrVaultSummary] = field(default_factory=list)
    total_protected_items: int = 0
    error: Optional[str] = None


class SiteRecoveryCollector:
    """Counts ASR replicated items across the provided vaults."""

    def __init__(
        self,
        subscription_id: str,
        credential: DefaultAzureCredential,
        vault_refs: Optional[list[tuple[str, str]]] = None,
        cloud: CloudEnvironment = DEFAULT_CLOUD,
    ) -> None:
        """
        Args:
            subscription_id: Subscription to collect from.
            credential: Validated credential.
            vault_refs: List of ``(resource_group, vault_name)`` tuples
                from the backup_posture collector.  Empty list → zero
                replicated items reported (expected when the customer
                has no RSV vaults at all).
            cloud: Target Azure cloud (public vs. sovereign); drives ARM endpoint + token scope.
        """
        self._sub_id = subscription_id
        self._credential = credential
        self._cloud = cloud
        self._vault_refs = vault_refs or []
        self._has_sdk = HAS_SDK
        self._client_factory = None
        if self._has_sdk:
            try:
                # SiteRecoveryManagementClient requires both resource_group
                # and resource_name (vault name); we construct one client
                # per vault since the API enforces that scoping.
                self._client_factory = _SiteRecoveryClient  # type: ignore[misc]
            except Exception as exc:
                logger.debug(
                    "[%s] SiteRecovery client factory unavailable: %s", subscription_id, exc
                )

    def collect(self) -> SiteRecoveryInventory:
        inv = SiteRecoveryInventory(subscription_id=self._sub_id, sdk_available=self._has_sdk)
        if not self._has_sdk or self._client_factory is None:
            inv.error = "azure-mgmt-recoveryservicessiterecovery not installed"
            return inv

        for rg, vault_name in self._vault_refs:
            vault = AsrVaultSummary(vault_name=vault_name, resource_group=rg)
            try:
                client = self._client_factory(
                    self._credential,
                    self._sub_id,
                    rg,
                    vault_name,
                    **self._cloud.client_kwargs(),
                )
                # replication_protected_items.list() returns the paged iterator
                # across all ASR replicated VMs in the vault.
                count = 0
                for _ in client.replication_protected_items.list():
                    count += 1
                vault.replicated_items_count = count
                inv.total_protected_items += count
            except HttpResponseError as exc:
                status = getattr(exc, "status_code", "?")
                vault.error = (
                    "ASR permissions missing"
                    if status in (401, 403)
                    else str(getattr(exc, "message", exc))
                )
                logger.debug(
                    "[%s] ASR list failed for %s/%s (HTTP %s)", self._sub_id, rg, vault_name, status
                )
            except Exception as exc:
                vault.error = str(exc)
                logger.debug(
                    "[%s] ASR client error for %s/%s: %s", self._sub_id, rg, vault_name, exc
                )
            inv.vaults.append(vault)

        logger.debug(
            "[%s] ASR: %d total protected items across %d vaults",
            self._sub_id,
            inv.total_protected_items,
            len(inv.vaults),
        )
        return inv
