"""Key Vaults and how many certificates, secrets and keys each holds (PowerShell's -GetKeyVaultAmounts).

The vaults come from the subscription's resource list (``azure-mgmt-resource``); the counts from the
vault's data plane with ``azure-keyvault-certificates``, ``-secrets`` and ``-keys``, signed in with the
same credential. Like ``Get-AzureKeyVaultInventory``, a count that cannot be read stays ``None`` (a
blank cell), so it is told apart from a vault that holds nothing (``0``). PowerShell says nothing about
why; this collector keeps the reason, and the run summary shows it.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Optional

from azure.mgmt.resource import ResourceManagementClient
from cloud import DEFAULT_CLOUD, CloudEnvironment
from collectors.aks_cosmos import _read_resources
from collectors.utils import parse_resource_group

try:
    from azure.keyvault.certificates import CertificateClient
    from azure.keyvault.keys import KeyClient
    from azure.keyvault.secrets import SecretClient

    HAS_SDK = True
except ImportError:  # pragma: no cover - the packages are in requirements.txt
    CertificateClient = KeyClient = SecretClient = None  # type: ignore[assignment,misc]
    HAS_SDK = False

logger = logging.getLogger(__name__)

KEY_VAULT_RESOURCE_TYPE = "Microsoft.KeyVault/vaults"
KEY_VAULT_API_VERSION = "2023-07-01"
KINDS = ("certificates", "secrets", "keys")


@dataclass
class KeyVault:
    """One vault and its counts; a count is None when it could not be read."""

    name: str
    resource_id: str
    resource_group: str
    location: str
    vault_uri: str
    certificates: Optional[int] = None
    secrets: Optional[int] = None
    keys: Optional[int] = None
    # kind ("certificates", "secrets" or "keys") -> why it could not be counted
    errors: dict[str, str] = field(default_factory=dict)


@dataclass
class KeyVaultInventory:
    """The Key Vaults of one subscription."""

    subscription_id: str
    vaults: list[KeyVault] = field(default_factory=list)
    total_vaults: int = 0


def error_reason(exc: BaseException) -> str:
    """A short reason: the service's error code, else the HTTP status, else the exception type."""
    error = getattr(exc, "error", None)
    code = getattr(error, "code", None) or getattr(exc, "error_code", None)
    if isinstance(code, str) and code:
        return code
    status = getattr(exc, "status_code", None)
    return f"HTTP {status}" if status else type(exc).__name__


def _count(listing: Callable[[], Iterable[Any]]) -> int:
    return sum(1 for _ in listing())


class KeyVaultCollector:
    """Lists the Key Vaults of a subscription and counts what each holds."""

    def __init__(
        self,
        subscription_id: str,
        credential: Any,
        regions: Optional[list[str]] = None,
        cloud: CloudEnvironment = DEFAULT_CLOUD,
    ) -> None:
        self._sub_id = subscription_id
        self._credential = credential
        self._cloud = cloud
        self._regions: Optional[frozenset[str]] = frozenset(regions) if regions else None
        self._rm = ResourceManagementClient(credential, subscription_id, **cloud.client_kwargs())

    def collect(self) -> KeyVaultInventory:
        inventory = KeyVaultInventory(subscription_id=self._sub_id)
        resources = _read_resources(
            self._rm, KEY_VAULT_RESOURCE_TYPE, KEY_VAULT_API_VERSION, self._regions, self._sub_id
        )
        for resource in resources:
            inventory.vaults.append(self._vault(resource))
        inventory.total_vaults = len(inventory.vaults)
        return inventory

    def _vault(self, resource: Any) -> KeyVault:
        name = resource.name or ""
        props = resource.properties or {}
        vault = KeyVault(
            name=name,
            resource_id=resource.id or "",
            resource_group=parse_resource_group(resource.id or ""),
            location=resource.location or "",
            vault_uri=props.get("vaultUri") or f"https://{name}.{self._cloud.key_vault_suffix}/",
        )
        if not HAS_SDK:
            vault.errors = {kind: "azure-keyvault packages are not installed" for kind in KINDS}
            return vault
        listings = {
            "certificates": lambda: CertificateClient(
                vault.vault_uri, self._credential
            ).list_properties_of_certificates(),
            "secrets": lambda: SecretClient(
                vault.vault_uri, self._credential
            ).list_properties_of_secrets(),
            "keys": lambda: KeyClient(vault.vault_uri, self._credential).list_properties_of_keys(),
        }
        for kind, listing in listings.items():
            try:
                setattr(vault, kind, _count(listing))
            except Exception as exc:  # noqa: BLE001 - a count that cannot be read stays blank
                vault.errors[kind] = error_reason(exc)
        if vault.errors:
            kinds = ", ".join(vault.errors)
            reasons = ", ".join(sorted(set(vault.errors.values())))
            logger.warning(
                "[%s] Key Vault %s: could not count %s (%s); left blank",
                self._sub_id,
                name,
                kinds,
                reasons,
            )
        return vault
