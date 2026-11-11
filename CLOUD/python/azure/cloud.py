"""Azure cloud-environment resolution (commercial vs. sovereign clouds).

Azure Government, China, and other sovereign clouds have different ARM
endpoints and AAD authorities from the public ("commercial") cloud.  The Azure
CLI is cloud-aware — ``az cloud set --name AzureUSGovernment`` redirects
``az login`` / ``az account show`` — but the Python SDK defaults every
management client and credential to the public cloud.  That mismatch is why a
Government-tenant customer whose ``az`` session works fine still gets
"No accessible subscriptions found": the SDK queries the *commercial* control
plane, which holds none of their subscriptions.

This module resolves the target cloud once and exposes the ARM endpoint, AAD
authority, and credential scope that ``auth.py`` and every collector thread
into their clients.
"""

from __future__ import annotations

import logging
import os
import subprocess
from dataclasses import dataclass
from typing import Optional

from azure.identity import AzureAuthorityHosts

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class CloudEnvironment:
    """Endpoints + authority for one Azure cloud."""

    name: str
    authority_host: str
    arm_endpoint: str
    # Data-plane DNS suffixes: <account>.blob.<storage_suffix>, <vault>.<key_vault_suffix>.
    storage_suffix: str = "core.windows.net"
    key_vault_suffix: str = "vault.azure.net"

    @property
    def credential_scope(self) -> str:
        """Management-plane token scope for this cloud (``<arm>/.default``)."""
        return self.arm_endpoint.rstrip("/") + "/.default"

    def client_kwargs(self) -> dict[str, object]:
        """Kwargs to pass to any azure-mgmt client so it targets this cloud.

        Both are required: track-2 management clients default ``base_url`` AND
        ``credential_scopes`` to the public cloud independently, so setting only
        one still leaks the commercial endpoint or audience.
        """
        return {
            "base_url": self.arm_endpoint,
            "credential_scopes": [self.credential_scope],
        }


# Keyed by the names the Azure CLI reports (`az cloud show --query name`).
_CLOUDS: dict[str, CloudEnvironment] = {
    "AzureCloud": CloudEnvironment(
        name="AzureCloud",
        authority_host=AzureAuthorityHosts.AZURE_PUBLIC_CLOUD,
        arm_endpoint="https://management.azure.com",
    ),
    "AzureUSGovernment": CloudEnvironment(
        name="AzureUSGovernment",
        authority_host=AzureAuthorityHosts.AZURE_GOVERNMENT,
        arm_endpoint="https://management.usgovcloudapi.net",
        storage_suffix="core.usgovcloudapi.net",
        key_vault_suffix="vault.usgovcloudapi.net",
    ),
}

DEFAULT_CLOUD = _CLOUDS["AzureCloud"]

# Friendly aliases a user might type for --cloud / AZURE_CLOUD.
_ALIASES: dict[str, str] = {
    "public": "AzureCloud",
    "commercial": "AzureCloud",
    "azurecloud": "AzureCloud",
    "gov": "AzureUSGovernment",
    "usgov": "AzureUSGovernment",
    "government": "AzureUSGovernment",
    "usgovernment": "AzureUSGovernment",
    "azureusgovernment": "AzureUSGovernment",
}


def _normalise(name: str) -> Optional[str]:
    """Map a user-supplied or CLI-reported cloud name to a known key."""
    key = name.strip()
    if key in _CLOUDS:
        return key
    return _ALIASES.get(key.lower())


def _detect_from_cli() -> Optional[str]:
    """Read the cloud the Azure CLI is currently pointed at."""
    try:
        result = subprocess.run(
            ["az", "cloud", "show", "--query", "name", "-o", "tsv"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except Exception as exc:  # noqa: BLE001 — CLI absent / not logged in is non-fatal
        logger.debug("az cloud show failed: %s", exc)
    return None


def resolve_cloud(explicit: Optional[str] = None) -> CloudEnvironment:
    """Resolve which Azure cloud to target.

    Priority: explicit ``--cloud`` > ``AZURE_CLOUD`` env > active ``az`` CLI
    cloud > public cloud.  An unrecognised value is logged and skipped rather
    than failing the run, so a typo degrades to the next source.

    Args:
        explicit: Value of the ``--cloud`` flag, or None.

    Returns:
        The resolved :class:`CloudEnvironment`.
    """
    candidates = [
        ("--cloud", explicit),
        ("AZURE_CLOUD", os.environ.get("AZURE_CLOUD")),
        ("az cloud show", _detect_from_cli()),
    ]
    for source, raw in candidates:
        if not raw:
            continue
        name = _normalise(raw)
        if name:
            cloud = _CLOUDS[name]
            logger.debug("Targeting Azure cloud %s (resolved via %s)", cloud.name, source)
            return cloud
        logger.warning("Unrecognised Azure cloud %r from %s — ignoring", raw, source)

    logger.debug("Defaulting to public cloud (%s)", DEFAULT_CLOUD.name)
    return DEFAULT_CLOUD
