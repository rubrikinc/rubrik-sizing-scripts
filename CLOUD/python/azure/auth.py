"""Authentication and subscription resolution for Rubrik Discovery — Azure Edition."""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
from typing import Any, Optional

from azure.core.exceptions import ClientAuthenticationError
from azure.identity import CredentialUnavailableError, DefaultAzureCredential
from azure.mgmt.subscription import SubscriptionClient
import tls
from cloud import DEFAULT_CLOUD, CloudEnvironment

logger = logging.getLogger(__name__)

# Seconds the Azure CLI may take to return a token; the SDK's default of 10 is too short for a
# cold `az` in Cloud Shell.
CLI_TIMEOUT_SECONDS = 60
# A cached token is renewed this many seconds before it expires.
_RENEW_BEFORE_SECONDS = 300


class CachedCredential:
    """A credential that fetches each token once and reuses it until shortly before it expires.

    The Azure CLI credential does not cache: every Azure client asks for its own token, and each
    request starts ``az account get-access-token``. With many clients created in parallel, those
    processes queue up and time out, notably in Cloud Shell. Requests for the same scopes share
    one fetch; a request that passes claims (a challenge) always goes to the wrapped credential.
    """

    def __init__(self, inner: Any) -> None:
        self._inner = inner
        self._lock = threading.Lock()
        self._tokens: dict = {}

    def get_token(self, *scopes: str, **kwargs: Any) -> Any:
        if kwargs.get("claims"):
            return self._inner.get_token(*scopes, **kwargs)
        key = (scopes, kwargs.get("tenant_id"), bool(kwargs.get("enable_cae")))
        with self._lock:
            token = self._tokens.get(key)
            if token is None or token.expires_on - _RENEW_BEFORE_SECONDS <= time.time():
                token = self._inner.get_token(*scopes, **kwargs)
                self._tokens[key] = token
            return token

    def close(self) -> None:
        close = getattr(self._inner, "close", None)
        if callable(close):
            close()

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


def get_credential(cloud: CloudEnvironment = DEFAULT_CLOUD) -> CachedCredential:
    """Build and eagerly validate a DefaultAzureCredential.

    Exits with a layered, actionable error message if authentication fails,
    with guidance tailored to the detected runtime environment (Cloud Shell,
    Azure VM with Managed Identity, or local workstation).

    In Azure Cloud Shell the managed-identity path is excluded: some Cloud
    Shell tenants expose an MSI endpoint that answers but cannot issue a
    management-plane token (``AudienceNotSupported``). Because that surfaces as
    a hard ``ClientAuthenticationError`` rather than ``CredentialUnavailableError``,
    it aborts the credential chain before it reaches ``AzureCliCredential`` —
    which is always present and authenticated in Cloud Shell. Excluding managed
    identity there lets the chain fall through to the CLI credential.

    Args:
        cloud: Target Azure cloud. Drives the AAD authority (so service-principal
            and managed-identity credentials hit the right endpoint) and the
            management-plane scope used for eager validation. Defaults to the
            public cloud.

    Returns:
        A validated DefaultAzureCredential, wrapped so each token is fetched once.
    """
    try:
        credential = CachedCredential(
            DefaultAzureCredential(
                exclude_managed_identity_credential=_in_cloud_shell(),
                authority=cloud.authority_host,
                process_timeout=CLI_TIMEOUT_SECONDS,
            )
        )
        # Eagerly validate by acquiring a management-plane token for this cloud.
        credential.get_token(cloud.credential_scope)
        return credential
    except (ClientAuthenticationError, CredentialUnavailableError) as exc:
        _print_auth_error(str(exc))
        sys.exit(1)
    except Exception as exc:
        _print_auth_error(f"Unexpected error: {exc}")
        sys.exit(1)


def _in_cloud_shell() -> bool:
    """Detect whether we are running inside Azure Cloud Shell."""
    return bool(
        "cloud-shell" in os.environ.get("AZURE_HTTP_USER_AGENT", "") or os.environ.get("ACC_CLOUD")
    )


def resolve_subscriptions(
    credential: DefaultAzureCredential,
    sub_ids: Optional[list[str]],
    all_subs: bool,
    cloud: CloudEnvironment = DEFAULT_CLOUD,
    skipped: Optional[list] = None,
    names: Optional[list[str]] = None,
    management_groups: Optional[list[str]] = None,
) -> list[str]:
    """Resolve the list of subscription IDs to operate on.

    Priority order:
    1. Explicit ``sub_ids`` list (--subs flag) — each is validated against the API.
    2. ``names`` (--subscriptions flag) — matched to display names, ignoring case.
    3. ``management_groups`` (--management-groups flag) — every Enabled subscription under them.
    4. ``all_subs=True`` (--all flag) — enumerate every Enabled subscription.
    5. None provided — auto-detect via ``az account show``.

    Args:
        credential: Authenticated Azure credential.
        sub_ids: Explicit subscription IDs, or None.
        all_subs: If True, enumerate all accessible subscriptions.
        cloud: Target Azure cloud. The ``SubscriptionClient`` must point at this
            cloud's ARM endpoint, otherwise a sovereign-cloud tenant queries the
            commercial control plane and finds nothing.
        skipped: When given, each explicit ID that could not be read is appended as
            ``(subscription_id, exception)``, so the caller can report it.

    Returns:
        List of validated subscription IDs.

    Raises:
        SystemExit: If no subscriptions can be resolved.
    """
    sub_client = SubscriptionClient(credential, **cloud.client_kwargs())

    if sub_ids:
        return _validate_explicit_subs(sub_client, sub_ids, skipped)

    if names:
        return _subs_by_name(sub_client, names, skipped)

    if management_groups:
        return _subs_in_management_groups(credential, sub_client, management_groups, cloud, skipped)

    if all_subs:
        return _enumerate_all_subs(sub_client)

    # No flags — fall back to current az login context.
    return _detect_current_subscription(sub_client)


def resolve_subscription_names(
    credential: DefaultAzureCredential,
    subscription_ids: list[str],
    cloud: CloudEnvironment = DEFAULT_CLOUD,
) -> dict[str, str]:
    """Best-effort subscription id -> display name lookup for the already-resolved scope.

    Separate from `resolve_subscriptions()` (which only ever needed the id) so that
    function's return type/every existing call site stays untouched — this display-name
    data is purely additive (see DiscoveryResult.subscription_names), used SE-side to tell
    subscriptions apart by name instead of an opaque GUID. A lookup failure for one
    subscription just omits its entry rather than failing discovery for the whole scope.
    """
    sub_client = SubscriptionClient(credential, **cloud.client_kwargs())
    names: dict[str, str] = {}
    for sub_id in subscription_ids:
        try:
            sub = sub_client.subscriptions.get(sub_id)
            if sub.display_name:
                names[sub_id] = sub.display_name
        except Exception as exc:
            logger.debug("Could not resolve display name for subscription %s: %s", sub_id, exc)
    return names


# The subscription and tenant models of azure-mgmt-subscription 3.x have no tenant id on a
# subscription and no display name on a tenant, so those two are read from the ARM REST API.
_ARM_API_VERSION = "2022-12-01"
_GUID = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}")


def _arm_get_json(credential: Any, cloud: CloudEnvironment, path: str) -> dict:
    """GET ``path`` on this cloud's ARM endpoint with the credential's token; the JSON body.

    The host is always the cloud's own ARM endpoint, and a token that is not text (a test double,
    a broken credential) stops here rather than going out as a request.
    """
    base = cloud.arm_endpoint.rstrip("/")
    if "api-version=" in path:
        url = f"{base}{path}"
    else:
        url = f"{base}{path}{'&' if '?' in path else '?'}api-version={_ARM_API_VERSION}"
    token = credential.get_token(cloud.credential_scope).token
    if not isinstance(token, str) or not token:
        raise RuntimeError("the credential returned no token")
    request = urllib.request.Request(
        url, headers={"Authorization": f"Bearer {token}", "Accept": "application/json"}
    )
    with urllib.request.urlopen(  # noqa: S310 - fixed ARM host
        request, timeout=30, context=tls.ssl_context()
    ) as response:
        return json.loads(response.read().decode("utf-8"))


def _arm_tenants(credential: Any, cloud: CloudEnvironment) -> list[dict]:
    """Every tenant the sign-in can see, from ``GET /tenants`` (following ``nextLink``)."""
    base = cloud.arm_endpoint.rstrip("/")
    tenants: list[dict] = []
    path = "/tenants"
    for _ in range(20):
        page = _arm_get_json(credential, cloud, path)
        tenants.extend(page.get("value") or [])
        link = page.get("nextLink") or ""
        if not link.startswith(base + "/"):
            break
        path = link[len(base) :]
    return tenants


def resolve_tenant_id(
    credential: Any,
    subscription_id: str,
    cloud: CloudEnvironment = DEFAULT_CLOUD,
) -> Optional[str]:
    """The id of the tenant a subscription belongs to, or None (with a warning saying why).

    A newer SDK gives it on the subscription; with azure-mgmt-subscription 3.x it is read from
    ``GET /subscriptions/{id}``.
    """
    try:
        sub = SubscriptionClient(credential, **cloud.client_kwargs()).subscriptions.get(
            subscription_id
        )
        tenant_id = getattr(sub, "tenant_id", None)
        if isinstance(tenant_id, str) and tenant_id:
            return tenant_id
        if not _GUID.fullmatch(subscription_id):
            raise ValueError("not a subscription id")
        tenant_id = _arm_get_json(credential, cloud, f"/subscriptions/{subscription_id}").get(
            "tenantId"
        )
        if tenant_id:
            return str(tenant_id)
        raise ValueError("the subscription has no tenantId")
    except Exception as exc:
        logger.warning(
            "Could not read the tenant of subscription %s: %s. The Tenant column is left "
            "blank (the SQL files show 'unknown').",
            subscription_id,
            exc,
        )
        return None


def resolve_tenant_name(
    credential: Any,
    tenant_id: str,
    cloud: CloudEnvironment = DEFAULT_CLOUD,
) -> Optional[str]:
    """Best-effort tenant display name, which PowerShell writes in the ``Tenant`` column.

    Returns None, with a warning saying why, when the tenant is not listed or has no display name.
    """
    reason = "it is not in the list of tenants this sign-in can see, or has no display name"
    try:
        sub_client = SubscriptionClient(credential, **cloud.client_kwargs())
        for tenant in sub_client.tenants.list():
            if (getattr(tenant, "tenant_id", "") or "").lower() == tenant_id.lower():
                name = getattr(tenant, "display_name", None)
                if name:
                    return str(name)
    except Exception as exc:
        logger.debug("The SDK could not list tenants: %s", exc)
    try:
        for tenant in _arm_tenants(credential, cloud):
            if (tenant.get("tenantId") or "").lower() == tenant_id.lower():
                name = tenant.get("displayName")
                if name:
                    return str(name)
    except Exception as exc:
        reason = str(exc)
    logger.warning(
        "Could not read the display name of tenant %s: %s. The Tenant column is left blank.",
        tenant_id,
        reason,
    )
    return None


def normalise_regions(regions: Optional[list[str]]) -> Optional[list[str]]:
    """Normalise region names to lowercase with no surrounding spaces.

    Args:
        regions: List of region strings, or None / empty to collect all.

    Returns:
        Normalised list, or None to signal "collect all regions".
    """
    if not regions:
        return None
    normalised = [r.strip().lower().replace(" ", "") for r in regions if r.strip()]
    return normalised or None


def _validate_explicit_subs(
    sub_client: SubscriptionClient, sub_ids: list[str], skipped: Optional[list] = None
) -> list[str]:
    """Validate explicitly provided subscription IDs against the Azure API."""
    validated: list[str] = []
    for raw_id in sub_ids:
        sub_id = raw_id.strip()
        if not sub_id:
            continue
        try:
            sub = sub_client.subscriptions.get(sub_id)
            validated.append(sub.subscription_id)
            logger.debug("Validated subscription: %s (%s)", sub.subscription_id, sub.display_name)
        except Exception as exc:
            logger.warning("Subscription %s not accessible: %s — skipping", sub_id, exc)
            if skipped is not None:
                skipped.append((sub_id, exc))

    if not validated:
        _exit_no_subs()
    return validated


def _subs_by_name(
    sub_client: SubscriptionClient, names: list[str], skipped: Optional[list] = None
) -> list[str]:
    """Subscription IDs whose display name matches one of ``names``, ignoring case.

    A name that matches nothing is logged and, when ``skipped`` is given, appended to it as
    ``(name, exception)``. Two subscriptions with the same name are both included.
    """
    wanted = [n.strip() for n in names if n.strip()]
    found: dict[str, list[str]] = {n.casefold(): [] for n in wanted}
    try:
        for sub in sub_client.subscriptions.list():
            key = (sub.display_name or "").casefold()
            if key in found and sub.state == "Enabled":
                found[key].append(sub.subscription_id)
    except Exception as exc:
        logger.error("Failed to enumerate subscriptions: %s", exc)
        _exit_no_subs()

    resolved: list[str] = []
    for name in wanted:
        ids = found[name.casefold()]
        if not ids:
            exc = LookupError(f"no enabled subscription is named {name!r}")
            logger.warning("%s — skipping", exc)
            if skipped is not None:
                skipped.append((name, exc))
        for sub_id in ids:
            if sub_id not in resolved:
                resolved.append(sub_id)
    if not resolved:
        _exit_no_subs()
    return resolved


_MANAGEMENT_API_VERSION = "2021-04-01"
_MG_SUBSCRIPTION_TYPE = "microsoft.management/managementgroups/subscriptions"


def _management_group_subscription_ids(
    credential: Any, cloud: CloudEnvironment, group: str
) -> list[str]:
    """IDs of every subscription under a management group, at any depth (``/descendants``)."""
    base = cloud.arm_endpoint.rstrip("/")
    quoted = urllib.parse.quote(group, safe="")
    path = (
        f"/providers/Microsoft.Management/managementGroups/{quoted}/descendants"
        f"?api-version={_MANAGEMENT_API_VERSION}"
    )
    ids: list[str] = []
    for _ in range(100):
        page = _arm_get_json(credential, cloud, path)
        for item in page.get("value") or []:
            if str(item.get("type") or "").casefold() == _MG_SUBSCRIPTION_TYPE and item.get("name"):
                ids.append(str(item["name"]))
        link = page.get("nextLink") or ""
        if not link.startswith(base + "/"):
            break
        path = link[len(base) :]
    return ids


def _subs_in_management_groups(
    credential: Any,
    sub_client: SubscriptionClient,
    groups: list[str],
    cloud: CloudEnvironment,
    skipped: Optional[list] = None,
) -> list[str]:
    """Enabled subscriptions under the given management groups (names or ids).

    A group that cannot be read is logged and appended to ``skipped`` as ``(group, exception)``.
    """
    candidates: list[str] = []
    for raw in groups:
        group = raw.strip()
        if not group:
            continue
        try:
            for sub_id in _management_group_subscription_ids(credential, cloud, group):
                if sub_id not in candidates:
                    candidates.append(sub_id)
        except Exception as exc:
            logger.warning("Management group %s not accessible: %s — skipping", group, exc)
            if skipped is not None:
                skipped.append((group, exc))
    if not candidates:
        _exit_no_subs()
    enabled = set(_enumerate_all_subs(sub_client))
    resolved = [c for c in candidates if c in enabled]
    for sub_id in candidates:
        if sub_id not in enabled:
            logger.warning("Subscription %s is not enabled or not readable — skipping", sub_id)
    if not resolved:
        _exit_no_subs()
    return resolved


def _enumerate_all_subs(sub_client: SubscriptionClient) -> list[str]:
    """Enumerate all Enabled subscriptions accessible to the credential."""
    subs: list[str] = []
    try:
        for sub in sub_client.subscriptions.list():
            if sub.state == "Enabled":
                subs.append(sub.subscription_id)
                logger.debug("Found subscription: %s (%s)", sub.subscription_id, sub.display_name)
    except Exception as exc:
        logger.error("Failed to enumerate subscriptions: %s", exc)
        _exit_no_subs()

    if not subs:
        _exit_no_subs()
    return subs


def _detect_current_subscription(sub_client: SubscriptionClient) -> list[str]:
    """Detect the active subscription via ``az account show``."""
    try:
        result = subprocess.run(
            ["az", "account", "show", "--query", "id", "-o", "tsv"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0 and result.stdout.strip():
            sub_id = result.stdout.strip()
            sub = sub_client.subscriptions.get(sub_id)
            logger.debug("Auto-detected subscription: %s (%s)", sub_id, sub.display_name)
            return [sub.subscription_id]
    except Exception as exc:
        logger.debug("az account show failed: %s", exc)

    _exit_no_subs()
    return []  # unreachable; satisfies type checker


def _print_auth_error(detail: str) -> None:
    """Print a context-aware authentication error message to stderr."""
    in_cloud_shell = _in_cloud_shell()
    in_azure_vm = bool(os.environ.get("MSI_ENDPOINT") or os.environ.get("IDENTITY_ENDPOINT"))

    from rich.console import Console
    from rich.panel import Panel

    # Locked-down tenants expose a Cloud Shell managed identity that answers but
    # cannot issue a management-plane token ("AudienceNotSupported"). When that
    # happens, Cloud Shell's automatic `az` sign-in also fails, so the fix is an
    # explicit device-code login as the user — not the ambient identity.
    locked_down = "AudienceNotSupported" in detail or "run 'az login'" in detail

    console = Console(stderr=True)
    lines = [f"[bold red]Authentication failed:[/bold red] {detail}", ""]

    if in_cloud_shell:
        lines += ["[bold]Running in Azure Cloud Shell:[/bold]"]
        if locked_down:
            lines += [
                "  Your tenant's automatic Cloud Shell sign-in isn't issuing a",
                "  management token. Sign in as yourself with a device code:",
                "",
                "    1. Run [cyan]az login --use-device-code[/cyan]",
                "    2. Open the printed link, enter the code, and sign in.",
                "    3. Confirm it worked: [cyan]az account show[/cyan]",
                "    4. Re-run this tool.",
                "",
                "  If [cyan]az login[/cyan] itself fails, your tenant likely blocks this",
                "  sign-in method by policy — your Azure admin must allow it.",
            ]
        else:
            lines += [
                "  1. Confirm you have an active login: [cyan]az account show[/cyan].",
                "  2. If not, run [cyan]az login --use-device-code[/cyan], then retry.",
                "  3. Select the right subscription: [cyan]az account set --subscription <id>[/cyan].",
                "  4. If it still fails, your Cloud Shell session token may have expired —",
                "     close and reopen Cloud Shell, then retry.",
            ]
    elif in_azure_vm:
        lines += [
            "[bold]Running on Azure VM (Managed Identity):[/bold]",
            "  1. Ensure a system-assigned or user-assigned managed identity is enabled.",
            "  2. Grant the identity [cyan]Reader[/cyan] role on the target subscriptions.",
            "  3. For user-assigned MI, set [cyan]AZURE_CLIENT_ID[/cyan] to the identity's client ID.",
        ]
    else:
        lines += [
            "[bold]Running locally:[/bold]",
            "  Option 1 (recommended): Run [cyan]az login[/cyan] and retry.",
            "  Option 2: Set [cyan]AZURE_CLIENT_ID[/cyan], [cyan]AZURE_CLIENT_SECRET[/cyan], "
            "[cyan]AZURE_TENANT_ID[/cyan] env vars.",
            "  Option 3: Run [cyan]az account set --subscription <id>[/cyan] to select the right account.",
        ]

    console.print(
        Panel(
            "\n".join(lines),
            title="[bold]Rubrik Discovery — Auth Error[/bold]",
            border_style="red",
        )
    )


def _exit_no_subs() -> None:
    """Exit with a helpful message when no subscriptions are found."""
    from rich.console import Console

    Console(stderr=True).print(
        "[bold red]No accessible subscriptions found.[/bold red]\n"
        "Use [cyan]--subs id1,id2[/cyan] to specify subscription IDs, "
        "or [cyan]--all[/cyan] to enumerate all accessible subscriptions.",
        highlight=False,
    )
    sys.exit(1)
