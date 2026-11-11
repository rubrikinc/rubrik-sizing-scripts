"""Azure side of the run log: what to do about each kind of error, and the console that logs itself.

The log itself (a transcript of the screen, the digest) is ``runlog_core``, shared by the three
tools. This module holds what is specific to Azure: the fixes, which names to treat as one problem,
the header, and a console whose output also goes to the log. Each fix has an id that is also a
section in ``docs/troubleshooting.md``.
"""

from __future__ import annotations

import io
import logging
import os
import re
from typing import Optional

import runlog_core as core
from rich.console import Console
from rich.markup import escape
from runlog_core import Solution

HERE = os.path.dirname(os.path.abspath(__file__))
PACKAGES = (
    "azure-identity",
    "azure-mgmt-compute",
    "azure-mgmt-storage",
    "azure-mgmt-monitor",
    "azure-mgmt-resource",
    "azure-mgmt-costmanagement",
    "azure-mgmt-dataprotection",
    "azure-mgmt-security",
    "azure-mgmt-purview",
    "rich",
)

SOLUTIONS = (
    Solution(
        "az-optional-package-missing",
        re.compile(r"azure-mgmt-(security|purview|dataprotection)[^|]*(not installed|needs)"),
        "A package from requirements.txt is missing from the tool's environment. Defender and "
        "Purview go to the JSON only; without azure-mgmt-dataprotection the three Backup Vault files "
        "are not written and Blob and PostgreSQL backup show as unprotected. Install it in the "
        "azure folder, with the tool's virtual environment active.\n"
        "Run: pip install -r requirements.txt",
    ),
    Solution(
        "az-devops",
        re.compile(r"Azure DevOps|DevOps discovery"),
        "Azure DevOps discovery runs on every Azure run, and this identity cannot read Azure "
        "DevOps. Signing in again does not help. Run with --no-devops, or name organizations you "
        "can read with --devops-orgs. Only the JSON is affected.",
    ),
    Solution(
        "az-cost-management",
        re.compile(
            r"Cost Management (?:(?!429\b)\d{3}\b|query failed(?! \(HTTP 429\)))|"
            r"Cost data requested but none returned|"
            r"Cost query error"
        ),
        "Cost Management did not return cost data. A 403 needs Cost Management Reader (or Reader) "
        "on the subscription; a 404 usually means the Microsoft.CostManagement provider is not "
        "registered; some offer types are not supported at all (then run with --no-cost). Only the "
        "cost figures and azure_backup_costs are affected.\n"
        "Run: az provider register --namespace Microsoft.CostManagement",
    ),
    Solution(
        "az-metrics-time-interval",
        re.compile(r"Detected invalid time interval"),
        "Azure Monitor rejected the time range this tool sent. Update the tool and run again; "
        "versions before this fix lose all storage capacity this way.\n"
        "Run: git pull --ff-only",
    ),
    Solution(
        "az-metrics-denied",
        re.compile(r"MetricsDenied"),
        "The identity cannot read Azure Monitor metrics. Grant Monitoring Reader (or Reader) at "
        "subscription scope, or run with --no-capacity.",
    ),
    # Before the authorization fixes: these need a data-plane role, which Reader does not include.
    Solution(
        "az-key-vault-contents-denied",
        re.compile(r"Key Vault \S+: could not count|(^|\| )key vault contents( \||: )"),
        "The sign-in cannot list what is inside a Key Vault, so that count is left blank "
        "(--get-key-vault-amounts). Grant Key Vault Reader on the vault, or the subscription; a vault "
        "that uses access policies instead needs the List permission on certificates, secrets and "
        "keys for this identity. A firewalled vault also has to allow your network.",
    ),
    Solution(
        "az-blob-data-denied",
        re.compile(
            r"Blob containers of \d+ storage account|Blobs of container"
            r"|(^|\| )blob containers( \||: )"
        ),
        "The sign-in cannot list blobs, which --get-container-details reads with Entra ID: grant "
        "Storage Blob Data Reader on the storage accounts or the subscription (Reader is not "
        "enough). A storage account with a firewall also has to allow your network.",
    ),
    Solution(
        "az-provider-not-registered",
        re.compile(
            r"MissingSubscriptionRegistration|NoRegisteredProviderFound|ResourceProviderNotRegistered"
        ),
        "A resource provider is not registered in the subscription. Register the provider named in "
        "the error, then run again.\n"
        "Run: az provider register --namespace <provider>",
    ),
    Solution(
        "az-authorization-failed",
        re.compile(r"AuthorizationFailed|does not have authorization to perform action|HTTP 403"),
        "The identity lacks permission on this scope. Assign Reader at subscription scope (plus "
        "Monitoring Reader for storage metrics and Cost Management Reader for cost); if the role "
        "is eligible (PIM), activate it. If the subscription is in another tenant, switch to it:\n"
        "Run: az account set --subscription <id>\n"
        "Or sign in to that tenant:\n"
        "Run: az login --tenant <tenant-id>",
    ),
    Solution(
        "az-throttled",
        re.compile(r"TooManyRequests|Too Many Requests|HTTP 429|throttl", re.I),
        "Azure is throttling the requests. Run again in a few minutes, or lower --workers.",
    ),
    Solution(
        "az-backup-vaults-unlisted",
        re.compile(
            r"Backup Vault (?:information|policies|backup instances)|"
            r"Backup Vaults\s+could not be listed|resource group for Backup Vault"
        ),
        "Backup Vaults (Blob and PostgreSQL backup) could not be read for this subscription or "
        "vault, so the azure_backup_data_protection_* files are incomplete and those backups can "
        "show as unprotected. Give the identity Reader and check that Microsoft.DataProtection is "
        "registered.\n"
        "Run: az provider show --namespace Microsoft.DataProtection --query registrationState",
    ),
    Solution(
        "az-storage-capacity-blank",
        re.compile(r"Used-capacity unavailable for ALL"),
        "No storage account returned a capacity metric, so storage capacity is blank. The words "
        "after 'Most common cause' name why: look them up in the troubleshooting page, or skip "
        "capacity with --no-capacity.",
    ),
    # Before az-not-signed-in, whose pattern also matches these messages.
    Solution(
        "az-cli-unavailable",
        re.compile(r"AzureCliUnavailable|Failed to invoke the Azure CLI"),
        "The Azure CLI did not return a sign-in token in time, or could not start, so those calls "
        "were not made; it does not mean access is missing. Run again. If it repeats, check that "
        "`az account get-access-token` answers within a few seconds, or run with --workers 1 so "
        "fewer requests wait on the CLI at once.",
    ),
    Solution(
        "az-not-signed-in",
        re.compile(
            r"az login|AzureCliCredential|DefaultAzureCredential failed|ClientAuthenticationError|AuthenticationFailed"
        ),
        "You are not signed in to Azure, or the sign-in has expired. Sign in, then run again.\n"
        "Run: az login",
    ),
    Solution(
        "az-no-subscriptions",
        re.compile(r"No accessible subscriptions found|SubscriptionNotFound"),
        "The sign-in cannot read any of the subscriptions asked for. Check the IDs in --subs and "
        "the tenant you signed in to.\n"
        "Run: az account list --all",
    ),
    Solution(
        "az-government-cloud",
        re.compile(r"Unrecognised Azure cloud"),
        "The cloud name was not recognised and was ignored. Use AzureCloud or AzureUSGovernment, "
        "and sign in to the same cloud with the az CLI first.\n"
        "Run: az cloud set --name AzureUSGovernment",
    ),
    Solution(
        "az-certificate-verify-failed",
        re.compile(r"CERTIFICATE_VERIFY_FAILED|certificate verify failed"),
        "A secure connection was refused because this machine's Python could not verify the "
        "server's certificate. Signing in again does not help, and neither does checking network "
        "access. If the message says 'unable to get local issuer certificate', run the Install "
        "Certificates step that comes with python.org Python on macOS; then only the Tenant column "
        "and the VM cost estimate are affected. If it says 'self-signed certificate in certificate "
        "chain', a proxy on your network is re-signing the traffic: point REQUESTS_CA_BUNDLE at the "
        "bundle of the certificate authorities your organization uses. The Azure SDK, the az CLI "
        "and the tool's own tenant and price requests all read it; SSL_CERT_FILE covers only those "
        "two requests.\n"
        "Run: export REQUESTS_CA_BUNDLE=/path/to/ca-bundle.pem",
    ),
    Solution(
        "az-tenant-lookup-failed",
        re.compile(r"Could not read the (?:display name of )?tenant"),
        "The tenant could not be read, so the Tenant column is left blank (the SQL files show "
        "'unknown'). It is read from the Azure Resource Manager API with your sign-in; check that "
        "this machine can reach it, and sign in again. The scan itself is not affected.\n"
        "Run: az login",
    ),
    Solution(
        "az-ltr-unreadable",
        re.compile(r"Long-term retention policy could not be read"),
        "The long-term retention policy of some SQL databases could not be read, so their LTR "
        "columns are blank. If the error is a denial, give the identity a role with read access "
        "to the SQL servers (Reader covers it). Nothing else in the output is affected.",
    ),
    Solution(
        "az-pricing-no-match",
        re.compile(r"price request\(s\) failed \(the prices service answered but had nothing"),
        "The prices service answered, but had no price for these VM sizes and regions, so those "
        "VMs have no cost estimate. Nothing needs fixing: the rest of the output is not affected.",
    ),
    Solution(
        "az-pricing-unreachable",
        re.compile(r"VM pricing: found|prices\.azure\.com|price request"),
        "The Azure retail prices service could not be reached or had nothing for these SKUs. Check "
        "outbound network access to prices.azure.com. Only the VM cost estimate is skipped.",
    ),
    # Last: these wrap another error, whose own fix is more specific when there is one.
    Solution(
        "az-subscription-failed",
        re.compile(
            r"subscription scan failed|failed and was skipped|subscription\(s\) failed and are excluded"
        ),
        "One subscription's scan stopped on an error the collectors did not handle, and that "
        "subscription is left out of every file. Look up the error after the colon; once it is "
        "fixed, scan that subscription on its own with --subs.",
    ),
)

# The same failure for every storage account is one problem: mask the resource path.
MASKS = (re.compile(r"/subscriptions/\S+"),)

_SUBSCRIPTION = r"\[(?P<scope>[0-9a-fA-F-]{36})\] "

#: Warnings that repeat once per container, storage account or vault: each kind is one problem per
#: error code, with the subscriptions it happened in, so a missing role is one line, not hundreds.
_REPEATED = (
    (
        "container-not-listed",
        re.compile(
            _SUBSCRIPTION + r"Blobs of container .+ could not be listed \((?P<code>[^)]*)\)"
        ),
    ),
    (
        "account-containers-not-listed",
        re.compile(
            _SUBSCRIPTION
            + r"Blob containers of \d+ storage account\(s\) could not be listed \((?P<code>[^)]*)\)"
        ),
    ),
    (
        "vault-not-counted",
        re.compile(
            _SUBSCRIPTION + r"Key Vault .+: could not count .+ \((?P<code>[^)]*)\); left blank"
        ),
    ),
)


def _cause(message: str) -> Optional[tuple]:
    """``(key, subscription)`` for a warning that repeats once per resource, else None."""
    for key, pattern in _REPEATED:
        match = pattern.match(message)
        if match:
            return f"{key}: {match.group('code')}", match.group("scope")
    return None


core.configure(SOLUTIONS, MASKS, cause=_cause, noun="subscription")

log = logging.getLogger(__name__)

_PRINT_OPTIONS = (
    "sep",
    "end",
    "style",
    "justify",
    "overflow",
    "no_wrap",
    "emoji",
    "markup",
    "highlight",
    "width",
    "height",
    "crop",
    "soft_wrap",
)


class LoggedConsole(Console):
    """A rich console whose output also goes to the run log, as the plain text a person saw.

    Spinners and other redraws are not logged; a print that shows nothing is skipped.
    """

    def print(self, *objects, **kwargs) -> None:  # type: ignore[override]
        super().print(*objects, **kwargs)
        sink = core.current()
        if sink is None:
            return
        try:
            probe = Console(
                file=io.StringIO(),
                width=self.width,
                force_terminal=False,
                color_system=None,
                legacy_windows=False,
            )
            probe.print(*objects, **{k: v for k, v in kwargs.items() if k in _PRINT_OPTIONS})
            text = probe.file.getvalue().rstrip("\n")  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001 - logging must never stop a run
            return
        if objects and not text.strip():
            return
        sink.write(text)


def start(argv: list) -> None:
    """Write the header: what ran, with what, so the log explains itself when read later."""
    core.write_header(
        "Azure sizing tool",
        [("Code", core.code_version(HERE)), ("Packages", core.package_versions(PACKAGES))],
        argv,
    )


def answered(question: str, suffix: str, answer: str) -> None:
    """A prompt and what was typed: the terminal shows it, the log has to say it."""
    core.screen(f"  {question} {suffix} {answer or '(default)'}")


def fix_lines(text: str, service: str = "", code: str = "") -> list:
    return core.fix_lines(text, service, code)


def problem_block(groups: list) -> list:
    """The blocked pre-flight groups as lines (the error, then the fix), and each one is counted in
    the digest at the end of the run."""
    for group in groups:
        text = (
            f"{group['service']}: {group.get('code') or group['status']} {group.get('message', '')}"
        )
        for _ in group.get("scopes") or [""]:
            core.ISSUES.add(logging.WARNING, "preflight", text)
    return core.problem_lines(
        groups, lambda g: core.fix_lines(g.get("message", ""), g["service"], g.get("code", ""))
    )


def install_stop_handlers() -> None:
    """Ctrl-C, SIGTERM and a closing terminal write the last line of the log, then exit."""
    core.install_stop_handlers()


def crashed(exc: BaseException) -> None:
    """Write how a run that raised ended, so its log is not simply cut off."""
    core.crashed(exc)


def finish(console: Console) -> None:
    """The last lines of the run, on the screen and in the log: every distinct problem once, then
    the line that says the scan finished."""
    console.print()
    console.print("[bold]Run summary[/bold]")
    for line in core.digest_lines():
        console.print(escape(line))
    core.finished()
