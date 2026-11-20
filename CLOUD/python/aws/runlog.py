"""AWS side of the run log: what to do about each kind of error, and the helpers main.py uses.

The log itself (a transcript of the screen, the digest) is ``runlog_core``, shared by the three
tools. This module holds what is specific to AWS: the fixes, which names to treat as one problem, and
what the log header says. Each fix has an id that is also a section in ``docs/troubleshooting.md``.
"""

from __future__ import annotations

import logging
import os
import re

import runlog_core as core
from runlog_core import Solution

HERE = os.path.dirname(os.path.abspath(__file__))
PACKAGES = ("boto3", "botocore", "awscrt")

SOLUTIONS = (
    Solution(
        "aws-sign-in-expired",
        re.compile(
            r"ExpiredToken|security token included in the request is expired|SSOTokenLoadError|"
            r"UnauthorizedSSOTokenError|TokenRetrievalError|LoginTokenLoadError|"
            r"credentials are still expired|Token has expired and refresh failed|"
            r"sign-in has expired",
            re.I,
        ),
        "Your AWS sign-in has expired. Sign in again, then run the scan again. In a multi-account "
        "scan, finished accounts are kept and the same command carries on.\n"
        "Run: aws sso login --profile <name>\n"
        "If you sign in with 'aws login' instead:\n"
        "Run: aws login",
    ),
    Solution(
        "aws-clock-skew",
        re.compile(r"RequestExpired|Request has expired|Signature expired|RequestTimeTooSkewed"),
        "AWS refused the request as signed at the wrong time. If signing in again does not help, "
        "this machine's clock is off: compare it with the real time in UTC and turn on automatic "
        "time setting.\n"
        "Run: date -u",
    ),
    Solution(
        "aws-crt-missing",
        re.compile(r"MissingDependencyException|botocore\[crt\]"),
        "A session made with 'aws login' needs the CRT extra. Install it:\n"
        'Run: pip install "botocore[crt]"\n'
        "Or export the credentials first and run the scan again:\n"
        'Run: eval "$(aws configure export-credentials --format env)"',
    ),
    Solution(
        "aws-no-credentials",
        re.compile(
            r"NoCredentialsError|Unable to locate credentials|PartialCredentialsError|ProfileNotFound"
        ),
        "No usable AWS credentials were found. Sign in, or set AWS_PROFILE, then run the scan "
        "again.\n"
        "Run: aws sso login --profile <name>",
    ),
    Solution(
        "aws-credentials-rejected",
        # Not "security token ... is invalid": a disabled region says that too, with
        # UnrecognizedClientException, and that is aws-region-not-enabled.
        re.compile(r"InvalidClientTokenId|SignatureDoesNotMatch|rejected the credentials"),
        "AWS does not know these credentials: deleted or deactivated keys, a stale "
        "AWS_SESSION_TOKEN next to long-term keys, or keys of the other partition (use "
        "--partition govcloud for GovCloud keys). Check what the tool will use:\n"
        "Run: aws sts get-caller-identity",
    ),
    Solution(
        "aws-assume-role-failed",
        re.compile(r"cannot assume|Failed to assume role|AssumeRole operation|sts:AssumeRole"),
        "The scan could not switch into the role in that account. Granting a read permission does "
        "not help: check that the role exists there, that its trust policy trusts the identity you "
        "run as, and that --role-name is right (--org defaults to RubrikDiscoveryRole). Try it by "
        "hand; this prints only the role's ARN:\n"
        "Run: aws sts assume-role --role-arn <role-arn> --role-session-name check "
        "--query AssumedRoleUser.Arn --output text",
    ),
    Solution(
        "aws-sso",
        re.compile(
            r"GetRoleCredentials|No SSO session configured|No token cached for|"
            r"No cached SSO login|No valid SSO token|Cannot list SSO accounts|"
            r"SSO authorization|SSO sign-in"
        ),
        "An IAM Identity Center (SSO) problem. 'No access' (ForbiddenException) means the "
        "permission set named by --role-name is not assigned to you in that account. "
        "'Session token not found or invalid' means the portal sign-in ended: sign in again and run "
        "the same command, which keeps finished accounts. A warning about another start URL means "
        "the tool is using a login of another organization; pass the right --sso-start-url.\n"
        "Run: aws sso login --profile <name>",
    ),
    Solution(
        "aws-org-accounts-unlisted",
        re.compile(
            r"Cannot list organization accounts|AWSOrganizationsNotInUseException|"
            r"organizations:ListAccounts"
        ),
        "The organization's accounts could not be listed. Run from the management account or a "
        "delegated administrator with organizations:ListAccounts, or name the accounts with "
        "--accounts or --accounts-file.",
    ),
    Solution(
        "aws-scp-deny",
        re.compile(
            r"service_control_policy|explicit deny|ServiceControlPolicy|SCP blocked read access",
            re.I,
        ),
        "An organization policy (a service control policy) blocks this call. Ask your AWS "
        "organization admin for an exception for the role you scan with, or leave the service or "
        "region out with --services or --exclude-regions. An account blocked this way is not "
        "counted as finished, so the same command scans it again.",
    ),
    Solution(
        "aws-cost-explorer",
        re.compile(r"ce:GetCostAndUsage|Cost Explorer|DataUnavailableException"),
        "Cost data needs Cost Explorer turned on and the ce:GetCostAndUsage permission. Turn it on "
        "in Billing and grant the permission, or run with --no-cost.",
    ),
    Solution(
        "aws-backup-plans-incomplete",
        re.compile(
            r"backup plan details are missing or incomplete|Access denied listing backup vaults"
        ),
        "Backup plans or vaults could not be read, so InBackupPlan falls back to AWS Backup's "
        "protected resources (or the region has no recovery points). Grant backup:GetBackupPlan, "
        "backup:ListBackupSelections, backup:GetBackupSelection, backup:ListBackupVaults and "
        "backup:ListRecoveryPointsByBackupVault, then run again.",
    ),
    Solution(
        "aws-recovery-points-truncated",
        re.compile(r"Recovery point listing in \S+ stopped after"),
        "Listing AWS Backup recovery points ran out of time in this region, so its counts and "
        "sizes are lower bounds. Accept them, or add --backup-recovery-point-timeout-minutes with "
        "a larger value and run again.",
    ),
    Solution(
        "aws-access-denied",
        re.compile(
            r"AccessDenied|UnauthorizedOperation|UnauthorizedAccess|not authorized to perform|"
            r"IAM permission error\(s\) prevented"
        ),
        "The role cannot make this read call. Grant the permission shown in the pre-flight table "
        "(or named in the error) to the role you scan with, then run the scan again.",
    ),
    Solution(
        "aws-region-not-enabled",
        re.compile(r"OptInRequired|UnrecognizedClientException|AuthFailure|opt-in", re.I),
        "This region is not enabled for the account (an opt-in region). Leave it out with "
        "--exclude-regions, or enable it in the account settings.",
    ),
    Solution(
        "aws-throttled",
        re.compile(r"Throttl|RequestLimitExceeded|TooManyRequests|Rate exceeded", re.I),
        "AWS is throttling the requests. Run the scan again in a few minutes, or lower --workers "
        "for a multi-account scan.",
    ),
    Solution(
        "aws-endpoint-unreachable",
        re.compile(
            r"Could not connect to the endpoint URL|EndpointConnectionError|Connect timeout"
        ),
        "The AWS endpoint could not be reached. Check the network or proxy; the region may also be "
        "disabled for this account.",
    ),
    Solution(
        "aws-certificate-verify-failed",
        re.compile(r"SSL validation failed|CERTIFICATE_VERIFY_FAILED|certificate verify failed"),
        "The AWS endpoint's certificate could not be verified, usually because a proxy on your "
        "network re-signs HTTPS traffic. Point boto3 at your organization's certificate bundle "
        "and run again; verification is never turned off.\n"
        "Run: export AWS_CA_BUNDLE=/path/to/ca-bundle.pem",
    ),
    # Last: these wrap another error, whose own fix is more specific when there is one.
    Solution(
        "aws-account-or-region-failed",
        re.compile(r"Scan failed for|Region \S+ scan failed|Cannot sign in to"),
        "An account or a region could not be scanned; the error after the colon says why. Fix it "
        "and run the same command again with --resume: a multi-account scan retries the accounts "
        "that failed and the ones that finished with gaps, a failed region among them.",
    ),
)

# Two messages that differ only by a region or an ARN are the same problem.
MASKS = (
    re.compile(r"\b[a-z]{2}(?:-[a-z]+)+-\d\b"),
    re.compile(r"arn:aws[\w-]*:\S+"),
)

core.configure(SOLUTIONS, MASKS)

log = logging.getLogger(__name__)


def start(argv: list) -> None:
    """Write the header: what ran, with what, so the log explains itself when read later."""
    core.write_header(
        "AWS sizing tool",
        [("Code", core.code_version(HERE)), ("Packages", core.package_versions(PACKAGES))],
        argv,
    )


def say(text: str = "") -> None:
    """Print to the screen and write the same text to the log."""
    print(text)
    core.screen(text)


def screen(text: str) -> None:
    core.screen(text)


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


def set_stop_hint(text: str) -> None:
    """What the last line of a run that stops early says about finished work (where it is kept)."""
    core.set_stop_hint(text)


def crashed(exc: BaseException) -> None:
    """Write how a run that raised ended, so its log is not simply cut off."""
    core.crashed(exc)


def finish() -> None:
    """The last lines of the run, on the screen and in the log: every distinct problem once, then
    the line that says the scan finished."""
    say("")
    say("Run summary")
    for line in core.digest_lines():
        say(line)
    core.finished()
