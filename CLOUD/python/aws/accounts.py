"""Which accounts to scan and how to sign in: the account list, local profiles, SSO device login.

Ports the account-selection and authentication parts of ``Get-AWSSizingInfo.ps1``:
``-UserSpecifiedAccounts`` / ``-UserSpecifiedAccountsFile``, ``-AllLocalProfiles`` /
``-UserSpecifiedProfileNames`` / ``-ProfileLocation``, and the IAM Identity Center sign-in that
PowerShell does itself (OIDC device authorization against ``-SSORegion``).
"""

from __future__ import annotations

import logging
import os
import time
from datetime import datetime, timezone
from typing import Any, Callable, Optional

import boto3
from botocore import exceptions as botocore_exceptions
from collectors.context import partition_id

log = logging.getLogger(__name__)

SSO_DEFAULT_REGION = "us-east-1"
CLIENT_NAME = "aws-sizing"


def _error_classes(*names: str) -> tuple:
    """The botocore exception classes among ``names`` (older botocore releases lack some)."""
    found = (getattr(botocore_exceptions, name, None) for name in names)
    return tuple(cls for cls in found if cls is not None)


_SIGN_IN_EXPIRED_ERRORS = _error_classes(
    "SSOTokenLoadError",
    "UnauthorizedSSOTokenError",
    "TokenRetrievalError",
    "LoginTokenLoadError",
)
_EXPIRED_CODES = frozenset({"ExpiredToken", "ExpiredTokenException", "RequestExpired"})
_REJECTED_CODES = frozenset(
    {"InvalidClientTokenId", "UnrecognizedClientException", "SignatureDoesNotMatch"}
)

_MSG_EXPIRED = (
    "Your AWS sign-in has expired ({detail}).\n"
    'Sign in again the way you did before ("aws sso login --profile NAME" or "aws login"), '
    'check it with "aws sts get-caller-identity", then run this again.\n'
    "Access keys exported in this terminal (AWS_ACCESS_KEY_ID and so on) take priority over "
    "your profile, so unset them or export fresh ones."
)
_MSG_NEEDS_CRT = (
    'This sign-in method ("aws login") needs one more package ({detail}).\n'
    'Install it with: pip install "botocore[crt]"\n'
    "Or give the tool temporary keys from the AWS CLI for this terminal: "
    'eval "$(aws configure export-credentials --format env)"'
)
_MSG_NO_CREDENTIALS = (
    "No AWS credentials were found.\n"
    'Sign in first ("aws sso login", "aws login" or "aws configure"), or set AWS_PROFILE to a '
    'profile that works, and check it with "aws sts get-caller-identity".'
)
_MSG_REJECTED = (
    "AWS rejected the credentials ({detail}).\n"
    "Check the access keys, and unset AWS_SESSION_TOKEN if you switched to long-term keys. "
    'Check with "aws sts get-caller-identity".'
)
_MSG_PARTIAL = (
    "Some of the AWS credentials are missing ({detail}).\n"
    "Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY together, and AWS_SESSION_TOKEN as well "
    "for temporary keys."
)
_MSG_NO_PROFILE = "{detail}\nList your profiles with: aws configure list-profiles"


def _detail(exc: BaseException) -> str:
    first_line = (str(exc).strip().splitlines() or [""])[0]
    return f"{type(exc).__name__}: {first_line}"[:300]


def _explain_one(exc: BaseException) -> Optional[str]:
    detail = _detail(exc)
    if isinstance(exc, botocore_exceptions.MissingDependencyException):
        return _MSG_NEEDS_CRT.format(detail=detail)
    if isinstance(exc, RuntimeError) and "credentials are still expired" in str(exc):
        return _MSG_EXPIRED.format(detail=detail)
    if _SIGN_IN_EXPIRED_ERRORS and isinstance(exc, _SIGN_IN_EXPIRED_ERRORS):
        return _MSG_EXPIRED.format(detail=detail)
    if isinstance(exc, botocore_exceptions.ClientError):
        code = exc.response.get("Error", {}).get("Code", "")
        if code in _EXPIRED_CODES:
            return _MSG_EXPIRED.format(detail=detail)
        if code in _REJECTED_CODES:
            return _MSG_REJECTED.format(detail=detail)
    if isinstance(exc, botocore_exceptions.NoCredentialsError):
        return _MSG_NO_CREDENTIALS
    if isinstance(exc, botocore_exceptions.PartialCredentialsError):
        return _MSG_PARTIAL.format(detail=detail)
    if isinstance(exc, botocore_exceptions.ProfileNotFound):
        return _MSG_NO_PROFILE.format(detail=detail)
    return None


def explain_credential_error(exc: BaseException) -> Optional[str]:
    """What to tell the user when ``exc`` (or what it was raised from) is a sign-in problem.

    Only errors about the credentials themselves match: an access denied on one service is not
    one. Anything else returns None, so the caller keeps the original error.
    """
    seen: set[int] = set()
    pending: list[Optional[BaseException]] = [exc]
    while pending and len(seen) < 10:
        current = pending.pop(0)
        if current is None or id(current) in seen:
            continue
        seen.add(id(current))
        message = _explain_one(current)
        if message is not None:
            return message
        pending.extend([current.__cause__, current.__context__])
    return None


def split_list(text: str) -> list[str]:
    """Items of a comma-separated option, trimmed, without empty ones."""
    return [item.strip() for item in (text or "").split(",") if item.strip()]


def read_accounts_file(path: str) -> list[str]:
    """Account ids from a file with one id per line (blank lines are skipped)."""
    with open(path, encoding="utf-8-sig") as handle:
        return [line.strip() for line in handle if line.strip()]


def resolve_account_ids(accounts: str = "", accounts_file: str = "") -> Optional[list[str]]:
    """The accounts named on the command line or in a file, or None when neither is given.

    Giving both is an error, as in PowerShell.
    """
    if accounts and accounts_file:
        raise ValueError("Only --accounts or --accounts-file can be specified, not both.")
    if accounts_file:
        return read_accounts_file(accounts_file)
    return split_list(accounts) or None


def role_arn(account_id: str, role_name: str) -> str:
    """``arn:<partition>:iam::<account>:role/<name>`` for the partition being queried."""
    return f"arn:{partition_id()}:iam::{account_id}:role/{role_name}"


def use_profile_location(path: str) -> None:
    """Read profiles from this credentials file (PowerShell's ``-ProfileLocation``)."""
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Profile location not found: {path}")
    os.environ["AWS_SHARED_CREDENTIALS_FILE"] = os.path.abspath(path)


def local_profile_names() -> list[str]:
    """Every profile boto3 can see in the credentials and config files."""
    return sorted(boto3.session.Session().available_profiles)


def select_profiles(names: str = "", all_profiles: bool = False) -> list[str]:
    """The profiles to scan: the ones named, or every local one.

    A named profile that does not exist is an error (PowerShell stops on it too).
    """
    available = local_profile_names()
    if all_profiles:
        return available
    wanted = split_list(names)
    missing = [n for n in wanted if n not in available]
    if missing:
        raise ValueError(f"Profile not found: {', '.join(missing)}")
    return wanted


# ── IAM Identity Center sign-in ───────────────────────────────────────────────


class SsoLoginError(RuntimeError):
    pass


def sso_device_login(
    start_url: str,
    region: str = SSO_DEFAULT_REGION,
    *,
    client: Any = None,
    show: Callable[[str], None] = print,
    sleep: Callable[[float], None] = time.sleep,
    now: Callable[[], float] = time.monotonic,
) -> str:
    """Sign in to IAM Identity Center with the OIDC device flow and return an access token.

    Registers a public client, prints the verification link and code, and polls until the user
    approves. Nothing needs to be installed or logged in beforehand.
    """
    oidc = client or boto3.client("sso-oidc", region_name=region)
    try:
        registered = oidc.register_client(clientName=CLIENT_NAME, clientType="public")
        auth = oidc.start_device_authorization(
            clientId=registered["clientId"],
            clientSecret=registered["clientSecret"],
            startUrl=start_url,
        )
    except Exception as exc:
        raise SsoLoginError(
            f"Unable to start SSO authorization for {start_url} in region {region}: {exc}"
        ) from exc

    expires_at = datetime.now(timezone.utc).timestamp() + int(auth.get("expiresIn", 600))
    show("")
    show("Open this link and check that the code shown is the one below:")
    show("")
    show(f"URL: {auth.get('verificationUriComplete') or auth.get('verificationUri', '')}")
    show("")
    show(f"User verification code: {auth.get('userCode', '')}")
    show("")
    show(
        "The authorization expires at "
        f"{datetime.fromtimestamp(expires_at).strftime('%H:%M:%S')}. Waiting for you to sign in..."
    )

    interval = max(int(auth.get("interval", 5)), 1)
    deadline = now() + int(auth.get("expiresIn", 600))
    while now() < deadline:
        sleep(interval)
        try:
            token = oidc.create_token(
                clientId=registered["clientId"],
                clientSecret=registered["clientSecret"],
                deviceCode=auth["deviceCode"],
                grantType="urn:ietf:params:oauth:grant-type:device_code",
            )
            return token["accessToken"]
        except Exception as exc:
            code = str(getattr(exc, "response", {}).get("Error", {}).get("Code", ""))
            if code == "AuthorizationPendingException":
                continue
            if code == "SlowDownException":
                interval += 5
                continue
            raise SsoLoginError(
                f"Unable to sign in to SSO {start_url} in region {region}: {exc}"
            ) from exc
    raise SsoLoginError(f"The SSO sign-in for {start_url} expired before it was approved.")
