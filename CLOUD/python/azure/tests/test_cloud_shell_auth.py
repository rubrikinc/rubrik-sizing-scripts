"""Sign-in in Azure Cloud Shell: tokens are fetched once, a slow `az` is not reported as missing
access, the identity library's tracebacks stay off the screen, and the Defender probe reads 7.x."""

import logging
import os
import sys
import threading
import time
from types import SimpleNamespace

import pytest
from azure.core.credentials import AccessToken
from azure.identity import CredentialUnavailableError

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import auth  # noqa: E402
import logging_setup  # noqa: E402
import preflight  # noqa: E402
import preflight_core as core  # noqa: E402
import runlog  # noqa: E402,F401 - importing it configures runlog_core with the Azure fixes
import runlog_core  # noqa: E402
from cloud import DEFAULT_CLOUD  # noqa: E402
from collectors import defender  # noqa: E402

SCOPE = "https://management.azure.com/.default"
SUB = "00000000-0000-0000-0000-000000000000"


class _Counting:
    """A credential that takes a while per token, like `az account get-access-token`."""

    def __init__(self, lifetime=3600, delay=0.05):
        self.calls = []
        self.lifetime = lifetime
        self.delay = delay
        self.closed = False

    def get_token(self, *scopes, **kwargs):
        self.calls.append((scopes, kwargs))
        time.sleep(self.delay)
        return AccessToken(f"token-{len(self.calls)}", int(time.time()) + self.lifetime)

    def close(self):
        self.closed = True


# ── token cache ───────────────────────────────────────────────────────────────


def test_parallel_clients_share_one_token_request():
    inner = _Counting()
    credential = auth.CachedCredential(inner)
    tokens = []
    threads = [
        threading.Thread(target=lambda: tokens.append(credential.get_token(SCOPE).token))
        for _ in range(20)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(inner.calls) == 1
    assert set(tokens) == {"token-1"}


def test_each_scope_and_tenant_has_its_own_token():
    inner = _Counting(delay=0)
    credential = auth.CachedCredential(inner)
    credential.get_token(SCOPE)
    credential.get_token("https://storage.azure.com/.default")
    credential.get_token(SCOPE, tenant_id="other")
    credential.get_token(SCOPE)
    assert len(inner.calls) == 3


def test_a_token_close_to_expiry_is_fetched_again():
    inner = _Counting(lifetime=60, delay=0)  # inside the renewal margin from the start
    credential = auth.CachedCredential(inner)
    credential.get_token(SCOPE)
    credential.get_token(SCOPE)
    assert len(inner.calls) == 2


def test_a_claims_challenge_always_reaches_the_credential():
    inner = _Counting(delay=0)
    credential = auth.CachedCredential(inner)
    credential.get_token(SCOPE)
    credential.get_token(SCOPE, claims='{"access_token": {}}')
    assert len(inner.calls) == 2


def test_close_and_other_attributes_reach_the_wrapped_credential():
    inner = _Counting(delay=0)
    inner.extra = "kept"
    credential = auth.CachedCredential(inner)
    credential.close()
    assert inner.closed and credential.extra == "kept"


def test_the_credential_is_cached_and_gives_the_cli_a_minute(monkeypatch):
    seen = {}

    class _Default(_Counting):
        def __init__(self, **kwargs):
            super().__init__(delay=0)
            seen.update(kwargs)

    monkeypatch.setattr(auth, "DefaultAzureCredential", _Default)
    credential = auth.get_credential(DEFAULT_CLOUD)
    assert isinstance(credential, auth.CachedCredential)
    assert seen["process_timeout"] == auth.CLI_TIMEOUT_SECONDS == 60
    credential.get_token(DEFAULT_CLOUD.credential_scope)  # validated already: no second fetch
    assert len(credential._inner.calls) == 1


# ── a slow or failing `az` is not missing access ─────────────────────────────


def test_an_azure_cli_timeout_is_not_checked_rather_than_denied():
    exc = CredentialUnavailableError(message="Failed to invoke the Azure CLI")
    assert preflight.classify(exc) == (core.ERROR, "AzureCliUnavailable")


def test_no_sign_in_at_all_is_still_reported_as_a_sign_in_problem():
    exc = CredentialUnavailableError(message="Please run 'az login' to set up an account")
    assert preflight.classify(exc) == (core.DENIED, "AuthenticationFailed")


@pytest.mark.parametrize(
    "text, service, code, expected",
    [
        (
            "Failed to invoke the Azure CLI",
            "virtual machines",
            "AzureCliUnavailable",
            "az-cli-unavailable",
        ),
        (
            "[sub] Storage listing failed: Failed to invoke the Azure CLI",
            "",
            "",
            "az-cli-unavailable",
        ),
        ("Please run 'az login' to set up an account", "", "", "az-not-signed-in"),
    ],
)
def test_each_failure_gets_its_own_fix(text, service, code, expected):
    solution_id, _ = runlog_core.solve(text, service, code)
    assert solution_id == expected


# ── the identity library's tracebacks ────────────────────────────────────────


@pytest.mark.parametrize("verbose, level", [(False, logging.ERROR), (True, logging.DEBUG)])
def test_identity_warnings_are_shown_only_when_verbose(verbose, level):
    try:
        logging_setup.setup_logging(verbose=verbose)
        assert logging.getLogger("azure.identity").level == level
    finally:
        logging.getLogger("azure.identity").setLevel(logging.NOTSET)


# ── the Defender probe ───────────────────────────────────────────────────────


class _Pricings:
    def __init__(self, plans):
        self.plans = plans

    def list(self, scope_id, filter=None, **kwargs):  # noqa: A002 - the SDK's own name
        return SimpleNamespace(value=self.plans)


@pytest.mark.parametrize(
    "plans, found", [([SimpleNamespace(name="VirtualMachines")], True), ([], False)]
)
def test_the_defender_probe_reads_the_plans_of_a_7x_pricing_list(monkeypatch, plans, found):
    monkeypatch.setattr(defender, "HAS_SDK", True)
    monkeypatch.setattr(
        defender, "_SecurityCenter", lambda *a, **k: SimpleNamespace(pricings=_Pricings(plans))
    )
    ctx = preflight.Context(sub_id=SUB, credential=object(), cloud=DEFAULT_CLOUD, regions=None)
    assert preflight._defender(ctx) is found
