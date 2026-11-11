"""The run summary: the access check's denials get their fix, and repeated warnings are grouped."""

import logging
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import runlog  # noqa: E402 - importing it configures runlog_core with the Azure fixes
import runlog_core as core  # noqa: E402

SUB = "00000000-0000-0000-0000-000000000000"


@pytest.fixture(autouse=True)
def _fresh_issues():
    core.ISSUES.reset()
    yield
    core.ISSUES.reset()


def _digest() -> str:
    return "\n".join(core.digest_lines())


@pytest.mark.parametrize(
    "service, code, message, anchor",
    [
        (
            "blob containers",
            "AuthorizationPermissionMismatch",
            "This request is not authorized to perform this operation using this permission.",
            "#az-blob-data-denied",
        ),
        (
            "key vault contents",
            "Forbidden",
            "(Forbidden) Caller is not authorized to perform action on resource.",
            "#az-key-vault-contents-denied",
        ),
    ],
)
def test_an_access_check_denial_gets_its_fix_in_the_run_summary(service, code, message, anchor):
    group = {"service": service, "code": code, "status": "denied", "message": message}
    runlog.problem_block([dict(group, scopes=[SUB])])

    digest = _digest()
    assert anchor in digest
    assert "no specific advice" not in digest


def _container(sub, n, code="AuthorizationPermissionMismatch"):
    return (
        f"[{sub}] Blobs of container c{n} in storage account acct{n} could not be listed ({code}); "
        "its row is left empty"
    )


def _vault(sub, n):
    return (
        f"[{sub}] Key Vault kv{n}: could not count certificates, secrets, keys (Forbidden); "
        "left blank"
    )


def test_a_role_missing_everywhere_is_one_line_and_a_one_off_problem_stays_visible():
    # The 28 October run: 234 containers and 19 vaults refused, then one unrelated failure.
    for n in range(234):
        core.ISSUES.add(logging.WARNING, "collectors.containers", _container(SUB, n))
    for n in range(19):
        core.ISSUES.add(logging.WARNING, "collectors.key_vault", _vault(SUB, n))
    core.ISSUES.add(
        logging.WARNING,
        "collectors.defender",
        f"[{SUB}] Defender pricings.list() failed: something unexpected",
    )

    digest = _digest()
    assert digest.splitlines()[0] == "3 distinct problems (254 warnings and errors in all):"
    assert "234x in 1 subscription: [" in digest
    assert "19x in 1 subscription: [" in digest
    assert "Defender pricings.list() failed" in digest
    assert "more distinct problems" not in digest
    assert "#az-blob-data-denied" in digest and "#az-key-vault-contents-denied" in digest


def test_the_same_denial_in_two_subscriptions_is_one_problem_naming_both():
    other = "11111111-1111-1111-1111-111111111111"
    for sub in (SUB, other):
        for n in range(3):
            core.ISSUES.add(logging.WARNING, "collectors.containers", _container(sub, n))

    digest = _digest()
    assert digest.splitlines()[0].startswith("1 distinct problem ")
    assert "6x in 2 subscriptions:" in digest
    assert SUB in digest and other in digest


def test_a_different_error_code_is_a_different_problem():
    core.ISSUES.add(logging.WARNING, "collectors.containers", _container(SUB, 1))
    firewall = _container(SUB, 2, code="AuthorizationFailure")
    core.ISSUES.add(logging.WARNING, "collectors.containers", firewall)

    assert _digest().splitlines()[0].startswith("2 distinct problems ")


def test_one_message_per_subscription_still_reads_as_before():
    core.ISSUES.add(logging.WARNING, "collectors.containers", _container(SUB, 1))

    digest = _digest()
    assert "1 subscription: [" in digest
    assert "1x in" not in digest
