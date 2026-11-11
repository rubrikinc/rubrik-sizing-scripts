"""The run summary must name the real cause of a certificate failure, whichever call hit it.

Both messages below are from a real run on a python.org Python for macOS. They match two older fixes as
well ("Could not read the tenant" -> run az login; "VM pricing: found" -> check network access), and
both pieces of advice are wrong for this cause, so the certificate fix has to be found first.
"""

from __future__ import annotations

import pytest

import runlog

TENANT = (
    "Could not read the tenant of subscription 00000000-0000-0000-0000-000000000000: "
    "<urlopen error [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: "
    "unable to get local issuer certificate (_ssl.c:1077)>. The Tenant column is left blank."
)
PRICING = (
    "VM pricing: found 0 of 4 SKUs; 4 price request(s) failed (first error: URLError: "
    "<urlopen error [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: "
    "self-signed certificate in certificate chain (_ssl.c:1077)>)"
)


def _fix_id(message: str) -> str:
    for solution in runlog.SOLUTIONS:
        if solution.pattern.search(message):
            return solution.id
    return ""


@pytest.mark.parametrize("message", [TENANT, PRICING], ids=["tenant lookup", "price lookup"])
def test_a_certificate_failure_gets_the_certificate_fix_not_the_sign_in_or_network_one(message):
    assert _fix_id(message) == "az-certificate-verify-failed"


def test_a_tenant_failure_for_another_reason_still_gets_the_tenant_fix():
    message = "Could not read the tenant of subscription x: HTTP Error 403: Forbidden"
    assert _fix_id(message) == "az-tenant-lookup-failed"


def test_a_pricing_failure_for_another_reason_still_gets_the_network_fix():
    message = "VM pricing: found 0 of 4 SKUs; 4 price request(s) failed (first error: URLError: timed out)"
    assert _fix_id(message) == "az-pricing-unreachable"


def test_the_certificate_fix_tells_the_user_what_to_set():
    fix = next(s for s in runlog.SOLUTIONS if s.id == "az-certificate-verify-failed").fix
    assert "SSL_CERT_FILE" in fix
    assert "az login" not in fix.split("Run:")[-1], "signing in again does not help"


def test_the_certificate_fix_keeps_the_two_causes_apart():
    fix = next(s for s in runlog.SOLUTIONS if s.id == "az-certificate-verify-failed").fix
    assert "unable to get local issuer certificate" in fix and "Install Certificates" in fix
    assert "self-signed certificate in certificate chain" in fix and "REQUESTS_CA_BUNDLE" in fix
    assert "Only the Tenant column".lower() in fix.lower(), "the Mac case must say what it costs"
