"""The two HTTPS calls outside the Azure SDK (the ARM tenant lookup and the VM price list) must use a
certificate store that exists.

``urllib`` trusts only the operating system's store. A python.org Python on macOS has none until its
"Install Certificates" step has been run, so both calls failed with CERTIFICATE_VERIFY_FAILED and the
Tenant column and the VM prices came out empty. The Azure SDK is not affected: it ships ``certifi``.
"""

from __future__ import annotations

import ssl
from unittest.mock import MagicMock

import pytest

import auth
import tls
from collectors import pricing


@pytest.fixture(autouse=True)
def _clean_environment(monkeypatch):
    """Start every test with no CA-bundle variable set and an empty cache, so a developer's own
    SSL_CERT_FILE, or the context an earlier test built, cannot change the result."""
    for name in ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"):
        monkeypatch.delenv(name, raising=False)
    tls.ssl_context.cache_clear()
    yield
    tls.ssl_context.cache_clear()


class _Body:
    def __init__(self, text: str = "{}"):
        self._text = text

    def read(self):
        return self._text.encode()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_the_context_trusts_the_certifi_bundle():
    certifi = pytest.importorskip("certifi")
    context = tls.ssl_context()
    assert isinstance(context, ssl.SSLContext)
    assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname is True
    expected = ssl.create_default_context(cafile=certifi.where())
    assert context.cert_store_stats()["x509_ca"] == expected.cert_store_stats()["x509_ca"] > 0


def test_it_never_turns_verification_off():
    context = tls.ssl_context()
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True


def test_it_falls_back_to_the_default_context_when_certifi_is_missing(monkeypatch):
    monkeypatch.setattr(tls, "_certifi_path", lambda: None)
    context = tls.ssl_context()
    assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname is True


def test_an_unreadable_bundle_falls_back_instead_of_failing(monkeypatch):
    monkeypatch.setattr(tls, "_certifi_path", lambda: "/nonexistent/cacert.pem")
    assert tls.ssl_context().verify_mode == ssl.CERT_REQUIRED


def test_the_context_is_built_once(monkeypatch):
    tls.ssl_context.cache_clear()
    first = tls.ssl_context()
    assert tls.ssl_context() is first


def test_the_tenant_lookup_passes_the_context_to_urlopen(monkeypatch):
    seen = {}

    def fake(request, timeout=None, context=None):
        seen["context"] = context
        return _Body('{"value": []}')

    monkeypatch.setattr(auth.urllib.request, "urlopen", fake)
    credential = MagicMock()
    credential.get_token.return_value.token = "not-a-real-token"
    auth._arm_get_json(credential, auth.DEFAULT_CLOUD, "/tenants")
    assert isinstance(seen["context"], ssl.SSLContext)
    assert seen["context"].verify_mode == ssl.CERT_REQUIRED


def test_the_price_lookup_passes_the_context_to_urlopen(monkeypatch):
    seen = {}

    def fake(request, timeout=None, context=None):
        seen["context"] = context
        return _Body('{"Items": [], "NextPageLink": null}')

    monkeypatch.setattr(pricing, "urlopen", fake)
    pricing._get_all_pages("armRegionName eq 'eastus'", timeout=5)
    assert isinstance(seen["context"], ssl.SSLContext)
    assert seen["context"].verify_mode == ssl.CERT_REQUIRED


# ── a bundle named in the environment wins over certifi (a proxy that re-signs traffic) ──────


@pytest.fixture
def one_cert_bundle(tmp_path):
    """A PEM bundle holding exactly one certificate, so the bundle that was loaded can be told apart."""
    import shutil
    import subprocess

    if shutil.which("openssl") is None:
        pytest.skip("openssl is not installed")
    key, crt = tmp_path / "k.pem", tmp_path / "one.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
         "-out", str(crt), "-days", "1", "-subj", "/CN=test-ca"],
        check=True,
        capture_output=True,
    )
    return str(crt)


@pytest.mark.parametrize("variable", ["SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"])
def test_a_bundle_named_in_the_environment_is_used_instead_of_certifi(
    monkeypatch, one_cert_bundle, variable
):
    for name in ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv(variable, one_cert_bundle)
    tls.ssl_context.cache_clear()
    assert tls.ssl_context().cert_store_stats()["x509_ca"] == 1


def test_the_first_variable_that_is_set_wins(monkeypatch, one_cert_bundle):
    monkeypatch.setenv("SSL_CERT_FILE", one_cert_bundle)
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", "/nonexistent/other.pem")
    tls.ssl_context.cache_clear()
    assert tls.ssl_context().cert_store_stats()["x509_ca"] == 1


def test_a_variable_that_names_a_missing_file_falls_back_to_certifi(monkeypatch):
    pytest.importorskip("certifi")
    for name in ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("SSL_CERT_FILE", "/nonexistent/ca.pem")
    tls.ssl_context.cache_clear()
    context = tls.ssl_context()
    assert context.verify_mode == ssl.CERT_REQUIRED and context.cert_store_stats()["x509_ca"] > 1


def test_an_empty_variable_is_ignored(monkeypatch):
    pytest.importorskip("certifi")
    for name in ("REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("SSL_CERT_FILE", "")
    tls.ssl_context.cache_clear()
    assert tls.ssl_context().cert_store_stats()["x509_ca"] > 1


def test_verification_stays_on_whatever_the_environment_says(monkeypatch, one_cert_bundle):
    monkeypatch.setenv("SSL_CERT_FILE", one_cert_bundle)
    tls.ssl_context.cache_clear()
    context = tls.ssl_context()
    assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname is True
