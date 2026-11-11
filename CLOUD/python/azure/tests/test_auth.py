"""Tests for auth.py — all Azure SDK calls are mocked."""

import sys
from unittest.mock import MagicMock, call, patch

import auth
import pytest


def test_normalise_regions_none():
    assert auth.normalise_regions(None) is None


def test_normalise_regions_empty_list():
    assert auth.normalise_regions([]) is None


def test_normalise_regions_strips_spaces():
    assert auth.normalise_regions(["East US", " westus2 "]) == ["eastus", "westus2"]


def test_normalise_regions_lowercases():
    assert auth.normalise_regions(["EastUS"]) == ["eastus"]


def test_normalise_regions_removes_internal_spaces():
    assert auth.normalise_regions(["East US 2"]) == ["eastus2"]


def test_normalise_regions_filters_blank_entries():
    result = auth.normalise_regions(["eastus", "", "  "])
    assert result == ["eastus"]


def test_normalise_regions_all_blank_returns_none():
    assert auth.normalise_regions(["", "  "]) is None


def _make_sub(sub_id: str, display_name: str = "Test", state: str = "Enabled"):
    sub = MagicMock()
    sub.subscription_id = sub_id
    sub.display_name = display_name
    sub.state = state
    return sub


def test_resolve_subscriptions_validates_explicit_ids():
    mock_sub_client = MagicMock()
    mock_sub_client.subscriptions.get.return_value = _make_sub("aaa-111")

    with patch("auth.SubscriptionClient", return_value=mock_sub_client):
        result = auth.resolve_subscriptions(MagicMock(), ["aaa-111"], all_subs=False)

    assert result == ["aaa-111"]
    mock_sub_client.subscriptions.get.assert_called_once_with("aaa-111")


def test_resolve_subscriptions_skips_inaccessible():
    mock_sub_client = MagicMock()
    mock_sub_client.subscriptions.get.side_effect = [
        Exception("not found"),
        _make_sub("bbb-222"),
    ]

    with patch("auth.SubscriptionClient", return_value=mock_sub_client):
        result = auth.resolve_subscriptions(MagicMock(), ["bad-id", "bbb-222"], all_subs=False)

    assert result == ["bbb-222"]


def test_resolve_subscriptions_exits_when_all_invalid():
    mock_sub_client = MagicMock()
    mock_sub_client.subscriptions.get.side_effect = Exception("not found")

    with patch("auth.SubscriptionClient", return_value=mock_sub_client):
        with patch("auth._exit_no_subs") as mock_exit:
            mock_exit.side_effect = SystemExit(1)
            with pytest.raises(SystemExit):
                auth.resolve_subscriptions(MagicMock(), ["bad-id"], all_subs=False)
        mock_exit.assert_called_once()


def test_resolve_subscriptions_all_flag_returns_enabled_only():
    subs = [
        _make_sub("s1", state="Enabled"),
        _make_sub("s2", state="Disabled"),
        _make_sub("s3", state="Enabled"),
    ]
    mock_sub_client = MagicMock()
    mock_sub_client.subscriptions.list.return_value = iter(subs)

    with patch("auth.SubscriptionClient", return_value=mock_sub_client):
        result = auth.resolve_subscriptions(MagicMock(), None, all_subs=True)

    assert result == ["s1", "s3"]


def test_resolve_subscriptions_all_flag_exits_when_empty():
    mock_sub_client = MagicMock()
    mock_sub_client.subscriptions.list.return_value = iter([])

    with patch("auth.SubscriptionClient", return_value=mock_sub_client):
        with patch("auth._exit_no_subs") as mock_exit:
            mock_exit.side_effect = SystemExit(1)
            with pytest.raises(SystemExit):
                auth.resolve_subscriptions(MagicMock(), None, all_subs=True)


def test_resolve_subscriptions_autodetect_via_az_account_show():
    mock_sub_client = MagicMock()
    mock_sub_client.subscriptions.get.return_value = _make_sub("detected-sub")

    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = "detected-sub\n"

    with patch("auth.SubscriptionClient", return_value=mock_sub_client):
        with patch("auth.subprocess.run", return_value=mock_proc):
            result = auth.resolve_subscriptions(MagicMock(), None, all_subs=False)

    assert result == ["detected-sub"]


def test_resolve_subscriptions_autodetect_falls_back_to_exit_on_failure():
    mock_sub_client = MagicMock()
    mock_proc = MagicMock()
    mock_proc.returncode = 1
    mock_proc.stdout = ""

    with patch("auth.SubscriptionClient", return_value=mock_sub_client):
        with patch("auth.subprocess.run", return_value=mock_proc):
            with patch("auth._exit_no_subs") as mock_exit:
                mock_exit.side_effect = SystemExit(1)
                with pytest.raises(SystemExit):
                    auth.resolve_subscriptions(MagicMock(), None, all_subs=False)


def test_resolve_subscription_names_returns_id_to_name_map():
    mock_sub_client = MagicMock()
    mock_sub_client.subscriptions.get.side_effect = [
        _make_sub("sub-1", display_name="Production"),
        _make_sub("sub-2", display_name="Dev/Test"),
    ]

    with patch("auth.SubscriptionClient", return_value=mock_sub_client):
        result = auth.resolve_subscription_names(MagicMock(), ["sub-1", "sub-2"])

    assert result == {"sub-1": "Production", "sub-2": "Dev/Test"}


def test_resolve_subscription_names_skips_failed_lookups_without_raising():
    """A lookup failure for one subscription must not fail discovery for the whole
    scope — matches this codebase's graceful-degradation convention."""
    mock_sub_client = MagicMock()
    mock_sub_client.subscriptions.get.side_effect = [
        _make_sub("sub-1", display_name="Production"),
        Exception("access denied"),
    ]

    with patch("auth.SubscriptionClient", return_value=mock_sub_client):
        result = auth.resolve_subscription_names(MagicMock(), ["sub-1", "sub-2"])

    assert result == {"sub-1": "Production"}


def test_resolve_subscription_names_empty_list_returns_empty_dict():
    mock_sub_client = MagicMock()
    with patch("auth.SubscriptionClient", return_value=mock_sub_client):
        result = auth.resolve_subscription_names(MagicMock(), [])
    assert result == {}
    mock_sub_client.subscriptions.get.assert_not_called()


# ── tenant of a subscription, and its display name ────────────────────────────

import json  # noqa: E402
from types import SimpleNamespace as _NS  # noqa: E402

from cloud import resolve_cloud  # noqa: E402

SUB = "11111111-2222-3333-4444-555555555555"
TENANT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


class _Response:
    def __init__(self, body):
        self._body = json.dumps(body).encode()

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _credential(token="not-a-real-token"):
    credential = MagicMock()
    credential.get_token.return_value.token = token
    return credential


def _arm(monkeypatch, routes):
    """Answer ARM requests from ``routes`` (URL prefix -> body) and record what was asked."""
    asked = []

    def fake(request, timeout=None, context=None):
        asked.append((request.full_url, dict(request.header_items())))
        for prefix, body in sorted(routes.items(), key=lambda kv: -len(kv[0])):
            if request.full_url.startswith(prefix):
                if isinstance(body, Exception):
                    raise body
                return _Response(body)
        raise AssertionError(f"unexpected request: {request.full_url}")

    monkeypatch.setattr(auth.urllib.request, "urlopen", fake)
    return asked


def _sdk(subscription=None, tenants=None):
    client = MagicMock()
    client.subscriptions.get.return_value = subscription or _NS()
    client.tenants.list.return_value = iter(tenants or [])
    return patch.object(auth, "SubscriptionClient", return_value=client)


def test_the_tenant_id_is_taken_from_the_sdk_when_it_has_one(monkeypatch):
    asked = _arm(monkeypatch, {})
    with _sdk(_NS(tenant_id=TENANT)):
        assert auth.resolve_tenant_id(_credential(), SUB) == TENANT
    assert asked == []


def test_the_tenant_id_is_read_from_arm_when_the_sdk_model_has_none(monkeypatch):
    asked = _arm(monkeypatch, {"https://management.azure.com/subscriptions/": {"tenantId": TENANT}})
    with _sdk(_NS(display_name="x")):
        assert auth.resolve_tenant_id(_credential("tok"), SUB) == TENANT
    [(url, headers)] = asked
    assert url == f"https://management.azure.com/subscriptions/{SUB}?api-version=2022-12-01"
    assert headers["Authorization"] == "Bearer tok"


def test_a_sovereign_cloud_uses_its_own_endpoint_and_scope(monkeypatch):
    cloud = resolve_cloud("AzureUSGovernment")
    asked = _arm(monkeypatch, {cloud.arm_endpoint: {"tenantId": TENANT}})
    credential = _credential()
    with _sdk():
        assert auth.resolve_tenant_id(credential, SUB, cloud) == TENANT
    assert asked[0][0].startswith(cloud.arm_endpoint + "/subscriptions/")
    credential.get_token.assert_called_with(cloud.credential_scope)


def test_a_failed_tenant_lookup_is_a_warning_naming_the_subscription_and_the_effect(
    monkeypatch, caplog
):
    _arm(monkeypatch, {"https://management.azure.com": RuntimeError("403 Forbidden")})
    with _sdk(), caplog.at_level("WARNING"):
        assert auth.resolve_tenant_id(_credential(), SUB) is None
    [message] = [r.getMessage() for r in caplog.records]
    assert (
        SUB in message and "403 Forbidden" in message and "Tenant column is left blank" in message
    )


def test_a_subscription_with_no_tenant_id_in_the_answer_is_a_failure_not_a_blank(
    monkeypatch, caplog
):
    _arm(monkeypatch, {"https://management.azure.com": {}})
    with _sdk(), caplog.at_level("WARNING"):
        assert auth.resolve_tenant_id(_credential(), SUB) is None
    assert "no tenantId" in caplog.text


def test_a_value_that_is_not_a_subscription_id_is_never_put_in_a_url(monkeypatch, caplog):
    asked = _arm(monkeypatch, {})
    with _sdk(), caplog.at_level("WARNING"):
        assert auth.resolve_tenant_id(_credential(), "../tenants?x=") is None
    assert asked == [] and "not a subscription id" in caplog.text


def test_a_credential_that_gives_no_text_token_sends_nothing(monkeypatch, caplog):
    asked = _arm(monkeypatch, {})
    with _sdk(), caplog.at_level("WARNING"):
        assert auth.resolve_tenant_id(MagicMock(), SUB) is None
    assert asked == [] and "no token" in caplog.text


def test_the_token_never_reaches_the_log(monkeypatch, caplog):
    _arm(monkeypatch, {"https://management.azure.com": RuntimeError("boom")})
    with _sdk(), caplog.at_level("DEBUG"):
        auth.resolve_tenant_id(_credential("secret-token-value"), SUB)
        auth.resolve_tenant_name(_credential("secret-token-value"), TENANT)
    assert "secret-token-value" not in caplog.text


def test_the_tenant_name_is_taken_from_the_sdk_when_it_has_one(monkeypatch):
    asked = _arm(monkeypatch, {})
    with _sdk(tenants=[_NS(tenant_id=TENANT, display_name="Contoso")]):
        assert auth.resolve_tenant_name(_credential(), TENANT) == "Contoso"
    assert asked == []


def test_the_tenant_name_is_read_from_arm_when_the_sdk_model_has_no_display_name(monkeypatch):
    asked = _arm(
        monkeypatch,
        {
            "https://management.azure.com/tenants": {
                "value": [
                    {"tenantId": "other", "displayName": "Other"},
                    {"tenantId": TENANT.upper(), "displayName": "Default Directory"},
                ]
            }
        },
    )
    with _sdk(tenants=[_NS(tenant_id=TENANT)]):
        assert auth.resolve_tenant_name(_credential(), TENANT) == "Default Directory"
    assert asked[0][0] == "https://management.azure.com/tenants?api-version=2022-12-01"


def test_tenants_on_a_later_page_are_found(monkeypatch):
    base = "https://management.azure.com"
    asked = _arm(
        monkeypatch,
        {
            f"{base}/tenants?api-version=2022-12-01": {
                "value": [{"tenantId": "x", "displayName": "X"}],
                "nextLink": f"{base}/tenants?api-version=2022-12-01&$skiptoken=abc",
            },
            f"{base}/tenants?api-version=2022-12-01&$skiptoken=abc": {
                "value": [{"tenantId": TENANT, "displayName": "Second Page"}]
            },
        },
    )
    with _sdk():
        assert auth.resolve_tenant_name(_credential(), TENANT) == "Second Page"
    assert len(asked) == 2 and "$skiptoken=abc" in asked[1][0]


def test_a_next_link_on_another_host_is_not_followed(monkeypatch):
    asked = _arm(
        monkeypatch,
        {
            "https://management.azure.com/tenants": {
                "value": [],
                "nextLink": "https://evil.example/tenants?x=1",
            }
        },
    )
    with _sdk():
        assert auth.resolve_tenant_name(_credential("tok"), TENANT) is None
    assert len(asked) == 1


def test_a_tenant_that_cannot_be_named_is_a_warning_with_the_reason(monkeypatch, caplog):
    _arm(monkeypatch, {"https://management.azure.com": RuntimeError("401 Unauthorized")})
    with _sdk(), caplog.at_level("WARNING"):
        assert auth.resolve_tenant_name(_credential(), TENANT) is None
    [message] = [r.getMessage() for r in caplog.records]
    assert TENANT in message and "401 Unauthorized" in message


def test_a_tenant_that_is_not_listed_says_so(monkeypatch, caplog):
    _arm(monkeypatch, {"https://management.azure.com": {"value": []}})
    with _sdk(), caplog.at_level("WARNING"):
        assert auth.resolve_tenant_name(_credential(), TENANT) is None
    assert "not in the list of tenants" in caplog.text
