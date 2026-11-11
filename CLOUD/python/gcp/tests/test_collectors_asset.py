"""Tests for collectors/asset.py — all GCP SDK calls are mocked."""

from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(__import__("pathlib").Path(__file__).parent.parent))

from collectors import asset as asset_module
from collectors.asset import AssetCollector, AssetInventory
from collectors.retry import RateLimiter
from google.api_core import exceptions as gexc

from tests.conftest import PROJECT_ID

_ASSET_CLIENT = "google.cloud.asset_v1.AssetServiceClient"
_ASSET_REQUEST = "google.cloud.asset_v1.ListAssetsRequest"


@pytest.fixture(autouse=True)
def _no_real_waiting(monkeypatch):
    """Every test runs with a limiter that never waits and a retry that never sleeps."""
    monkeypatch.setattr(asset_module, "_list_assets_limiter", RateLimiter(10_000, 60.0))
    monkeypatch.setattr("time.sleep", lambda _seconds: None)


def _make_asset(asset_type: str, name: str = "test-resource") -> MagicMock:
    asset = MagicMock()
    asset.name = f"//compute.googleapis.com/projects/{PROJECT_ID}/{name}"
    asset.asset_type = asset_type
    return asset


def _page(assets, next_token: str = "") -> MagicMock:
    page = MagicMock()
    page.assets = assets
    page.next_page_token = next_token
    return page


def _client_serving(outcomes: list) -> MagicMock:
    """A client whose ``list_assets`` serves one outcome per call: a page, or an exception.

    Like the real client, ``list_assets`` makes the call itself and returns a pager whose first
    page is the response, so a raised outcome surfaces from ``list_assets`` and the call count is
    the RPC count.
    """
    queue = list(outcomes)
    client = MagicMock()

    def list_assets(request, retry=None, **_kwargs):
        outcome = queue.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        pager = MagicMock()
        pager.pages = iter([outcome])
        return pager

    client.list_assets.side_effect = list_assets
    return client


def _collect(client, **kwargs) -> AssetInventory:
    with patch(_ASSET_CLIENT, return_value=client):
        return AssetCollector(PROJECT_ID, MagicMock(), **kwargs).collect()


def test_asset_collector_returns_all_assets():
    page = _page(
        [
            _make_asset("compute.googleapis.com/Instance", "instances/vm-1"),
            _make_asset("compute.googleapis.com/Instance", "instances/vm-2"),
            _make_asset("storage.googleapis.com/Bucket", "buckets/bucket-1"),
        ]
    )

    result = _collect(_client_serving([page]))

    assert result.total_assets == 3
    assert result.assets_by_type["compute.googleapis.com/Instance"] == 2
    assert result.assets_by_type["storage.googleapis.com/Bucket"] == 1
    assert result.project_id == PROJECT_ID
    assert result.failed is False


def test_asset_collector_empty_project():
    result = _collect(_client_serving([_page([])]))

    assert result.total_assets == 0
    assert result.assets_by_type == {}
    assert result.failed is False


def test_asset_collector_graceful_on_permission_error():
    client = _client_serving(
        [Exception("403 Cloud Asset Inventory API has not been used in project")]
    )

    result = _collect(client)

    assert result.total_assets == 0
    assert result.raw_assets == []
    assert result.failed is True
    assert result.failure_category == "API_DISABLED"


def test_asset_collector_passes_correct_parent():
    with patch(_ASSET_REQUEST) as mock_request_cls:
        mock_request_cls.return_value = MagicMock()
        _collect(_client_serving([_page([])]))

    _, kwargs = mock_request_cls.call_args
    assert kwargs["parent"] == f"projects/{PROJECT_ID}"


def test_asset_collector_with_type_filter():
    page = _page([_make_asset("compute.googleapis.com/Instance")])

    result = _collect(_client_serving([page]), asset_types=["compute.googleapis.com/Instance"])

    assert result.total_assets == 1


def test_asset_collector_asks_for_the_maximum_page_size():
    with patch(_ASSET_REQUEST) as mock_request_cls:
        mock_request_cls.return_value = MagicMock()
        _collect(_client_serving([_page([])]))

    _, kwargs = mock_request_cls.call_args
    assert kwargs["page_size"] == 1000


# ── Pagination and retry ────────────────────────────────────────────────────────


def test_asset_collector_follows_page_tokens_across_pages():
    pages = [
        _page([_make_asset("t/A", "a1"), _make_asset("t/A", "a2")], next_token="tok2"),
        _page([_make_asset("t/B", "b1")], next_token="tok3"),
        _page([_make_asset("t/A", "a3")]),
    ]
    client = _client_serving(pages)
    tokens = []
    with patch(_ASSET_REQUEST) as mock_request_cls:
        mock_request_cls.side_effect = lambda **kw: tokens.append(kw["page_token"]) or MagicMock()
        with patch(_ASSET_CLIENT, return_value=client):
            result = AssetCollector(PROJECT_ID, MagicMock()).collect()

    assert tokens == ["", "tok2", "tok3"]
    assert result.total_assets == 4
    assert result.assets_by_type == {"t/A": 3, "t/B": 1}


def test_a_throttled_page_is_retried_alone_not_the_whole_listing():
    """A 429 on page 3 costs one extra call for page 3; pages 1 and 2 are not fetched again."""
    client = _client_serving(
        [
            _page([_make_asset("t/A", "a1")], next_token="tok2"),
            _page([_make_asset("t/A", "a2")], next_token="tok3"),
            gexc.TooManyRequests("429 Quota exceeded"),
            gexc.TooManyRequests("429 Quota exceeded"),
            _page([_make_asset("t/A", "a3")]),
        ]
    )

    result = _collect(client)

    assert result.failed is False
    assert result.total_assets == 3
    # 3 pages + 2 retries of page 3.  Retrying the whole listing would have re-fetched pages 1-2.
    assert client.list_assets.call_count == 5


def test_a_listing_still_throttled_after_the_retries_is_failed_not_empty():
    client = _client_serving([gexc.TooManyRequests("429 Quota exceeded for quota metric")] * 400)
    clock = iter(range(0, 100_000, 30))  # each attempt looks 30s later, so the budget runs out
    with patch("google.api_core.retry.retry_unary.time") as fake_time:
        fake_time.monotonic.side_effect = lambda: next(clock)
        collector = AssetCollector(PROJECT_ID, MagicMock())
        with patch(_ASSET_CLIENT, return_value=client):
            result = collector.collect()

    assert result.failed is True
    assert result.failure_category == "RATE_LIMITED"
    assert result.total_assets == 0
    assert [e["category"] for e in collector.errors] == ["RATE_LIMITED"]


def test_a_failure_on_a_later_page_discards_the_partial_listing():
    """Half a project's assets would undercount it, so a mid-listing failure keeps none of them."""
    client = _client_serving(
        [
            _page([_make_asset("t/A", "a1")], next_token="tok2"),
            gexc.PermissionDenied("403 denied by Cloud IAM"),
        ]
    )

    result = _collect(client)

    assert result.failed is True
    assert result.raw_assets == []
    assert result.total_assets == 0


def test_the_client_is_asked_for_one_page_with_its_own_retry_off():
    client = _client_serving([_page([])])
    _collect(client)

    _, kwargs = client.list_assets.call_args
    assert kwargs["retry"] is None


def test_each_page_waits_for_the_shared_limiter(monkeypatch):
    acquired = []
    limiter = MagicMock()
    limiter.acquire.side_effect = lambda: acquired.append(1)
    monkeypatch.setattr(asset_module, "_list_assets_limiter", limiter)
    pages = [_page([], next_token="tok2"), _page([])]

    _collect(_client_serving(pages))

    assert len(acquired) == 2
