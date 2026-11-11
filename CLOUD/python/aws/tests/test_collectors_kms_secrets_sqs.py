"""Tests for collectors/kms.py, secrets.py, and sqs.py."""

from unittest.mock import MagicMock

from collectors.kms import fetch_kms
from collectors.secrets import fetch_secrets
from collectors.sqs import fetch_sqs

ACCT = "123456789012"
ALIAS = "test-account"
REGION = "us-east-1"


def _mock_session(client):
    s = MagicMock()
    s.client.return_value = client
    return s


def _paginator(pages):
    pag = MagicMock()
    pag.paginate.return_value = pages
    return pag


class TestFetchKMS:
    def test_counts_keys_single_page(self):
        client = MagicMock()
        client.get_paginator.return_value = _paginator(
            [
                {"Keys": [{"KeyId": "k1"}, {"KeyId": "k2"}, {"KeyId": "k3"}]},
            ]
        )
        result = fetch_kms(_mock_session(client), REGION, ACCT, ALIAS)
        assert result.key_count == 3
        assert result.region == REGION
        assert result.account_id == ACCT

    def test_counts_keys_across_pages(self):
        client = MagicMock()
        client.get_paginator.return_value = _paginator(
            [
                {"Keys": [{"KeyId": "k1"}, {"KeyId": "k2"}]},
                {"Keys": [{"KeyId": "k3"}]},
            ]
        )
        result = fetch_kms(_mock_session(client), REGION, ACCT, ALIAS)
        assert result.key_count == 3

    def test_api_error_returns_zero(self):
        client = MagicMock()
        client.get_paginator.side_effect = Exception("AccessDenied")
        result = fetch_kms(_mock_session(client), REGION, ACCT, ALIAS)
        assert result.key_count == 0

    def test_empty_region_returns_zero(self):
        client = MagicMock()
        client.get_paginator.return_value = _paginator([{"Keys": []}])
        result = fetch_kms(_mock_session(client), REGION, ACCT, ALIAS)
        assert result.key_count == 0

    def test_account_alias_stored(self):
        client = MagicMock()
        client.get_paginator.return_value = _paginator([{"Keys": []}])
        result = fetch_kms(_mock_session(client), REGION, ACCT, ALIAS)
        assert result.account_alias == ALIAS


class TestFetchSecrets:
    def test_counts_secrets(self):
        client = MagicMock()
        client.get_paginator.return_value = _paginator(
            [
                {"SecretList": [{"Name": "s1"}, {"Name": "s2"}]},
            ]
        )
        result = fetch_secrets(_mock_session(client), REGION, ACCT, ALIAS)
        assert result.secret_count == 2
        assert result.region == REGION

    def test_counts_across_pages(self):
        client = MagicMock()
        client.get_paginator.return_value = _paginator(
            [
                {"SecretList": [{"Name": "s1"}]},
                {"SecretList": [{"Name": "s2"}, {"Name": "s3"}]},
            ]
        )
        result = fetch_secrets(_mock_session(client), REGION, ACCT, ALIAS)
        assert result.secret_count == 3

    def test_api_error_returns_zero(self):
        client = MagicMock()
        client.get_paginator.side_effect = Exception("Throttled")
        result = fetch_secrets(_mock_session(client), REGION, ACCT, ALIAS)
        assert result.secret_count == 0

    def test_empty_returns_zero(self):
        client = MagicMock()
        client.get_paginator.return_value = _paginator([{"SecretList": []}])
        result = fetch_secrets(_mock_session(client), REGION, ACCT, ALIAS)
        assert result.secret_count == 0


class TestFetchSQS:
    def test_counts_queues(self):
        client = MagicMock()
        client.get_paginator.return_value = _paginator(
            [
                {
                    "QueueUrls": [
                        "https://sqs.us-east-1.amazonaws.com/123/q1",
                        "https://sqs.us-east-1.amazonaws.com/123/q2",
                    ]
                },
            ]
        )
        result = fetch_sqs(_mock_session(client), REGION, ACCT, ALIAS)
        assert result.queue_count == 2
        assert result.region == REGION

    def test_counts_across_pages(self):
        client = MagicMock()
        client.get_paginator.return_value = _paginator(
            [
                {"QueueUrls": ["https://sqs.us-east-1.amazonaws.com/123/q1"]},
                {
                    "QueueUrls": [
                        "https://sqs.us-east-1.amazonaws.com/123/q2",
                        "https://sqs.us-east-1.amazonaws.com/123/q3",
                    ]
                },
            ]
        )
        result = fetch_sqs(_mock_session(client), REGION, ACCT, ALIAS)
        assert result.queue_count == 3

    def test_api_error_returns_zero(self):
        client = MagicMock()
        client.get_paginator.side_effect = Exception("AccessDenied")
        result = fetch_sqs(_mock_session(client), REGION, ACCT, ALIAS)
        assert result.queue_count == 0

    def test_empty_returns_zero(self):
        client = MagicMock()
        client.get_paginator.return_value = _paginator([{"QueueUrls": []}])
        result = fetch_sqs(_mock_session(client), REGION, ACCT, ALIAS)
        assert result.queue_count == 0

    def test_account_alias_stored(self):
        client = MagicMock()
        client.get_paginator.return_value = _paginator([{"QueueUrls": []}])
        result = fetch_sqs(_mock_session(client), REGION, ACCT, ALIAS)
        assert result.account_alias == ALIAS
