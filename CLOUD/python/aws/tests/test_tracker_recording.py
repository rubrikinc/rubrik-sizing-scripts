"""Collectors must record denials on a fresh (empty) DenialTracker."""

from unittest.mock import MagicMock

from collectors import DenialTracker
from collectors.dynamodb import fetch_dynamodb
from collectors.kms import fetch_kms
from collectors.rds import fetch_rds

ACCT = "123456789012"
ALIAS = "test-account"
REGION = "us-east-1"
SCP = Exception("AccessDeniedException: explicit deny in a service_control_policy")


def _session_failing(exc):
    client = MagicMock()
    client.get_paginator.side_effect = exc
    client.list_tables.side_effect = exc
    s = MagicMock()
    s.client.return_value = client
    return s


def test_fresh_tracker_is_falsy_but_not_none():
    t = DenialTracker()
    assert not t and t is not None


def test_scp_denial_recorded_on_empty_tracker_kms():
    t = DenialTracker()
    fetch_kms(_session_failing(SCP), REGION, ACCT, ALIAS, t)
    assert t.denied_services() == frozenset({"kms"})
    assert bool(t)


def test_scp_denial_recorded_on_empty_tracker_rds():
    t = DenialTracker()
    fetch_rds(_session_failing(SCP), REGION, ACCT, ALIAS, set(), t)
    assert "rds" in t.denied_services()


def test_permission_error_recorded_on_empty_tracker_rds():
    t = DenialTracker()
    fetch_rds(
        _session_failing(Exception("AccessDenied: no rds:Describe")), REGION, ACCT, ALIAS, set(), t
    )
    assert [e["service"] for e in t.permission_errors()] == ["rds"]


def test_scp_denial_recorded_on_empty_tracker_dynamodb():
    t = DenialTracker()
    fetch_dynamodb(_session_failing(SCP), REGION, ACCT, ALIAS, set(), t)
    assert "dynamodb" in t.denied_services()


def test_metric_failures_are_summarised_by_class():
    from collectors import classify_metric_error, record_metric_failures

    class Boto(Exception):
        def __init__(self, code):
            super().__init__(code)
            self.response = {"Error": {"Code": code}}

    errors = [Boto("ThrottlingException"), Boto("ThrottlingException"), Boto("AccessDenied")]
    assert [classify_metric_error(e) for e in errors] == ["throttled", "throttled", "access denied"]
    assert classify_metric_error(Exception("boom")) == "error"

    t = DenialTracker()
    record_metric_failures(t, REGION, "S3 CloudWatch metrics", errors)
    [entry] = t.permission_errors()
    assert "3 time(s)" in entry["error"]
    assert "1 access denied" in entry["error"] and "2 throttled" in entry["error"]
    assert not t, "metric errors must not look like an SCP denial"
