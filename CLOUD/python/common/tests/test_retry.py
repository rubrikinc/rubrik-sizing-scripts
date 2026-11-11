import pytest
from common import retry as r


class Transient(Exception):
    pass


class Fatal(Exception):
    pass


def _is_transient(exc):
    return isinstance(exc, Transient)


def test_returns_first_success_without_sleep():
    slept = []
    assert r.retry_call(lambda: 5, is_retryable=_is_transient, sleep=slept.append) == 5
    assert slept == []


def test_retries_then_succeeds():
    calls = []

    def f():
        calls.append(1)
        if len(calls) < 3:
            raise Transient()
        return "ok"

    slept = []
    assert r.retry_call(f, is_retryable=_is_transient, sleep=slept.append) == "ok"
    assert len(calls) == 3 and len(slept) == 2


def test_non_retryable_raises_immediately():
    calls = []

    def f():
        calls.append(1)
        raise Fatal()

    with pytest.raises(Fatal):
        r.retry_call(f, is_retryable=_is_transient, sleep=lambda s: None)
    assert len(calls) == 1


def test_budget_exhausted_raises_last_error():
    now = [0.0]

    def f():
        raise Transient()

    def sleep(s):
        now[0] += 400

    with pytest.raises(Transient):
        r.retry_call(
            f,
            is_retryable=_is_transient,
            sleep=sleep,
            clock=lambda: now[0],
            timeout=600,
            initial=500,
            maximum=500,
        )


def test_backoff_capped_at_maximum(monkeypatch):
    waits = []
    monkeypatch.setattr(r.random, "uniform", lambda a, b: b)
    n = [0]

    def f():
        n[0] += 1
        if n[0] < 8:
            raise Transient()

    r.retry_call(
        f, is_retryable=_is_transient, sleep=waits.append, initial=1, maximum=10, timeout=1e9
    )
    assert waits == [1, 2, 4, 8, 10, 10, 10]


class _Boto(Exception):
    def __init__(self, code=None, http=None):
        self.response = {"Error": {"Code": code}, "ResponseMetadata": {"HTTPStatusCode": http}}


def test_aws_predicate():
    assert r.aws_is_retryable(_Boto("ThrottlingException", 400))
    assert r.aws_is_retryable(_Boto("Whatever", 503))
    assert not r.aws_is_retryable(_Boto("AccessDenied", 403))
    assert not r.aws_is_retryable(ValueError())


class _Az(Exception):
    def __init__(self, status_code):
        self.status_code = status_code


def test_azure_predicate():
    assert r.azure_is_retryable(_Az(429))
    assert r.azure_is_retryable(_Az(503))
    assert not r.azure_is_retryable(_Az(404))


def test_google_predicate_non_google_error_is_false():
    assert r.google_is_retryable(Transient()) is False


def test_retry_after_header():
    class Resp:
        headers = {"Retry-After": "7"}

    e = Exception()
    e.response = Resp()
    assert r.retry_after_seconds(e) == 7.0
    assert r.retry_after_seconds(Exception()) is None


class _WithRetryAfter(Exception):
    def __init__(self, seconds):
        class Resp:
            headers = {"Retry-After": str(seconds)}

        self.response = Resp()


def test_retry_after_header_sets_the_minimum_wait(monkeypatch):
    monkeypatch.setattr(r.random, "uniform", lambda a, b: 0.0)
    waits = []
    calls = []

    def f():
        calls.append(1)
        if len(calls) == 1:
            raise _WithRetryAfter(7)
        return "ok"

    assert r.retry_call(f, is_retryable=lambda e: True, sleep=waits.append, timeout=1e9) == "ok"
    assert waits == [7.0]


def test_retry_after_is_capped_at_the_maximum_backoff(monkeypatch):
    monkeypatch.setattr(r.random, "uniform", lambda a, b: 0.0)
    waits = []
    calls = []

    def f():
        calls.append(1)
        if len(calls) == 1:
            raise _WithRetryAfter(500)

    r.retry_call(f, is_retryable=lambda e: True, sleep=waits.append, maximum=60, timeout=1e9)
    assert waits == [60]


def test_limit_exceeded_is_a_quota_error_not_a_throttle():
    assert not r.aws_is_retryable(_Boto("LimitExceededException", 400))
    assert r.aws_is_retryable(_Boto("RequestLimitExceeded", 503))
