"""Lifecycle rules and requester pays, read from the bucket listing.

A bucket is a MagicMock, so every property a test does not set would answer with a MagicMock.
``_bucket`` sets the ones the collector reads to a plain value or to None.
"""

from __future__ import annotations

from collectors.storage import StorageCollector, _lifecycle
from tests.test_collectors_storage import _make_bucket
from tests.test_collectors_storage_sizes import _collect, _monitoring

DAY = 86400


def _bucket(**props):
    bucket = _make_bucket("b1")
    for name in ("lifecycle_rules", "requester_pays"):
        setattr(bucket, name, props.get(name))
    return bucket


def _rule(kind, storage_class=None, **condition):
    action = {"type": kind}
    if storage_class:
        action["storageClass"] = storage_class
    return {"action": action, "condition": condition}


def test_a_delete_rule_on_age_is_how_long_live_data_is_kept():
    found = _lifecycle(_bucket(lifecycle_rules=[_rule("Delete", age=365)]))
    assert found["lifecycle_rule_count"] == 1
    assert found["lifecycle_delete_days"] == 365
    assert found["lifecycle_noncurrent_delete_days"] is None


def test_the_shortest_delete_rule_wins():
    bucket = _bucket(lifecycle_rules=[_rule("Delete", age=730), _rule("Delete", age=90)])
    assert _lifecycle(bucket)["lifecycle_delete_days"] == 90


def test_a_rule_for_older_versions_is_kept_apart_from_live_data():
    bucket = _bucket(
        lifecycle_rules=[
            _rule("Delete", daysSinceNoncurrentTime=30),
            _rule("Delete", age=14, isLive=False),
        ]
    )
    found = _lifecycle(bucket)
    assert found["lifecycle_noncurrent_delete_days"] == 14
    assert found["lifecycle_delete_days"] is None


def test_storage_class_changes_are_listed_by_age():
    bucket = _bucket(
        lifecycle_rules=[
            _rule("SetStorageClass", "ARCHIVE", age=365),
            _rule("SetStorageClass", "NEARLINE", age=30),
        ]
    )
    assert _lifecycle(bucket)["lifecycle_transitions"] == "NEARLINE@30d; ARCHIVE@365d"


def test_a_rule_with_a_prefix_suffix_or_version_count_is_counted_but_not_read_as_retention():
    bucket = _bucket(
        lifecycle_rules=[
            _rule("Delete", age=7, matchesPrefix=["tmp/"]),
            _rule("Delete", age=7, matchesSuffix=[".log"]),
            _rule("Delete", age=7, numNewerVersions=3),
        ]
    )
    found = _lifecycle(bucket)
    assert found["lifecycle_rule_count"] == 3 and found["lifecycle_delete_days"] is None


def test_a_delete_rule_for_one_storage_class_is_not_the_bucket_retention():
    bucket = _bucket(lifecycle_rules=[_rule("Delete", age=30, matchesStorageClass=["STANDARD"])])
    assert _lifecycle(bucket)["lifecycle_delete_days"] is None


def test_a_class_change_limited_to_one_class_is_still_a_transition():
    rule = _rule("SetStorageClass", "COLDLINE", age=90, matchesStorageClass=["NEARLINE"])
    assert _lifecycle(_bucket(lifecycle_rules=[rule]))["lifecycle_transitions"] == "COLDLINE@90d"


def test_a_bucket_with_no_rules_has_a_zero_count_and_no_days():
    found = _lifecycle(_bucket(lifecycle_rules=[]))
    assert found["lifecycle_rule_count"] == 0
    assert found["lifecycle_delete_days"] is None and found["lifecycle_transitions"] is None


def test_unreadable_rules_are_unknown_not_zero():
    assert _lifecycle(_bucket(lifecycle_rules=None)) == {}


def test_the_abort_multipart_rule_does_not_count_as_a_delete():
    bucket = _bucket(lifecycle_rules=[_rule("AbortIncompleteMultipartUpload", age=1)])
    assert _lifecycle(bucket)["lifecycle_delete_days"] is None


def test_the_listing_fills_lifecycle_and_requester_pays_on_the_bucket():
    bucket = _bucket(lifecycle_rules=[_rule("Delete", age=60)], requester_pays=True)
    _, inventory = _collect([bucket], _monitoring()[0])
    found = inventory.buckets[0]
    assert found.lifecycle_delete_days == 60 and found.requester_pays is True


def test_requester_pays_off_is_false_and_not_reported_is_none():
    on, off = _bucket(requester_pays=True), _bucket(requester_pays=False)
    settings = StorageCollector._settings
    assert settings(on, None, "region")["requester_pays"] is True
    assert settings(off, None, "region")["requester_pays"] is False
    assert settings(_bucket(), None, "region")["requester_pays"] is None
