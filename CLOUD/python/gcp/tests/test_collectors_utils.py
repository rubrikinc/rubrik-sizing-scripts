"""Tests for collectors/utils.py."""

from __future__ import annotations

import sys

sys.path.insert(0, str(__import__("pathlib").Path(__file__).parent.parent))

from collectors.utils import (
    LabelSummary,
    brief_error,
    build_label_summary,
    classify_error,
    collection_error,
    parse_leaf_name,
    parse_project_from_resource_name,
)

# ── classify_error / collection_error ───────────────────────────────────────────


def test_classify_error_api_disabled():
    exc = Exception("403 Cloud Spanner API has not been used in project foo or it is disabled.")
    assert classify_error(exc) == "API_DISABLED"


def test_classify_error_permission_denied():
    exc = Exception("403 Request denied by Cloud IAM. Missing required IAM permission on scope.")
    assert classify_error(exc) == "PERMISSION_DENIED"


def test_classify_error_sdk_missing_importerror():
    assert classify_error(ImportError("cannot import name 'backupdr_v1'")) == "SDK_MISSING"


def test_classify_error_sdk_missing_by_message():
    assert classify_error(Exception("No module named 'google.cloud.alloydb'")) == "SDK_MISSING"


def test_classify_error_other():
    assert classify_error(Exception("connection reset by peer")) == "OTHER"


def test_collection_error_shape():
    err = collection_error("database:spanner", Exception("403 ... it is disabled. [reason: X]"))
    assert err == {
        "collector": "database:spanner",
        "category": "API_DISABLED",
        "message": "403 ... it is disabled.",
    }


# ── brief_error ─────────────────────────────────────────────────────────────────


def test_brief_error_strips_protobuf_detail_dump():
    # Mimics a google.api_core SERVICE_DISABLED error: human message, then a
    # multi-line protobuf detail list that must not reach the console.
    exc = Exception(
        "403 Cloud Spanner API has not been used in project foo or it is disabled. "
        '[reason: "SERVICE_DISABLED"\nmetadata {\n  key: "service"\n}\n]'
    )
    result = brief_error(exc)
    assert result == ("403 Cloud Spanner API has not been used in project foo or it is disabled.")
    assert "reason" not in result
    assert "\n" not in result


def test_brief_error_first_line_only():
    assert brief_error(Exception("boom\ntraceback line\nmore")) == "boom"


def test_brief_error_falls_back_to_class_name():
    assert brief_error(Exception("")) == "Exception"


# ── build_label_summary ────────────────────────────────────────────────────────


def test_build_label_summary_empty():
    result = build_label_summary([])
    assert result.key_coverage == {}
    assert result.unlabelled_count == 0
    assert result.unlabelled_pct == 0.0
    assert result.missing_keys == []


def test_build_label_summary_all_unlabelled():
    result = build_label_summary([None, {}, None])
    assert result.unlabelled_count == 3
    assert result.unlabelled_pct == 100.0
    assert result.key_coverage == {}


def test_build_label_summary_full_coverage():
    labels = [{"env": "prod", "team": "platform"}, {"env": "prod", "team": "data"}]
    result = build_label_summary(labels)
    assert result.key_coverage["env"] == 100.0
    assert result.key_coverage["team"] == 100.0
    assert result.unlabelled_count == 0
    assert result.missing_keys == []


def test_build_label_summary_partial_coverage():
    labels = [{"env": "prod"}, {"env": "dev"}, None]
    result = build_label_summary(labels)
    assert round(result.key_coverage["env"], 1) == pytest_round(2 / 3 * 100)
    assert result.unlabelled_count == 1
    assert round(result.unlabelled_pct, 1) == pytest_round(1 / 3 * 100)


def pytest_round(val: float) -> float:
    return round(val, 1)


def test_build_label_summary_missing_keys_below_50_pct():
    # 2 labelled, 3 unlabelled → 40% coverage → missing
    labels = [{"env": "prod"}, {"env": "dev"}, None, None, None]
    result = build_label_summary(labels)
    assert "env" in result.missing_keys


def test_build_label_summary_common_values_top_5():
    labels = [{"env": v} for v in ["a", "b", "c", "d", "e", "f"]]
    result = build_label_summary(labels)
    assert len(result.common_values["env"]) == 5


# ── parse_project_from_resource_name ──────────────────────────────────────────


def test_parse_project_full_resource_name():
    name = "//compute.googleapis.com/projects/my-project/zones/us-central1-a/instances/vm1"
    assert parse_project_from_resource_name(name) == "my-project"


def test_parse_project_relative_resource_name():
    name = "projects/my-project/zones/us-central1-a/instances/vm1"
    assert parse_project_from_resource_name(name) == "my-project"


def test_parse_project_gcs_bucket():
    name = "//storage.googleapis.com/projects/my-project/buckets/my-bucket"
    assert parse_project_from_resource_name(name) == "my-project"


def test_parse_project_empty_string():
    assert parse_project_from_resource_name("") == ""


def test_parse_project_no_projects_segment():
    assert parse_project_from_resource_name("//compute.googleapis.com/global/images/img1") == ""


# ── parse_leaf_name ────────────────────────────────────────────────────────────


def test_parse_leaf_name_standard():
    name = "//compute.googleapis.com/projects/my-project/zones/us-central1-a/instances/my-vm"
    assert parse_leaf_name(name) == "my-vm"


def test_parse_leaf_name_empty():
    assert parse_leaf_name("") == ""


def test_parse_leaf_name_trailing_slash():
    assert parse_leaf_name("projects/my-project/buckets/my-bucket/") == "my-bucket"
