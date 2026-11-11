"""Tests for collectors/utils.py — no Azure credentials required."""

from collectors.utils import (
    TagSummary,
    build_tag_summary,
    parse_resource_group,
    parse_resource_name,
)


def test_build_tag_summary_empty():
    result = build_tag_summary([])
    assert result.key_coverage == {}
    assert result.untagged_count == 0
    assert result.untagged_pct == 0.0
    assert result.missing_keys == []


def test_build_tag_summary_all_untagged():
    result = build_tag_summary([None, None, {}])
    assert result.untagged_count == 3
    assert result.untagged_pct == 100.0
    assert result.key_coverage == {}


def test_build_tag_summary_full_coverage():
    tags = [
        {"env": "prod", "owner": "alice"},
        {"env": "dev", "owner": "bob"},
        {"env": "prod", "owner": "carol"},
    ]
    result = build_tag_summary(tags)
    assert result.key_coverage["env"] == 100.0
    assert result.key_coverage["owner"] == 100.0
    assert result.untagged_count == 0
    assert result.untagged_pct == 0.0
    assert result.missing_keys == []


def test_build_tag_summary_partial_coverage():
    # "env" on 2 of 4 = 50% → NOT in missing_keys (threshold is < 50%)
    # "owner" on 1 of 4 = 25% → in missing_keys
    tags = [
        {"env": "prod", "owner": "alice"},
        {"env": "dev"},
        {},
        None,
    ]
    result = build_tag_summary(tags)
    assert result.key_coverage["env"] == 50.0
    assert result.key_coverage["owner"] == 25.0
    assert result.untagged_count == 2
    assert result.untagged_pct == 50.0
    assert "owner" in result.missing_keys
    assert "env" not in result.missing_keys


def test_build_tag_summary_common_values_capped_at_five():
    tags = [{"env": v} for v in ["a", "b", "c", "d", "e", "f"]]
    result = build_tag_summary(tags)
    assert len(result.common_values["env"]) == 5


def test_build_tag_summary_common_values_sorted_by_frequency():
    tags = [{"env": "prod"}] * 3 + [{"env": "dev"}] * 1
    result = build_tag_summary(tags)
    values = list(result.common_values["env"].keys())
    assert values[0] == "prod"


_VAULT_ID = (
    "/subscriptions/00000000-0000-0000-0000-000000000001"
    "/resourceGroups/my-rg"
    "/providers/Microsoft.RecoveryServices/vaults/my-vault"
)


def test_parse_resource_group_valid():
    assert parse_resource_group(_VAULT_ID) == "my-rg"


def test_parse_resource_group_preserves_case():
    rid = "/subscriptions/sub/resourceGroups/MyRG/providers/Foo/bars/bar1"
    assert parse_resource_group(rid) == "MyRG"


def test_parse_resource_group_empty_string():
    assert parse_resource_group("") == ""


def test_parse_resource_group_no_rg_segment():
    assert parse_resource_group("/subscriptions/sub/providers/Foo") == ""


def test_parse_resource_name_valid():
    assert parse_resource_name(_VAULT_ID) == "my-vault"


def test_parse_resource_name_none():
    assert parse_resource_name(None) is None


def test_parse_resource_name_empty():
    assert parse_resource_name("") is None


def test_parse_resource_name_trailing_slash():
    assert parse_resource_name("/foo/bar/baz/") == "baz"


def test_decimal_units_from_bytes():
    from collectors.utils import decimal_gb, decimal_tb

    assert decimal_gb(107374182400) == 107.374  # 100 GiB
    assert decimal_tb(107374182400) == 0.1074
    assert decimal_gb(None) is None and decimal_tb(None) is None
    assert decimal_gb(0) == 0.0
