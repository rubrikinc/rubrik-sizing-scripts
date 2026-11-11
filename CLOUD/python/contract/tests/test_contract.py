"""Tests for contract/contract.py and the committed contract data."""

import pytest
from contract.contract import Contract, assert_conforms

C = Contract.load()
RDS = C.spec("aws_rds_info")


def _good_rds_header():
    return list(RDS.static)


def test_loads_all_files_with_unique_prefixes():
    assert len(C.files) == 51
    assert (
        len(C.for_cloud("aws")) == 26
        and len(C.for_cloud("azure")) == 19
        and len(C.for_cloud("gcp")) == 6
    )


def test_file_name_rules():
    assert RDS.file_name("2025-01-31_093015") == "aws_rds_info-2025-01-31_093015.csv"
    assert C.match_file_name("aws_rds_info-2025-01-31_093015.csv") is RDS
    assert C.match_file_name("aws_rds_info_2025-01-31_093015.csv") is None  # needs a hyphen
    assert C.match_file_name("aws_rds_info-2025-01-31.csv") is None
    azure = C.spec("azure_vmdisk_info")
    assert azure.file_name("2025-01-31_0930") == "azure_vmdisk_info-2025-01-31_0930.csv"
    with pytest.raises(ValueError):
        azure.file_name("2025-01-31_093015")


def test_azure_summary_keeps_underscore_and_flags_open_decision():
    s = C.spec("azure_sizing_summary")
    assert s.separator == "_" and s.decision == "DEC-8"
    assert C.match_file_name("azure_sizing_summary_2025-01-31_0930.csv") is s


def test_exact_header_conforms_and_tags_are_accepted_anywhere():
    assert RDS.check_header(_good_rds_header()) == []
    with_tags = _good_rds_header() + ["Tag: env", "Tag: cost center"]
    assert RDS.check_header(with_tags) == []
    mid = _good_rds_header()
    mid.insert(3, "Tag: env")
    assert RDS.check_header(mid) == []


def test_drift_is_reported():
    h = _good_rds_header()
    missing = [c for c in h if c != "Engine"]
    assert any("required columns missing" in p for p in RDS.check_header(missing))
    assert any("not in contract" in p for p in RDS.check_header(h + ["Surprise"]))
    swapped = h.copy()
    swapped[0], swapped[1] = swapped[1], swapped[0]
    assert any("order" in p for p in RDS.check_header(swapped))
    assert any("duplicate" in p for p in RDS.check_header(h + ["Engine"]))


def test_optional_columns_may_be_absent():
    fsx = C.spec("aws_fsx_filesystem_info")
    assert fsx.optional, "expected conditional FSx columns"
    header = [c for c in fsx.static if c not in fsx.optional]
    assert fsx.check_header(header) == []


def test_partial_and_unresolved_files_are_lenient_but_reported():
    s3 = C.spec("aws_s3_info")
    assert s3.status == "partial"
    assert s3.check_header(list(reversed(s3.required))) == []  # order not enforced
    assert s3.check_header([*s3.required, "StandardStorage_SizeGB"]) == []  # run-time columns
    assert C.spec("aws_rds_info").check_header([*C.spec("aws_rds_info").static, "Surprise"])
    assert C.spec("azure_backup_vault_info").check_header(["anything"]) == []
    gaps = C.strict_gaps()
    assert "aws_s3_info: partial" in gaps and len([g for g in gaps if "unresolved" in g]) == 5


def test_check_csv_by_name():
    assert (
        C.check_csv("gce_spanner_info-2025-01-31_093015.csv", C.spec("gce_spanner_info").static)
        == []
    )
    assert C.check_csv("unknown-2025-01-31_093015.csv", ["a"])[0].startswith("file name")
    with pytest.raises(AssertionError):
        assert_conforms(C, "gce_spanner_info-2025-01-31_093015.csv", ["Wrong"])


def test_backup_cost_expanded_metric_columns_are_static():
    spec = C.spec("aws_backup_costs")
    assert "AWSBackupUnblendedCost" in spec.static and "AWSBackupUsageQuantity" in spec.static


def test_value_format_rules():
    from contract.contract import VALUE_FORMAT

    assert VALUE_FORMAT["quote_all_fields"] and VALUE_FORMAT["empty_collection"] == "header only"
    assert VALUE_FORMAT["boolean"] == ["True", "False"] and VALUE_FORMAT["bom"] is False
