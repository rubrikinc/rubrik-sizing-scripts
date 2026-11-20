"""The Recovery Services vault item (CSV) and policy (JSON) files, ``azure_backup_vault_*``.

The golden files in ``tests/data/vault`` are the output of the real ``Get-AzRecoveryServicesBackupItem``
and ``Get-AzRecoveryServicesBackupProtectionPolicy`` (Az.RecoveryServices 7.15.0) on two test vaults,
and ``vault_rest.json`` is what the SDK returned for the same vaults. Names, ids and the subscription
were replaced with synthetic ones. The exporter is fed the REST payloads and must write the same text.

Checked against a real run: the VM and Azure Files items, and the VM (standard and enhanced), Azure
Files and SQL in VM policies. SQL in VM items, Azure SQL Database items and Azure SQL Database
policies had no data in the test vaults; their tests only check what the code promises (file names,
routing, the join), not a match with PowerShell.
"""

import json
from pathlib import Path
from unittest.mock import MagicMock

import csv_export
import pytest
from anonymize import Anonymizer
from collectors.backup_posture import rest_payload

DATA = Path(__file__).parent / "data" / "vault"
SUB = "11111111-2222-3333-4444-555555555555"
RG = "rg-backup"
MANAGEMENT_TO_WORKLOAD = {"AzureIaasVM": "VM", "AzureStorage": "Files", "AzureWorkload": "SQL"}


def _golden(name: str) -> str:
    # Newer ICU writes U+202F before AM/PM (AZ-Q8 of the parity plan); the exporter writes a space.
    return (DATA / name).read_bytes().decode("utf-8").replace(" ", " ")


def _posture(vault: str, payload: dict) -> dict:
    """What the collector stores for one vault, built from the REST payloads."""
    items, policies = [], []
    for item in payload["items"]:
        props = item["properties"]
        policy_id = props.get("policyId")
        items.append(
            {
                "name": item["name"],
                "resource_id": item["id"],
                "workload_type": MANAGEMENT_TO_WORKLOAD[props["backupManagementType"]],
                "vault_name": vault,
                "resource_group": RG,
                "subscription_id": SUB,
                "policy_name": policy_id.rsplit("/", 1)[-1] if policy_id else None,
                "policy_id": policy_id,
                "last_backup_status": props.get("lastBackupStatus"),
                "last_backup_time": props.get("lastBackupTime"),
                "protection_state": props.get("protectionState"),
                "source_resource_id": props.get("sourceResourceId") or props.get("virtualMachineId"),
                "friendly_name": props.get("friendlyName")
                if props["backupManagementType"] == "AzureStorage"
                else None,
                "rest_properties": props,
            }
        )
    for policy in payload["policies"]:
        props = policy["properties"]
        policies.append(
            {
                "name": policy["name"],
                "resource_id": policy["id"],
                "vault_name": vault,
                "resource_group": RG,
                "subscription_id": SUB,
                "workload_type": MANAGEMENT_TO_WORKLOAD[props["backupManagementType"]],
                "rest_properties": props,
            }
        )
    return {
        "subscription_id": SUB,
        "vaults": [{"name": vault, "location": "centralus"}],
        "protected_items": items,
        "policies": policies,
    }


def _result(*vaults: str) -> dict:
    rest = json.loads((DATA / "vault_rest.json").read_text(encoding="utf-8"))
    return {
        "tenant_name": "TENANT",
        "tenant_id": "t",
        "subscription_names": {SUB: "SUB"},
        "backup_posture": [_posture(v, rest[v]) for v in (vaults or rest)],
    }


def _files(result: dict, anonymizer=None) -> dict[str, str]:
    return csv_export.build_csv_files(result, "S", anonymizer)


# ── real-output goldens ───────────────────────────────────────────────────────


def test_vm_items_match_the_real_cmdlet_output():
    text = _files(_result("vault-a"))["azure_backup_vault_VM_items-S.csv"]
    assert text == _golden("items_vm.csv")


def test_azure_files_items_match_the_real_cmdlet_output():
    text = _files(_result("vault-a"))["azure_backup_vault_Azure_Files_items-S.csv"]
    assert text == _golden("items_files.csv")


@pytest.mark.parametrize(
    "prefix,vaults,golden",
    [
        ("azure_backup_vault_VM_policies-S.json", ("vault-a",), "policies_vm_a.json"),
        ("azure_backup_vault_VM_policies-S.json", ("vault-b",), "policies_vm_b.json"),
        ("azure_backup_vault_VM_SQL_policies-S.json", ("vault-a",), "policies_sql_a.json"),
        ("azure_backup_vault_Azure_Files_Policies-S.json", ("vault-a",), "policies_files_a.json"),
    ],
)
def test_policies_match_the_real_cmdlet_output_byte_for_byte(prefix, vaults, golden):
    assert _files(_result(*vaults))[prefix] == _golden(golden)


def test_vm_policy_enums_are_numbers_and_the_enhanced_schedule_is_hourly():
    policies = json.loads(_files(_result("vault-a"))["azure_backup_vault_VM_policies-S.json"])
    by_name = {p["Name"]: p for p in policies}
    standard, enhanced = by_name["vm-daily-lrs"], by_name["EnhancedPolicy"]
    assert (standard["WorkloadType"], standard["BackupManagementType"]) == (1, 1)
    assert standard["PolicySubType"] == 1 and enhanced["PolicySubType"] == 2
    assert standard["SchedulePolicy"]["ScheduleRunFrequency"] == 1
    assert enhanced["SchedulePolicy"]["ScheduleRunFrequency"] == 3
    assert enhanced["SchedulePolicy"]["HourlySchedule"]["Interval"] == 4


# ── rendering rules checked in pwsh ───────────────────────────────────────────


def test_no_rows_gives_an_empty_file_not_an_empty_array():
    assert csv_export._render_ps_json([]) == ""


def test_one_policy_is_a_bare_object_and_several_are_an_array():
    one = csv_export._render_ps_json([{"A": 1}])
    many = csv_export._render_ps_json([{"A": 1}, {"A": 2}])
    assert json.loads(one) == {"A": 1}
    assert json.loads(many) == [{"A": 1}, {"A": 2}]
    assert many.endswith("]\n") and one.endswith("}\n")


def test_a_vault_with_no_policies_or_items_still_writes_all_eight_files_empty():
    files = _files({"tenant_name": "T", "subscription_names": {}, "backup_posture": []})
    vault_files = {n: t for n, t in files.items() if "backup_vault_" in n and "_info" not in n}
    assert len(vault_files) == 8
    assert set(vault_files.values()) == {""}


def test_the_eight_file_names_are_the_ones_the_script_writes():
    written = set(_files(_result("vault-a")))
    assert {
        "azure_backup_vault_VM_items-S.csv",
        "azure_backup_vault_VM_SQL_items-S.csv",
        "azure_backup_vault_Azure_SQL_Database_items-S.csv",
        "azure_backup_vault_Azure_Files_items-S.csv",
        "azure_backup_vault_VM_policies-S.json",
        "azure_backup_vault_VM_SQL_policies-S.json",
        # capital P in the last two, as in Get-AzureSizingInfo.ps1
        "azure_backup_vault_Azure_SQL_Database_Policies-S.json",
        "azure_backup_vault_Azure_Files_Policies-S.json",
    } <= written


def test_a_value_that_is_a_date_has_no_fraction_and_a_12_hour_clock():
    assert csv_export._ps_datetime_or_none("2026-10-27T23:18:06.3921437Z") == "10/27/2026 11:18:06 PM"
    assert csv_export._ps_datetime_or_none(None) is None
    assert csv_export._ps_datetime_or_none("") is None


# ── routing ───────────────────────────────────────────────────────────────────


def test_each_item_goes_to_exactly_one_file():
    files = _files(_result("vault-a"))
    assert files["azure_backup_vault_VM_items-S.csv"].count("\n") == 2  # header + one VM
    assert files["azure_backup_vault_Azure_Files_items-S.csv"].count("\n") == 2
    assert files["azure_backup_vault_VM_SQL_items-S.csv"] == ""
    assert files["azure_backup_vault_Azure_SQL_Database_items-S.csv"] == ""


def test_policy_kind_is_read_from_the_payload_not_the_class_name():
    sql = {"rest_properties": {"backupManagementType": "AzureWorkload", "workLoadType": "SQLDataBase"}}
    db = {"rest_properties": {"backupManagementType": "AzureSql"}}
    other = {"rest_properties": {"backupManagementType": "AzureWorkload", "workLoadType": "SAPHanaDatabase"}}
    assert csv_export._vault_kind(sql) == "VM_SQL"
    assert csv_export._vault_kind(db) == "Azure_SQL_Database"
    assert csv_export._vault_kind(other) is None  # PowerShell lists no HANA files


def test_a_row_without_a_payload_falls_back_to_the_workload_label():
    assert csv_export._vault_kind({"workload_type": "VM"}) == "VM"
    assert csv_export._vault_kind({"workload_type": "Files"}) == "Azure_Files"
    assert csv_export._vault_kind({"workload_type": "On-Premises"}) is None


# ── SQL in VM: the BackupPolicies join (AZ-CSV-4b) ────────────────────────────


def _sql_item(server: str, policy: str, vault: str = "vault-a") -> dict:
    return {
        "name": f"SQLDataBase;mssqlserver;{server}_db",
        "resource_id": "x",
        "workload_type": "SQL",
        "vault_name": vault,
        "resource_group": RG,
        "subscription_id": SUB,
        "policy_name": policy,
        "policy_id": f"/p/{policy}",
        "protection_state": "Protected",
        "source_resource_id": f"/subscriptions/{SUB}/resourceGroups/{RG}/providers/Microsoft.Compute/virtualMachines/{server}",
        "rest_properties": {
            "backupManagementType": "AzureWorkload",
            "workloadType": "SQLDataBase",
            "serverName": server,
            "policyId": f"/p/{policy}",
        },
    }


def test_sql_in_vm_items_join_the_vm_on_server_name():
    result = _result("vault-a")
    result["backup_posture"][0]["protected_items"].append(_sql_item("vm-1", "SQLPolicy"))
    joined = csv_export._vm_policies(result)
    # the VM's own backup policy first, then the SQL policy, as the script goes through a vault
    assert joined[(SUB, "vm-1", "centralus")] == ["vm-daily-lrs", "SQLPolicy"]


def test_a_server_with_several_databases_on_one_policy_lists_it_once():
    result = _result("vault-a")
    items = result["backup_posture"][0]["protected_items"]
    items += [_sql_item("sqlhost", "SQLPolicy"), _sql_item("sqlhost", "SQLPolicy")]
    joined = csv_export._vm_policies(result)
    assert joined[(SUB, "sqlhost", "centralus")] == ["SQLPolicy", "SQLPolicy"]
    assert csv_export._backup_cells(joined[(SUB, "sqlhost", "centralus")], True)["BackupPolicies"] == "SQLPolicy"


def test_a_sql_item_without_a_server_name_is_not_joined():
    item = _sql_item("", "SQLPolicy")
    result = _result("vault-a")
    result["backup_posture"][0]["protected_items"].append(item)
    assert not any(key[1] == "" for key in csv_export._vm_policies(result))


# ── anonymized run ────────────────────────────────────────────────────────────


def _leaks(text: str) -> list[str]:
    """Columns of the CSV text that still hold a real name, id or subscription."""
    import csv
    import io

    header, *rows = csv.reader(io.StringIO(text))
    real = (SUB, "vm-1", "rg-backup", "storage1", "vault-a", "vm-daily-lrs", "files-daily-lrs")
    return [
        col for col, value in zip(header, rows[0], strict=True) if any(r in value for r in real)
    ]


def test_the_item_csvs_are_anonymized_and_the_policy_json_is_left_out():
    files = _files(_result("vault-a"), Anonymizer())
    assert _leaks(files["azure_backup_vault_Azure_Files_items-S.csv"]) == []
    assert _leaks(files["azure_backup_vault_VM_items-S.csv"]) == []
    assert not [n for n in files if n.endswith(".json") and "backup_vault_" in n]


def test_the_vm_items_hold_no_real_subscription_id_when_anonymized():
    files = _files(_result("vault-a"), Anonymizer())
    assert _leaks(files["azure_backup_vault_VM_items-S.csv"]) == []


# ── the collector's payload helper ────────────────────────────────────────────


def test_rest_payload_reads_an_sdk_model_and_ignores_test_doubles():
    class Model:
        def as_dict(self):
            return {"backupManagementType": "AzureIaasVM"}

    assert rest_payload(Model()) == {"backupManagementType": "AzureIaasVM"}
    assert rest_payload(MagicMock()) == {}
    assert rest_payload(None) == {}

    class Broken:
        def as_dict(self):
            raise RuntimeError("boom")

    assert rest_payload(Broken()) == {}


# ── shapes the test vaults did not have ───────────────────────────────────────
#
# The real vaults only held daily policies, so these run synthetic REST payloads through the builders.
# They catch crashes and check the structure taken from the Az objects the module builds locally
# (property names and order, enum numbers); no real policy with weekly, monthly or yearly retention
# was compared with PowerShell.


def _policy_row(rest_properties: dict, workload_type: str = "VM") -> dict:
    return {
        "name": "p",
        "resource_id": "/p",
        "vault_name": "vault-a",
        "resource_group": RG,
        "subscription_id": SUB,
        "workload_type": workload_type,
        "rest_properties": rest_properties,
    }


def _build(rest_properties: dict, workload_type: str = "VM", kind: str = "VM") -> dict:
    result = {
        "tenant_name": "T",
        "subscription_names": {SUB: "S"},
        "backup_posture": [
            {
                "subscription_id": SUB,
                "vaults": [{"name": "vault-a", "location": "centralus"}],
                "policies": [_policy_row(rest_properties, workload_type)],
                "protected_items": [],
            }
        ],
    }
    (row,) = csv_export._vault_policy_rows(kind)(csv_export._context_for(result)[1], result)
    return row


LONG_TERM = {
    "retentionPolicyType": "LongTermRetentionPolicy",
    "dailySchedule": {
        "retentionTimes": ["2026-10-23T23:00:00Z"],
        "retentionDuration": {"count": 7, "durationType": "Days"},
    },
    "weeklySchedule": {
        "daysOfTheWeek": ["Sunday", "Saturday"],
        "retentionTimes": ["2026-10-23T23:00:00Z"],
        "retentionDuration": {"count": 4, "durationType": "Weeks"},
    },
    "monthlySchedule": {
        "retentionScheduleFormatType": "Weekly",
        "retentionScheduleWeekly": {"daysOfTheWeek": ["Friday"], "weeksOfTheMonth": ["Last"]},
        "retentionTimes": ["2026-10-23T23:00:00Z"],
        "retentionDuration": {"count": 12, "durationType": "Months"},
    },
    "yearlySchedule": {
        "retentionScheduleFormatType": "Daily",
        "monthsOfYear": ["January", "December"],
        "retentionScheduleDaily": {"daysOfTheMonth": [{"date": 1, "isLast": False}]},
        "retentionTimes": ["2026-10-23T23:00:00Z"],
        "retentionDuration": {"count": 5, "durationType": "Years"},
    },
}


def test_weekly_monthly_and_yearly_retention_build_with_the_az_names_and_numbers():
    row = _build({"backupManagementType": "AzureIaasVM", "retentionPolicy": LONG_TERM})
    retention = row["RetentionPolicy"]
    assert [retention[k] for k in ("IsDailyScheduleEnabled", "IsWeeklyScheduleEnabled")] == [True, True]
    assert retention["WeeklySchedule"]["DurationCountInWeeks"] == 4
    assert retention["WeeklySchedule"]["DaysOfTheWeek"] == [0, 6]  # Sunday, Saturday
    monthly = retention["MonthlySchedule"]
    assert monthly["DurationCountInMonths"] == 12
    assert monthly["RetentionScheduleFormatType"] == 2  # Weekly
    assert monthly["RetentionScheduleWeekly"] == {"DaysOfTheWeek": [5], "WeeksOfTheMonth": [5]}
    assert monthly["RetentionScheduleDaily"] is None
    yearly = retention["YearlySchedule"]
    assert yearly["DurationCountInYears"] == 5
    assert yearly["MonthsOfYear"] == [1, 12]
    assert yearly["RetentionScheduleDaily"] == {"DaysOfTheMonth": [{"Date": 1, "IsLast": False}]}
    assert list(monthly) == [
        "DurationCountInMonths",
        "RetentionScheduleFormatType",
        "RetentionScheduleDaily",
        "RetentionScheduleWeekly",
        "RetentionTimes",
        "BackupManagementType",
    ]
    assert list(yearly)[:3] == ["DurationCountInYears", "RetentionScheduleFormatType", "MonthsOfYear"]


def test_a_weekly_vm_schedule_numbers_its_days():
    schedule = {
        "schedulePolicyType": "SimpleSchedulePolicy",
        "scheduleRunFrequency": "Weekly",
        "scheduleRunDays": ["Monday", "Wednesday"],
        "scheduleRunTimes": ["2026-10-23T23:00:00Z"],
    }
    row = _build({"backupManagementType": "AzureIaasVM", "schedulePolicy": schedule})
    assert row["SchedulePolicy"]["ScheduleRunFrequency"] == 2
    assert row["SchedulePolicy"]["ScheduleRunDays"] == [1, 3]


def test_azure_sql_database_policy_builds_with_a_retention_policy_only():
    row = _build(
        {"backupManagementType": "AzureSql", "retentionPolicy": {"retentionPolicyType": "SimpleRetentionPolicy", "retentionDuration": {"count": 35, "durationType": "Days"}}},
        workload_type="SQL",
        kind="Azure_SQL_Database",
    )
    assert row["RetentionPolicy"] == {"RetentionDurationType": 1, "RetentionCount": 35}
    assert (row["WorkloadType"], row["BackupManagementType"]) == (2, 4)  # AzureSQLDatabase, AzureSQL
    assert "SchedulePolicy" not in row


def test_az_enum_helpers_keep_unknown_names_as_text_and_none_as_none():
    table = {"A": 1}
    assert csv_export._az_enum(table, "A") == 1
    assert csv_export._az_enum(table, "Z") == "Z"
    assert csv_export._az_enum(table, None) is None and csv_export._az_enum(table, "") is None
    assert csv_export._az_enums(table, ["A", "Z"]) == [1, "Z"]
    assert csv_export._az_enums(table, None) == []
