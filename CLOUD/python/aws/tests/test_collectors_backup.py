"""Tests for collectors/backup.py."""

import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock

import boto3
import pytest
from botocore.stub import Stubber
from collectors import BOTO_BACKUP_CFG, DenialTracker
from collectors.backup import (
    _plan_export,
    _ps_json_datetime,
    fetch_backup_costs,
    fetch_backup_plans,
    fetch_backup_vaults,
    fetch_protected_arns,
)
from models.discovery import BackupPlan, BackupSelection

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


def _paginators(client, **pages_by_operation):
    """Stub ``get_paginator`` by operation name, as the plan collector uses one per list call."""

    def get_paginator(name):
        return _paginator(pages_by_operation[name])

    client.get_paginator.side_effect = get_paginator


class TestFetchProtectedArns:
    def test_returns_arns_from_all_pages(self):
        client = MagicMock()
        client.get_paginator.return_value = _paginator(
            [
                {
                    "Results": [
                        {"ResourceArn": "arn:aws:ec2:us-east-1:123:instance/i-1"},
                        {"ResourceArn": "arn:aws:ec2:us-east-1:123:instance/i-2"},
                    ]
                },
                {
                    "Results": [
                        {"ResourceArn": "arn:aws:rds:us-east-1:123:db:mydb"},
                    ]
                },
            ]
        )
        arns = fetch_protected_arns(_mock_session(client), REGION)
        assert "arn:aws:ec2:us-east-1:123:instance/i-1" in arns
        assert "arn:aws:ec2:us-east-1:123:instance/i-2" in arns
        assert "arn:aws:rds:us-east-1:123:db:mydb" in arns
        assert len(arns) == 3

    def test_api_error_returns_empty_set(self):
        client = MagicMock()
        client.get_paginator.side_effect = Exception("AccessDenied")
        arns = fetch_protected_arns(_mock_session(client), REGION)
        assert arns == set()

    def test_filters_empty_arn_strings(self):
        client = MagicMock()
        client.get_paginator.return_value = _paginator(
            [
                {"Results": [{"ResourceArn": ""}, {"ResourceArn": "arn:aws:ec2:::instance/i-1"}]},
            ]
        )
        arns = fetch_protected_arns(_mock_session(client), REGION)
        assert "" not in arns
        assert len(arns) == 1

    def test_empty_results_returns_empty_set(self):
        client = MagicMock()
        client.get_paginator.return_value = _paginator([{"Results": []}])
        arns = fetch_protected_arns(_mock_session(client), REGION)
        assert arns == set()


class TestFetchBackupPlans:
    def _make_client(self, plans, plan_detail, selections):
        client = MagicMock()
        _paginators(
            client,
            list_backup_plans=[{"BackupPlansList": plans}],
            list_backup_selections=[selections],
        )
        client.get_backup_plan.return_value = plan_detail
        client.get_backup_selection.return_value = {
            "BackupSelection": {"Resources": ["arn:aws:ec2:*:*:instance/*"]}
        }
        return client

    def test_basic_plan_with_rule(self):
        now = datetime.now(timezone.utc)
        plans = [
            {
                "BackupPlanId": "plan-1",
                "BackupPlanArn": "arn:aws:backup:::plan/plan-1",
                "BackupPlanName": "DailyBackup",
                "VersionId": "v1",
                "CreationDate": now,
                "LastExecutionDate": now,
            }
        ]
        detail = {
            "BackupPlan": {
                "Rules": [
                    {
                        "RuleName": "daily",
                        "TargetBackupVaultName": "Default",
                        "ScheduleExpression": "cron(0 5 ? * * *)",
                        "StartWindowMinutes": 60,
                        "CompletionWindowMinutes": 180,
                        "Lifecycle": {"DeleteAfterDays": 35},
                    }
                ]
            }
        }
        selections = {"BackupSelectionsList": [{"SelectionId": "sel-1"}]}
        client = self._make_client(plans, detail, selections)
        result = fetch_backup_plans(_mock_session(client), REGION, ACCT, ALIAS)

        assert len(result) == 1
        plan = result[0]
        assert plan.plan_name == "DailyBackup"
        assert plan.plan_id == "plan-1"
        assert len(plan.rules) == 1
        assert plan.rules[0].rule_name == "daily"
        assert plan.rules[0].delete_after_days == 35
        assert "arn:aws:ec2:*:*:instance/*" in plan.resources

    def test_captures_tag_and_condition_selection_criteria(self):
        """A tag-based org policy has empty Resources but real ListOfTags/Conditions — both must
        be captured so a resource can be attributed to the plan that protects it SE-side."""
        now = datetime.now(timezone.utc)
        plans = [
            {
                "BackupPlanId": "orgs/abc",
                "BackupPlanArn": "arn:aws:backup:::plan/orgs/abc",
                "BackupPlanName": "lucid-backup",
                "VersionId": "v1",
                "CreationDate": now,
                "LastExecutionDate": now,
            }
        ]
        detail = {
            "BackupPlan": {
                "Rules": [
                    {
                        "RuleName": "daily",
                        "TargetBackupVaultName": "lucid-backup",
                        "ScheduleExpression": "cron(0 5/12 ? * * *)",
                        "Lifecycle": {"DeleteAfterDays": 7},
                    }
                ]
            }
        }
        selections = {"BackupSelectionsList": [{"SelectionId": "sel-1"}]}
        client = MagicMock()
        _paginators(
            client,
            list_backup_plans=[{"BackupPlansList": plans}],
            list_backup_selections=[selections],
        )
        client.get_backup_plan.return_value = detail
        client.get_backup_selection.return_value = {
            "BackupSelection": {
                "Resources": [],  # tag-based org policy → no explicit ARNs
                "ListOfTags": [
                    {
                        "ConditionType": "STRINGEQUALS",
                        "ConditionKey": "lucid-backup",
                        "ConditionValue": "true",
                    },
                ],
                "Conditions": {
                    "StringEquals": [
                        {"ConditionKey": "aws:ResourceTag/Environment", "ConditionValue": "prod"},
                    ]
                },
            }
        }
        result = fetch_backup_plans(_mock_session(client), REGION, ACCT, ALIAS)
        assert len(result) == 1
        plan = result[0]
        assert plan.resources == []
        assert plan.selection_tags == [
            {
                "ConditionType": "STRINGEQUALS",
                "ConditionKey": "lucid-backup",
                "ConditionValue": "true",
            }
        ]
        assert plan.selection_conditions == [
            {
                "StringEquals": [
                    {"ConditionKey": "aws:ResourceTag/Environment", "ConditionValue": "prod"}
                ]
            }
        ]

    def test_selection_criteria_default_empty(self):
        """Plans whose selections carry only explicit Resources leave the criteria lists empty."""
        now = datetime.now(timezone.utc)
        plans = [
            {
                "BackupPlanId": "plan-1",
                "BackupPlanArn": "",
                "BackupPlanName": "n",
                "VersionId": "v1",
                "CreationDate": now,
                "LastExecutionDate": now,
            }
        ]
        detail = {"BackupPlan": {"Rules": []}}
        selections = {"BackupSelectionsList": [{"SelectionId": "sel-1"}]}
        client = self._make_client(plans, detail, selections)
        result = fetch_backup_plans(_mock_session(client), REGION, ACCT, ALIAS)
        assert result[0].selection_tags == []
        assert result[0].selection_conditions == []

    def test_api_error_returns_empty_list(self):
        client = MagicMock()
        client.get_paginator.side_effect = Exception("AccessDenied")
        result = fetch_backup_plans(_mock_session(client), REGION, ACCT, ALIAS)
        assert result == []

    def test_get_backup_plan_error_yields_incomplete_placeholder(self):
        """A plan whose details cannot be read stays in the list, marked incomplete, so readers
        do not trust the plans that did load."""
        plans = [
            {
                "BackupPlanId": "bad-plan",
                "BackupPlanArn": "",
                "BackupPlanName": "x",
                "VersionId": "v1",
                "CreationDate": None,
                "LastExecutionDate": None,
            }
        ]
        client = MagicMock()
        _paginators(client, list_backup_plans=[{"BackupPlansList": plans}])
        client.get_backup_plan.side_effect = Exception("NotFound")
        tracker = DenialTracker()
        result = fetch_backup_plans(_mock_session(client), REGION, ACCT, ALIAS, tracker)
        assert len(result) == 1
        plan = result[0]
        assert (plan.plan_id, plan.plan_name, plan.version_id) == ("bad-plan", "x", "v1")
        assert plan.rules == [] and plan.selections == [] and plan.plan_export == {}
        assert plan.selections_complete is False
        assert len(tracker.permission_errors()) == 1

    def test_plan_with_no_lifecycle(self):
        now = datetime.now(timezone.utc)
        plans = [
            {
                "BackupPlanId": "p1",
                "BackupPlanArn": "",
                "BackupPlanName": "n",
                "VersionId": "v1",
                "CreationDate": now,
                "LastExecutionDate": now,
            }
        ]
        detail = {
            "BackupPlan": {
                "Rules": [
                    {
                        "RuleName": "r",
                        "TargetBackupVaultName": "v",
                        "ScheduleExpression": "",
                        "Lifecycle": None,
                    }
                ]
            }
        }
        client = MagicMock()
        _paginators(
            client,
            list_backup_plans=[{"BackupPlansList": plans}],
            list_backup_selections=[{"BackupSelectionsList": []}],
        )
        client.get_backup_plan.return_value = detail
        result = fetch_backup_plans(_mock_session(client), REGION, ACCT, ALIAS)
        assert len(result) == 1
        assert result[0].rules[0].delete_after_days == 0


SCP_DENIAL = "An error occurred (AccessDeniedException): explicit deny in a service_control_policy"


def _plan_item(plan_id="p1", name="Daily"):
    return {
        "BackupPlanId": plan_id,
        "BackupPlanArn": f"arn:aws:backup:{REGION}:{ACCT}:backup-plan:{plan_id}",
        "BackupPlanName": name,
        "VersionId": "v1",
        "CreationDate": datetime(2022, 6, 6, 23, 33, 40, 22000, tzinfo=timezone.utc),
        "LastExecutionDate": datetime(2024, 10, 2, 5, 43, 6, tzinfo=timezone.utc),
    }


def _plan_client(selection_pages, selection_details=None, plan_items=None):
    """A mock backup client with one plan (or ``plan_items``) and the given selection pages."""
    client = MagicMock()
    _paginators(
        client,
        list_backup_plans=[{"BackupPlansList": plan_items or [_plan_item()]}],
        list_backup_selections=selection_pages,
    )
    client.get_backup_plan.return_value = {"BackupPlan": {"Rules": []}}
    details = selection_details or {}
    client.get_backup_selection.side_effect = lambda BackupPlanId, SelectionId: details.get(
        SelectionId, {"BackupSelection": {}}
    )
    return client


def _page(*selection_ids):
    return {"BackupSelectionsList": [{"SelectionId": sel_id} for sel_id in selection_ids]}


class TestPlanSelections:
    def test_selections_stay_separate_and_keep_not_resources(self):
        details = {
            "s1": {
                "BackupSelection": {
                    "Resources": ["arn:aws:ec2:*:*:instance/*"],
                    "NotResources": ["arn:aws:ec2:us-east-1:1:instance/i-skip"],
                    "ListOfTags": [
                        {
                            "ConditionType": "STRINGEQUALS",
                            "ConditionKey": "backup",
                            "ConditionValue": "true",
                        }
                    ],
                }
            },
            "s2": {
                "BackupSelection": {
                    "Conditions": {
                        "StringNotEquals": [
                            {"ConditionKey": "aws:ResourceTag/tier", "ConditionValue": "gold"}
                        ],
                        "StringLike": [
                            {"ConditionKey": "aws:ResourceTag/env", "ConditionValue": "pr*"}
                        ],
                    }
                }
            },
        }
        client = _plan_client([_page("s1", "s2")], details)
        (plan,) = fetch_backup_plans(_mock_session(client), REGION, ACCT, ALIAS)

        first, second = plan.selections
        assert first == BackupSelection(
            selection_id="s1",
            resources=["arn:aws:ec2:*:*:instance/*"],
            not_resources=["arn:aws:ec2:us-east-1:1:instance/i-skip"],
            list_of_tags=details["s1"]["BackupSelection"]["ListOfTags"],
            string_equals=[],
            string_like=[],
            string_not_equals=[],
            string_not_like=[],
        )
        assert second.resources == [] and second.list_of_tags == []
        assert second.string_not_equals == [
            {"ConditionKey": "aws:ResourceTag/tier", "ConditionValue": "gold"}
        ]
        assert second.string_like == [
            {"ConditionKey": "aws:ResourceTag/env", "ConditionValue": "pr*"}
        ]
        # The flat fields other readers use are unchanged: everything merged together.
        assert plan.resources == ["arn:aws:ec2:*:*:instance/*"]
        assert len(plan.selection_tags) == 1 and len(plan.selection_conditions) == 1
        assert plan.selections_complete is True

    def test_second_page_of_selections_is_read(self):
        client = _plan_client([_page("s1", "s2"), _page("s3")])
        (plan,) = fetch_backup_plans(_mock_session(client), REGION, ACCT, ALIAS)
        assert [s.selection_id for s in plan.selections] == ["s1", "s2", "s3"]
        assert client.get_backup_selection.call_count == 3

    def test_listing_failure_midway_keeps_first_page_and_marks_incomplete(self):
        def pages():
            yield _page("s1", "s2")
            raise Exception("ThrottlingException: Rate exceeded")

        client = _plan_client([])
        _paginators(
            client,
            list_backup_plans=[{"BackupPlansList": [_plan_item()]}],
            list_backup_selections=pages(),
        )
        tracker = DenialTracker()
        (plan,) = fetch_backup_plans(_mock_session(client), REGION, ACCT, ALIAS, tracker)
        assert [s.selection_id for s in plan.selections] == ["s1", "s2"]
        assert plan.selections_complete is False
        assert len(tracker.permission_errors()) == 1

    def test_failed_selection_keeps_others_and_records_one_error(self):
        details = {"s1": {"BackupSelection": {"Resources": ["arn:a"]}}}
        client = _plan_client([_page("s1", "s2", "s3")], details)
        real = client.get_backup_selection.side_effect

        def flaky(BackupPlanId, SelectionId):
            if SelectionId == "s2":
                raise Exception("ThrottlingException: Rate exceeded")
            return real(BackupPlanId, SelectionId)

        client.get_backup_selection.side_effect = flaky
        tracker = DenialTracker()
        (plan,) = fetch_backup_plans(_mock_session(client), REGION, ACCT, ALIAS, tracker)

        assert [s.selection_id for s in plan.selections] == ["s1", "s3"]
        assert plan.selections_complete is False
        errors = tracker.permission_errors()
        assert len(errors) == 1
        assert errors[0]["service"] == "backup" and errors[0]["region"] == REGION
        assert "1 throttled" in errors[0]["error"]
        assert not tracker.denied_services()  # a throttle does not mark the account denied

    def test_many_failures_in_a_region_are_one_scan_error(self):
        client = _plan_client([_page("s1", "s2", "s3")])
        client.get_backup_selection.side_effect = Exception("AccessDenied")
        client.get_backup_plan.side_effect = None
        tracker = DenialTracker()
        (plan,) = fetch_backup_plans(_mock_session(client), REGION, ACCT, ALIAS, tracker)
        assert plan.selections == [] and plan.selections_complete is False
        errors = tracker.permission_errors()
        assert len(errors) == 1 and "3 time(s)" in errors[0]["error"]

    def test_scp_denial_on_a_selection_alone_marks_the_account_denied(self):
        client = _plan_client([_page("s1")])
        client.get_backup_selection.side_effect = Exception(SCP_DENIAL)
        tracker = DenialTracker()
        fetch_backup_plans(_mock_session(client), REGION, ACCT, ALIAS, tracker)
        assert tracker.denied_services() == frozenset({"backup"})

    def test_scp_denial_listing_plans_marks_the_account_denied(self):
        client = MagicMock()
        client.get_paginator.side_effect = Exception(SCP_DENIAL)
        tracker = DenialTracker()
        assert fetch_backup_plans(_mock_session(client), REGION, ACCT, ALIAS, tracker) == []
        assert tracker.denied_services() == frozenset({"backup"})

    def test_non_scp_listing_failure_is_recorded_not_silent(self):
        client = MagicMock()
        client.get_paginator.side_effect = Exception("ThrottlingException: Rate exceeded")
        tracker = DenialTracker()
        assert fetch_backup_plans(_mock_session(client), REGION, ACCT, ALIAS, tracker) == []
        assert len(tracker.permission_errors()) == 1
        assert not tracker.denied_services()

    def test_no_tracker_is_fine(self):
        client = _plan_client([_page("s1")])
        client.get_backup_selection.side_effect = Exception("boom")
        (plan,) = fetch_backup_plans(_mock_session(client), REGION, ACCT, ALIAS)
        assert plan.selections_complete is False

    def test_client_uses_the_backup_retry_config(self):
        client = _plan_client([_page()])
        session = _mock_session(client)
        fetch_backup_plans(session, REGION, ACCT, ALIAS)
        assert session.client.call_args.kwargs["config"] is BOTO_BACKUP_CFG
        assert BOTO_BACKUP_CFG.retries == {"max_attempts": 10, "mode": "standard"}
        assert (BOTO_BACKUP_CFG.connect_timeout, BOTO_BACKUP_CFG.read_timeout) == (15, 30)

    def test_real_response_shapes_via_botocore_stubber(self):
        """The mocks above use hand-written dicts; the Stubber validates real response shapes."""
        client = boto3.client(
            "backup",
            region_name=REGION,
            aws_access_key_id="testing",
            aws_secret_access_key="testing",
        )
        role = f"arn:aws:iam::{ACCT}:role/backup"
        item = _plan_item()
        with Stubber(client) as stub:
            stub.add_response("list_backup_plans", {"BackupPlansList": [item]})
            stub.add_response(
                "get_backup_plan",
                {
                    "BackupPlan": {
                        "BackupPlanName": "Daily",
                        "Rules": [
                            {
                                "RuleName": "daily",
                                "TargetBackupVaultName": "Default",
                                "ScheduleExpression": "cron(0 5 ? * * *)",
                                "StartWindowMinutes": 480,
                                "CompletionWindowMinutes": 10080,
                                "Lifecycle": {"DeleteAfterDays": 35},
                                "RecoveryPointTags": {"team": "x"},
                                "RuleId": "rule-1",
                                "EnableContinuousBackup": False,
                                "ScheduleExpressionTimezone": "Etc/UTC",
                            }
                        ],
                    },
                    "BackupPlanId": "p1",
                    "BackupPlanArn": item["BackupPlanArn"],
                    "VersionId": "v1",
                    "CreationDate": item["CreationDate"],
                    "LastExecutionDate": item["LastExecutionDate"],
                },
            )
            stub.add_response(
                "list_backup_selections",
                {
                    "BackupSelectionsList": [
                        {
                            "SelectionId": "s1",
                            "SelectionName": "n",
                            "BackupPlanId": "p1",
                            "IamRoleArn": role,
                        }
                    ]
                },
            )
            stub.add_response(
                "get_backup_selection",
                {
                    "BackupSelection": {
                        "SelectionName": "n",
                        "IamRoleArn": role,
                        "Resources": ["arn:aws:s3:::*"],
                        "NotResources": ["arn:aws:s3:::skip"],
                        "ListOfTags": [
                            {
                                "ConditionType": "STRINGEQUALS",
                                "ConditionKey": "backup",
                                "ConditionValue": "true",
                            }
                        ],
                        "Conditions": {
                            "StringEquals": [
                                {"ConditionKey": "aws:ResourceTag/env", "ConditionValue": "prod"}
                            ],
                            "StringNotLike": [
                                {"ConditionKey": "aws:ResourceTag/tmp", "ConditionValue": "*"}
                            ],
                        },
                    },
                    "SelectionId": "s1",
                    "BackupPlanId": "p1",
                },
            )
            (plan,) = fetch_backup_plans(_mock_session(client), REGION, ACCT, ALIAS)
            stub.assert_no_pending_responses()

        (selection,) = plan.selections
        assert selection.resources == ["arn:aws:s3:::*"]
        assert selection.not_resources == ["arn:aws:s3:::skip"]
        assert selection.list_of_tags[0]["ConditionType"] == "STRINGEQUALS"
        assert selection.string_equals[0]["ConditionKey"] == "aws:ResourceTag/env"
        assert selection.string_not_like[0]["ConditionValue"] == "*"
        assert plan.selections_complete is True
        assert plan.plan_export["BackupPlan"]["Rules"][0]["Lifecycle"]["DeleteAfterDays"] == 35


class TestPlanExport:
    def _export(self, desc=None, item=None):
        client = _plan_client([_page()], plan_items=[item or _plan_item()])
        client.get_backup_plan.return_value = desc or {"BackupPlan": {"Rules": []}}
        (plan,) = fetch_backup_plans(_mock_session(client), REGION, ACCT, ALIAS)
        return plan.plan_export

    def test_has_powershells_keys_and_no_sdk_transport_fields(self):
        export = self._export()
        assert list(export) == [
            "AdvancedBackupSettings",
            "BackupPlan",
            "BackupPlanArn",
            "BackupPlanId",
            "CreationDate",
            "CreatorRequestId",
            "DeletionDate",
            "LastExecutionDate",
            "ScheduledRunsPreview",
            "VersionId",
        ]
        assert list(export["BackupPlan"]) == [
            "AdvancedBackupSettings",
            "BackupPlanName",
            "Rules",
            "ScanSettings",
        ]
        assert "Resources" not in export  # added from the explicit selections when written
        for sdk_key in ("ResponseMetadata", "ContentLength", "HttpStatusCode"):
            assert sdk_key not in export

    def test_a_field_the_api_leaves_out_is_null_like_awstools_5(self):
        item = _plan_item()
        item["LastExecutionDate"] = None
        export = self._export(item=item)
        assert export["CreationDate"] == "2022-06-06T23:33:40.022Z"
        for key in (
            "LastExecutionDate",
            "DeletionDate",
            "CreatorRequestId",
            "AdvancedBackupSettings",
            "ScheduledRunsPreview",
        ):
            assert export[key] is None, key
        assert export["BackupPlan"] == {
            "AdvancedBackupSettings": None,
            "BackupPlanName": "Daily",
            "Rules": [],
            "ScanSettings": None,
        }

    def test_rules_have_every_awstools_5_key_and_nothing_else(self):
        rule = {
            "RuleName": "r",
            "TargetBackupVaultName": "v",
            "SomethingBoto3AddsLater": 1,  # not in PowerShell's output
        }
        export = self._export({"BackupPlan": {"BackupPlanName": "Daily", "Rules": [rule]}})
        (out,) = export["BackupPlan"]["Rules"]
        assert list(out) == [
            "CompletionWindowMinutes",
            "CopyActions",
            "EnableContinuousBackup",
            "IndexActions",
            "Lifecycle",
            "RecoveryPointTags",
            "RuleId",
            "RuleName",
            "ScanActions",
            "ScheduleExpression",
            "ScheduleExpressionTimezone",
            "StartWindowMinutes",
            "TargetBackupVaultName",
            "TargetLogicallyAirGappedBackupVaultArn",
        ]
        assert out["RuleName"] == "r" and out["CopyActions"] is None and out["Lifecycle"] is None
        assert out["RecoveryPointTags"] is None and out["EnableContinuousBackup"] is None

    def test_values_the_api_does_send_are_kept(self):
        utc = timezone.utc
        rule = {
            "RuleName": "r",
            "CopyActions": [
                {"DestinationBackupVaultArn": "arn:v", "Lifecycle": {"DeleteAfterDays": 60}}
            ],
            "EnableContinuousBackup": True,
            "RecoveryPointTags": {"a": "b"},
            "Lifecycle": {
                "DeleteAfterDays": 35,
                "MoveToColdStorageAfterDays": 30,
                "OptInToArchiveForSupportedResources": True,
            },
        }
        desc = {
            "BackupPlan": {
                "BackupPlanName": "Daily",
                "Rules": [rule],
                "AdvancedBackupSettings": [{"ResourceType": "EC2", "BackupOptions": {"A": "b"}}],
            },
            "DeletionDate": datetime(2027, 2, 3, 4, 5, 6, tzinfo=utc),
            "LastExecutionDate": datetime(2026, 1, 2, 3, 4, 5, 500000, tzinfo=utc),
            "ScheduledRunsPreview": [datetime(2027, 1, 1, 5, 0, tzinfo=utc)],
        }
        export = self._export(desc)
        (out,) = export["BackupPlan"]["Rules"]
        assert out["CopyActions"] == [
            {
                "DestinationBackupVaultArn": "arn:v",
                "Lifecycle": {
                    "DeleteAfterDays": 60,
                    "DeleteAfterEvent": None,
                    "MoveToColdStorageAfterDays": None,
                    "OptInToArchiveForSupportedResources": None,
                },
            }
        ]
        assert out["EnableContinuousBackup"] is True and out["RecoveryPointTags"] == {"a": "b"}
        assert out["Lifecycle"]["MoveToColdStorageAfterDays"] == 30
        assert export["BackupPlan"]["AdvancedBackupSettings"][0]["ResourceType"] == "EC2"
        assert export["DeletionDate"] == "2027-02-03T04:05:06Z"
        assert export["LastExecutionDate"] == "2026-01-02T03:04:05.5Z"
        assert export["ScheduledRunsPreview"] == ["2027-01-01T05:00:00Z"]

    def test_matches_what_powershell_writes_with_awstools_5(self):
        """A plan as boto3 returns it, against the element PowerShell (AWS.Tools 5.0.313) wrote for
        the same plan in a real run (ids and the account are sanitized)."""
        path = Path(__file__).parent / "data" / "ps_backup_plan_awstools_5_0_313.json"
        expected = json.loads(path.read_text(encoding="utf-8"))
        created = datetime(2026, 10, 7, 22, 2, 26, 233000, tzinfo=timezone.utc)
        common = {
            "BackupPlanArn": expected["BackupPlanArn"],
            "BackupPlanId": expected["BackupPlanId"],
            "VersionId": expected["VersionId"],
            "CreationDate": created,
            "CreatorRequestId": expected["CreatorRequestId"],
        }
        rule = expected["BackupPlan"]["Rules"][0]
        boto3_rule = {  # what the API sends: no field that PowerShell shows as null
            "RuleName": rule["RuleName"],
            "TargetBackupVaultName": rule["TargetBackupVaultName"],
            "ScheduleExpression": rule["ScheduleExpression"],
            "StartWindowMinutes": rule["StartWindowMinutes"],
            "CompletionWindowMinutes": rule["CompletionWindowMinutes"],
            "Lifecycle": {"DeleteAfterDays": rule["Lifecycle"]["DeleteAfterDays"]},
            "RuleId": rule["RuleId"],
            "ScheduleExpressionTimezone": rule["ScheduleExpressionTimezone"],
        }
        item = {**common, "BackupPlanName": "example-plan"}
        desc = {**common, "BackupPlan": {"BackupPlanName": "example-plan", "Rules": [boto3_rule]}}
        got = _plan_export(item, desc)
        assert got == expected
        assert json.dumps(got) == json.dumps(expected)  # same keys in the same order

    def test_export_is_plain_json(self):
        export = self._export()
        assert json.loads(json.dumps(export)) == export  # no default= needed

    def test_datetime_format_is_powershells(self):
        utc = timezone.utc
        assert _ps_json_datetime(datetime(2024, 1, 30, 6, 12, 18, 572000, tzinfo=utc)).endswith(
            ".572Z"
        )
        assert _ps_json_datetime(datetime(2024, 1, 30, 6, 12, 18, tzinfo=utc)) == (
            "2024-01-30T06:12:18Z"
        )
        assert _ps_json_datetime(None) is None  # a date the API did not send
        assert _ps_json_datetime("2024-01-01T00:00:00Z") == "2024-01-01T00:00:00Z"

    def test_discovery_json_round_trip_keeps_selections_and_export(self):
        import main

        client = _plan_client(
            [_page("s1")],
            {"s1": {"BackupSelection": {"Resources": ["arn:a"], "NotResources": ["arn:b"]}}},
        )
        plans = fetch_backup_plans(_mock_session(client), REGION, ACCT, ALIAS)
        loaded = json.loads(json.dumps(main._to_dict(plans), default=str))
        assert loaded[0]["selections"][0]["not_resources"] == ["arn:b"]
        assert loaded[0]["selections_complete"] is True
        assert loaded[0]["plan_export"]["VersionId"] == "v1"


class TestBackupPlanDefaults:
    def test_older_positional_construction_still_works(self):
        plan = BackupPlan(ACCT, ALIAS, REGION, "p1", "", "Plan1", "v1", "", "", [], [])
        assert plan.selections == [] and plan.selections_complete is True
        assert plan.plan_export == {}


class TestFetchBackupVaults:
    def test_captures_lock_recovery_points_and_encryption(self):
        client = MagicMock()
        client.get_paginator.return_value = _paginator(
            [
                {
                    "BackupVaultList": [
                        {
                            "BackupVaultName": "lucid-backup",
                            "BackupVaultArn": "arn:aws:backup:us-east-1:1:backup-vault:lucid-backup",
                            "EncryptionKeyArn": "arn:aws:kms:us-east-1:1:key/abc",
                            "NumberOfRecoveryPoints": 4210,
                            "Locked": True,
                            "MinRetentionDays": 7,
                            "MaxRetentionDays": 3650,
                        },
                        {"BackupVaultName": "", "BackupVaultArn": "skip-me-no-name"},
                    ]
                }
            ]
        )
        vaults = fetch_backup_vaults(_mock_session(client), REGION, ACCT, ALIAS)
        assert len(vaults) == 1  # the nameless vault is skipped
        v = vaults[0]
        assert v.vault_name == "lucid-backup"
        assert v.recovery_point_count == 4210
        assert v.encryption_key_arn == "arn:aws:kms:us-east-1:1:key/abc"
        assert v.locked is True and v.lock_state == "compliance"
        assert v.min_retention_days == 7 and v.max_retention_days == 3650

    def test_unlocked_vault_has_no_lock_state(self):
        client = MagicMock()
        client.get_paginator.return_value = _paginator(
            [{"BackupVaultList": [{"BackupVaultName": "Default", "Locked": False}]}]
        )
        vaults = fetch_backup_vaults(_mock_session(client), REGION, ACCT, ALIAS)
        assert vaults[0].locked is False and vaults[0].lock_state == ""
        assert vaults[0].recovery_point_count == 0

    def test_api_error_returns_empty_list(self):
        client = MagicMock()
        client.get_paginator.side_effect = Exception("AccessDenied")
        assert fetch_backup_vaults(_mock_session(client), REGION, ACCT, ALIAS) == []


class TestFetchBackupCosts:
    def _make_ce_session(self, result_response):
        client = MagicMock()
        client.get_cost_and_usage.return_value = result_response
        s = MagicMock()
        s.client.return_value = client
        return s

    def _ce_response(self, months):
        results = []
        for m in months:
            results.append(
                {
                    "TimePeriod": {"Start": m["start"], "End": m["end"]},
                    "Total": {
                        "AmortizedCost": {"Amount": str(m["amt"])},
                        "BlendedCost": {"Amount": str(m["amt"])},
                        "UnblendedCost": {"Amount": str(m["amt"])},
                    },
                }
            )
        return {"ResultsByTime": results}

    def test_parses_monthly_entries(self):
        months = [
            {"start": "2023-01-01", "end": "2023-02-01", "amt": 100.50},
            {"start": "2023-02-01", "end": "2023-03-01", "amt": 200.75},
        ]
        session = self._make_ce_session(self._ce_response(months))
        entries = fetch_backup_costs(session, ACCT, ALIAS)
        assert len(entries) == 2
        assert entries[0].period_start == "2023-01-01"
        assert entries[0].amortized_cost == pytest.approx(100.50)
        assert entries[1].amortized_cost == pytest.approx(200.75)

    def test_amounts_are_float(self):
        months = [{"start": "2023-01-01", "end": "2023-02-01", "amt": 50.0}]
        session = self._make_ce_session(self._ce_response(months))
        entries = fetch_backup_costs(session, ACCT, ALIAS)
        assert isinstance(entries[0].amortized_cost, float)

    def test_api_error_returns_empty_list(self):
        client = MagicMock()
        client.get_cost_and_usage.side_effect = Exception("AccessDenied")
        s = MagicMock()
        s.client.return_value = client
        entries = fetch_backup_costs(s, ACCT, ALIAS)
        assert entries == []

    def test_empty_results_returns_empty_list(self):
        session = self._make_ce_session({"ResultsByTime": []})
        entries = fetch_backup_costs(session, ACCT, ALIAS)
        assert entries == []
