"""Tests for backup_plan_membership.py: which backup plans select a resource, as PowerShell does."""

import dataclasses
import json
import random
import re
import shutil
import subprocess
import time
from pathlib import Path

import pytest
from backup_plan_membership import (
    KINDS,
    Cond,
    Criteria,
    Membership,
    RowView,
    compute_membership,
    cond_matches,
    criteria_from_selection,
    ps_like,
    row_matches,
    tag_column_name,
    tag_index,
)
from models.discovery import BackupPlan, BackupSelection

SCRIPT = Path(__file__).resolve().parents[3] / "Get-AWSSizingInfo.ps1"
ACCT = "111"
REGION = "us-east-1"


# ── builders ──────────────────────────────────────────────────────────────────────────────────


def mk(kind, ids, arn, tags=None, account=ACCT, region=REGION):
    return RowView(kind, account, region, ids, arn, tags or {})


def ec2(i, **kw):
    region, account = kw.get("region", REGION), kw.get("account", ACCT)
    return mk(
        "ec2_instance",
        {"InstanceId": i},
        f"arn:aws:ec2:{region}:{account}:instance/{i}",
        kw.get("tags"),
        account,
        region,
    )


def tag(key, value):
    return {"ConditionType": "STRINGEQUALS", "ConditionKey": key, "ConditionValue": value}


def cond(key, value):
    return {"ConditionKey": key, "ConditionValue": value}


def sel(resources=(), not_resources=(), tags=(), eq=(), like=(), not_eq=(), not_like=()):
    return BackupSelection(
        "s",
        list(resources),
        list(not_resources),
        list(tags),
        list(eq),
        list(like),
        list(not_eq),
        list(not_like),
    )


def plan(name, *selections, account=ACCT, region=REGION):
    """A plan dict as the serialized discovery JSON has it."""
    return dataclasses.asdict(
        BackupPlan(
            account,
            "alias",
            region,
            f"id-{name}",
            "",
            name,
            "v1",
            "",
            "",
            [],
            [],
            selections=list(selections),
        )
    )


def result(plans, rows, group_order=None):
    return [(m.plan_names, m.in_plan) for m in compute_membership(plans, rows, group_order)]


# ── explicit ARNs, per type ───────────────────────────────────────────────────────────────────

BASE_ROWS = [
    ("ec2:i-a", ec2("i-a")),
    ("ec2:i-b", ec2("i-b")),
    (
        "ebs:vol-1",
        mk("ebs_attached", {"VolumeId": "vol-1"}, f"arn:aws:ec2:{REGION}:{ACCT}:volume/vol-1"),
    ),
    ("rds:prod-1", mk("rds", {"DBInstanceIdentifier": "prod-1"}, "arn:rds:prod-1")),
    ("rds:prod-2", mk("rds", {"DBInstanceIdentifier": "prod-2"}, "arn:rds:prod-2")),
    ("efs:fs-1", mk("efs", {"FileSystemId": "fs-1"}, "arn:efs:fs-1")),
    (
        "fsxvol:fs-1/v1",
        mk("fsx_volume", {"FileSystemId": "fs-1", "VolumeId": "v1"}, "arn:fsx:fs-1/v1"),
    ),
    (
        "fsxvol:fs-2/v2",
        mk("fsx_volume", {"FileSystemId": "fs-2", "VolumeId": "v2"}, "arn:fsx:fs-2/v2"),
    ),
    ("fsxfs:fs-1", mk("fsx_filesystem", {"FileSystemId": "fs-1"}, "arn:fsx:fs-1")),
    ("s3:bkt", mk("s3", {"BucketName": "bkt"}, "arn:aws:s3:::bkt")),
    ("s3:other", mk("s3", {"BucketName": "other"}, "arn:aws:s3:::other")),
    ("s3t:tb1", mk("s3_table", {"TableBucketName": "tb1"}, "arn:s3tables:tb1/t")),
    ("ddb:tbl-a", mk("dynamodb", {"TableName": "tbl-a"}, "arn:ddb:tbl-a")),
    ("ddb:tbl-b", mk("dynamodb", {"TableName": "tbl-b"}, "arn:ddb:tbl-b")),
]
EC2_BOTH = {"ec2:i-a", "ec2:i-b"}
RDS_BOTH = {"rds:prod-1", "rds:prod-2"}
FSX_VOLUMES = {"fsxvol:fs-1/v1", "fsxvol:fs-2/v2"}
S3_BOTH = {"s3:bkt", "s3:other"}
DDB_BOTH = {"ddb:tbl-a", "ddb:tbl-b"}


def selected_by(arn):
    rows = [r for _, r in BASE_ROWS]
    got = compute_membership([plan("P", sel(resources=[arn]))], rows)
    return {label for (label, _), m in zip(BASE_ROWS, got) if m.plan_names}


@pytest.mark.parametrize(
    "arn, expected",
    [
        ("arn:aws:ec2:us-east-1:111:instance/i-a", {"ec2:i-a"}),
        ("arn:aws:ec2:us-east-1:111:instance/I-A", {"ec2:i-a"}),  # case-insensitive
        ("arn:aws:ec2:*:*:instance/*", EC2_BOTH),
        ("arn:aws:ec2:*:*:volume/*", {"ebs:vol-1"}),
        ("arn:aws:ec2:us-east-1:111:volume/vol-1", {"ebs:vol-1"}),
        ("arn:aws:ec2:us-east-1:111:snapshot/snap-1", set()),
        ("arn:aws:ec2:us-east-1:111", set()),  # no segment 5
        ("arn:aws:EC2:us-east-1:111:instance/i-b", {"ec2:i-b"}),  # type switch ignores case
        ("arn:aws:rds:us-east-1:111:db:prod-1", {"rds:prod-1"}),
        ("arn:aws:rds:*:*:db:*", RDS_BOTH),
        ("arn:aws:rds:us-east-1:111:cluster:*", RDS_BOTH),  # segment 5 is not inspected
        ("arn:aws:rds:us-east-1:111:snapshot:prod-2", {"rds:prod-2"}),
        ("arn:aws:rds:us-east-1:111:db", set()),  # no segment 6
        ("arn:aws:elasticfilesystem:us-east-1:111:file-system/fs-1", {"efs:fs-1"}),
        ("arn:aws:elasticfilesystem:*:*:file-system/*", {"efs:fs-1"}),
        ("arn:aws:fsx:us-east-1:111:volume/fs-1/v1", {"fsxvol:fs-1/v1"}),
        ("arn:aws:fsx:us-east-1:111:volume/fs-1/v2", set()),  # both ids must match
        ("arn:aws:fsx:*:*:*", FSX_VOLUMES),  # volume rows only, never file systems
        ("arn:aws:fsx:us-east-1:111:file-system/fs-1", set()),  # no volume id
        ("arn:aws:s3:::*", S3_BOTH),
        ("arn:aws:s3:::bkt", set()),  # no "/", so PowerShell has no name
        ("arn:aws:s3:::bkt/*", set()),  # the name would be "*"
        ("arn:aws:s3:::x/bkt", {"s3:bkt"}),  # split("/")[1] is what is compared
        ("arn:aws:s3tables:us-east-1:111:bucket/tb1", {"s3t:tb1"}),
        ("arn:aws:s3tables:us-east-1:111:bucket/*", set()),
        ("arn:aws:s3tables:*:*:*", {"s3t:tb1"}),
        ("arn:aws:dynamodb:*:*:*", DDB_BOTH),
        ("arn:aws:dynamodb:us-east-1:111:table/*", set()),
        ("arn:aws:dynamodb:us-east-1:111:table/tbl-a", set()),  # never by name
        ("arn:aws:dynamodb:us-east-1:111:table", DDB_BOTH),  # null name equals the missing property
        ("*", set()),
        ("arn:aws:*:*:*:*", set()),
        ("arn:aws:backup:us-east-1:111:backup-vault:v", set()),
        ("", set()),
    ],
)
def test_explicit_arn_rules(arn, expected):
    assert selected_by(arn) == expected


def test_explicit_arn_only_reaches_the_plans_own_account_and_region():
    rows = [
        ec2("i-a"),
        ec2("i-a", region="eu-west-1"),
        ec2("i-a", account="222"),
    ]
    got = result([plan("P", sel(resources=["arn:aws:ec2:*:*:instance/*"]))], rows)
    assert got == [(["P"], True), ([], False), ([], False)]


def test_unattached_volumes_are_not_a_matchable_kind():
    assert "ebs_unattached" not in KINDS


# ── tag criteria ──────────────────────────────────────────────────────────────────────────────


def tagged(**tags):
    return ec2("i-x", tags={f"Tag: {k}": v for k, v in tags.items()})


def names_for(selection, *rows):
    return [names for names, _ in result([plan("P", selection)], list(rows))]


def test_list_of_tags_are_or_ed_and_only_stringequals_counts():
    s = sel(tags=[tag("backup", "true"), tag("env", "prod")])
    assert names_for(s, tagged(env="prod"), tagged(backup="true"), tagged(team="x")) == [
        ["P"],
        ["P"],
        [],
    ]
    other = {"ConditionType": "STRINGLIKE", "ConditionKey": "backup", "ConditionValue": "true"}
    assert names_for(sel(tags=[other]), tagged(backup="true")) == [[]]  # no criteria at all


def test_conditions_are_and_ed_and_negations_disqualify():
    s = sel(
        eq=[cond("aws:ResourceTag/env", "prod")],
        like=[cond("aws:ResourceTag/team", "plat*")],
        not_eq=[cond("aws:ResourceTag/tier", "gold")],
    )
    rows = [
        tagged(env="prod", team="platform"),
        tagged(env="prod", team="platform", tier="gold"),
        tagged(env="prod", team="platform", tier="silver"),
        tagged(env="prod"),  # team missing: a Like condition cannot match
        tagged(env="dev", team="platform"),
    ]
    assert names_for(s, *rows) == [["P"], [], ["P"], [], []]


def test_negation_only_selection_matches_rows_missing_the_tag_even_without_tag_columns():
    s = sel(not_eq=[cond("aws:ResourceTag/tier", "gold")])
    ddb = mk("dynamodb", {"TableName": "t"}, "arn:ddb:t")  # no tag columns at all
    got = names_for(s, tagged(tier="silver"), tagged(tier="gold"), tagged(), ddb)
    assert got == [["P"], [], ["P"], ["P"]]


def test_selections_of_one_plan_are_evaluated_apart():
    first = sel(tags=[tag("env", "prod")])
    second = sel(not_eq=[cond("aws:ResourceTag/tier", "gold")])
    rows = [
        tagged(env="dev", tier="silver"),  # only the second selection
        tagged(env="prod", tier="gold"),  # only the first: merged criteria would drop it
        tagged(),  # only the second
        tagged(env="dev", tier="gold"),  # neither
    ]
    assert names_for_two(first, second, rows) == [["P"], ["P"], ["P"], []]


def names_for_two(first, second, rows):
    return [n for n, _ in result([plan("P", first, second)], rows)]


@pytest.mark.parametrize(
    "criteria_key, column, row_value, condition_value, expected",
    [
        ("Env", "Tag: env", "PROD", "prod", True),  # key and value ignore case
        ("ENV", "Tag: Env", "prod", "prod", True),
        ("aws:ResourceTag/env", "Tag: env", "prod", "prod", True),
        ("AWS:RESOURCETAG/env", "Tag: env", "prod", "prod", True),  # prefix ignores case too
        ("my-tag", "Tag: my_tag", "x", "x", True),  # key is sanitized like the column
        ("a b/c", "Tag: a_b_c", "x", "x", True),
        ("env", "Tag: env", "", "", True),  # an empty value is present
        ("env", "Tag: env", None, "", False),  # a null value is missing
        ("env", "Tag: other", "x", "x", False),
        (None, "Tag: ", "x", "x", True),  # a null key is the empty string
    ],
)
def test_condition_matching_rules(criteria_key, column, row_value, condition_value, expected):
    criteria = Criteria(or_tags=(Cond("Equals", criteria_key or "", condition_value),))
    assert row_matches(tag_index({column: row_value}), criteria) is expected


def test_columns_that_differ_only_by_case_collapse_and_the_last_wins():
    index = tag_index({"Tag: Env": "dev", "Tag: env": "prod"})
    assert cond_matches(index, Cond("Equals", "env", "prod"))
    assert not cond_matches(index, Cond("Equals", "env", "dev"))


@pytest.mark.parametrize(
    "value, pattern, expected",
    [
        ("abc", "a*", True),
        ("abc", "A*", True),
        ("abc", "a?c", True),
        ("abc", "[ab]bc", True),
        ("abc", "[a-b]bc", True),
        ("ABC", "[a-c]*", True),
        ("abc", "[!a]bc", True),  # "!" and "^" are plain members, not negation
        ("xbc", "[!a]bc", False),
        ("xbc", "[^a]bc", False),
        ("a*c", "a`*c", True),  # a backtick escapes
        ("abc", "a`*c", False),
        ("a-c", "a[-]c", True),
        ("a.c", "a.c", True),
        ("abc", "a.c", False),
        ("a\nb", "a*b", True),
        ("", "*", True),
        ("abc", "[abc", False),  # invalid: PowerShell throws, here it matches nothing
        ("abc", "[]", False),
    ],
)
def test_like_follows_powershell_wildcards(value, pattern, expected):
    assert ps_like(value, pattern) is expected


def test_selection_criteria_are_read_from_a_serialized_selection():
    selection = dataclasses.asdict(
        sel(
            tags=[tag("a", "1"), {"ConditionType": "STRINGLIKE", "ConditionKey": "b"}],
            eq=[cond("aws:ResourceTag/c", "3")],
            not_like=[cond("aws:ResourceTag/d", None)],
        )
    )
    criteria = criteria_from_selection(selection)
    assert criteria.or_tags == (Cond("Equals", "a", "1"),)
    assert criteria.and_conds == (Cond("Equals", "aws:ResourceTag/c", "3"),)
    assert criteria.not_conds == (Cond("Like", "aws:ResourceTag/d", ""),)  # null value is ""
    assert tag_column_name("aws:ResourceTag/My-Key") == "tag: my_key"


# ── names, order and dedupe ───────────────────────────────────────────────────────────────────


def test_plan_names_follow_plan_order_and_match_across_plans():
    plans = [
        plan("Daily", sel(resources=["arn:aws:ec2:*:*:instance/*"])),
        plan("Weekly", sel(tags=[tag("backup", "true")])),
    ]
    rows = [tagged(backup="true"), tagged()]
    assert result(plans, rows) == [(["Daily", "Weekly"], True), (["Daily"], True)]


def test_explicit_arns_do_not_dedupe_but_the_tag_path_does():
    both = sel(resources=["arn:aws:ec2:*:*:instance/i-x", "arn:aws:ec2:*:*:instance/*"])
    assert result([plan("D", both)], [tagged()]) == [(["D", "D"], True)]

    tag_twice = [plan("D", sel(tags=[tag("a", "1")]), sel(eq=[cond("aws:ResourceTag/a", "1")]))]
    assert result(tag_twice, [tagged(a="1")]) == [(["D"], True)]

    # explicit first, then tags in the same selection: the tag path sees the name already there
    mixed = sel(resources=["arn:aws:ec2:*:*:instance/*"], tags=[tag("a", "1")])
    assert result([plan("D", mixed)], [tagged(a="1")]) == [(["D"], True)]

    # a later selection's explicit ARN appends again
    later = [plan("D", sel(tags=[tag("a", "1")]), sel(resources=["arn:aws:ec2:*:*:instance/*"]))]
    assert result(later, [tagged(a="1")]) == [(["D", "D"], True)]


def test_tag_dedupe_ignores_case_of_the_plan_name():
    plans = [plan("Daily", sel(tags=[tag("a", "1")])), plan("DAILY", sel(tags=[tag("a", "1")]))]
    assert result(plans, [tagged(a="1")]) == [(["Daily"], True)]


# ── NotResources ──────────────────────────────────────────────────────────────────────────────


def test_not_resources_strips_the_plan_from_the_listed_row():
    s = sel(
        resources=["arn:aws:ec2:*:*:instance/*"],
        not_resources=["arn:aws:ec2:us-east-1:111:instance/i-skip"],
    )
    got = result([plan("All", s)], [ec2("i-skip"), ec2("i-other")])
    assert got == [([], False), (["All"], True)]


def test_not_resources_arn_ignores_case_and_keeps_rows_with_other_plans_in_plan():
    plans = [
        plan("A", sel(resources=["arn:aws:ec2:*:*:instance/*"])),
        plan(
            "B",
            sel(
                resources=["arn:aws:ec2:*:*:instance/*"],
                not_resources=["ARN:AWS:EC2:US-EAST-1:111:INSTANCE/I-A"],
            ),
        ),
    ]
    assert result(plans, [ec2("i-a")]) == [(["A"], True)]


def test_not_resources_in_a_later_selection_removes_all_occurrences_and_can_be_readded():
    arn = "arn:aws:ec2:us-east-1:111:instance/i-a"
    explicit = sel(resources=["arn:aws:ec2:*:*:instance/*", "arn:aws:ec2:*:*:instance/i-a"])
    assert result([plan("P", explicit)], [ec2("i-a")]) == [(["P", "P"], True)]
    strip = sel(not_resources=[arn])
    assert result([plan("P", explicit, strip)], [ec2("i-a")]) == [([], False)]
    readd = sel(resources=["arn:aws:ec2:*:*:instance/*"])
    assert result([plan("P", explicit, strip, readd)], [ec2("i-a")]) == [(["P"], True)]


def test_not_resources_reaches_earlier_groups_but_not_later_ones():
    a_row = ec2("i-a", region="a")
    b_row = ec2("i-b", region="b")
    org_a = plan(
        "Org",
        sel(resources=["arn:aws:ec2:*:*:instance/*"], not_resources=[b_row.resource_arn]),
        region="a",
    )
    org_b = plan(
        "Org",
        sel(resources=["arn:aws:ec2:*:*:instance/*"], not_resources=[a_row.resource_arn]),
        region="b",
    )
    rows = [a_row, b_row]
    # a is scanned first: its NotResources cannot reach b yet, b's reaches a
    assert result([org_a, org_b], rows, [(ACCT, "a"), (ACCT, "b")]) == [
        ([], False),
        (["Org"], True),
    ]
    # the other scan order mirrors it
    assert result([org_a, org_b], rows, [(ACCT, "b"), (ACCT, "a")]) == [
        (["Org"], True),
        ([], False),
    ]


def test_a_group_with_plans_but_no_rows_still_strips_earlier_rows():
    a_row = ec2("i-a", region="a")
    in_a = plan("Org", sel(resources=["arn:aws:ec2:*:*:instance/*"]), region="a")
    in_c = plan("Org", sel(not_resources=[a_row.resource_arn]), region="c")
    assert result([in_a, in_c], [a_row]) == [([], False)]


def test_not_resources_naming_nothing_changes_nothing():
    s = sel(resources=["arn:aws:ec2:*:*:instance/*"], not_resources=["arn:aws:ec2:::nope", ""])
    assert result([plan("P", s)], [ec2("i-a")]) == [(["P"], True)]


# ── the rest of the contract ──────────────────────────────────────────────────────────────────


def test_a_plan_without_selections_selects_nothing_and_rows_come_back_in_order():
    legacy = {"account_id": ACCT, "region": REGION, "plan_name": "Old"}  # no "selections" key
    assert result([legacy], [ec2("i-a"), ec2("i-b")]) == [([], False), ([], False)]
    assert compute_membership([], []) == []
    assert isinstance(compute_membership([], [ec2("i-a")])[0], Membership)


def test_groups_match_regions_without_regard_to_case():
    rows = [ec2("i-a", region="US-EAST-1")]
    got = result(
        [plan("P", sel(resources=["arn:aws:ec2:*:*:instance/*"]), region="us-east-1")], rows
    )
    assert got == [(["P"], True)]


def test_invalid_wildcard_matches_nothing_and_does_not_stop_other_plans():
    plans = [
        plan("Bad", sel(like=[cond("aws:ResourceTag/env", "[oops")])),
        plan("Good", sel(eq=[cond("aws:ResourceTag/env", "prod")])),
    ]
    assert result(plans, [tagged(env="prod")]) == [(["Good"], True)]


# ── the indexed matcher equals a naive per-row reference ──────────────────────────────────────


def _part(parts, i):
    return parts[i] if i < len(parts) else None


def naive_explicit(arn, row):
    """PowerShell's explicit-ARN switch written row by row (independent of the index)."""
    parts = arn.split(":")
    slashed = arn.split("/")
    t = (_part(parts, 2) or "").lower() if _part(parts, 2) is not None else None
    if t is None:
        return False
    ids = row.ids

    def eq(a, b):
        return a is not None and b is not None and a.lower() == b.lower()

    if t == "ec2":
        seg = _part(parts, 5)
        if seg is None:
            return False
        sub = seg.split("/")
        what, ident = sub[0].lower(), _part(sub, 1)
        if what == "instance" and row.kind == "ec2_instance":
            return ident == "*" or eq(ident, ids["InstanceId"])
        if what == "volume" and row.kind == "ebs_attached":
            return ident == "*" or eq(ident, ids["VolumeId"])
        return False
    if t == "rds":
        ident = _part(parts, 6)
        return row.kind == "rds" and (ident == "*" or eq(ident, ids["DBInstanceIdentifier"]))
    if t == "elasticfilesystem":
        ident = _part(slashed, 1)
        return row.kind == "efs" and (ident == "*" or eq(ident, ids["FileSystemId"]))
    wildcard = parts[-1] == "*"
    if t == "fsx":
        if row.kind != "fsx_volume":
            return False
        if wildcard:
            return True
        return eq(_part(slashed, 1), ids["FileSystemId"]) and eq(_part(slashed, 2), ids["VolumeId"])
    if t == "s3":
        return row.kind == "s3" and (wildcard or eq(_part(slashed, 1), ids["BucketName"]))
    if t == "s3tables":
        return row.kind == "s3_table" and (
            wildcard or eq(_part(slashed, 1), ids["TableBucketName"])
        )
    if t == "dynamodb":
        return row.kind == "dynamodb" and (wildcard or _part(slashed, 1) is None)
    return False


def naive_membership(plans, rows, group_order=None):
    keys = []

    def key_of(account, region):
        return (str(account), str(region).lower())

    for account, region in group_order or ():
        if key_of(account, region) not in keys:
            keys.append(key_of(account, region))
    for row in rows:
        if key_of(row.account_id, row.region) not in keys:
            keys.append(key_of(row.account_id, row.region))
    for p in plans:
        if key_of(p["account_id"], p["region"]) not in keys:
            keys.append(key_of(p["account_id"], p["region"]))
    names = [[] for _ in rows]
    in_plan = [False] * len(rows)

    def add(pos, name, dedupe):
        if not (dedupe and name.lower() in [n.lower() for n in names[pos]]):
            names[pos].append(name)
        in_plan[pos] = True

    for position, key in enumerate(keys):
        members = [i for i, r in enumerate(rows) if key_of(r.account_id, r.region) == key]
        for p in plans:
            if key_of(p["account_id"], p["region"]) != key:
                continue
            for selection in p["selections"]:
                for arn in selection["resources"]:
                    for i in members:
                        if naive_explicit(arn, rows[i]):
                            add(i, p["plan_name"], False)
                criteria = criteria_from_selection(selection)
                for i in members:
                    if criteria.any() and row_matches(tag_index(rows[i].tag_columns), criteria):
                        add(i, p["plan_name"], True)
                excluded = {a.lower() for a in selection["not_resources"]}
                for i, r in enumerate(rows):
                    if keys.index(key_of(r.account_id, r.region)) > position:
                        continue
                    if r.resource_arn and r.resource_arn.lower() in excluded:
                        names[i] = [n for n in names[i] if n.lower() != p["plan_name"].lower()]
                        if not names[i]:
                            in_plan[i] = False
    return [(names[i], in_plan[i]) for i in range(len(rows))]


_VALUES = ["true", "prod", "Prod", "dev", "gold", "silver", "", None, "pr0d-1"]
_TAG_KEYS = ["backup", "Env", "tier", "my-tag", "team"]


def _tag_columns(rnd):
    columns = {}
    for key in rnd.sample(_TAG_KEYS, rnd.randint(0, 4)):
        column = "Tag: " + re.sub(r"[^a-zA-Z0-9]", "_", key)
        columns[column.upper() if rnd.random() < 0.1 else column] = rnd.choice(_VALUES)
    return columns


def _random_row(rnd, kind, n, account, region):
    arn_prefix = f"arn:aws:%s:{region}:{account}:"
    tags = {} if kind == "dynamodb" else _tag_columns(rnd)
    if kind == "ec2_instance":
        return mk(
            kind,
            {"InstanceId": f"i-{n}"},
            arn_prefix % "ec2" + f"instance/i-{n}",
            tags,
            account,
            region,
        )
    if kind == "ebs_attached":
        return mk(
            kind,
            {"VolumeId": f"vol-{n}"},
            arn_prefix % "ec2" + f"volume/vol-{n}",
            tags,
            account,
            region,
        )
    if kind == "rds":
        return mk(
            kind,
            {"DBInstanceIdentifier": f"db-{n}"},
            arn_prefix % "rds" + f"db:db-{n}",
            tags,
            account,
            region,
        )
    if kind == "efs":
        return mk(
            kind,
            {"FileSystemId": f"fs-{n}"},
            arn_prefix % "elasticfilesystem" + f"file-system/fs-{n}",
            tags,
            account,
            region,
        )
    if kind == "fsx_volume":
        ids = {"FileSystemId": f"fs-{n // 2}", "VolumeId": f"v-{n}"}
        return mk(
            kind, ids, arn_prefix % "fsx" + f"volume/fs-{n // 2}/v-{n}", tags, account, region
        )
    if kind == "fsx_filesystem":
        return mk(
            kind,
            {"FileSystemId": f"fs-{n}"},
            arn_prefix % "fsx" + f"file-system/fs-{n}",
            tags,
            account,
            region,
        )
    if kind == "s3":
        return mk(kind, {"BucketName": f"bkt-{n}"}, f"arn:aws:s3:::bkt-{n}", tags, account, region)
    if kind == "dynamodb":
        return mk(
            kind,
            {"TableName": f"t-{n}"},
            arn_prefix % "dynamodb" + f"table/t-{n}",
            tags,
            account,
            region,
        )
    return mk(
        kind,
        {"TableBucketName": f"tb-{n}"},
        arn_prefix % "s3tables" + f"bucket/tb-{n}/table/t",
        tags,
        account,
        region,
    )


def _exact_arn(row):
    ids, region, account = row.ids, row.region, row.account_id
    return {
        "ec2_instance": f"arn:aws:ec2:{region}:{account}:instance/{ids.get('InstanceId')}",
        "ebs_attached": f"arn:aws:ec2:{region}:{account}:volume/{ids.get('VolumeId')}",
        "rds": f"arn:aws:rds:{region}:{account}:db:{ids.get('DBInstanceIdentifier')}",
        "efs": f"arn:aws:elasticfilesystem:{region}:{account}:file-system/{ids.get('FileSystemId')}",
        "fsx_volume": f"arn:aws:fsx:{region}:{account}:volume/{ids.get('FileSystemId')}/{ids.get('VolumeId')}",
        "fsx_filesystem": f"arn:aws:fsx:{region}:{account}:file-system/{ids.get('FileSystemId')}",
        "s3": f"arn:aws:s3:::x/{ids.get('BucketName')}",
        "s3_table": f"arn:aws:s3tables:{region}:{account}:bucket/{ids.get('TableBucketName')}",
        "dynamodb": f"arn:aws:dynamodb:{region}:{account}:table",
    }[row.kind]


_WILDCARDS = [
    "arn:aws:ec2:*:*:instance/*",
    "arn:aws:ec2:*:*:volume/*",
    "arn:aws:rds:*:*:db:*",
    "arn:aws:elasticfilesystem:*:*:file-system/*",
    "arn:aws:fsx:*:*:*",
    "arn:aws:s3:::*",
    "arn:aws:s3tables:*:*:*",
    "arn:aws:dynamodb:*:*:*",
    "arn:aws:dynamodb:us-east-1:111:table/*",
    "*",
]
_CONDITION_KEYS = [
    "backup",
    "aws:ResourceTag/Env",
    "aws:ResourceTag/tier",
    "my-tag",
    "AWS:RESOURCETAG/team",
]
_LIKES = ["pr*", "*o*", "[pg]*", "?o??", "d*v", "[oops", "p`*", "*"]


def _random_selection(rnd, rows):
    def conds(n, with_like=False):
        out = []
        for _ in range(n):
            pattern = rnd.choice(_LIKES) if with_like else rnd.choice(_VALUES)
            out.append(cond(rnd.choice(_CONDITION_KEYS), pattern))
        return out

    resources = [
        rnd.choice([_exact_arn(rnd.choice(rows)), rnd.choice(_WILDCARDS)])
        for _ in range(rnd.randint(0, 3))
    ]
    not_resources = [
        (
            rnd.choice(rows).resource_arn.upper()
            if rnd.random() < 0.3
            else rnd.choice(rows).resource_arn
        )
        for _ in range(rnd.randint(0, 2))
    ]
    tags = [tag(rnd.choice(_CONDITION_KEYS), rnd.choice(_VALUES)) for _ in range(rnd.randint(0, 2))]
    return sel(
        resources,
        not_resources,
        tags,
        conds(rnd.randint(0, 1)),
        conds(rnd.randint(0, 1), with_like=True),
        conds(rnd.randint(0, 1)),
        conds(rnd.randint(0, 1), with_like=True),
    )


def _random_world(seed):
    rnd = random.Random(seed)
    rows = []
    for account in ("111", "222"):
        for region in ("us-east-1", "eu-west-1"):
            for n in range(rnd.randint(6, 18)):
                rows.append(_random_row(rnd, rnd.choice(KINDS), n, account, region))
    plans = []
    for account, region in {(r.account_id, r.region) for r in rows} | {("333", "ap-south-1")}:
        for _ in range(rnd.randint(0, 3)):
            selections = [_random_selection(rnd, rows) for _ in range(rnd.randint(1, 3))]
            plans.append(
                plan(
                    rnd.choice(["Daily", "daily", "Weekly", "Org"]),
                    *selections,
                    account=account,
                    region=region,
                )
            )
    rnd.shuffle(plans)
    order = [("222", "eu-west-1"), ("111", "us-east-1")] if seed % 2 else None
    return plans, rows, order


@pytest.mark.parametrize("seed", range(40))
def test_indexed_matcher_equals_the_naive_reference(seed):
    plans, rows, order = _random_world(seed)
    assert result(plans, rows, order) == naive_membership(plans, rows, order)


def test_random_worlds_exercise_the_interesting_paths():
    totals = [0, 0, 0]
    for seed in range(40):
        plans, rows, order = _random_world(seed)
        for names, in_plan in result(plans, rows, order):
            totals[0] += bool(names)
            totals[1] += len(names) > len(set(n.lower() for n in names))  # an explicit repeat
            totals[2] += in_plan is False and not names
    assert all(totals), totals


# ── scale ─────────────────────────────────────────────────────────────────────────────────────


def test_many_tag_selections_over_many_rows_stay_fast():
    """50k rows in one group, 5 tag keys (one with 5k distinct values), 300 selections."""
    rnd = random.Random(7)
    rows = []
    for n in range(50_000):
        rows.append(
            mk(
                "ec2_instance",
                {"InstanceId": f"i-{n}"},
                f"arn:aws:ec2:{REGION}:{ACCT}:instance/i-{n}",
                {
                    "Tag: id": f"v{rnd.randrange(5000)}",
                    "Tag: env": rnd.choice(["prod", "dev", "test"]),
                    "Tag: tier": rnd.choice(["gold", "silver", "bronze", ""]),
                    "Tag: team": f"team-{rnd.randrange(40)}",
                    "Tag: backup": rnd.choice(["true", "false"]),
                },
            )
        )
    plans = []
    for p in range(100):
        selections = [
            sel(
                tags=[tag("env", rnd.choice(["prod", "dev"]))],
                eq=[cond("aws:ResourceTag/backup", "true")],
            ),
            sel(like=[cond("aws:ResourceTag/id", f"v{rnd.randrange(50)}*")]),
            (
                sel(
                    not_eq=[cond("aws:ResourceTag/tier", "gold")],
                    eq=[cond("aws:ResourceTag/team", f"team-{rnd.randrange(40)}")],
                )
                if p % 2
                else sel(not_eq=[cond("aws:ResourceTag/tier", "bronze")])
            ),
        ]
        plans.append(plan(f"plan-{p}", *selections))
    started = time.perf_counter()
    got = compute_membership(plans, rows)
    elapsed = time.perf_counter() - started
    assert elapsed < 10, f"took {elapsed:.1f}s"
    assert sum(1 for m in got if m.plan_names) > 40_000  # the negation selections hit most rows


def test_many_explicit_arns_over_many_rows_stay_fast():
    rows = [
        mk(
            "rds",
            {"DBInstanceIdentifier": f"db-{n}"},
            f"arn:aws:rds:{REGION}:{ACCT}:db:db-{n}",
        )
        for n in range(50_000)
    ]
    plans = [
        plan(
            f"p{p}",
            sel(resources=[f"arn:aws:rds:{REGION}:{ACCT}:db:db-{p * 7 + k}" for k in range(50)]),
        )
        for p in range(100)
    ]
    started = time.perf_counter()
    got = compute_membership(plans, rows)
    assert time.perf_counter() - started < 5
    # plan p covers db-(7p)..db-(7p+49), so db-7 is in p0 and p1, and db-0 only in p0
    assert got[0].plan_names == ["p0"] and got[7].plan_names == ["p0", "p1"]
    assert got[49_999].plan_names == []


# ── the tag functions against PowerShell itself ───────────────────────────────────────────────

_CASES = [
    # (row tags as (column, value) pairs, OR conds, AND conds, NOT conds); a cond is (op, key, value)
    ([("Tag: env", "prod")], [("Equals", "env", "prod")], [], []),
    ([("Tag: env", "prod")], [("Equals", "env", "PROD")], [], []),
    ([("Tag: Env", "prod")], [("Equals", "ENV", "prod")], [], []),
    ([("Tag: env", "prod")], [("Equals", "aws:ResourceTag/env", "prod")], [], []),
    ([("Tag: env", "prod")], [("Equals", "AWS:RESOURCETAG/env", "prod")], [], []),
    ([("Tag: my_tag", "x")], [("Equals", "my-tag", "x")], [], []),
    ([("Tag: a_b_c", "x")], [("Equals", "a b/c", "x")], [], []),
    ([("Tag: env", "prod")], [("Equals", "team", "x")], [], []),
    ([], [("Equals", "env", "prod")], [], []),
    ([("Tag: env", "prod")], [], [], [("Equals", "env", "prod")]),
    ([("Tag: env", "dev")], [], [], [("Equals", "env", "prod")]),
    ([], [], [], [("Equals", "env", "prod")]),
    ([("Tag: env", "prod")], [("Equals", "team", "x"), ("Equals", "env", "prod")], [], []),
    ([("Tag: env", "prod")], [("Equals", "team", "x"), ("Equals", "backup", "y")], [], []),
    (
        [("Tag: env", "prod"), ("Tag: team", "plat")],
        [],
        [("Equals", "env", "prod"), ("Like", "team", "pl*")],
        [],
    ),
    (
        [("Tag: env", "prod"), ("Tag: team", "ops")],
        [],
        [("Equals", "env", "prod"), ("Like", "team", "pl*")],
        [],
    ),
    ([("Tag: env", "prod")], [], [("Like", "env", "pr*")], []),
    ([("Tag: env", "prod")], [], [("Like", "env", "[!p]rod")], []),
    ([("Tag: env", "xrod")], [], [("Like", "env", "[!p]rod")], []),
    ([("Tag: env", "xrod")], [], [("Like", "env", "[^p]rod")], []),
    ([("Tag: env", "prod")], [], [("Like", "env", "[prod")], []),
    ([("Tag: env", "prod")], [], [("Like", "env", "p?od")], []),
    ([("Tag: env", "p*d")], [], [("Like", "env", "p`*d")], []),
    ([("Tag: env", "prod")], [], [("Like", "env", "p`*d")], []),
    ([("Tag: env", "a\nb")], [], [("Like", "env", "a*b")], []),
    ([("Tag: env", "PROD")], [], [("Like", "env", "[o-q]*")], []),
    ([("Tag: env", "prod")], [], [], [("Like", "env", "pr*")]),
    ([("Tag: env", "dev")], [], [], [("Like", "env", "pr*")]),
    ([("Tag: env", "")], [("Equals", "env", None)], [], []),
    ([("Tag: env", None)], [("Equals", "env", "")], [], []),
    ([("Tag: env", "x")], [("Equals", None, "x")], [], []),
    ([("Tag: ", "x")], [("Equals", None, "x")], [], []),
    ([("Tag: Env", "dev"), ("Tag: env", "prod")], [("Equals", "env", "prod")], [], []),
    ([("Tag: Env", "dev"), ("Tag: env", "prod")], [("Equals", "env", "dev")], [], []),
    (
        [("Tag: env", "prod"), ("Tag: tier", "silver")],
        [("Equals", "env", "prod")],
        [],
        [("Equals", "tier", "gold")],
    ),
    (
        [("Tag: env", "prod"), ("Tag: tier", "gold")],
        [("Equals", "env", "prod")],
        [],
        [("Equals", "tier", "gold")],
    ),
    ([("Tag: env", "prod")], [], [], []),
    ([("Tag: env", "prod")], [("Equals", "aws:ResourceTag/", "prod")], [], []),
]


def _powershell_harness(tmp_path):
    lines = SCRIPT.read_text(encoding="utf-8").split("\n")
    start = next(
        i for i, l in enumerate(lines) if l.startswith("function Test-RowTagConditionMatch")
    )
    end = next(
        i for i, l in enumerate(lines) if l.startswith("function Get-AWSBackupPlanInventory")
    )
    head = "param([string]$InFile,[string]$OutFile)\n"
    tail = (
        "\n$cases = Get-Content -Raw $InFile | ConvertFrom-Json\n"
        "$out = @()\n"
        "foreach ($case in $cases) {\n"
        "  $row = [PSCustomObject]@{}\n"
        "  foreach ($t in @($case.tags)) {\n"
        "    Add-Member -InputObject $row -MemberType NoteProperty -Name $t.name -Value $t.value -Force\n"
        "  }\n"
        "  $or = @($case.or | ForEach-Object { @{ Op = $_.op; Key = $_.key; Value = $_.value } })\n"
        "  $and = @($case.and | ForEach-Object { @{ Op = $_.op; Key = $_.key; Value = $_.value } })\n"
        "  $not = @($case.not | ForEach-Object { @{ Op = $_.op; Key = $_.key; Value = $_.value } })\n"
        "  try { $r = Test-RowMatchesSelection -Row $row -OrTags $or -AndConds $and -NotConds $not }\n"
        "  catch { $r = 'ERR' }\n"
        "  $out += $r\n"
        "}\n"
        "ConvertTo-Json -InputObject @($out) -Compress | Set-Content -Path $OutFile -Encoding utf8\n"
    )
    path = tmp_path / "harness.ps1"
    path.write_text(head + "\n".join(lines[start:end]) + tail, encoding="utf-8")
    return path


@pytest.mark.skipif(not shutil.which("pwsh") or not SCRIPT.exists(), reason="needs pwsh")
def test_tag_matching_agrees_with_the_powershell_functions(tmp_path):
    def conds(entries):
        return [{"op": op, "key": key, "value": value} for op, key, value in entries]

    infile, outfile = tmp_path / "cases.json", tmp_path / "out.json"
    infile.write_text(
        json.dumps(
            [
                {
                    "tags": [{"name": n, "value": v} for n, v in tags],
                    "or": conds(or_tags),
                    "and": conds(and_conds),
                    "not": conds(not_conds),
                }
                for tags, or_tags, and_conds, not_conds in _CASES
            ]
        ),
        encoding="utf-8",
    )
    subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-File",
            str(_powershell_harness(tmp_path)),
            "-InFile",
            str(infile),
            "-OutFile",
            str(outfile),
        ],
        check=True,
        capture_output=True,
    )
    expected = json.loads(outfile.read_text(encoding="utf-8-sig"))
    assert len(expected) == len(_CASES)

    def as_conds(entries):
        return tuple(Cond(op, key or "", value or "") for op, key, value in entries)

    mismatches = []
    for number, ((tags, or_tags, and_conds, not_conds), want) in enumerate(zip(_CASES, expected)):
        criteria = Criteria(as_conds(or_tags), as_conds(and_conds), as_conds(not_conds))
        got = row_matches(tag_index(dict(tags)), criteria)
        if want == "ERR":  # PowerShell throws on an invalid wildcard; here it matches nothing
            want = False
        if got is not want:
            mismatches.append((number, _CASES[number], want, got))
    assert not mismatches, mismatches
