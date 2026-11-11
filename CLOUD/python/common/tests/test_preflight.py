import csv
import io

from common import preflight as p


def _classify(exc):
    text = str(exc)
    if "denied" in text:
        return p.DENIED, "AccessDenied"
    if "disabled" in text:
        return p.NOT_ENABLED, "ServiceDisabled"
    return p.ERROR, "Boom"


def _boom(message):
    def call():
        raise RuntimeError(message)

    return call


def _run(probes):
    return p.run_probes("owner-1", "Owner One", probes, _classify)


def test_a_passing_probe_is_captured_and_reports_whether_it_saw_a_resource():
    checks = _run(
        [
            p.Probe("ec2", "us-east-1", lambda: True, ("a_file",)),
            p.Probe("rds", "us-east-1", lambda: False),
            p.Probe("sqs", "us-east-1", lambda: None),
        ]
    )
    assert [c.status for c in checks] == [p.OK, p.OK, p.OK]
    assert [c.found for c in checks] == [True, False, None]
    assert all(c.outcome == p.CAPTURED for c in checks)


def test_failures_are_classified_and_never_raised():
    checks = _run(
        [
            p.Probe("ec2", "r", _boom("denied here"), ("f1",)),
            p.Probe("rds", "r", _boom("api disabled"), ("f2",)),
            p.Probe("sqs", "r", _boom("something else")),
        ]
    )
    assert [(c.status, c.code) for c in checks] == [
        (p.DENIED, "AccessDenied"),
        (p.NOT_ENABLED, "ServiceDisabled"),
        (p.ERROR, "Boom"),
    ]
    assert [c.outcome for c in checks] == [p.DROPPED, p.DROPPED, p.UNKNOWN]


def test_a_classifier_that_itself_fails_still_gives_an_error_result():
    def bad_classifier(exc):
        raise ValueError("no")

    checks = p.run_probes("o", "n", [p.Probe("ec2", "r", _boom("x"))], bad_classifier)
    assert (checks[0].status, checks[0].code) == (p.ERROR, "RuntimeError")


def test_results_keep_the_order_of_the_probes():
    probes = [p.Probe(f"svc{i}", "r", lambda i=i: i % 2 == 0) for i in range(40)]
    checks = p.run_probes("o", "n", probes, _classify, max_workers=8)
    assert [c.service for c in checks] == [f"svc{i}" for i in range(40)]


def test_no_probes_gives_no_checks():
    assert _run([]) == []


def test_the_message_of_an_error_is_never_kept():
    secret = "arn:aws:iam::123456789012:user/someone is not authorized: denied"
    checks = _run([p.Probe("ec2", "r", _boom(secret))])
    row = checks[0].to_row()
    assert "123456789012" not in " ".join(str(v) for v in row.values())


def test_the_files_affected_are_named_only_when_the_service_is_not_readable():
    ok, denied = _run(
        [
            p.Probe("ec2", "r", lambda: True, ("f1", "f2")),
            p.Probe("rds", "r", _boom("denied"), ("f3",)),
        ]
    )
    assert ok.to_row()["OutputFilesAffected"] == ""
    assert denied.to_row()["OutputFilesAffected"] == "f3"
    assert denied.to_row()["Outcome"] == "dropped"


def test_a_skipped_service_says_it_was_not_requested():
    check = p.skipped("o", "n", "r", "ec2", ("f1",), reason="no-cost")
    row = check.to_row()
    assert (row["Access"], row["Outcome"]) == ("not requested", "not requested")
    assert (row["OutputFilesAffected"], row["Detail"]) == ("f1", "no-cost")


def test_counts_by_outcome():
    checks = _run(
        [
            p.Probe("a", "r", lambda: True),
            p.Probe("b", "r", _boom("denied")),
            p.Probe("c", "r", _boom("zz")),
        ]
    )
    checks.append(p.skipped("o", "n", "r", "d"))
    assert p.counts(checks) == {p.CAPTURED: 1, p.DROPPED: 1, p.UNKNOWN: 1, p.NOT_REQUESTED: 1}


def test_blocked_groups_merge_the_scopes_of_one_service_and_cause():
    checks = []
    for region in ("us-east-1", "eu-west-1", "us-east-1"):
        checks += _run([p.Probe("rds", region, _boom("denied"), ("aws_rds_info",))])
    checks += _run([p.Probe("rds", "ap-south-1", _boom("api disabled"))])
    groups = p.blocked_groups(checks)
    assert len(groups) == 2
    denied = next(g for g in groups if g["status"] == p.DENIED)
    assert denied["scopes"] == ["us-east-1", "eu-west-1"]


def test_summary_when_nothing_is_blocked():
    checks = _run([p.Probe("a", "r", lambda: True), p.Probe("b", "r", lambda: False)])
    assert p.summary_lines(checks, "acct") == [
        "Pre-flight access check for acct: all 2 checks readable, nothing blocked"
    ]


def test_the_headline_says_nothing_to_check_when_everything_was_skipped():
    assert p.summary_lines([p.skipped("o", "n", "r", "a")]) == [
        "Pre-flight access check: nothing to check"
    ]


def test_summary_names_the_blocked_service_scopes_and_files():
    checks = _run([p.Probe("a", "r", lambda: True)])
    for region in ("r1", "r2", "r3", "r4", "r5", "r6"):
        checks += _run([p.Probe("rds", region, _boom("denied"), ("aws_rds_info",))])
    lines = p.summary_lines(checks)
    assert lines[0] == "Pre-flight access check: 1 of 7 checks readable"
    assert (
        lines[1]
        == "  access denied: rds (r1, r2, r3, r4 +2 more) -> aws_rds_info will be empty or partial"
    )


def test_an_unchecked_service_is_not_reported_as_losing_files():
    lines = p.summary_lines(_run([p.Probe("rds", "r", _boom("zz"), ("aws_rds_info",))]))
    assert lines[1] == "  could not be checked: rds (r)"


def test_services_that_were_not_requested_stay_out_of_the_headline():
    checks = _run([p.Probe("a", "r", lambda: True)]) + [p.skipped("o", "n", "r", "b")]
    assert p.summary_lines(checks) == [
        "Pre-flight access check: all 1 check readable, nothing blocked"
    ]


def test_csv_has_every_column_quoted_and_crlf_line_ends():
    checks = _run(
        [
            p.Probe("ec2", "us-east-1", lambda: True),
            p.Probe("rds", "us-east-1", _boom("denied"), ("f1", "f2")),
        ]
    )
    text = p.csv_text(c.to_row() for c in checks)
    assert text.startswith('"Owner","OwnerName","Scope","Service","Permission","Access","Outcome"')
    assert text.endswith("\r\n")
    rows = list(csv.DictReader(io.StringIO(text)))
    assert [r["Service"] for r in rows] == ["ec2", "rds"]
    assert rows[1]["OutputFilesAffected"] == "f1; f2"
    assert rows[0]["ResourcesFound"] == "no" or rows[0]["ResourcesFound"] == "yes"


def test_csv_of_no_rows_is_just_the_header():
    assert p.csv_text([]).count("\r\n") == 1


def test_file_name_follows_the_other_output_files():
    assert (
        p.file_name("aws_access_check", "2026-10-05_140650")
        == "aws_access_check-2026-10-05_140650.csv"
    )


def test_a_hint_is_shown_under_a_blocked_service_but_never_written_to_the_csv():
    probe = p.Probe("monitor", "r", _boom("denied"), ("a_file",), hint="grant Monitoring Reader")
    checks = _run([probe])
    lines = p.summary_lines(checks)
    assert lines[-1] == "    to fix: grant Monitoring Reader"
    assert "grant Monitoring Reader" not in p.csv_text(c.to_row() for c in checks)


def test_a_hint_is_not_shown_for_a_service_that_could_not_be_checked():
    probe = p.Probe("monitor", "r", _boom("zz"), ("a_file",), hint="grant Monitoring Reader")
    assert not any("to fix" in line for line in p.summary_lines(_run([probe])))


def test_scopes_can_be_left_out_of_the_summary():
    checks = _run([p.Probe("vms", "subscription", _boom("denied"), ("a_file",))])
    assert "(subscription)" in p.summary_lines(checks)[1]
    assert "(subscription)" not in p.summary_lines(checks, show_scope=False)[1]


# ── permissions and the table ─────────────────────────────────────────────────


def _ck(scope, service, status, found=None, permission="x:Y", affects=("f1",), code="", hint=""):
    return p.Check("o", "n", scope, service, status, found, code, affects, hint, permission)


def _rows_of(lines):
    return [line.split() for line in lines[2:] if not line.startswith("  to fix")]


def test_the_permission_is_kept_for_a_pass_a_failure_and_a_skipped_service():
    probes = [
        p.Probe("a", "r", lambda: True, permission="svc:ListA"),
        p.Probe("b", "r", _boom("denied"), permission="svc:ListB"),
    ]
    ok, denied = _run(probes)
    skipped = p.skipped("o", "n", "r", "c", permission="svc:ListC")
    assert [c.permission for c in (ok, denied, skipped)] == ["svc:ListA", "svc:ListB", "svc:ListC"]
    assert denied.to_row()["Permission"] == "svc:ListB"


def test_the_csv_has_a_permission_column():
    text = p.csv_text(
        [_ck("r", "ec2 instances", p.OK, permission="ec2:DescribeInstances").to_row()]
    )
    (row,) = csv.DictReader(io.StringIO(text))
    assert row["Permission"] == "ec2:DescribeInstances"


def test_the_table_has_a_header_and_a_row_per_permission():
    lines = p.table_lines(
        [_ck("r", "a", p.OK, permission="s:A"), _ck("r", "b", p.OK, permission="s:B")]
    )
    assert lines[0].split()[:3] == ["SERVICE", "PERMISSION", "ACCESS"]
    assert set(lines[1].replace(" ", "")) == {"-"}
    assert [row[:3] for row in _rows_of(lines)] == [
        ["a", "s:A", "granted"],
        ["b", "s:B", "granted"],
    ]


def test_missing_permissions_come_first_then_the_rest_then_the_ones_not_requested():
    checks = [
        _ck("r", "fine", p.OK, permission="s:Fine"),
        p.skipped("o", "n", "", "off", ("f9",), "--no-cost", "s:Off"),
        _ck("r", "denied", p.DENIED, permission="s:Denied"),
        _ck("r", "disabled", p.NOT_ENABLED, permission="s:Disabled"),
        _ck("r", "unsure", p.ERROR, permission="s:Unsure"),
    ]
    order = [(row[0], row[2]) for row in _rows_of(p.table_lines(checks))]
    assert order == [
        ("denied", "MISSING"),
        ("disabled", "API"),
        ("unsure", "NOT"),
        ("fine", "granted"),
        ("off", "not"),
    ]


def test_a_missing_permission_names_the_files_it_leaves_empty_and_a_granted_one_does_not():
    lines = p.table_lines(
        [
            _ck("r", "rds", p.DENIED, permission="rds:Describe", affects=("aws_rds_info", "aws_x")),
            _ck("r", "ec2", p.OK, permission="ec2:Describe", affects=("aws_ec2_instance_info",)),
        ]
    )
    text = "\n".join(lines)
    assert text.count("aws_rds_info; aws_x") == 1
    assert "aws_ec2_instance_info" not in text


def test_a_service_that_could_not_be_checked_claims_no_impact():
    lines = p.table_lines([_ck("r", "x", p.ERROR, affects=("aws_x",), code="Boom")])
    assert "aws_x" not in "\n".join(lines) and "unknown" in lines[-1]


def test_where_says_how_many_scopes_are_blocked_and_names_the_first_few():
    regions = ["r1", "r2", "r3", "r4", "r5"]
    checks = [_ck(r, "rds", p.DENIED if r != "r5" else p.OK) for r in regions]
    where = "\n".join(p.table_lines(checks, "region"))
    assert "4 of 5 regions: r1, r2 +2 more" in where


def test_where_says_all_when_every_scope_is_readable_and_dash_with_one_scope():
    checks = [_ck(r, "ec2", p.OK) for r in ("r1", "r2", "r3")]
    assert "all 3 regions" in "\n".join(p.table_lines(checks, "region"))
    assert "all" not in "\n".join(p.table_lines([_ck("r1", "ec2", p.OK)], "region")[2:])
    assert "regions" not in "\n".join(p.table_lines(checks))


def test_the_global_scope_does_not_count_as_a_region():
    checks = [_ck("global", "s3", p.DENIED), _ck("r1", "ec2", p.OK), _ck("r2", "ec2", p.OK)]
    text = "\n".join(p.table_lines(checks, "region"))
    assert "all 2 regions" in text and "of 3" not in text


def test_resources_found_says_yes_with_how_many_none_or_dash():
    checks = (
        [
            _ck("r1", "some", p.OK, True),
            _ck("r2", "some", p.OK, False),
            _ck("r3", "some", p.OK, True),
        ]
        + [_ck("r1", "empty", p.OK, False), _ck("r2", "empty", p.OK, False)]
        + [_ck("r1", "blind", p.OK, None)]
    )
    rows = {row[0]: " ".join(row) for row in _rows_of(p.table_lines(checks, "region"))}
    assert "yes (2 of 3)" in rows["some"] and " none " in rows["empty"] + " "
    assert "yes" not in rows["blind"] and "none" not in rows["blind"]


def test_a_blocked_service_with_advice_gets_a_to_fix_line_under_the_table():
    lines = p.table_lines([_ck("r", "spanner", p.NOT_ENABLED, hint="enable the API")])
    assert lines[-1] == "  to fix spanner: enable the API"


def test_columns_line_up_and_long_values_are_clipped():
    long_files = tuple(f"file_{i:02d}" for i in range(30))
    lines = p.table_lines(
        [
            _ck(
                "r",
                "a very long service name that goes on and on and on",
                p.DENIED,
                affects=long_files,
            ),
            _ck("r", "b", p.OK),
        ],
        impact_width=40,
    )
    assert lines[0].index("PERMISSION") == lines[2].index("x:Y") == lines[3].index("x:Y")
    assert lines[2].rstrip().endswith("...") and len(lines[2].split("  ")[-1]) <= 40


def test_the_table_never_shows_a_provider_message():
    check = _run(
        [
            p.Probe(
                "a", "r", _boom("User arn:aws:iam::999999999999:user/x is denied"), permission="s:A"
            )
        ]
    )[0]
    assert "999999999999" not in "\n".join(p.table_lines([check]))


# ── nothing the reader needs is clipped ───────────────────────────────────────


def test_a_resource_count_across_17_regions_is_not_clipped():
    checks = [_ck(f"r{i}", "ec2", p.OK, found=i < 16) for i in range(17)]
    text = "\n".join(p.table_lines(checks, "region"))
    assert "yes (16 of 17)" in text and "..." not in text


def test_a_count_across_150_projects_is_not_clipped():
    checks = [_ck(f"p{i}", "ec2", p.OK, found=True) for i in range(150)]
    assert "yes (150 of 150)" in "\n".join(p.table_lines(checks, "project"))


def test_long_permission_names_are_shown_in_full():
    names = [
        "Microsoft.Resources/subscriptions/resources/read",
        "Microsoft.DBforPostgreSQL/flexibleServers/read",
        "elasticloadbalancing:DescribeLoadBalancers",
        "backupdr.backupPlanAssociations.list",
    ]
    text = "\n".join(
        p.table_lines([_ck("r", f"svc{i}", p.OK, permission=n) for i, n in enumerate(names)])
    )
    assert all(name in text for name in names) and "..." not in text


def test_where_shows_two_real_project_names_in_full_then_how_many_more():
    names = ["gcp-rubrikcom-mysql-dev-1", "sizing-eng-test", "cnp-bigquery-dev-1"]
    checks = [_ck(n, "compute", p.DENIED) for n in names] + [_ck("galactus-gcp-1", "compute", p.OK)]
    text = "\n".join(p.table_lines(checks, "project"))
    assert "3 of 4 projects: gcp-rubrikcom-mysql-dev-1, sizing-eng-test +1 more" in text
    assert "..." not in text


def test_a_service_that_could_not_be_checked_shows_why():
    one = p.table_lines([_ck("r", "x", p.ERROR, code="MetricsInconclusive")])
    assert one[-1].rstrip().endswith("unknown (MetricsInconclusive)")
    many = p.table_lines(
        [
            _ck("r1", "x", p.ERROR, code="b"),
            _ck("r2", "x", p.ERROR, code="a"),
            _ck("r3", "x", p.ERROR, code="a"),
        ],
        "region",
    )
    assert many[-1].rstrip().endswith("unknown (a, b)")
    assert p.table_lines([_ck("r", "x", p.ERROR)])[-1].rstrip().endswith("unknown")


# ── what the cloud said ───────────────────────────────────────────────────────


def test_a_failed_check_keeps_the_message_on_one_line_but_it_is_not_in_the_row_or_the_table():
    secret = "User arn:aws:iam::999999999999:user/x\nis not authorized"
    (check,) = _run([p.Probe("rds", "r", _boom(secret), ("f1",), permission="rds:Describe")])
    assert check.message == "User arn:aws:iam::999999999999:user/x is not authorized"
    assert check.message not in " ".join(str(v) for v in check.to_row().values())
    assert "999999999999" not in "\n".join(p.table_lines([check]))


def test_a_passing_check_has_no_message():
    (check,) = _run([p.Probe("a", "r", lambda: True)])
    assert check.message == ""


def test_a_long_message_is_cut():
    (check,) = _run([p.Probe("a", "r", _boom("x" * 500))])
    assert len(check.message) == 300 and check.message.endswith("...")


def test_a_blocked_group_carries_the_first_message_of_its_members():
    checks = [
        p.Check("o", "n", "r1", "svc", p.DENIED, None, "AccessDenied", message=""),
        p.Check("o", "n", "r2", "svc", p.DENIED, None, "AccessDenied", message="first words"),
        p.Check("o", "n", "r3", "svc", p.DENIED, None, "AccessDenied", message="later words"),
    ]
    (group,) = p.blocked_groups(checks)
    assert group["message"] == "first words" and group["scopes"] == ["r1", "r2", "r3"]
