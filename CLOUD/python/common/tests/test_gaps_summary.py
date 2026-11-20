"""The lines that end a run when some units finished with gaps."""

from common import checkpoint as ck


def _lines(gaps, total=10, **kwargs):
    return ck.gaps_summary("account", gaps, total, kept=kwargs.pop("kept", True), **kwargs)


def test_a_run_with_no_gaps_says_nothing():
    assert _lines([]) == []


def test_it_counts_names_and_explains_each_unit():
    lines = _lines([("111", "rds: AccessDenied"), ("222", "region eu-west-1 could not be scanned")])
    assert lines[0] == "2 of 10 accounts finished with gaps (something in them was not read):"
    assert "  111  rds: AccessDenied" in lines
    assert "  222  region eu-west-1 could not be scanned" in lines


def test_one_unit_reads_in_the_singular():
    lines = _lines([("111", "x")], total=1)
    assert lines[0] == "1 of 1 account finished with gaps (something in it was not read):"
    assert _lines([("111", "x")], total=5)[0].startswith("1 of 5 accounts finished with gaps")
    assert "only the account with gaps is scanned again" in lines[-1]
    assert "keep it as it is" in lines[-1]


def test_when_the_folder_is_kept_it_says_how_to_scan_just_those_again():
    lines = _lines([("111", "x"), ("222", "y")], kept=True)
    assert "same command with --resume" in lines[-1]
    assert "only the accounts with gaps are scanned again" in lines[-1]
    assert "keep them as they are" in lines[-1]


def test_when_the_folder_is_gone_it_does_not_offer_a_resume_that_cannot_work():
    lines = _lines([("111", "x")], kept=False)
    assert "--resume" not in "\n".join(lines)
    assert "scan the account again by name" in lines[-1]
    assert "include this account with what was read" in lines[-1]


def test_the_hint_can_name_the_tools_own_option():
    assert "with --resume --verbose" in _lines([("1", "x")], resume_hint="--resume --verbose")[-1]


def test_a_long_list_names_the_first_few_and_counts_the_rest():
    gaps = [(f"acct-{i:03d}", "x") for i in range(25)]
    lines = _lines(gaps, total=300)
    named = [line for line in lines if line.startswith("  acct-")]
    assert len(named) == ck.SUMMARY_SHOWN == 10
    assert "  ... and 15 more" in lines
    assert lines[0].startswith("25 of 300 accounts")


def test_exactly_the_limit_adds_no_and_more_line():
    lines = _lines([(f"a{i}", "x") for i in range(ck.SUMMARY_SHOWN)])
    assert not [line for line in lines if "and" in line and "more" in line]


def test_the_noun_is_the_tools_own():
    assert "projects" in ck.gaps_summary("project", [("p", "x"), ("q", "y")], 5, kept=True)[0]
    assert "subscription" in ck.gaps_summary("subscription", [("s", "x")], 5, kept=False)[-1]
