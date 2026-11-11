import logging
import re
import threading

import pytest

from common import runlog as r


@pytest.fixture(autouse=True)
def _clean():
    r.ISSUES.reset()
    r.configure()
    yield
    r.ISSUES.reset()
    r.configure()


@pytest.fixture
def log(tmp_path):
    """A handler on a private logger, so these tests never touch the root logger."""
    handler = r.TranscriptHandler(str(tmp_path / "run.log"), logging.INFO)
    logger = logging.getLogger("runlog-test")
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    logger.handlers = [handler]
    yield logger, handler, tmp_path / "run.log"
    handler.close()


def _text(path):
    return path.read_text(encoding="utf-8")


# ── plain text ────────────────────────────────────────────────────────────────


def test_colour_codes_are_removed():
    assert r.plain("\x1b[36mINFO\x1b[0m  \x1b[1mhello\x1b[0m") == "INFO  hello"


def test_a_spinner_that_redraws_keeps_only_its_last_frame():
    assert r.plain("⠋ Working…\r⠙ Working…\r✓ Done") == "✓ Done"


def test_trailing_spaces_go_and_lines_stay_in_order():
    assert r.plain("a   \n\nb  ") == "a\n\nb"


def test_one_line_collapses_whitespace_and_cuts_long_text():
    assert r.one_line("a\n  b\t c") == "a b c"
    assert r.one_line("x" * 400, 50) == "x" * 47 + "..."


# ── the transcript ────────────────────────────────────────────────────────────


def test_screen_text_is_written_to_the_log_in_order(log):
    _, _, path = log
    r.screen("first")
    r.screen("second\nthird")
    assert _text(path) == "first\nsecond\nthird\n"


def test_screen_does_nothing_when_no_log_is_open():
    r.screen("nobody is listening")


def test_records_at_info_and_above_are_written_with_the_screen_format(log):
    logger, _, path = log
    logger.info("hello %s", "world")
    logger.warning("careful")
    lines = _text(path).splitlines()
    assert re.fullmatch(r"\d\d:\d\d:\d\d INFO    runlog-test — hello world", lines[0])
    assert re.fullmatch(r"\d\d:\d\d:\d\d WARNING runlog-test — careful", lines[1])


def test_debug_records_never_reach_the_log(log):
    logger, _, path = log
    logger.debug("wire noise")
    assert _text(path) == ""


def test_libraries_are_recognised_by_name_and_not_by_a_shared_prefix():
    assert r.is_noisy("botocore.hooks") and r.is_noisy("azure.identity._credentials.chained")
    assert r.is_noisy("urllib3") and not r.is_noisy("botocorefoo")
    assert not r.is_noisy("collectors.storage") and not r.is_noisy("__main__")


def _handled(tmp_path, level):
    path = tmp_path / f"lib-{level}.log"
    handler = r.TranscriptHandler(str(path), logging.INFO)
    try:
        handler.handle(
            logging.LogRecord("urllib3.connectionpool", level, "f", 1, "retrying", (), None)
        )
    finally:
        handler.close()
    return path.read_text(encoding="utf-8")


def test_library_info_is_dropped(tmp_path):
    assert _handled(tmp_path, logging.INFO) == ""


def test_library_warnings_are_kept(tmp_path):
    assert "WARNING urllib3.connectionpool — retrying" in _handled(tmp_path, logging.WARNING)


def test_a_level_name_wrapped_in_colour_codes_by_the_console_formatter_is_still_plain(log):
    logger, _, path = log
    record = logging.LogRecord("runlog-test", logging.WARNING, "f", 1, "msg", (), None)
    record.levelname = "\x1b[33mWARNING\x1b[0m"
    logger.handle(record)
    assert "\x1b" not in _text(path) and " WARNING " in _text(path)


def test_every_warning_and_error_is_recorded_for_the_digest(log):
    logger, _, _ = log
    logger.info("fine")
    logger.warning("w one")
    logger.error("e one")
    assert r.ISSUES.total == 2


def test_closing_the_handler_ends_the_log(tmp_path):
    handler = r.TranscriptHandler(str(tmp_path / "c.log"), logging.INFO)
    assert r.current() is handler.transcript
    handler.close()
    assert r.current() is None
    r.screen("after the end")


def test_lines_written_from_many_threads_stay_whole(log):
    _, _, path = log

    def work(n):
        for i in range(40):
            r.screen(f"thread {n} line {i} " + "x" * 50)

    threads = [threading.Thread(target=work, args=(n,)) for n in range(12)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    lines = _text(path).splitlines()
    assert len(lines) == 12 * 40
    assert all(re.fullmatch(r"thread \d+ line \d+ x{50}", line) for line in lines)


# ── the header ────────────────────────────────────────────────────────────────


def test_the_header_says_what_ran_and_with_what(log):
    _, _, path = log
    r.write_header("AWS", [("Code", "abc1234 2026-10-14")], ["--no-cost", "--output", "./out"])
    text = _text(path)
    assert text.startswith("# Run log: AWS\n")
    assert "# Code: abc1234 2026-10-14" in text and "# Python: " in text
    assert "# Command line: --no-cost --output ./out" in text


def test_a_run_with_no_options_says_so(log):
    _, _, path = log
    r.write_header("GCP", [], [])
    assert "# Command line: (no options)" in _text(path)


def test_package_versions_name_what_is_not_installed():
    text = r.package_versions(["pytest", "definitely-not-a-package"])
    assert re.search(r"pytest \d", text) and "definitely-not-a-package not installed" in text


def test_the_code_version_of_a_folder_that_is_not_a_checkout_is_unknown(tmp_path):
    assert r.code_version(str(tmp_path)) == "unknown"


# ── the same problem counts once ──────────────────────────────────────────────

GUID = "9d73069d-8df8-4b1b-874d-174ca86f447a"


def test_ids_times_and_long_numbers_do_not_make_two_problems():
    a = r.normalize(f"[{GUID}] failed at 2026-10-14T07:43:08.151577 for 123456789012")
    b = r.normalize(
        "[11111111-1111-1111-1111-111111111111] failed at 2026-10-13T01:02:03Z for 999999999999"
    )
    assert a == b == "[<id>] failed at <time> for <n>"


def test_a_tools_own_masks_merge_names(tmp_path):
    r.configure(masks=[re.compile(r"(?<=project )[a-z][a-z0-9-]+")])
    assert r.normalize("failed for project alpha-1") == r.normalize("failed for project beta-22")


def test_one_problem_on_three_projects_is_one_group_with_a_count(log):
    r.configure(masks=[re.compile(r"(?<=project )[a-z][a-z0-9-]+")])
    logger, _, _ = log
    for name in ("alpha-1", "beta-22", "gamma-3"):
        logger.warning("Storage failed for project %s: 403", name)
    logger.error("A different error")
    groups = r.ISSUES.groups()
    assert [g["count"] for g in groups] == [1, 3]  # the error sorts first, then by count
    assert groups[1]["examples"][0].startswith("Storage failed for project alpha-1")
    assert len(groups[1]["examples"]) == 3


# ── what to do about it ───────────────────────────────────────────────────────

RULES = [
    r.Solution(
        "api-off",
        re.compile(r"has not been used in project (?P<project>[\w-]+)"),
        "Enable it in {project}.",
    ),
    r.Solution("denied", re.compile(r"denied|AccessDenied"), "Grant the missing permission."),
]


def test_the_first_matching_solution_wins_and_fills_in_what_the_error_said():
    r.configure(solutions=RULES)
    assert r.solve("API has not been used in project cnp-1 before, denied") == (
        "api-off",
        "Enable it in cnp-1.",
    )


def test_a_group_the_pattern_did_not_capture_shows_its_name_not_a_crash():
    r.configure(solutions=[r.Solution("x", re.compile("boom"), "Fix {thing}.")])
    assert r.solve("boom") == ("x", "Fix <thing>.")


def test_the_service_and_code_can_decide_the_solution():
    r.configure(
        solutions=[
            r.Solution(
                "metrics", re.compile(r"storage metrics \| AccessDenied"), "Monitoring Reader."
            )
        ]
    )
    assert r.solve("403", service="storage metrics", code="AccessDenied") == (
        "metrics",
        "Monitoring Reader.",
    )
    assert r.solve("403", service="other", code="AccessDenied") is None


def test_the_fix_points_at_the_troubleshooting_section_or_says_there_is_none():
    r.configure(solutions=RULES)
    assert r.fix_lines("AccessDenied on x") == [
        "Fix: Grant the missing permission.",
        "     (docs/troubleshooting.md#denied)",
    ]
    assert r.fix_lines("something new") == [
        "Fix: no specific advice for this one; see docs/troubleshooting.md"
    ]


def test_a_clean_run_says_so():
    assert r.digest_lines() == ["No warnings or errors were recorded."]


def test_the_digest_lists_each_problem_once_with_its_count_example_and_fix(log):
    r.configure(solutions=RULES)
    logger, _, _ = log
    for _ in range(249):
        logger.warning("AccessDenied for %s", GUID)
    logger.error("Totally new failure")
    lines = r.digest_lines()
    assert lines[0] == "2 distinct problems (250 warnings and errors in all):"
    assert lines[1].startswith("  1. [ERROR] 1x Totally new failure")
    assert lines[2].strip().startswith("Fix: no specific advice")
    assert lines[3].startswith("  2. [WARNING] 249x AccessDenied for")
    assert lines[4].strip() == "Fix: Grant the missing permission."
    assert lines[5].strip() == "(docs/troubleshooting.md#denied)"


def test_a_long_example_is_cut_and_a_long_list_is_summarised(log):
    logger, _, _ = log
    logger.warning("x" * 500)
    for i in range(15):
        logger.warning("distinct problem %s" % ("y" * (i + 1)))
    lines = r.digest_lines(max_groups=3, limit=40)
    assert any(line.endswith("...") for line in lines)
    assert lines[-1] == "  ... and 13 more distinct problems"


def test_one_distinct_problem_is_not_called_problems(log):
    logger, _, _ = log
    logger.warning("only one")
    assert r.digest_lines()[0] == "1 distinct problem (1 warnings and errors in all):"


# ── problems found by the pre-flight check ────────────────────────────────────


def test_problem_lines_show_the_error_and_the_fix_for_each_blocked_group():
    groups = [
        {
            "service": "rds",
            "status": "denied",
            "code": "AccessDenied",
            "scopes": ["r1", "r2", "r3", "r4"],
            "message": "not authorized\nfor rds",
        },
        {"service": "backup", "status": "error", "code": "", "scopes": [""], "message": ""},
    ]
    lines = r.problem_lines(groups, lambda g: [f"Fix: for {g['service']}", "     (anchor)"])
    assert lines == [
        "  rds (r1, r2, r3 +1 more): AccessDenied",
        "      Error: not authorized for rds",
        "      Fix: for rds",
        "           (anchor)",
        "  backup: error",
        "      Fix: for backup",
        "           (anchor)",
    ]


# ── how a fix is laid out ─────────────────────────────────────────────────────

LONG = (
    "gcloud services enable bigtableadmin.googleapis.com --project a-project-with-a-long-name-1234"
)


def _fix(text, width=60):
    r.configure(solutions=[r.Solution("x", re.compile("boom"), text)])
    return r.fix_lines("boom", width=width)


def test_a_long_sentence_is_wrapped_under_a_fix_label_with_a_hanging_indent():
    lines = _fix("This is a long explanation of what to do about the problem, in several words.")
    assert lines[0].startswith("Fix: This is a long explanation")
    assert all(line.startswith("     ") for line in lines[1:])
    assert all(len(line) <= 60 for line in lines)


def test_a_command_stays_on_one_line_however_long_so_it_can_be_copied():
    lines = _fix(f"Enable it.\nRun: {LONG}\nThen run again.")
    assert f"     Run: {LONG}" in lines and len(f"     Run: {LONG}") > 60


def test_sentences_before_and_after_a_command_are_wrapped_separately():
    lines = _fix("First sentence.\nRun: do-it --now\nSecond sentence after the command.")
    assert lines[0] == "Fix: First sentence."
    assert lines[1] == "     Run: do-it --now"
    assert lines[2] == "     Second sentence after the command."


def test_every_fix_ends_with_its_troubleshooting_anchor():
    assert _fix("One sentence.")[-1] == "     (docs/troubleshooting.md#x)"


# ── one problem per cause ─────────────────────────────────────────────────────


def _by_prefix(message):
    """A cause hook for the tests: ``"<service>: <text> @<scope>"`` is about <service>."""
    head, _, scope = message.partition(" @")
    return (head.split(":")[0].strip().lower(), scope) if ":" in head else None


def test_messages_with_the_same_cause_are_one_problem_however_they_are_worded():
    r.configure(cause=_by_prefix, noun="project")
    r.ISSUES.add(logging.WARNING, "preflight", "Bigtable: off in the billing project @alpha")
    r.ISSUES.add(logging.WARNING, "scan", "Bigtable: the collector failed, API disabled @beta")
    [group] = r.ISSUES.groups()
    assert group["count"] == 2 and group["scopes"] == ["alpha", "beta"]


def test_a_scope_is_listed_once_however_many_times_it_is_reported():
    r.configure(cause=_by_prefix)
    for _ in range(3):
        r.ISSUES.add(logging.WARNING, "x", "Bigtable: off @alpha")
    [group] = r.ISSUES.groups()
    assert group["count"] == 3 and group["scopes"] == ["alpha"]


def test_a_scope_given_by_the_caller_wins_over_the_one_in_the_message():
    r.configure(cause=_by_prefix)
    r.ISSUES.add(logging.WARNING, "x", "Bigtable: off @from-the-message", "from-the-caller")
    assert r.ISSUES.groups()[0]["scopes"] == ["from-the-caller"]


def test_different_causes_stay_different_problems():
    r.configure(cause=_by_prefix)
    r.ISSUES.add(logging.WARNING, "x", "Bigtable: off @a")
    r.ISSUES.add(logging.WARNING, "x", "Spanner: off @a")
    assert len(r.ISSUES.groups()) == 2


def test_without_a_cause_hook_nothing_changes():
    r.configure(masks=[re.compile(r"(?<=project )[a-z][a-z0-9-]+")])
    for name in ("alpha-1", "beta-22"):
        r.ISSUES.add(logging.WARNING, "x", f"Storage failed for project {name}: 403")
    [group] = r.ISSUES.groups()
    assert group["count"] == 2 and group["scopes"] == []
    assert r.digest_lines()[1].startswith("  1. [WARNING] 2x Storage failed")


def test_a_message_the_hook_has_no_cause_for_falls_back_to_the_masked_message():
    r.configure(cause=lambda m: None)
    r.ISSUES.add(logging.WARNING, "x", "same text 1")
    r.ISSUES.add(logging.WARNING, "x", "same text 1")
    [group] = r.ISSUES.groups()
    assert group["count"] == 2 and group["scopes"] == []


def test_a_hook_that_fails_never_stops_the_run():
    def broken(message):
        raise ValueError("boom")

    r.configure(cause=broken)
    r.ISSUES.add(logging.WARNING, "x", "still recorded")
    assert r.ISSUES.total == 1 and len(r.ISSUES.groups()) == 1


def test_the_digest_names_how_many_scopes_and_which_ones_with_the_tools_noun():
    r.configure(cause=_by_prefix, noun="project")
    for scope in ("a", "b", "c", "d", "e", "f", "g"):
        r.ISSUES.add(logging.WARNING, "x", f"Bigtable: off @{scope}")
    lines = r.digest_lines()
    assert lines[0] == "1 distinct problem (7 warnings and errors in all):"
    assert lines[1].startswith("  1. [WARNING] 7 projects: Bigtable: off @a")
    assert lines[2] == "     Projects: a, b, c, d, e +2 more"


def test_one_scope_reads_as_a_singular_noun():
    r.configure(cause=_by_prefix, noun="account")
    r.ISSUES.add(logging.WARNING, "x", "S3: denied @111")
    lines = r.digest_lines()
    assert lines[1].startswith("  1. [WARNING] 1 account: ") and lines[2] == "     Accounts: 111"


def test_the_problem_on_the_most_scopes_is_listed_first_among_equals():
    r.configure(cause=_by_prefix)
    r.ISSUES.add(logging.WARNING, "x", "Few: off @a")
    for scope in ("a", "b", "c"):
        r.ISSUES.add(logging.WARNING, "x", f"Many: off @{scope}")
    assert [g["examples"][0].split(":")[0] for g in r.ISSUES.groups()] == ["Many", "Few"]
