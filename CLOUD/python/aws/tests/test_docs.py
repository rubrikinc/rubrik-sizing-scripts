"""The documentation matches this tool: every option, permission, output file and fix is documented."""

import re
from pathlib import Path

import csv_export
import main
import preflight
import pytest
import runlog

DOCS = Path(__file__).resolve().parents[2] / "docs"
TOOL = "aws"
HEADING = {"aws": "AWS", "azure": "Azure", "gcp": "GCP"}[TOOL]


def _section(text, start, stop_at=("\n### ", "\n## ")):
    begin = text.index(start) + len(start)
    ends = [text.find(marker, begin) for marker in stop_at]
    return text[begin : min([e for e in ends if e != -1] or [len(text)])]


def _options_section():
    guide = (DOCS / "user-guide.md").read_text(encoding="utf-8")
    return _section(
        _section(guide, "\n## 10. Options", ("\n## ",)) + "\n## end", f"### {HEADING}\n"
    )


def _parser_options():
    parser = main._build_parser()
    return {
        o for a in parser._actions for o in a.option_strings if o.startswith("--") and o != "--help"
    }


def test_every_option_of_the_tool_is_in_the_user_guide():
    section = _options_section()
    missing = sorted(o for o in _parser_options() if f"`{o}" not in section)
    assert missing == [], f"add these to docs/user-guide.md: {missing}"


def test_every_option_the_user_guide_lists_still_exists():
    documented = set(re.findall(r"`(--[a-z0-9-]+)", _options_section()))
    assert sorted(documented - _parser_options()) == []


def test_every_permission_the_access_check_uses_is_on_the_permissions_page():
    text = _section((DOCS / "permissions.md").read_text(encoding="utf-8"), f"\n## {HEADING}\n")
    missing = sorted(
        {
            a.permission
            for a in (*preflight.ACCOUNT_APIS, preflight.COST_API, *preflight.REGIONAL_APIS)
        }
        - set(re.findall(r"`([^`]+)`", text))
    )
    assert missing == [], f"add these to docs/permissions.md: {missing}"


def test_every_output_file_is_listed_in_the_user_guide():
    guide = (DOCS / "user-guide.md").read_text(encoding="utf-8")
    section = _section(guide, f"### {HEADING} files\n")
    missing = sorted(spec.prefix for spec in csv_export.FILES if f"`{spec.prefix}`" not in section)
    assert missing == [], f"add these to docs/user-guide.md: {missing}"


def test_every_fix_has_a_section_and_an_index_row_on_the_troubleshooting_page():
    text = (DOCS / "troubleshooting.md").read_text(encoding="utf-8")
    for solution in runlog.SOLUTIONS:
        assert f'<a id="{solution.id}"></a>' in text, f"no section for {solution.id}"
        assert f"](#{solution.id})" in text, f"no index row for {solution.id}"


def test_the_defaults_the_troubleshooting_page_names_are_the_tools_defaults():
    from collectors.context import DEFAULT_RECOVERY_POINT_TIMEOUT_MINUTES

    text = (DOCS / "troubleshooting.md").read_text(encoding="utf-8")
    parser = main._build_parser()
    assert f"`--org` uses `{main.DEFAULT_ORG_ROLE}`" in text
    assert f"(the default is {parser.get_default('workers')} accounts" in text
    assert f"({DEFAULT_RECOVERY_POINT_TIMEOUT_MINUTES} minutes by default)" in text
    assert "max_workers = min(len(regions), 20)" in Path(main.__file__).read_text(encoding="utf-8")
    assert "up to 20 regions at a time" in text
