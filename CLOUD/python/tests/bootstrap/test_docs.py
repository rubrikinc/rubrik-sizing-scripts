"""The user-facing docs are safe to publish and their links, anchors and layout hold."""

import re

import pytest
from bootstrap_support import PY_DIR
from test_deny_list import DENY

PAGES = ["README.md"] + [
    f"docs/{name}.md"
    for name in (
        "user-guide",
        "troubleshooting",
        "permissions",
        "logging",
    )
]
GUID = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I)
ACCOUNT_ID = re.compile(r"(?<![\w.-])\d{12}(?![\w.-])")
WIDTH = 125


def _text(page):
    return (PY_DIR / page).read_text(encoding="utf-8")


def _prose_lines(page):
    in_fence = False
    for number, line in enumerate(_text(page).splitlines(), 1):
        if line.startswith("```"):
            in_fence = not in_fence
        elif not in_fence:
            yield number, line


def _slug(heading):
    heading = re.sub(r"[^\w\s-]", "", heading.strip().lower())
    return re.sub(r"\s", "-", heading)


@pytest.mark.parametrize("page", PAGES)
def test_the_page_exists_and_holds_nothing_that_must_stay_private(page):
    text = _text(page)
    hits = [line.strip()[:100] for line in text.splitlines() if DENY.search(line)]
    assert not hits, hits
    assert not GUID.findall(text), "a real subscription or tenant ID would be a leak"
    assert not ACCOUNT_ID.findall(text), "a 12-digit number looks like an AWS account ID"


@pytest.mark.parametrize("page", PAGES)
def test_every_link_to_an_anchor_resolves(page):
    text = _text(page)
    anchors = set(re.findall(r'<a id="([^"]+)"', text))
    anchors |= {_slug(m) for m in re.findall(r"^#{1,6} (.+)$", text, re.M)}
    missing = sorted(set(re.findall(r"\]\(#([^)]+)\)", text)) - anchors)
    assert missing == []


@pytest.mark.parametrize("page", PAGES)
def test_every_page_it_names_exists(page):
    named = set(re.findall(r"`(?:docs/)?([a-z-]+\.md)`", _text(page)))
    missing = sorted(
        n for n in named if not (PY_DIR / "docs" / n).exists() and not (PY_DIR / n).exists()
    )
    assert missing == []


@pytest.mark.parametrize("page", PAGES)
def test_prose_is_wrapped(page):
    long_lines = [
        n
        for n, line in _prose_lines(page)
        if len(line) > WIDTH and not line.startswith(("|", "#", "<a ")) and "http" not in line
    ]
    assert long_lines == [], f"lines too long in {page}: {long_lines}"


@pytest.mark.parametrize("page", PAGES)
def test_commands_to_paste_have_no_comments(page):
    fenced, in_fence = [], False
    for line in _text(page).splitlines():
        if line.startswith("```"):
            in_fence = not in_fence
        elif in_fence:
            fenced.append(line)
    assert [line for line in fenced if line.lstrip().startswith("#") or " #" in line] == []
