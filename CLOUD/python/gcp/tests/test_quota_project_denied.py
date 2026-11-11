"""A quota project that refuses the calls (USER_PROJECT_DENIED) is explained once, with the fix,
instead of every project being reported as not accessible."""

import logging
import os
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import auth  # noqa: E402
import runlog  # noqa: E402,F401 - importing it configures runlog_core with the GCP fixes
import runlog_core  # noqa: E402

BILLING = "billing-proj-1"


def _denied(consumer=BILLING):
    """The error Google returned in Cloud Shell, as the client library renders it."""
    return Exception(
        f"403 Caller does not have required permission to use project {consumer}. Grant the "
        "caller the roles/serviceusage.serviceUsageConsumer role, or a custom role with the "
        "serviceusage.services.use permission, by visiting "
        f"https://console.developers.google.com/iam-admin/iam?project={consumer} and then retry. "
        'Propagation of the new permission may take a few minutes. [reason: "USER_PROJECT_DENIED"\n'
        'domain: "googleapis.com"\nmetadata {\n  key: "consumer"\n'
        f'  value: "projects/{consumer}"\n}}\n]'
    )


class _Client:
    def __init__(self, readable=(), error=None):
        self.readable = set(readable)
        self.error = error or _denied()

    def get_project(self, name):
        project_id = name.split("/", 1)[1]
        if project_id in self.readable:
            return SimpleNamespace(project_id=project_id, display_name=project_id)
        raise self.error

    def search_projects(self, query):
        raise self.error


@pytest.fixture
def client(monkeypatch):
    from google.cloud import resourcemanager_v3

    holder = {}

    def install(**kwargs):
        holder["client"] = _Client(**kwargs)
        monkeypatch.setattr(
            resourcemanager_v3, "ProjectsClient", lambda credentials: holder["client"]
        )
        return holder["client"]

    return install


def test_the_charged_project_is_read_from_googles_message():
    assert auth.quota_project_denied(_denied("example.com:proj-2")) == "example.com:proj-2"
    assert auth.quota_project_denied(_denied()) == BILLING


def test_other_errors_are_not_mistaken_for_it():
    assert auth.quota_project_denied(Exception("404 Project not found")) is None
    assert (
        auth.quota_project_denied(Exception("403 Permission 'resourcemanager.projects.get' denied"))
        is None
    )


def test_every_project_refused_by_the_quota_project_ends_with_the_cause_and_the_fix(
    client, monkeypatch, caplog, capsys
):
    client()
    monkeypatch.setenv("GOOGLE_CLOUD_QUOTA_PROJECT", BILLING)
    skipped = []
    with caplog.at_level(logging.WARNING), pytest.raises(SystemExit):
        auth.resolve_projects(object(), ["p1", "p2", "p3"], skipped=skipped)

    warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 3
    assert all("charged to quota project billing-proj-1" in w for w in warnings)
    assert not any("metadata" in w or "not accessible" in w for w in warnings)
    assert [project for project, _ in skipped] == ["p1", "p2", "p3"]

    screen = capsys.readouterr().err
    assert "No project could be read" in screen and "No accessible projects found" not in screen
    assert "set by GOOGLE_CLOUD_QUOTA_PROJECT" in screen
    assert "unset GOOGLE_CLOUD_QUOTA_PROJECT" in screen


def test_projects_that_can_be_read_are_kept(client, caplog):
    client(readable={"p2"})
    with caplog.at_level(logging.WARNING):
        assert auth.resolve_projects(object(), ["p1", "p2"]) == ["p2"]
    assert "Project p1 not checked" in caplog.text


def test_listing_every_project_explains_the_quota_project_too(client, capsys):
    client()
    with pytest.raises(SystemExit):
        auth.resolve_projects(object(), None, all_projects=True)
    assert "quota project" in capsys.readouterr().err


def test_any_other_failure_is_one_line_on_screen(client, caplog):
    client(error=Exception("404 Project not found\nmore detail\nand more"))
    with caplog.at_level(logging.WARNING), pytest.raises(SystemExit):
        auth.resolve_projects(object(), ["p1"])
    warning = next(r.getMessage() for r in caplog.records if r.levelno == logging.WARNING)
    assert warning == "Project p1 not accessible: 404 Project not found — skipping"


@pytest.mark.parametrize(
    "text, expected",
    [
        (
            "Project p1 not checked: API calls are charged to quota project x, which refuses them "
            "(USER_PROJECT_DENIED)",
            "gcp-quota-project-denied",
        ),
        ("Project p1 not accessible: 404 Project not found — skipping", "gcp-no-projects"),
    ],
)
def test_each_message_gets_its_fix(text, expected):
    assert runlog_core.solve(text)[0] == expected
