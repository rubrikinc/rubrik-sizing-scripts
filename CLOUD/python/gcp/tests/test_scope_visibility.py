"""Who the scan runs as, how the project list was chosen, and what else the login can see.

Everything here is mocked: no test calls Google. The cases that matter are the ones that hid the
problem for a customer: a short ``--projects`` list on a login that sees far more, and a login
that sees fewer projects than the person expects.
"""

from __future__ import annotations

import json
import types
from unittest.mock import MagicMock, patch

import auth
import main
import manifest_core
import pytest
import runlog
from rich.console import Console


def _search(visible, system=0):
    return patch.object(auth, "_search_active_projects", return_value=(list(visible), system))


# ── describe_scope ──────────────────────────────────────────────────────────────


def test_a_named_list_reports_the_other_projects_the_login_can_see():
    with _search(["a", "b", "c", "d", "e", "f", "g", "h"]):
        facts = auth.describe_scope(MagicMock(), mode="named", scanned=["a", "b"], named=2)

    assert (facts.mode, facts.scanned, facts.named) == ("named", 2, 2)
    assert facts.visible_not_scanned == 6
    assert facts.visible_examples == ["c", "d", "e", "f", "g"]  # sorted, capped at five
    assert facts.lookup_error == ""


def test_a_named_list_that_covers_everything_visible_reports_none_left():
    with _search(["a", "b"]):
        facts = auth.describe_scope(MagicMock(), mode="named", scanned=["a", "b"], named=2)

    assert facts.visible_not_scanned == 0


def test_a_named_project_the_login_cannot_list_is_not_counted_as_another_one():
    """--projects can name a project the search does not return; that is not an 'other' project."""
    with _search(["a"]):
        facts = auth.describe_scope(MagicMock(), mode="named", scanned=["a", "hidden"], named=2)

    assert facts.visible_not_scanned == 0


def test_the_default_scope_counts_the_google_system_projects_it_left_out():
    with _search(["a", "b"], system=7):
        facts = auth.describe_scope(MagicMock(), mode="all", scanned=["a", "b"])

    assert facts.left_out_system == 7
    assert facts.visible_not_scanned is None  # the scan already is the visible list


def test_including_system_projects_leaves_none_out():
    with _search(["a"], system=7):
        facts = auth.describe_scope(
            MagicMock(), mode="all", scanned=["a"], include_system_projects=True
        )

    assert facts.left_out_system == 0


def test_a_failed_lookup_never_stops_the_scan():
    with patch.object(auth, "_search_active_projects", side_effect=RuntimeError("503 boom\nmore")):
        facts = auth.describe_scope(MagicMock(), mode="named", scanned=["a"], named=1)

    assert facts.visible_not_scanned is None  # unknown, not zero
    assert facts.lookup_error == "503 boom"


def test_the_search_counts_system_projects_without_returning_them():
    def project(pid):
        return types.SimpleNamespace(project_id=pid, display_name=pid)

    client = MagicMock()
    client.search_projects.return_value = iter([project("a"), project("sys-1234"), project("b")])
    with patch("google.cloud.resourcemanager_v3.ProjectsClient", return_value=client):
        projects, system = auth._search_active_projects(MagicMock())

    assert (projects, system) == (["a", "b"], 1)


# ── identity_of ─────────────────────────────────────────────────────────────────


def test_a_service_account_names_itself_without_a_network_call():
    creds = types.SimpleNamespace(service_account_email="svc@p.iam.gserviceaccount.com", token="t")
    with patch("requests.get") as get:
        assert auth.identity_of(creds) == "svc@p.iam.gserviceaccount.com"
    get.assert_not_called()


def test_the_gce_placeholder_identity_is_not_reported_as_an_email():
    creds = types.SimpleNamespace(service_account_email="default", token=None)
    assert auth.identity_of(creds) == ""


def test_a_user_login_is_looked_up_from_its_token():
    creds = types.SimpleNamespace(token="tok")
    response = MagicMock(ok=True)
    response.json.return_value = {"email": "irshad@example.com"}
    with patch("requests.get", return_value=response) as get:
        assert auth.identity_of(creds) == "irshad@example.com"
    assert get.call_args.kwargs["params"] == {"access_token": "tok"}


def test_a_token_without_an_email_is_unknown_not_guessed():
    creds = types.SimpleNamespace(token="tok")
    response = MagicMock(ok=True)
    response.json.return_value = {"scope": "https://www.googleapis.com/auth/cloud-platform"}
    with patch("requests.get", return_value=response):
        assert auth.identity_of(creds) == ""


@pytest.mark.parametrize("failure", [ConnectionError("offline"), ValueError("bad json")])
def test_a_failed_identity_lookup_is_unknown_not_an_error(failure):
    creds = types.SimpleNamespace(token="tok")
    with patch("requests.get", side_effect=failure):
        assert auth.identity_of(creds) == ""


# ── The words on screen ─────────────────────────────────────────────────────────


def _facts(**kw):
    return auth.ScopeFacts(**{"mode": "named", "scanned": 12, "named": 12, **kw})


def test_a_named_list_with_other_visible_projects_gets_a_warning_that_names_the_fix():
    text = "\n".join(
        runlog.scope_lines(
            _facts(visible_not_scanned=38, visible_examples=["x1", "x2", "x3", "x4", "x5"])
        )
    )

    assert "the 12 project(s) you named" in text
    assert "WARNING" in text and "38 other active project(s)" in text
    assert "x1, x2, x3, x4, x5 and 33 more" in text
    assert "--all" in text


def test_a_named_list_that_is_everything_says_so_without_a_warning():
    text = "\n".join(runlog.scope_lines(_facts(visible_not_scanned=0)))

    assert "WARNING" not in text
    assert "can see no other active projects" in text


def test_a_failed_lookup_is_said_not_hidden():
    text = "\n".join(runlog.scope_lines(_facts(lookup_error="503")))

    assert "Could not check what else this login can see" in text
    assert "WARNING" not in text


def test_the_default_scope_says_a_missing_project_may_be_a_missing_grant():
    text = "\n".join(runlog.scope_lines(auth.ScopeFacts(mode="all", scanned=12, left_out_system=3)))

    assert "all 12 active project(s) this login can see" in text
    assert "Left out 3 Google system project(s)" in text
    assert "a missing project may be a missing grant" in text


def test_the_wording_never_claims_a_total_that_google_does_not_report():
    for facts in (
        _facts(visible_not_scanned=5, visible_examples=["a"]),
        auth.ScopeFacts(mode="all", scanned=3),
    ):
        text = "\n".join(runlog.scope_lines(facts)).lower()
        assert "exist" not in text and "total" not in text


def test_the_account_line_names_the_account_or_says_unknown():
    assert runlog.account_line("a@b.com") == "Signed in as: a@b.com"
    unknown = runlog.account_line("")
    assert "unknown" in unknown and "print-access-token" in unknown


def test_the_live_run_prints_the_account_and_the_scope(monkeypatch):
    console = Console(record=True, width=160)
    monkeypatch.setattr(main, "console", console)
    creds = types.SimpleNamespace(service_account_email="svc@p.iam.gserviceaccount.com")
    with _search(["a", "b", "c"]):
        facts, account = main._print_who_and_scope(
            creds, ["a"], named=1, current_only=False, include_system_projects=False
        )

    text = console.export_text()
    assert "Signed in as: svc@p.iam.gserviceaccount.com" in text
    assert "WARNING" in text and "2 other active project(s)" in text
    assert (facts.visible_not_scanned, account) == (2, "svc@p.iam.gserviceaccount.com")


# ── manifest.json ───────────────────────────────────────────────────────────────


def test_the_manifest_has_no_scope_unless_one_is_given():
    """AWS and Azure pass none, so their manifests are the bytes they were before."""
    document = json.loads(manifest_core.build({}, tool="gcp"))

    assert "scope" not in document
    assert list(document) == [
        "manifest_version",
        "tool",
        "tool_version",
        "code_version",
        "generated_at",
        "files",
    ]


def test_the_manifest_records_the_scope_before_the_file_list():
    scope = {"mode": "named", "scanned": 12}
    document = json.loads(manifest_core.build({}, tool="gcp", scope=scope))

    assert document["scope"] == scope
    assert list(document)[-2:] == ["scope", "files"]


def test_the_scope_record_is_counts_only():
    facts = auth.ScopeFacts(
        mode="named",
        scanned=12,
        named=12,
        left_out_system=0,
        visible_not_scanned=38,
        visible_examples=["secret-project-1", "secret-project-2"],
    )

    record = main._scope_for_manifest(facts)

    assert record == {
        "mode": "named",
        "scanned": 12,
        "named": 12,
        "left_out_system_projects": 0,
        "other_visible_projects": 38,
    }
    assert "secret-project" not in json.dumps(record)


def test_an_unknown_visible_count_stays_null_not_zero():
    facts = auth.ScopeFacts(mode="named", scanned=1, named=1, lookup_error="503")

    assert main._scope_for_manifest(facts)["other_visible_projects"] is None


def test_a_mock_run_has_no_scope_to_record():
    assert main._scope_for_manifest(None) is None
    assert "scope" not in json.loads(main._manifest_text({}))


def test_the_manifest_text_carries_the_scope_it_is_given():
    text = main._manifest_text({}, {"mode": "all", "scanned": 3})

    assert json.loads(text)["scope"] == {"mode": "all", "scanned": 3}
