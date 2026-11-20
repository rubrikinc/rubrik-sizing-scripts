"""The checkpoint core: atomic writes, resume decisions and the guards against mixing runs."""

import json
import os

import pytest

from common import checkpoint as ck

REQUEST = {"scope": ["a", "b"], "regions": None, "cost": True}


def _prepare(tmp_path, **kwargs):
    options = dict(prefix="run", tool="t", request=REQUEST, interactive=False)
    options.update(kwargs)
    return ck.prepare(str(tmp_path), **options)


# ── atomic writes ─────────────────────────────────────────────────────────────


def test_write_is_whole_or_absent(tmp_path):
    path = tmp_path / "x" / "f.json"
    ck.write_json_atomic(str(path), {"a": 1})
    assert json.loads(path.read_text()) == {"a": 1}
    assert [p.name for p in path.parent.iterdir()] == ["f.json"]  # no temp file left


def test_a_failed_write_leaves_the_old_file_and_no_temp_file(tmp_path):
    path = tmp_path / "f.json"
    ck.write_json_atomic(str(path), {"old": True})

    class Unserialisable:
        def __repr__(self):
            raise RuntimeError("cannot serialise")

    with pytest.raises(RuntimeError):
        ck.write_json_atomic(str(path), {"bad": Unserialisable()})
    assert json.loads(path.read_text()) == {"old": True}
    assert [p.name for p in tmp_path.iterdir()] == ["f.json"]


def test_safe_unit_name_keeps_plain_ids_and_cleans_the_rest():
    assert ck.safe_unit_name("123456789012") == "123456789012"
    assert ck.safe_unit_name("my-project-1") == "my-project-1"
    assert ck.safe_unit_name("a/b") != "a/b"
    assert "/" not in ck.safe_unit_name("../../etc")
    assert ck.safe_unit_name("..") not in ("..", ".")
    assert ck.safe_unit_name("a/b") != ck.safe_unit_name("a_b")  # the hash keeps them apart


def test_fingerprint_ignores_key_order_and_sees_changes():
    assert ck.fingerprint({"a": 1, "b": 2}) == ck.fingerprint({"b": 2, "a": 1})
    assert ck.fingerprint({"a": 1}) != ck.fingerprint({"a": 2})


# ── the store ─────────────────────────────────────────────────────────────────


def test_save_load_and_completed_round_trip(tmp_path):
    store, resumed = _prepare(tmp_path)
    assert resumed is False
    store.save("proj-1", {"n": 1})
    store.save("proj-2", {"n": 2}, partial=True)
    assert store.load("proj-1") == ({"n": 1}, False)
    assert store.load("proj-2") == ({"n": 2}, True)
    assert store.load("proj-3") is None
    assert store.completed() == {"proj-1": False, "proj-2": True}


def test_unit_ids_that_need_cleaning_round_trip_by_their_real_id(tmp_path):
    store, _ = _prepare(tmp_path)
    store.save("org/odd name", {"n": 1})
    assert store.completed() == {"org/odd name": False}
    assert store.load("org/odd name") == ({"n": 1}, False)


def test_an_unreadable_checkpoint_is_dropped_so_the_unit_is_scanned_again(tmp_path):
    store, _ = _prepare(tmp_path)
    store.save("good", {"n": 1})
    store.save("bad", {"n": 2})
    with open(store.unit_path("bad"), "w") as f:
        f.write('{"checkpoint": {"unit": "bad"}, "da')  # a truncated file
    assert store.completed() == {"good": False}
    assert not os.path.exists(store.unit_path("bad"))
    assert len(store.discarded) == 1


def test_a_file_that_is_valid_json_but_not_a_checkpoint_is_dropped(tmp_path):
    store, _ = _prepare(tmp_path)
    os.makedirs(store.unit_dir("x"))
    with open(store.unit_path("x"), "w") as f:
        json.dump({"unrelated": True}, f)
    assert store.completed() == {}


def test_without_an_envelope_the_unit_document_is_the_file(tmp_path):
    store, _ = _prepare(tmp_path, envelope=False, filename="aws_sizing_discovery.json")
    ck.write_json_atomic(store.unit_path("111122223333"), {"account_id": "111122223333"})
    assert store.completed() == {"111122223333": False}
    assert store.load("111122223333") == ({"account_id": "111122223333"}, False)


def test_without_an_envelope_a_truncated_document_is_dropped(tmp_path):
    store, _ = _prepare(tmp_path, envelope=False, filename="aws_sizing_discovery.json")
    os.makedirs(store.unit_dir("111122223333"))
    with open(store.unit_path("111122223333"), "w") as f:
        f.write('{"account_id": "1111')
    assert store.completed() == {}


# ── resuming ──────────────────────────────────────────────────────────────────


def test_a_rerun_with_the_same_options_resumes(tmp_path):
    first, _ = _prepare(tmp_path)
    first.save("a", {"n": 1})
    second, resumed = _prepare(tmp_path, mode=ck.RESUME)
    assert resumed is True
    assert second.root == first.root
    assert second.completed() == {"a": False}


def test_without_a_terminal_an_unfinished_run_is_not_resumed_silently(tmp_path):
    first, _ = _prepare(tmp_path)
    first.save("a", {"n": 1})
    with pytest.raises(ck.ResumeRefused, match="--resume.*--fresh"):
        _prepare(tmp_path)
    assert os.path.isdir(first.root) and first.load("a") is not None  # nothing was touched


def test_different_options_are_refused_not_mixed(tmp_path):
    first, _ = _prepare(tmp_path)
    first.save("a", {"n": 1})
    with pytest.raises(ck.ResumeRefused, match="different options"):
        _prepare(tmp_path, request={**REQUEST, "cost": False})
    assert os.path.isdir(first.root)  # nothing was deleted


def test_fresh_deletes_the_old_run_even_when_the_options_differ(tmp_path):
    first, _ = _prepare(tmp_path)
    first.save("a", {"n": 1})
    second, resumed = _prepare(tmp_path, mode=ck.FRESH, request={**REQUEST, "cost": False})
    assert resumed is False
    # The new folder may reuse the old name (the names are one-second stamps): what matters is
    # that the old run's data is gone and the new run records the new options.
    assert second.completed() == {}
    assert second.load("a") is None
    assert ck.read_manifest(second.root)["fingerprint"] == ck.fingerprint(
        {**REQUEST, "cost": False}
    )


def test_resume_without_a_previous_run_fails(tmp_path):
    with pytest.raises(ck.ResumeRefused, match="no unfinished run"):
        _prepare(tmp_path, mode=ck.RESUME)


def test_resume_with_different_options_fails(tmp_path):
    first, _ = _prepare(tmp_path)
    first.save("a", {"n": 1})
    with pytest.raises(ck.ResumeRefused):
        _prepare(tmp_path, mode=ck.RESUME, request={**REQUEST, "regions": ["us-east-1"]})


def test_a_finished_run_is_never_resumed(tmp_path):
    first, _ = _prepare(tmp_path)
    first.save("a", {"n": 1})
    first.finish(keep=True)
    second, resumed = _prepare(tmp_path)
    assert resumed is False
    assert second.root != first.root
    assert second.completed() == {}


def test_finish_removes_the_folder_by_default(tmp_path):
    first, _ = _prepare(tmp_path)
    first.save("a", {"n": 1})
    first.finish()
    assert not os.path.exists(first.root)


def test_a_folder_with_no_manifest_is_ignored_and_reported(tmp_path):
    old = tmp_path / "run-20200101-000000"
    (old / "a").mkdir(parents=True)
    (old / "a" / "checkpoint.json").write_text("{}")
    said = []
    store, resumed = _prepare(tmp_path, say=said.append)
    assert resumed is False
    assert store.root != str(old)
    assert any("older version" in line for line in said)
    assert old.exists()  # never deleted without being asked


def test_the_newest_unfinished_run_wins(tmp_path):
    older, _ = _prepare(tmp_path)
    older.finish(keep=True)
    newer, _ = _prepare(tmp_path)
    newer.save("a", {"n": 1})
    again, resumed = _prepare(tmp_path, mode=ck.RESUME)
    assert resumed and again.root == newer.root


def test_two_runs_started_in_the_same_second_get_different_folders(tmp_path):
    first, _ = _prepare(tmp_path)
    first.finish(keep=True)
    second, _ = _prepare(tmp_path)
    second.finish(keep=True)
    third, _ = _prepare(tmp_path)
    assert len({first.root, second.root, third.root}) == 3


# ── asking on a terminal ──────────────────────────────────────────────────────


def test_on_a_terminal_declining_the_resume_starts_over(tmp_path):
    first, _ = _prepare(tmp_path)
    first.save("a", {"n": 1})
    second, resumed = _prepare(tmp_path, interactive=True, ask=lambda q, d: False)
    assert resumed is False
    assert second.completed() == {} and second.load("a") is None


def test_on_a_terminal_accepting_the_resume_resumes(tmp_path):
    first, _ = _prepare(tmp_path)
    first.save("a", {"n": 1})
    asked = []
    second, resumed = _prepare(
        tmp_path, interactive=True, ask=lambda q, d: asked.append((q, d)) or True
    )
    assert resumed is True and second.root == first.root
    assert asked and asked[0][1] is True and "1 units done" in asked[0][0]
    assert "started just now" in asked[0][0]


def test_on_a_terminal_a_mismatch_can_be_replaced_when_the_person_says_yes(tmp_path):
    first, _ = _prepare(tmp_path)
    first.save("a", {"n": 1})
    second, resumed = _prepare(
        tmp_path, interactive=True, ask=lambda q, d: True, request={**REQUEST, "cost": False}
    )
    assert resumed is False
    assert second.completed() == {} and second.load("a") is None
    assert ck.read_manifest(second.root)["fingerprint"] == ck.fingerprint(
        {**REQUEST, "cost": False}
    )


def test_on_a_terminal_a_mismatch_declined_is_refused(tmp_path):
    first, _ = _prepare(tmp_path)
    with pytest.raises(ck.ResumeRefused):
        _prepare(
            tmp_path, interactive=True, ask=lambda q, d: False, request={**REQUEST, "cost": False}
        )
    assert os.path.isdir(first.root)


def test_a_code_version_change_is_mentioned_but_does_not_block(tmp_path):
    first, _ = _prepare(tmp_path, code_version="abc 2026-11-01")
    first.save("a", {"n": 1})
    said = []
    _, resumed = _prepare(tmp_path, mode=ck.RESUME, code_version="def 2026-11-12", say=said.append)
    assert resumed is True
    assert any("abc 2026-11-01" in line for line in said)
