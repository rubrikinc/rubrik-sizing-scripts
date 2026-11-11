"""PowerShell-style GCP CSV files (VMs and disks) and the data they rely on.

Expected lines were produced by the real ``Get-GCEInstancesAndDisks`` and ``Get-GCEUnattachedDisks``
of Get-GCPSizingInfo.ps1, run in pwsh with a ``gcloud`` function returning fixture JSON, on the same
scenario as the tests below.
"""

from __future__ import annotations

import csv
import dataclasses
import io
import json
import logging
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from google.cloud import compute_v1

import csv_export
from collectors.compute import ComputeCollector, _encryption_key
from csv_export import (
    _format_float,
    _image_parts,
    _label_cells,
    _object_text,
    _ps_sum,
    build_csv_files,
    render,
)

sys.path.insert(0, str(Path(__file__).parent.parent))

from tests.conftest import PROJECT_ID

_DEBIAN = "https://www.googleapis.com/compute/v1/projects/debian-cloud/global/images/debian-11-bullseye-v20240101"


def _parse(text: str) -> list[list[str]]:
    return list(csv.reader(io.StringIO(text)))


# ── formatting ────────────────────────────────────────────────────────────────


def test_render_quotes_everything_but_nulls_and_keeps_empty_strings_quoted():
    text = render(["a", "b", "c", "d"], [{"a": 1, "b": None, "c": "", "d": 'x"y'}])
    assert text == '"a","b","c","d"\n"1",,"","x""y"\n'


def test_no_rows_gives_an_empty_file():
    assert render(["a"], []) == ""


@pytest.mark.parametrize(
    "value,text",
    [
        (100.0, "100"),
        (0.1, "0.1"),
        (0.075, "0.075"),
        (0.001, "0.001"),
        (1e15, "1000000000000000"),
        (1.5e16, "15000000000000000"),
        (1e17, "1E+17"),
        (1e-05, "1E-05"),
    ],
)
def test_double_text_matches_dotnet(value, text):
    assert _format_float(value) == text


def test_sums_are_a_running_total():
    assert _ps_sum([0.1, 0.2, 0.3]) == 0.6000000000000001
    assert _ps_sum([]) == 0.0


# ── labels ────────────────────────────────────────────────────────────────────


def test_label_names_replace_every_non_alphanumeric_character_with_an_underscore():
    assert list(_label_cells({"my-label.v1/x y": "1"})) == ["Label/Tag: my_label_v1_x_y"]


def test_labels_that_become_the_same_name_leave_the_later_value_at_the_end():
    cells = _label_cells({"cost-center": "x y", "env": "p", "cost_center": "z"})
    assert list(cells.items()) == [("Label/Tag: env", "p"), ("Label/Tag: cost_center", "z")]


def test_an_empty_label_value_is_a_value_not_a_null():
    files = build_csv_files(_result(label_vm3={"env": "x", "team": ""}), "S")
    assert files["gce_vm_info-S.csv"].splitlines()[3].endswith('"RUNNING","x",""')


# ── objects PowerShell writes as text ─────────────────────────────────────────


def test_a_key_object_is_written_as_powershell_writes_a_custom_object():
    assert _object_text({"kmsKeyName": "projects/k/x", "sha256": "q="}) == (
        "@{kmsKeyName=projects/k/x; sha256=q=}"
    )
    assert _object_text(None) is None and _object_text({}) is None


def test_the_source_image_project_and_name_are_taken_from_the_path():
    assert _image_parts(_DEBIAN) == ("debian-cloud", "debian-11-bullseye-v20240101")
    assert _image_parts(None) == (None, None)
    assert _image_parts("short/path") == (None, None)


# ── the files ─────────────────────────────────────────────────────────────────


def _disk(
    name,
    size,
    *,
    zone="zones/us-central1-a",
    did="1",
    labels=None,
    key=None,
    image=None,
    encrypted=None,
):
    return {
        "name": name,
        "zone": zone,
        "size_gb": size,
        "disk_id": did,
        "labels": labels or {},
        "encrypted": bool(key) if encrypted is None else encrypted,
        "encryption_key": key,
        "source_image": image,
    }


def _result(label_vm3=None) -> dict:
    cmek = {"kmsKeyName": "projects/k/locations/l/keyRings/r/cryptoKeys/c", "sha256": "abc="}
    uniform = {"env": "x", "team": "y"}
    stub = _disk("d3-missing", 0, did=None)
    return {
        "projects_scanned": ["proj-a", "proj-b"],
        "compute": [
            {
                "project_id": "proj-b",
                "instances": [
                    {
                        "name": "vm4",
                        "zone": "europe-west1-b",
                        "status": "STOPPED",
                        "labels": uniform,
                        "disks": [
                            _disk(
                                "d4",
                                75,
                                zone="zones/europe-west1-b",
                                did="4444",
                                labels=uniform,
                                image=_DEBIAN,
                            )
                        ],
                    },
                ],
                "unattached_disks": [],
            },
            {
                "project_id": "proj-a",
                "instances": [
                    {
                        "name": "vm1",
                        "zone": "us-central1-a",
                        "status": "RUNNING",
                        "labels": uniform,
                        "disks": [
                            _disk("d1", 100, did="1111", labels=uniform, key=cmek, image=_DEBIAN),
                            _disk("d2", 500, did="2222", labels=uniform),
                            stub,
                        ],
                    },
                    {
                        "name": "vm2",
                        "zone": "us-east1-b",
                        "status": "TERMINATED",
                        "labels": uniform,
                        "disks": [
                            _disk(
                                "rd1",
                                200,
                                zone="regions/us-east1",
                                did="3333",
                                labels=uniform,
                                key={"sha256": "zzz="},
                            )
                        ],
                    },
                    {
                        "name": "vm3",
                        "zone": "us-east1-c",
                        "status": "RUNNING",
                        "labels": label_vm3 or uniform,
                        "disks": [],
                    },
                ],
                "unattached_disks": [
                    _disk(
                        "u1",
                        50,
                        zone="zones/us-central1-c",
                        did="5555",
                        labels=uniform,
                        image=_DEBIAN,
                        key={
                            "kmsKeyName": "projects/k/x",
                            "kmsKeyServiceAccount": "sa@p.iam",
                            "sha256": "q=",
                        },
                    ),
                    _disk("u2", 10, zone="regions/us-east1", did="6666", labels=uniform),
                    _disk("u3", 1, zone="zones/us-west1-a", did="7777", labels=uniform),
                ],
            },
        ],
    }


def test_vm_file_matches_powershell():
    lines = build_csv_files(_result(), "S")["gce_vm_info-S.csv"].splitlines()
    assert lines == [
        '"Project","Zone","Name","TotalDiskCount","TotalDiskSizeGb","TotalDiskSizeTb","TotalDiskSizeGiB","TotalDiskSizeTiB","EncryptedDisksCount","EncryptedDisksSizeGb","EncryptedDisksSizeTb","EncryptedDisksSizeGiB","EncryptedDisksSizeTiB","Status","Label/Tag: env","Label/Tag: team"',
        '"proj-a","us-central1-a","vm1","2","600","0.6","600","0.5859","1","100","0.1","100","0.0977","RUNNING","x","y"',
        '"proj-a","us-east1-b","vm2","1","200","0.2","200","0.1953","1","200","0.2","200","0.1953","TERMINATED","x","y"',
        '"proj-a","us-east1-c","vm3","0","0","0","0","0","0","0","0","0","0","RUNNING","x","y"',
        '"proj-b","europe-west1-b","vm4","1","75","0.075","75","0.0732","0","0","0","0","0","STOPPED","x","y"',
    ]


def test_attached_disk_file_matches_powershell():
    lines = build_csv_files(_result(), "S")["gce_attached_disk_info-S.csv"].splitlines()
    assert lines == [
        '"Project","Zone","VMName","DiskName","Id","SizeGb","SizeTb","SizeGiB","SizeTiB","DiskEncryptionKey","SourceImageSource","SourceImageName","Label/Tag: env","Label/Tag: team"',
        '"proj-a","us-central1-a","vm1","d1","1111","100","0.1","100","0.0977","True","debian-cloud","debian-11-bullseye-v20240101","x","y"',
        '"proj-a","us-central1-a","vm1","d2","2222","500","0.5","500","0.4883","False",,,"x","y"',
        '"proj-a","us-east1","vm2","rd1","3333","200","0.2","200","0.1953","True",,,"x","y"',
        '"proj-b","europe-west1-b","vm4","d4","4444","75","0.075","75","0.0732","False","debian-cloud","debian-11-bullseye-v20240101","x","y"',
    ]


def test_unattached_disk_file_matches_powershell():
    lines = build_csv_files(_result(), "S")["gce_unattached_disk_info-S.csv"].splitlines()
    assert lines == [
        '"Project","Zone","DiskName","Id","SizeGb","SizeTb","SizeGiB","SizeTiB","DiskEncryptionKey","SourceImageSource","SourceImageName","Label/Tag: env","Label/Tag: team"',
        '"proj-a","us-central1-c","u1","5555","50","0.05","50","0.0488","@{kmsKeyName=projects/k/x; kmsKeyServiceAccount=sa@p.iam; sha256=q=}","debian-cloud","debian-11-bullseye-v20240101","x","y"',
        '"proj-a","us-east1","u2","6666","10","0.01","10","0.0098",,,,"x","y"',
        '"proj-a","us-west1-a","u3","7777","1","0.001","1","0.001",,,,"x","y"',
    ]


# size in GiB -> (SizeGiB, SizeTiB) exactly as ConvertTo-GCPSizeUnits -InputUnit GiB writes them in
# master's Get-GCPSizingInfo.ps1 (run in pwsh). Four decimals, .NET half-to-even: 100000 / 1024 =
# 97.65625 is written 97.6562.
_POWERSHELL_GIB_TIB = [
    (0, 0, 0),
    (1, 1, 0.001),
    (3, 3, 0.0029),
    (7, 7, 0.0068),
    (10, 10, 0.0098),
    (13, 13, 0.0127),
    (29, 29, 0.0283),
    (30, 30, 0.0293),
    (75, 75, 0.0732),
    (100, 100, 0.0977),
    (333, 333, 0.3252),
    (500, 500, 0.4883),
    (777, 777, 0.7588),
    (999, 999, 0.9756),
    (1111, 1111, 1.085),
    (1500, 1500, 1.4648),
    (2048, 2048, 2),
    (4096, 4096, 4),
    (12345, 12345, 12.0557),
    (65536, 65536, 64),
    (100000, 100000, 97.6562),
]


@pytest.mark.parametrize("size,gib,tib", _POWERSHELL_GIB_TIB)
def test_gib_and_tib_match_the_powershell_helper(size, gib, tib):
    assert csv_export._gib_tib(float(size), "Size") == {"SizeGiB": gib, "SizeTiB": tib}


def test_the_legacy_gb_and_tb_columns_are_unchanged_next_to_the_new_ones():
    row = dict(zip(*_parse(build_csv_files(_result(), "S")["gce_attached_disk_info-S.csv"])[:2]))
    assert (row["SizeGb"], row["SizeTb"], row["SizeGiB"], row["SizeTiB"]) == (
        "100",
        "0.1",
        "100",
        "0.0977",
    )


def test_ps_round_rounds_a_tie_to_even_like_dotnet():
    assert csv_export._ps_round(12.345, 2) == 12.34
    assert round(12.345, 2) == 12.35  # Python's round differs, which is why the helper exists


def test_a_disk_the_listing_did_not_return_is_in_no_row_and_no_count():
    files = build_csv_files(_result(), "S")
    assert "d3-missing" not in files["gce_attached_disk_info-S.csv"]
    vm1 = _parse(files["gce_vm_info-S.csv"])[1]
    assert vm1[3] == "2"  # d1 and d2 only


def test_rows_follow_the_order_the_projects_were_scanned():
    names = [r[0] for r in _parse(build_csv_files(_result(), "S")["gce_vm_info-S.csv"])[1:]]
    assert names == ["proj-a", "proj-a", "proj-a", "proj-b"]


def test_label_columns_are_the_union_in_first_seen_order_and_a_missing_label_is_empty():
    result = _result()
    result["compute"][1]["instances"][0]["labels"] = {"env": "p"}
    result["compute"][1]["instances"][1]["labels"] = {"zone_tag": "z"}
    header, vm1, vm2, *_ = _parse(build_csv_files(result, "S")["gce_vm_info-S.csv"])
    assert header[14:] == ["Label/Tag: env", "Label/Tag: zone_tag", "Label/Tag: team"]
    assert dict(zip(header, vm1))["Label/Tag: zone_tag"] == ""
    assert dict(zip(header, vm2))["Label/Tag: env"] == ""
    assert dict(zip(header, vm2))["Label/Tag: zone_tag"] == "z"


def test_empty_result_gives_empty_files_with_powershell_names():
    assert build_csv_files({"projects_scanned": [], "compute": []}, "2026-10-06_120000") == {
        "gce_vm_info-2026-10-06_120000.csv": "",
        "gce_attached_disk_info-2026-10-06_120000.csv": "",
        "gce_unattached_disk_info-2026-10-06_120000.csv": "",
        "gce_cloudsql_info-2026-10-06_120000.csv": "",
        "gce_spanner_info-2026-10-06_120000.csv": "",
        "gce_bigquery_info-2026-10-06_120000.csv": "",
    }


# ── the collector records what the files need ─────────────────────────────────

_INSTANCES_CLIENT = "google.cloud.compute_v1.InstancesClient"
_DISKS_CLIENT = "google.cloud.compute_v1.DisksClient"


def _collect(instances, scoped_disks):
    inst_client = MagicMock()
    scoped_instances = MagicMock()
    scoped_instances.instances = instances
    inst_client.aggregated_list.return_value = iter([("zones/us-central1-a", scoped_instances)])
    disk_client = MagicMock()
    pages = []
    for scope, disks in scoped_disks:
        scoped = MagicMock()
        scoped.disks = disks
        pages.append((scope, scoped))
    disk_client.aggregated_list.return_value = iter(pages)
    with patch(_INSTANCES_CLIENT, return_value=inst_client), patch(
        _DISKS_CLIENT, return_value=disk_client
    ):
        return ComputeCollector(PROJECT_ID, MagicMock()).collect()


def _instance(name, source_disks):
    inst = MagicMock()
    inst.name = name
    inst.zone = "zones/us-central1-a"
    inst.machine_type = "zones/us-central1-a/machineTypes/n2-standard-4"
    inst.status = "RUNNING"
    inst.labels = {"env": "prod"}
    attached = []
    for source in source_disks:
        a = MagicMock()
        a.boot = False
        a.source = source
        a.licenses = []
        attached.append(a)
    inst.disks = attached
    return inst


def _proto_disk(name, **kwargs):
    base = dict(
        name=name,
        size_gb=100,
        type_="zones/us-central1-a/diskTypes/pd-ssd",
        status="READY",
        self_link=f"https://www.googleapis.com/compute/v1/projects/p/zones/us-central1-a/disks/{name}",
    )
    base.update(kwargs)
    return compute_v1.Disk(**base)


def test_the_collector_records_id_labels_image_and_key_from_real_disk_protos():
    key = compute_v1.CustomerEncryptionKey(kms_key_name="projects/k/x", sha256="q=")
    disks = [
        _proto_disk(
            "d1",
            id=111,
            labels={"env": "prod"},
            source_image=_DEBIAN,
            disk_encryption_key=key,
            users=["vm1"],
        ),
        _proto_disk("d2", id=222, users=["vm1"]),
        _proto_disk(
            "u1", id=333, labels={"a-b": "1"}, disk_encryption_key=key, source_image=_DEBIAN
        ),
        _proto_disk("u2", id=444),
    ]
    sources = [f"projects/p/zones/us-central1-a/disks/{n}" for n in ("d1", "d2", "missing")]
    result = _collect([_instance("vm1", sources)], [("zones/us-central1-a", disks)])

    d1, d2, stub = result.instances[0].disks
    assert (d1.disk_id, d1.labels, d1.source_image) == ("111", {"env": "prod"}, _DEBIAN)
    assert d1.encrypted is True and d1.encryption_key == {
        "kmsKeyName": "projects/k/x",
        "sha256": "q=",
    }
    assert (d2.disk_id, d2.labels, d2.encrypted, d2.encryption_key, d2.source_image) == (
        "222",
        {},
        False,
        None,
        None,
    )
    assert stub.disk_id is None and stub.size_gb == 0

    u1, u2 = result.unattached_disks
    assert (u1.disk_id, u1.labels, u1.encrypted) == ("333", {"a-b": "1"}, True)
    assert (u2.disk_id, u2.encrypted, u2.encryption_key) == ("444", False, None)


def test_a_disk_without_an_encryption_key_has_none_not_an_empty_message():
    assert _encryption_key(compute_v1.Disk(name="x")) is None
    only_sha = compute_v1.Disk(disk_encryption_key=compute_v1.CustomerEncryptionKey(sha256="zzz="))
    assert _encryption_key(only_sha) == {"sha256": "zzz="}
    all_three = compute_v1.Disk(
        disk_encryption_key=compute_v1.CustomerEncryptionKey(
            kms_key_name="projects/k/x", kms_key_service_account="sa@p.iam", sha256="q="
        )
    )
    assert list(_encryption_key(all_three)) == ["kmsKeyName", "kmsKeyServiceAccount", "sha256"]


def test_collected_data_goes_through_json_into_the_files():
    key = compute_v1.CustomerEncryptionKey(kms_key_name="projects/k/x")
    disks = [
        _proto_disk("d1", id=111, labels={"env": "prod"}, disk_encryption_key=key, users=["vm1"]),
        _proto_disk("u1", id=333, labels={"env": "dev"}, disk_encryption_key=key),
    ]
    inventory = _collect(
        [_instance("vm1", ["projects/p/zones/us-central1-a/disks/d1"])],
        [("zones/us-central1-a", disks)],
    )
    result = json.loads(
        json.dumps({"projects_scanned": [PROJECT_ID], "compute": [dataclasses.asdict(inventory)]})
    )
    files = build_csv_files(result, "S")
    assert _parse(files["gce_attached_disk_info-S.csv"])[1][3:10] == [
        "d1",
        "111",
        "100",
        "0.1",
        "100",
        "0.0977",
        "True",
    ]
    assert _parse(files["gce_unattached_disk_info-S.csv"])[1][8] == "@{kmsKeyName=projects/k/x}"


# ── the ZIP ───────────────────────────────────────────────────────────────────


def _finalise(tmp_path, started, **kwargs):
    import main

    out = tmp_path / "gcp-sizing-discovery-20261006-175900.json"
    out.write_text(json.dumps(_result()))
    log = tmp_path / "run.log"
    log.write_text("log text")
    handler = logging.NullHandler()
    return main._finalise_zip(out, handler, str(log), started=started, **kwargs), out, log


def test_the_zip_log_and_csv_files_take_the_powershell_names(tmp_path):
    started = datetime(2026, 10, 6, 17, 59, 3, tzinfo=timezone.utc)
    zip_path, out, log = _finalise(tmp_path, started)
    assert zip_path.name == "gcp_sizing_results_2026-10-06_175903.zip"
    names = zipfile.ZipFile(zip_path).namelist()
    assert sorted(names) == sorted(
        [
            out.name,
            "gce_vm_info-2026-10-06_175903.csv",
            "gce_attached_disk_info-2026-10-06_175903.csv",
            "gce_unattached_disk_info-2026-10-06_175903.csv",
            "gce_cloudsql_info-2026-10-06_175903.csv",
            "gce_spanner_info-2026-10-06_175903.csv",
            "gce_bigquery_info-2026-10-06_175903.csv",
            "manifest.json",
            "output_gcp_2026-10-06_175903.log",
        ]
    )
    assert not out.exists() and not log.exists()
    assert zipfile.ZipFile(zip_path).read("output_gcp_2026-10-06_175903.log") == b"log text"


def test_no_csv_leaves_only_the_json_the_manifest_and_the_log(tmp_path):
    zip_path, out, _ = _finalise(
        tmp_path, datetime(2026, 10, 6, 17, 59, 3, tzinfo=timezone.utc), write_csv=False
    )
    assert sorted(zipfile.ZipFile(zip_path).namelist()) == sorted(
        [out.name, "manifest.json", "output_gcp_2026-10-06_175903.log"]
    )


def test_a_mock_run_writes_the_zip_with_csv_files(monkeypatch, tmp_path):
    import main

    monkeypatch.setattr(sys, "argv", ["main.py", "--mock", "--output", str(tmp_path)])
    main.main()
    (archive,) = tmp_path.glob("gcp_sizing_results_*.zip")
    names = zipfile.ZipFile(archive).namelist()
    assert sum(n.startswith("gce_") and n.endswith(".csv") for n in names) == 6
    assert any(n.startswith("gce_bigquery_info-") for n in names)
    assert any(n.startswith("output_gcp_") for n in names)
    assert sorted(p.name for p in tmp_path.iterdir()) == [archive.name]


def test_a_mock_run_with_no_csv_has_no_csv_files(monkeypatch, tmp_path):
    import main

    monkeypatch.setattr(sys, "argv", ["main.py", "--mock", "--no-csv", "--output", str(tmp_path)])
    main.main()
    (archive,) = tmp_path.glob("gcp_sizing_results_*.zip")
    assert not [n for n in zipfile.ZipFile(archive).namelist() if n.endswith(".csv")]
