"""azure_aks_info, azure_cosmos_db and the collectors behind them.

Expected cell text comes from the real row blocks of Get-AzureSizingInfo.ps1 run in pwsh with the
Az cmdlets stubbed, on the same inputs as the cases below.
"""

from __future__ import annotations

import csv
import io
from types import SimpleNamespace as NS
from unittest.mock import MagicMock, patch

import pytest

import csv_export
from azure.core.exceptions import HttpResponseError
from collectors import aks_cosmos
from collectors.aks_cosmos import (
    AKS_API_VERSION,
    AKS_RESOURCE_TYPE,
    COSMOS_API_VERSION,
    COSMOS_RESOURCE_TYPE,
    AksCollector,
    AksNodePool,
    CosmosCollector,
)
from csv_export import build_csv_files

_SUB = "00000000-0000-0000-0000-000000000001"


def _parse(text: str) -> list[list[str]]:
    return list(csv.reader(io.StringIO(text)))


def _result(aks=(), cosmos=()) -> dict:
    return {
        "tenant_name": None,
        "tenant_id": "t",
        "subscription_names": {"sub-1": "Sub One"},
        "tag_names": {"sub-1": ["Env", "owner", "unused"]},
        "aks": [{"subscription_id": "sub-1", "clusters": list(aks)}],
        "cosmos_db": [{"subscription_id": "sub-1", "accounts": list(cosmos)}],
    }


# ── azure_aks_info ────────────────────────────────────────────────────────────


def _cluster(**overrides) -> dict:
    cluster = {
        "name": "aks1",
        "resource_group": "rg-1",
        "location": "westus2",
        "resource_id": "/subscriptions/s/resourceGroups/rg-1/providers/Microsoft.ContainerService/managedClusters/aks1",
        "kubernetes_version": "1.29.4",
        "provisioning_state": "Succeeded",
        "power_state": "Running",
        "dns_prefix": "aks1-dns",
        "fqdn": "aks1-dns.hcp.westus2.azmk8s.io",
        "node_resource_group": "MC_rg-1_aks1_westus2",
        "node_pools": [
            {
                "name": "system",
                "vm_size": "Standard_D4s_v3",
                "count": 3,
                "max_count": 10,
                "os_disk_size_gb": 128,
            },
            {
                "name": "spot",
                "vm_size": None,
                "count": None,
                "max_count": None,
                "os_disk_size_gb": None,
            },
            {
                "name": "user",
                "vm_size": "Standard_E8s_v5",
                "count": 5,
                "max_count": 8,
                "os_disk_size_gb": 256,
            },
        ],
        "tags": {"Env": "prod", "owner": ""},
    }
    cluster.update(overrides)
    return cluster


def test_aks_rows_match_powershell():
    clusters = [
        _cluster(),
        _cluster(
            name="aks2",
            resource_group="rg-2",
            location="eastus",
            resource_id="/subscriptions/s/resourceGroups/rg-2/providers/Microsoft.ContainerService/managedClusters/aks2",
            kubernetes_version=None,
            provisioning_state=None,
            power_state=None,
            dns_prefix=None,
            fqdn=None,
            node_resource_group=None,
            node_pools=[
                {
                    "name": None,
                    "vm_size": None,
                    "count": 0,
                    "max_count": None,
                    "os_disk_size_gb": None,
                }
            ],
            tags={"env": "lower"},
        ),
        _cluster(
            name="aks3",
            resource_group="rg-3",
            location="northeurope",
            resource_id="/subscriptions/s/resourceGroups/rg-3/providers/Microsoft.ContainerService/managedClusters/aks3",
            kubernetes_version="1.30.0",
            provisioning_state="Updating",
            power_state="Stopped",
            dns_prefix="d3",
            fqdn="f3",
            node_resource_group="MC_rg-3",
            node_pools=[],
            tags={},
        ),
    ]
    lines = build_csv_files(_result(aks=clusters), "S")["azure_aks_info-S.csv"].splitlines()
    assert lines[0].split(",")[:6] == [f'"{c}"' for c in csv_export._AKS_COLUMNS[:6]]
    assert lines[1:] == [
        '"Sub One",,"aks1","rg-1","westus2","/subscriptions/s/resourceGroups/rg-1/providers/Microsoft.ContainerService/managedClusters/aks1","1.29.4","Succeeded","Running","aks1-dns","aks1-dns.hcp.westus2.azmk8s.io","MC_rg-1_aks1_westus2","3","system; spot; user","Standard_D4s_v3; -; Standard_E8s_v5","3; 0; 5","10; -; 8","128; -; 256","8","prod","-","-"',
        # PowerShell writes the pool's node count (0) here for a one-pool cluster; this is the pool count.
        '"Sub One",,"aks2","rg-2","eastus","/subscriptions/s/resourceGroups/rg-2/providers/Microsoft.ContainerService/managedClusters/aks2","-","-","-","-","-","-","1","-","-","0","-","-","0","-","-","-"',
        '"Sub One",,"aks3","rg-3","northeurope","/subscriptions/s/resourceGroups/rg-3/providers/Microsoft.ContainerService/managedClusters/aks3","1.30.0","Updating","Stopped","d3","f3","MC_rg-3","0","","","","","","0","-","-","-"',
    ]


def test_aks_tag_lookup_is_case_sensitive():
    (row,) = _parse(
        build_csv_files(_result(aks=[_cluster(tags={"env": "x"})]), "S")["azure_aks_info-S.csv"]
    )[1:]
    assert row[-3:] == ["-", "-", "-"]


def test_no_clusters_gives_an_empty_file():
    assert build_csv_files(_result(), "S")["azure_aks_info-S.csv"] == ""


# ── azure_cosmos_db ───────────────────────────────────────────────────────────


def _account(**overrides) -> dict:
    account = {
        "name": "cosmos1",
        "location": "West US 2",
        "resource_id": "/subscriptions/s/resourceGroups/rg-1/providers/Microsoft.DocumentDB/databaseAccounts/cosmos1",
        "kind": "GlobalDocumentDB",
        "instance_id": "11111111-2222-3333-4444-555555555555",
        "backup_type": "Periodic",
        "backup_interval_minutes": 240,
        "backup_retention_hours": 8,
        "backup_storage_redundancy": "Geo",
        "backup_tier": None,
        "minimal_tls_version": "Tls12",
        "offer_type": None,
        "document_count": 12345.0,
        "data_usage": 5.4e9,
        "physical_partition_size_info": 1e9,
        "physical_partition_count": 3.0,
        "index_usage": 7.2e8,
        "tags": {"Env": "prod", "env": "x"},
    }
    account.update(overrides)
    return account


def test_cosmos_rows_match_powershell():
    accounts = [
        _account(),
        _account(
            name="cosmos2",
            location="East US",
            resource_id="/subscriptions/s/resourceGroups/rg-2/providers/Microsoft.DocumentDB/databaseAccounts/cosmos2",
            kind="MongoDB",
            instance_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            backup_type="Continuous",
            backup_interval_minutes=None,
            backup_retention_hours=None,
            backup_storage_redundancy=None,
            backup_tier="Continuous7Days",
            minimal_tls_version=None,
            document_count=None,
            data_usage=None,
            physical_partition_size_info=None,
            physical_partition_count=None,
            index_usage=None,
            tags={},
        ),
        _account(
            name="cosmos3",
            location="North Europe",
            resource_id="/subscriptions/s/resourceGroups/rg-3/providers/Microsoft.DocumentDB/databaseAccounts/cosmos3",
            instance_id=None,
            backup_type=None,
            backup_interval_minutes=None,
            backup_retention_hours=None,
            backup_storage_redundancy=None,
            minimal_tls_version="Tls",
            document_count=1.2345678901234568e17,
            data_usage=0.0,
            physical_partition_size_info=None,
            physical_partition_count=None,
            index_usage=None,
            tags={"owner": "me"},
        ),
    ]
    lines = build_csv_files(_result(cosmos=accounts), "S")["azure_cosmos_db-S.csv"].splitlines()
    assert lines[0].split(",")[:5] == [f'"{c}"' for c in csv_export._COSMOS_COLUMNS[:5]]
    assert lines[1:] == [
        '"Sub One",,"cosmos1","West US 2","/subscriptions/s/resourceGroups/rg-1/providers/Microsoft.DocumentDB/databaseAccounts/cosmos1","GlobalDocumentDB","11111111-2222-3333-4444-555555555555","240","8","Periodic","Geo",,"Tls12",,"12345","5400000000","1000000000","3","720000000","prod","-","-"',
        '"Sub One",,"cosmos2","East US","/subscriptions/s/resourceGroups/rg-2/providers/Microsoft.DocumentDB/databaseAccounts/cosmos2","MongoDB","aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",,,"Continuous",,"Continuous7Days",,,,,,,,"-","-","-"',
        '"Sub One",,"cosmos3","North Europe","/subscriptions/s/resourceGroups/rg-3/providers/Microsoft.DocumentDB/databaseAccounts/cosmos3","GlobalDocumentDB",,,,,,,"Tls",,"1.2345678901234568E+17","0",,,,"-","me","-"',
    ]


def test_cosmos_offer_type_is_written_when_collected():
    (row,) = _parse(
        build_csv_files(_result(cosmos=[_account(offer_type="Standard")]), "S")[
            "azure_cosmos_db-S.csv"
        ]
    )[1:]
    assert row[csv_export._COSMOS_COLUMNS.index("NameDatabaseAccountOfferType")] == "Standard"


# ── collection ────────────────────────────────────────────────────────────────


def _resource(name, rtype, location, properties, tags=None, kind=None):
    return NS(
        id=f"/subscriptions/{_SUB}/resourceGroups/rg-{name}/providers/{rtype}/{name}",
        name=name,
        location=location,
        kind=kind,
        tags=tags or {},
        properties=properties,
    )


def _arm(listed, full):
    """A resource client whose list returns ``listed`` and whose get returns ``full`` by id."""
    client = MagicMock()
    client.resources.list.return_value = iter(listed)
    client.resources.get_by_id.side_effect = lambda rid, api: full[rid]
    return client


def _aks_collector(client, regions=None):
    with patch.object(aks_cosmos, "ResourceManagementClient", return_value=client):
        return AksCollector(_SUB, MagicMock(), regions)


def _cosmos_collector(client, monitor=None, regions=None, collect_capacity=True):
    with (
        patch.object(aks_cosmos, "ResourceManagementClient", return_value=client),
        patch.object(aks_cosmos, "MonitorManagementClient", return_value=monitor or MagicMock()),
    ):
        return CosmosCollector(_SUB, MagicMock(), regions, collect_capacity=collect_capacity)


_AKS_PROPS = {
    "kubernetesVersion": "1.29.4",
    "provisioningState": "Succeeded",
    "powerState": {"code": "Running"},
    "dnsPrefix": "aks1-dns",
    "fqdn": "aks1-dns.hcp.westus2.azmk8s.io",
    "nodeResourceGroup": "MC_rg-1_aks1_westus2",
    "agentPoolProfiles": [
        {
            "name": "system",
            "vmSize": "Standard_D4s_v3",
            "count": 3,
            "maxCount": 10,
            "osDiskSizeGB": 128,
        },
        {"name": "user", "vmSize": "Standard_E8s_v5", "count": 5},
    ],
}


def test_aks_clusters_are_read_as_arm_json():
    stub = _resource("aks1", AKS_RESOURCE_TYPE, "westus2", None)
    full = _resource("aks1", AKS_RESOURCE_TYPE, "westus2", _AKS_PROPS, tags={"Env": "prod"})
    client = _arm([stub], {stub.id: full})
    inventory = _aks_collector(client).collect()

    (cluster,) = inventory.clusters
    assert (cluster.name, cluster.resource_group, cluster.location) == (
        "aks1",
        "rg-aks1",
        "westus2",
    )
    assert (cluster.kubernetes_version, cluster.power_state, cluster.fqdn) == (
        "1.29.4",
        "Running",
        "aks1-dns.hcp.westus2.azmk8s.io",
    )
    assert cluster.node_pools == [
        AksNodePool("system", "Standard_D4s_v3", 3, 10, 128),
        AksNodePool("user", "Standard_E8s_v5", 5, None, None),
    ]
    assert cluster.tags == {"Env": "prod"}
    assert (inventory.total_clusters, inventory.total_nodes) == (1, 8)
    client.resources.list.assert_called_once_with(filter=f"resourceType eq '{AKS_RESOURCE_TYPE}'")
    client.resources.get_by_id.assert_called_once_with(stub.id, AKS_API_VERSION)


def test_cluster_without_properties_gets_empty_fields_not_an_error():
    stub = _resource("aks1", AKS_RESOURCE_TYPE, "westus2", None)
    full = _resource("aks1", AKS_RESOURCE_TYPE, "westus2", None)
    (cluster,) = _aks_collector(_arm([stub], {stub.id: full})).collect().clusters
    assert cluster.node_pools == [] and cluster.power_state is None


def test_a_failed_list_or_get_is_survived():
    client = MagicMock()
    client.resources.list.side_effect = HttpResponseError(message="denied")
    assert _aks_collector(client).collect().clusters == []

    ok = _resource("ok", AKS_RESOURCE_TYPE, "westus2", _AKS_PROPS)
    bad = _resource("bad", AKS_RESOURCE_TYPE, "westus2", None)
    client = MagicMock()
    client.resources.list.return_value = iter([bad, ok])
    client.resources.get_by_id.side_effect = lambda rid, api: (
        ok if rid == ok.id else (_ for _ in ()).throw(RuntimeError("boom"))
    )
    assert [c.name for c in _aks_collector(client).collect().clusters] == ["ok"]


def test_regions_filter_ignores_spaces_and_case():
    west = _resource("a", COSMOS_RESOURCE_TYPE, "West US 2", {})
    east = _resource("b", COSMOS_RESOURCE_TYPE, "East US", {})
    client = _arm([west, east], {west.id: west, east.id: east})
    inventory = _cosmos_collector(client, regions=["westus2"]).collect()
    assert [a.name for a in inventory.accounts] == ["a"]


def _metric(value):
    return NS(value=[NS(timeseries=[NS(data=[NS(maximum=None), NS(maximum=value)])])])


def test_cosmos_account_is_read_as_arm_json_with_metrics():
    props = {
        "instanceId": "inst",
        "minimalTlsVersion": "Tls12",
        "databaseAccountOfferType": "Standard",
        "backupPolicy": {
            "type": "Periodic",
            "periodicModeProperties": {
                "backupIntervalInMinutes": 240,
                "backupRetentionIntervalInHours": 8,
                "backupStorageRedundancy": "Geo",
            },
        },
    }
    stub = _resource("c1", COSMOS_RESOURCE_TYPE, "West US 2", None)
    full = _resource(
        "c1", COSMOS_RESOURCE_TYPE, "West US 2", props, tags={"Env": "p"}, kind="GlobalDocumentDB"
    )
    values = {
        "DocumentCount": 12.0,
        "DataUsage": 34.0,
        "PhysicalPartitionSizeInfo": 5.0,
        "PhysicalPartitionCount": 2.0,
        "IndexUsage": 6.0,
    }
    monitor = MagicMock()
    monitor.metrics.list.side_effect = lambda **kw: _metric(values[kw["metricnames"]])
    client = _arm([stub], {stub.id: full})
    inventory = _cosmos_collector(client, monitor).collect()

    (account,) = inventory.accounts
    assert (account.location, account.kind, account.instance_id) == (
        "West US 2",
        "GlobalDocumentDB",
        "inst",
    )
    assert (
        account.backup_type,
        account.backup_interval_minutes,
        account.backup_retention_hours,
    ) == ("Periodic", 240, 8)
    assert (account.backup_storage_redundancy, account.backup_tier) == ("Geo", None)
    assert (account.minimal_tls_version, account.offer_type) == ("Tls12", "Standard")
    assert (account.document_count, account.data_usage, account.index_usage) == (12.0, 34.0, 6.0)
    assert (account.physical_partition_size_info, account.physical_partition_count) == (5.0, 2.0)
    assert inventory.total_accounts == 1
    assert full.id in {c.kwargs["resource_uri"] for c in monitor.metrics.list.call_args_list}
    assert {c.kwargs["aggregation"] for c in monitor.metrics.list.call_args_list} == {"Maximum"}
    assert {c.kwargs["metricnamespace"] for c in monitor.metrics.list.call_args_list} == {
        "Microsoft.DocumentDB/databaseAccounts"
    }
    client.resources.list.assert_called_once_with(
        filter=f"resourceType eq '{COSMOS_RESOURCE_TYPE}'"
    )
    client.resources.get_by_id.assert_called_once_with(stub.id, COSMOS_API_VERSION)


@pytest.mark.parametrize(
    "policy,expected",
    [
        (
            {"type": "Continuous", "continuousModeProperties": {"tier": "Continuous7Days"}},
            ("Continuous", None, None, None, "Continuous7Days"),
        ),
        (
            {"type": "Periodic", "periodicModeProperties": {"backupIntervalInMinutes": 60}},
            ("Periodic", 60, None, None, None),
        ),
        ({"type": "Other"}, (None, None, None, None, None)),
        (None, (None, None, None, None, None)),
    ],
)
def test_backup_policy_fields_follow_the_mode(policy, expected):
    props = {"backupPolicy": policy} if policy is not None else {}
    stub = _resource("c1", COSMOS_RESOURCE_TYPE, "eastus", None)
    full = _resource("c1", COSMOS_RESOURCE_TYPE, "eastus", props)
    (account,) = (
        _cosmos_collector(_arm([stub], {stub.id: full}), collect_capacity=False).collect().accounts
    )
    assert (
        account.backup_type,
        account.backup_interval_minutes,
        account.backup_retention_hours,
        account.backup_storage_redundancy,
        account.backup_tier,
    ) == expected


def test_metrics_are_skipped_when_capacity_collection_is_off():
    stub = _resource("c1", COSMOS_RESOURCE_TYPE, "eastus", None)
    full = _resource("c1", COSMOS_RESOURCE_TYPE, "eastus", {})
    monitor = MagicMock()
    (account,) = (
        _cosmos_collector(_arm([stub], {stub.id: full}), monitor, collect_capacity=False)
        .collect()
        .accounts
    )
    assert account.document_count is None and account.index_usage is None
    monitor.metrics.list.assert_not_called()


def test_unavailable_metrics_are_none():
    stub = _resource("c1", COSMOS_RESOURCE_TYPE, "eastus", None)
    full = _resource("c1", COSMOS_RESOURCE_TYPE, "eastus", {})
    monitor = MagicMock()
    monitor.metrics.list.side_effect = HttpResponseError(message="no metric")
    (account,) = _cosmos_collector(_arm([stub], {stub.id: full}), monitor).collect().accounts
    assert account.document_count is None


# ── the run ───────────────────────────────────────────────────────────────────


def test_mock_run_writes_empty_aks_and_cosmos_files_and_json_keys(monkeypatch, tmp_path):
    import json
    import sys
    import zipfile

    import main

    monkeypatch.setattr(sys, "argv", ["main.py", "--mock", "--output", str(tmp_path)])
    main.main()
    (archive,) = tmp_path.glob("azure_sizing_results_*.zip")
    zf = zipfile.ZipFile(archive)
    names = zf.namelist()
    assert any(n.startswith("azure_aks_info-") for n in names)
    assert any(n.startswith("azure_cosmos_db-") for n in names)
    data = json.loads(zf.read(next(n for n in names if n.endswith(".json"))))
    assert data["aks"] == [] and data["cosmos_db"] == []
    assert (data["total_aks_clusters"], data["total_aks_nodes"], data["total_cosmos_accounts"]) == (
        0,
        0,
        0,
    )
