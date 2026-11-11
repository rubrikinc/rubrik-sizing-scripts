"""Tests for collectors/rds.py."""

from unittest.mock import MagicMock

import pytest
from collectors.rds import fetch_rds

ACCT = "123456789012"
ALIAS = "test-account"
REGION = "us-east-1"


def _mock_session(client):
    s = MagicMock()
    s.client.return_value = client
    return s


def _make_client(db_pages, tags_resp=None):
    pag = MagicMock()
    pag.paginate.return_value = db_pages
    client = MagicMock()
    client.get_paginator.return_value = pag
    if tags_resp is not None:
        client.list_tags_for_resource.return_value = tags_resp
    return client


def _db(
    db_id,
    db_arn=None,
    engine="mysql",
    storage_type="gp2",
    size_gib=100,
    db_name="mydb",
    instance_class="db.t3.medium",
    multi_az=False,
):
    return {
        "DBInstanceIdentifier": db_id,
        "DBInstanceArn": db_arn or f"arn:aws:rds:{REGION}:{ACCT}:db:{db_id}",
        "DBName": db_name,
        "AllocatedStorage": size_gib,
        "Engine": engine,
        "DBInstanceClass": instance_class,
        "MultiAZ": multi_az,
        "StorageType": storage_type,
    }


class TestFetchRDS:
    def test_basic_instance_returned(self):
        db = _db("mydb-1")
        client = _make_client(
            db_pages=[{"DBInstances": [db]}],
            tags_resp={"TagList": [{"Key": "Env", "Value": "prod"}]},
        )
        result = fetch_rds(_mock_session(client), REGION, ACCT, ALIAS, set())
        assert len(result) == 1
        r = result[0]
        assert r.db_instance_identifier == "mydb-1"
        assert r.engine == "mysql"
        assert r.size_gib == 100
        assert r.size_tb == pytest.approx(100 / 1024, abs=1e-6)
        assert r.size_bytes_derived == 100 * 1024**3
        assert r.tags == {"Env": "prod"}

    def test_backup_protection_marked(self):
        db_arn = f"arn:aws:rds:{REGION}:{ACCT}:db:mydb-1"
        db = _db("mydb-1", db_arn=db_arn)
        client = _make_client(
            db_pages=[{"DBInstances": [db]}],
            tags_resp={"TagList": []},
        )
        result = fetch_rds(_mock_session(client), REGION, ACCT, ALIAS, {db_arn})
        assert result[0].in_backup_plan is True
        assert result[0].backup_plans == ["AWS Backup"]

    def test_unprotected_instance(self):
        db = _db("mydb-2")
        client = _make_client(
            db_pages=[{"DBInstances": [db]}],
            tags_resp={"TagList": []},
        )
        result = fetch_rds(_mock_session(client), REGION, ACCT, ALIAS, set())
        assert result[0].in_backup_plan is False
        assert result[0].backup_plans == []

    def test_tag_fetch_failure_returns_empty_tags(self):
        db = _db("mydb-3")
        client = _make_client(db_pages=[{"DBInstances": [db]}])
        client.list_tags_for_resource.side_effect = Exception("AccessDenied")
        result = fetch_rds(_mock_session(client), REGION, ACCT, ALIAS, set())
        assert len(result) == 1
        assert result[0].tags == {}

    def test_api_error_returns_empty_list(self):
        client = MagicMock()
        client.get_paginator.side_effect = Exception("AccessDenied")
        result = fetch_rds(_mock_session(client), REGION, ACCT, ALIAS, set())
        assert result == []

    def test_multi_page_results(self):
        db1 = _db("db-1")
        db2 = _db("db-2")
        client = _make_client(
            db_pages=[{"DBInstances": [db1]}, {"DBInstances": [db2]}],
            tags_resp={"TagList": []},
        )
        result = fetch_rds(_mock_session(client), REGION, ACCT, ALIAS, set())
        assert len(result) == 2

    def test_missing_db_name_defaults_empty(self):
        db = _db("mydb-4", db_name=None)
        client = _make_client(
            db_pages=[{"DBInstances": [db]}],
            tags_resp={"TagList": []},
        )
        result = fetch_rds(_mock_session(client), REGION, ACCT, ALIAS, set())
        assert result[0].db_name == ""


# ── Cluster (Aurora) storage via CloudWatch VolumeBytesUsed ──


def _cluster_session(rds_client, cw_client):
    """Session whose .client() dispatches by service name (rds vs cloudwatch)."""
    s = MagicMock()
    s.client.side_effect = lambda svc, **kw: cw_client if svc == "cloudwatch" else rds_client
    return s


def _aurora_db(db_id, cluster_id, engine="aurora-mysql"):
    d = _db(db_id, engine=engine, size_gib=1, instance_class="db.r6g.large")
    d["DBClusterIdentifier"] = cluster_id
    return d


def _cw_with_volume(bytes_used):
    cw = MagicMock()
    cw.get_metric_statistics.return_value = {
        "Datapoints": [{"Timestamp": 1, "Average": bytes_used}]
    }
    return cw


class TestClusterSizing:
    def test_aurora_sized_from_cluster_volume_not_allocated_storage(self):
        # AllocatedStorage=1 (placeholder); CloudWatch reports 500 GiB used.
        db = _aurora_db("aurora-w", "clstr-1")
        rds = _make_client([{"DBInstances": [db]}], tags_resp={"TagList": []})
        cw = _cw_with_volume(500 * 1024**3)
        result = fetch_rds(_cluster_session(rds, cw), REGION, ACCT, ALIAS, set())
        assert result[0].size_gib == 500  # from VolumeBytesUsed, not AllocatedStorage=1
        cw.get_metric_statistics.assert_called_once()
        ns = cw.get_metric_statistics.call_args.kwargs["Namespace"]
        assert ns == "AWS/RDS"

    def test_cluster_volume_counted_once_across_members(self):
        # Two members of the same cluster → volume charged once, replica gets 0.
        w = _aurora_db("aurora-w", "clstr-1")
        r = _aurora_db("aurora-r", "clstr-1")
        rds = _make_client([{"DBInstances": [w, r]}], tags_resp={"TagList": []})
        cw = _cw_with_volume(500 * 1024**3)
        result = fetch_rds(_cluster_session(rds, cw), REGION, ACCT, ALIAS, set())
        sizes = sorted(x.size_gib for x in result)
        assert sizes == [0, 500]
        assert sum(sizes) == 500  # not double-counted
        cw.get_metric_statistics.assert_called_once()  # looked up once per cluster

    def test_falls_back_to_allocated_storage_when_no_metric(self):
        db = _aurora_db("aurora-w", "clstr-1")
        db["AllocatedStorage"] = 123
        rds = _make_client([{"DBInstances": [db]}], tags_resp={"TagList": []})
        cw = MagicMock()
        cw.get_metric_statistics.return_value = {"Datapoints": []}
        result = fetch_rds(_cluster_session(rds, cw), REGION, ACCT, ALIAS, set())
        assert result[0].size_gib == 123

    @pytest.mark.parametrize("engine", ["docdb", "neptune", "DocDB"])
    def test_unsupported_engines_excluded(self, engine):
        db = _aurora_db("x-1", "xclstr", engine=engine)
        keep = _db("pg-1", engine="postgres", size_gib=50)
        rds = _make_client([{"DBInstances": [db, keep]}], tags_resp={"TagList": []})
        cw = MagicMock()
        result = fetch_rds(_cluster_session(rds, cw), REGION, ACCT, ALIAS, set())
        assert [r.db_instance_identifier for r in result] == ["pg-1"]
        cw.get_metric_statistics.assert_not_called()

    def test_standard_rds_never_calls_cloudwatch(self):
        db = _db("pg-1", engine="postgres", size_gib=200)
        rds = _make_client([{"DBInstances": [db]}], tags_resp={"TagList": []})
        cw = MagicMock()
        result = fetch_rds(_cluster_session(rds, cw), REGION, ACCT, ALIAS, set())
        assert result[0].size_gib == 200
        cw.get_metric_statistics.assert_not_called()

    def test_cluster_metric_failure_recorded(self):
        from collectors import DenialTracker

        db = _aurora_db("aurora-w", "clstr-1")
        rds = _make_client([{"DBInstances": [db]}], tags_resp={"TagList": []})
        cw = MagicMock()
        cw.get_metric_statistics.side_effect = Exception("AccessDenied")
        tracker = DenialTracker()
        result = fetch_rds(_cluster_session(rds, cw), REGION, ACCT, ALIAS, set(), tracker)
        assert len(result) == 1
        errs = tracker.permission_errors()
        assert [e["service"] for e in errs] == ["cloudwatch"]

    def test_cluster_no_data_not_recorded(self):
        from collectors import DenialTracker

        db = _aurora_db("aurora-w", "clstr-1")
        rds = _make_client([{"DBInstances": [db]}], tags_resp={"TagList": []})
        cw = MagicMock()
        cw.get_metric_statistics.return_value = {"Datapoints": []}
        tracker = DenialTracker()
        fetch_rds(_cluster_session(rds, cw), REGION, ACCT, ALIAS, set(), tracker)
        assert tracker.permission_errors() == []
