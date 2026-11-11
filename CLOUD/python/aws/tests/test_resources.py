"""Tests for the VPC, load balancer, EKS, KMS, Route53, IAM and Redshift collectors."""

from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from collectors import DenialTracker
from collectors.eks import fetch_eks
from collectors.kms import fetch_kms_inventory
from collectors.network import fetch_load_balancers, fetch_vpcs
from collectors.redshift import fetch_redshift
from collectors.route53 import fetch_iam_summary, fetch_route53_zones

ACCT = "123456789012"
ALIAS = "acct"
REGION = "us-west-2"


def _paginated(pages_by_operation=None, errors=None):
    pages_by_operation, errors = pages_by_operation or {}, errors or {}

    def get_paginator(operation):
        paginator = MagicMock()
        if operation in errors:
            paginator.paginate.side_effect = errors[operation]
        else:
            paginator.paginate.return_value = pages_by_operation.get(operation, [])
        return paginator

    client = MagicMock()
    client.get_paginator.side_effect = get_paginator
    return client


def _session(**clients):
    """Session whose client(service) returns the matching mock."""
    session = MagicMock()
    session.client.side_effect = lambda service, **kw: clients[service]
    return session


# ── VPC ───────────────────────────────────────────────────────────────────────


def test_vpcs_are_collected_with_their_tags():
    ec2 = _paginated(
        {
            "describe_vpcs": [
                {
                    "Vpcs": [
                        {
                            "VpcId": "vpc-1",
                            "OwnerId": ACCT,
                            "CidrBlock": "10.0.0.0/16",
                            "State": "available",
                            "IsDefault": True,
                            "Tags": [
                                {"Key": "Name", "Value": "main"},
                                {"Key": "map-migrated", "Value": "x"},
                            ],
                        },
                        {"VpcId": "vpc-2", "CidrBlock": "10.1.0.0/16", "State": "available"},
                    ]
                }
            ]
        }
    )
    vpcs = fetch_vpcs(_session(ec2=ec2), REGION, ACCT, ALIAS)
    assert [v.vpc_id for v in vpcs] == ["vpc-1", "vpc-2"]
    assert vpcs[0].is_default is True and vpcs[1].is_default is False
    assert vpcs[0].tags == {"Name": "main", "map-migrated": "x"} and vpcs[1].tags == {}


def test_vpc_failure_is_recorded():
    tracker = DenialTracker()
    ec2 = _paginated(errors={"describe_vpcs": Exception("AccessDenied: DescribeVpcs")})
    assert fetch_vpcs(_session(ec2=ec2), REGION, ACCT, ALIAS, tracker) == []
    [err] = tracker.permission_errors()
    assert err["service"] == "network" and "1 access denied" in err["error"]


# ── load balancers ────────────────────────────────────────────────────────────


def _elb():
    elb = _paginated(
        {
            "describe_load_balancers": [
                {
                    "LoadBalancerDescriptions": [
                        {
                            "LoadBalancerName": "classic-1",
                            "Scheme": "internet-facing",
                            "VPCId": "vpc-1",
                            "DNSName": "c.example",
                        }
                    ]
                }
            ]
        }
    )
    elb.describe_tags.return_value = {
        "TagDescriptions": [
            {"LoadBalancerName": "classic-1", "Tags": [{"Key": "env", "Value": "prod"}]}
        ]
    }
    return elb


def _elbv2(count=1):
    arns = [
        f"arn:aws:elasticloadbalancing:{REGION}:{ACCT}:loadbalancer/app/lb-{i}/abc"
        for i in range(count)
    ]
    elbv2 = _paginated(
        {
            "describe_load_balancers": [
                {
                    "LoadBalancers": [
                        {
                            "LoadBalancerName": f"lb-{i}",
                            "Type": "application",
                            "Scheme": "internal",
                            "VpcId": "vpc-1",
                            "DNSName": f"lb-{i}.example",
                            "LoadBalancerArn": arn,
                        }
                        for i, arn in enumerate(arns)
                    ]
                }
            ]
        }
    )
    elbv2.describe_tags.side_effect = lambda ResourceArns: {
        "TagDescriptions": [
            {"ResourceArn": a, "Tags": [{"Key": "elbv2.k8s.aws/cluster", "Value": "c"}]}
            for a in ResourceArns
        ]
    }
    return elbv2


def test_classic_then_v2_load_balancers_with_tags():
    lbs = fetch_load_balancers(_session(elb=_elb(), elbv2=_elbv2()), REGION, ACCT, ALIAS)
    assert [(lb.type, lb.name) for lb in lbs] == [("classic", "classic-1"), ("application", "lb-0")]
    assert lbs[0].arn == f"arn:aws:elasticloadbalancing:{REGION}:{ACCT}:loadbalancer/classic-1"
    assert lbs[0].tags == {"env": "prod"} and lbs[1].tags == {"elbv2.k8s.aws/cluster": "c"}
    assert (lbs[0].scheme, lbs[0].vpc_id, lbs[0].dns_name) == (
        "internet-facing",
        "vpc-1",
        "c.example",
    )


def test_v2_tags_are_fetched_in_batches_of_twenty():
    elbv2 = _elbv2(45)
    lbs = fetch_load_balancers(_session(elb=_paginated(), elbv2=elbv2), REGION, ACCT, ALIAS)
    assert len(lbs) == 45 and all(lb.tags for lb in lbs)
    assert [len(c.kwargs["ResourceArns"]) for c in elbv2.describe_tags.call_args_list] == [
        20,
        20,
        5,
    ]


def test_load_balancer_tag_failure_keeps_the_load_balancer_and_is_recorded():
    tracker = DenialTracker()
    elb = _elb()
    elb.describe_tags.side_effect = Exception("AccessDenied: DescribeTags")
    lbs = fetch_load_balancers(_session(elb=elb, elbv2=_elbv2()), REGION, ACCT, ALIAS, tracker)
    assert [lb.name for lb in lbs] == ["classic-1", "lb-0"] and lbs[0].tags == {}
    assert [e["service"] for e in tracker.permission_errors()] == ["network"]


# ── EKS ───────────────────────────────────────────────────────────────────────


def _eks(clusters=("c1",), groups=None, fail=None):
    groups = groups or {"c1": ["ng-a", "ng-b"]}
    client = _paginated({"list_clusters": [{"clusters": list(clusters)}]}, errors=fail or {})
    client.get_paginator.side_effect = lambda op: _ng_paginator(op, clusters, groups, client)
    client.describe_cluster.side_effect = lambda name: {
        "cluster": {
            "name": name,
            "version": "1.30",
            "platformVersion": "eks.5",
            "status": "ACTIVE",
            "arn": f"arn:aws:eks:{REGION}:{ACCT}:cluster/{name}",
            "roleArn": "arn:aws:iam::1:role/r",
            "tags": {"Project": "p", "Name": name},
        }
    }
    client.describe_nodegroup.side_effect = lambda clusterName, nodegroupName: {
        "nodegroup": {
            "nodegroupName": nodegroupName,
            "clusterName": clusterName,
            "diskSize": 20,
            "capacityType": "ON_DEMAND",
            "amiType": "AL2_x86_64",
            "nodegroupArn": "arn:ng",
            "nodeRole": "arn:role",
            "status": "ACTIVE",
            "releaseVersion": "1.30.0-20240101",
            "version": "1.30",
            "tags": {"Project": "p"},
        }
    }
    return client


def _ng_paginator(operation, clusters, groups, client):
    paginator = MagicMock()
    if operation == "list_clusters":
        paginator.paginate.return_value = [{"clusters": list(clusters)}]
    else:
        paginator.paginate.side_effect = lambda clusterName: [
            {"nodegroups": groups.get(clusterName, [])}
        ]
    return paginator


def test_eks_clusters_and_their_node_groups():
    clusters, groups = fetch_eks(_session(eks=_eks()), REGION, ACCT, ALIAS)
    assert [(c.name, c.version, c.platform_version, c.status) for c in clusters] == [
        ("c1", "1.30", "eks.5", "ACTIVE")
    ]
    assert clusters[0].tags == {"Project": "p", "Name": "c1"} and clusters[0].role_arn.startswith(
        "arn:"
    )
    assert [(g.nodegroup_name, g.cluster_name, g.disk_size, g.capacity_type) for g in groups] == [
        ("ng-a", "c1", 20, "ON_DEMAND"),
        ("ng-b", "c1", 20, "ON_DEMAND"),
    ]
    assert groups[0].region == REGION and groups[0].tags == {"Project": "p"}


def test_eks_describe_failure_skips_that_cluster_only():
    tracker = DenialTracker()
    client = _eks(clusters=("bad", "good"), groups={"good": ["ng"]})
    real = client.describe_cluster.side_effect

    def describe(name):
        if name == "bad":
            raise Exception("AccessDenied: DescribeCluster")
        return real(name)

    client.describe_cluster.side_effect = describe
    clusters, groups = fetch_eks(_session(eks=client), REGION, ACCT, ALIAS, tracker)
    assert [c.name for c in clusters] == ["good"] and len(groups) == 1
    assert [e["service"] for e in tracker.permission_errors()] == ["eks"]


# ── KMS ───────────────────────────────────────────────────────────────────────


def _kms(keys, aliases, meta_error=None):
    client = _paginated()

    def get_paginator(operation):
        paginator = MagicMock()
        if operation == "list_keys":
            paginator.paginate.return_value = [{"Keys": [{"KeyId": k} for k in keys]}]
        else:
            paginator.paginate.side_effect = lambda KeyId: [
                {"Aliases": [{"AliasName": a} for a in aliases.get(KeyId, [])]}
            ]
        return paginator

    client.get_paginator.side_effect = get_paginator

    def describe(KeyId):
        if meta_error and KeyId == meta_error:
            raise Exception("AccessDenied: DescribeKey")
        return {
            "KeyMetadata": {
                "KeyId": KeyId,
                "Arn": f"arn:aws:kms:{REGION}:{ACCT}:key/{KeyId}",
                "KeyManager": "AWS" if KeyId == "aws-key" else "CUSTOMER",
                "KeyState": "Enabled",
                "CreationDate": datetime(2026, 8, 13, 6, 40, 7, 941000, tzinfo=timezone.utc),
            }
        }

    client.describe_key.side_effect = describe
    return client


def test_kms_rows_have_aliases_joined_and_a_seven_digit_creation_date():
    client = _kms(
        ["aws-key", "mine"], {"aws-key": ["alias/aws/rds"], "mine": ["alias/a", "alias/b"]}
    )
    count, keys = fetch_kms_inventory(_session(kms=client), REGION, ACCT, ALIAS)
    assert count.key_count == 2 and count.region == REGION
    assert [(k.key_id, k.alias, k.key_manager) for k in keys] == [
        ("aws-key", "alias/aws/rds", "AWS"),
        ("mine", "alias/a; alias/b", "CUSTOMER"),
    ]
    assert keys[0].creation_date == "2026-08-13T06:40:07.9409999Z"
    assert keys[0].arn.endswith("key/aws-key") and keys[0].key_state == "Enabled"


def test_kms_key_without_alias_has_an_empty_alias_and_an_undescribable_key_is_skipped():
    tracker = DenialTracker()
    client = _kms(["a", "b"], {}, meta_error="b")
    count, keys = fetch_kms_inventory(_session(kms=client), REGION, ACCT, ALIAS, tracker)
    assert count.key_count == 2  # still listed
    assert [(k.key_id, k.alias) for k in keys] == [("a", "")]
    assert [e["service"] for e in tracker.permission_errors()] == ["kms"]


def test_kms_listing_failure_gives_zero_and_is_recorded():
    tracker = DenialTracker()
    client = _paginated(errors={"list_keys": Exception("AccessDenied: ListKeys")})
    count, keys = fetch_kms_inventory(_session(kms=client), REGION, ACCT, ALIAS, tracker)
    assert (count.key_count, keys) == (0, [])
    assert [e["service"] for e in tracker.permission_errors()] == ["kms"]


# ── Route53 and IAM ───────────────────────────────────────────────────────────


def test_route53_zones():
    client = _paginated(
        {
            "list_hosted_zones": [
                {
                    "HostedZones": [
                        {
                            "Id": "/hostedzone/Z1",
                            "Name": "a.example.",
                            "Config": {"PrivateZone": False},
                            "ResourceRecordSetCount": 4,
                        },
                        {
                            "Id": "/hostedzone/Z2",
                            "Name": "b.example.",
                            "Config": {"PrivateZone": True},
                            "ResourceRecordSetCount": 2,
                        },
                    ]
                }
            ]
        }
    )
    zones = fetch_route53_zones(_session(route53=client), ACCT, ALIAS)
    assert [(z.hosted_zone_id, z.private_zone, z.resource_record_set_count) for z in zones] == [
        ("/hostedzone/Z1", False, 4),
        ("/hostedzone/Z2", True, 2),
    ]


def _iam(users=None, roles=None, policies=None, errors=None):
    return _paginated(
        {
            "list_users": [{"Users": users or []}],
            "list_roles": [{"Roles": roles or []}],
            "list_policies": [{"Policies": policies or []}],
        },
        errors,
    )


def test_iam_counts_roles_users_and_customer_managed_policies():
    iam = _iam(users=[{}] * 3, roles=[{}] * 5, policies=[{}] * 2)
    summary = fetch_iam_summary(_session(iam=iam), ACCT, ALIAS)
    assert (summary.users, summary.roles, summary.customer_managed_policies) == (3, 5, 2)


def test_iam_lists_only_customer_managed_policies():
    seen = {}
    iam = _iam()
    real = iam.get_paginator.side_effect

    def get_paginator(operation):
        paginator = real(operation)
        original = paginator.paginate.return_value
        paginator.paginate.side_effect = (
            lambda **kwargs: seen.setdefault(operation, kwargs) and original
        )
        return paginator

    iam.get_paginator.side_effect = get_paginator
    fetch_iam_summary(_session(iam=iam), ACCT, ALIAS)
    assert seen["list_policies"] == {"Scope": "Local"}


def test_iam_a_single_failure_counts_zero_but_all_failures_give_no_row():
    denied = Exception("AccessDenied: iam")
    partial = fetch_iam_summary(
        _session(iam=_iam(roles=[{}], errors={"list_users": denied})), ACCT, ALIAS
    )
    assert (partial.users, partial.roles) == (0, 1)
    tracker = DenialTracker()
    iam = _iam(errors={"list_users": denied, "list_roles": denied, "list_policies": denied})
    assert fetch_iam_summary(_session(iam=iam), ACCT, ALIAS, tracker) is None
    assert {e["service"] for e in tracker.permission_errors()} == {"iam"}


# ── Redshift ──────────────────────────────────────────────────────────────────


def test_redshift_clusters():
    client = _paginated(
        {
            "describe_clusters": [
                {
                    "Clusters": [
                        {
                            "ClusterIdentifier": "rs-1",
                            "NodeType": "ra3.xlplus",
                            "NumberOfNodes": 2,
                            "ClusterStatus": "available",
                            "MasterUsername": "admin",
                            "DBName": "dev",
                            "ClusterCreateTime": datetime(2026, 3, 4, 5, 6, 7, tzinfo=timezone.utc),
                            "AutomatedSnapshotRetentionPeriod": 1,
                            "ManualSnapshotRetentionPeriod": -1,
                        }
                    ]
                }
            ]
        }
    )
    [cluster] = fetch_redshift(_session(redshift=client), REGION, ACCT, ALIAS)
    assert (cluster.cluster_identifier, cluster.node_type, cluster.number_of_nodes) == (
        "rs-1",
        "ra3.xlplus",
        2,
    )
    assert cluster.cluster_create_time == "2026-03-04T05:06:07+00:00"
    assert (
        cluster.automated_snapshot_retention_period,
        cluster.manual_snapshot_retention_period,
    ) == (1, -1)


# ── wiring ────────────────────────────────────────────────────────────────────


def test_iac_is_not_part_of_the_default_services_but_everything_else_is():
    import main

    assert "iac" in main.ALL_SERVICES and "iac" not in main.DEFAULT_SERVICES
    assert {
        "vpc",
        "lb",
        "eks",
        "kms",
        "route53",
        "iam",
        "redshift",
        "snapshots",
    } <= main.DEFAULT_SERVICES


@pytest.mark.parametrize(
    "services, expected",
    [
        ({"vpc"}, {"vpcs"}),
        ({"lb"}, {"load_balancers"}),
        ({"eks"}, {"eks_clusters"}),
        ({"kms"}, {"kms_keys"}),
        ({"redshift"}, {"redshift"}),
    ],
)
def test_region_scan_runs_only_the_selected_resource_collectors(monkeypatch, services, expected):
    import main

    one = MagicMock(name="row")
    monkeypatch.setattr(main, "fetch_vpcs", lambda *a, **k: [one])
    monkeypatch.setattr(main, "fetch_load_balancers", lambda *a, **k: [one])
    monkeypatch.setattr(main, "fetch_eks", lambda *a, **k: ([one], [one]))
    monkeypatch.setattr(main, "fetch_kms_inventory", lambda *a, **k: (MagicMock(), [one]))
    monkeypatch.setattr(main, "fetch_redshift", lambda *a, **k: [one])
    result = main._scan_region(MagicMock(), REGION, ACCT, ALIAS, frozenset(services))
    filled = {
        k for k in ("vpcs", "load_balancers", "eks_clusters", "kms_keys", "redshift") if result[k]
    }
    assert filled == expected


# ── backup, S3 Tables and Glue wiring ─────────────────────────────────────────


def _wired_scan(monkeypatch, services):
    """Run _scan_region with every collector replaced by a recorder; returns (result, calls)."""
    import main
    from collectors.recovery_points import RecoveryPointResult
    from models.discovery import RecoveryPointAggregate

    calls: list[str] = []

    def recorder(name, value=None):
        def fn(*args, **kwargs):
            calls.append(name)
            return [] if value is None else value

        return fn

    result = RecoveryPointResult()
    result.rows = ["row"]
    result.aggregates = [RecoveryPointAggregate(ACCT, REGION, "arn:x", "EC2", "x")]
    result.truncated = True
    for name in (
        "fetch_instances",
        "fetch_unattached_volumes",
        "fetch_rds",
        "fetch_dynamodb",
        "fetch_efs",
        "fetch_fsx",
        "fetch_fsx_volumes",
        "fetch_secrets",
        "fetch_sqs",
        "fetch_backup_plans",
        "fetch_backup_vaults",
        "fetch_cfn_stacks",
        "fetch_vpcs",
        "fetch_load_balancers",
        "fetch_redshift",
        "fetch_s3",
        "fetch_s3_tables",
        "fetch_glue_iceberg",
        "fetch_rds_snapshots",
        "fetch_ebs_and_ami",
        "fetch_fsx_backups",
        "fetch_dynamodb_backups",
        "fetch_redshift_snapshots",
    ):
        if hasattr(main, name):
            if name in ("fetch_rds_snapshots", "fetch_ebs_and_ami"):
                monkeypatch.setattr(main, name, recorder(name, ([], [])))
            else:
                monkeypatch.setattr(main, name, recorder(name))
    monkeypatch.setattr(main, "fetch_protected_arns", lambda *a, **k: set())
    monkeypatch.setattr(main, "fetch_eks", lambda *a, **k: ([], []))
    monkeypatch.setattr(main, "fetch_kms_inventory", lambda *a, **k: (MagicMock(), []))
    monkeypatch.setattr(main, "list_plan_names", lambda *a, **k: calls.append("plan_names") or {})
    monkeypatch.setattr(
        main, "fetch_recovery_points", lambda *a, **k: calls.append("recovery_points") or result
    )
    return main._scan_region(MagicMock(), REGION, ACCT, ALIAS, frozenset(services)), calls


def test_recovery_points_always_run_with_backup_capacity_and_flag_truncated_regions(monkeypatch):
    scan, calls = _wired_scan(monkeypatch, {"snapshots"})
    assert "recovery_points" in calls and "plan_names" in calls
    assert scan["recovery_points"] == ["row"] and len(scan["recovery_aggregates"]) == 1
    assert scan["truncated_backup_regions"] == [REGION]
    assert not {"fetch_fsx_backups", "fetch_dynamodb_backups", "fetch_redshift_snapshots"} & set(
        calls
    )


def test_each_native_backup_source_follows_its_own_service(monkeypatch):
    _, calls = _wired_scan(monkeypatch, {"snapshots", "fsx", "dynamodb", "redshift"})
    assert {"fetch_fsx_backups", "fetch_dynamodb_backups", "fetch_redshift_snapshots"} <= set(calls)
    _, calls = _wired_scan(monkeypatch, {"snapshots", "fsx"})
    assert "fetch_fsx_backups" in calls
    assert not {"fetch_dynamodb_backups", "fetch_redshift_snapshots"} & set(calls)


def test_no_recovery_points_without_backup_capacity(monkeypatch):
    scan, calls = _wired_scan(monkeypatch, {"fsx", "dynamodb"})
    assert "recovery_points" not in calls and scan["recovery_points"] == []
    assert not {"fetch_fsx_backups", "fetch_dynamodb_backups"} & set(calls)


def test_plan_names_come_from_the_collected_plans_when_backup_is_selected(monkeypatch):
    _, calls = _wired_scan(monkeypatch, {"snapshots", "backup"})
    assert "plan_names" not in calls and "fetch_backup_plans" in calls


def test_s3_tables_and_glue_follow_their_services(monkeypatch):
    _, calls = _wired_scan(monkeypatch, {"s3tables"})
    assert "fetch_s3_tables" in calls and "fetch_glue_iceberg" not in calls
    _, calls = _wired_scan(monkeypatch, {"glue"})
    assert "fetch_glue_iceberg" in calls and "fetch_s3_tables" not in calls


def test_default_services_include_the_new_ones_and_iac_stays_opt_in():
    import main

    assert {"s3tables", "glue", "snapshots"} <= main.DEFAULT_SERVICES
    assert "iac" not in main.DEFAULT_SERVICES


def test_kms_creation_date_truncates_the_exact_double_like_powershell():
    from collectors.kms import _iso_ticks

    # Both pairs come from a real PowerShell run: .941 is written .9409999, .743 stays .7430000.
    assert _iso_ticks(datetime(2026, 8, 13, 6, 40, 7, 941000, tzinfo=timezone.utc)) == (
        "2026-08-13T06:40:07.9409999Z"
    )
    assert _iso_ticks(datetime(2025, 11, 24, 5, 37, 24, 743000, tzinfo=timezone.utc)) == (
        "2025-11-24T05:37:24.7430000Z"
    )
    assert _iso_ticks(datetime(2025, 11, 24, 5, 37, 24, tzinfo=timezone.utc)) == (
        "2025-11-24T05:37:24.0000000Z"
    )
    assert _iso_ticks(None) == ""
