"""EC2 instance and EBS volume collector."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from models.discovery import EC2Instance, EC2Volume

from collectors import BOTO_ADAPTIVE_CFG, DenialTracker, is_scp_denial, record_metric_failures
from collectors.arns import instance_arn, volume_arn
from collectors.exclusion import VolumeExclusionEngine

# Keywords that suggest a volume is archival/log storage and should be
# excluded from Rubrik change-rate sizing to avoid inflating the estimate.
_ARCHIVAL_KEYWORDS = frozenset(
    {
        "log",
        "logs",
        "logging",
        "archive",
        "archival",
        "archived",
        "backup",
        "cold",
        "glacier",
        "temp",
        "tmp",
        "cache",
        "audit",
    }
)


def _tags_to_dict(tag_list: list) -> dict[str, str]:
    return {t["Key"]: t["Value"] for t in (tag_list or [])}


def _name_from_tags(tags: dict[str, str]) -> str:
    return tags.get("Name", "")


def _round_tb(gib: float) -> float:
    return round(gib / 1024, 6)


def _is_archival_volume(name: str, instance_name: str, tags: dict) -> bool:
    """Return True if name/tags suggest log or archival storage."""
    tokens: set[str] = set()
    for text in [name, instance_name] + list(tags.values()):
        for word in str(text).lower().replace("-", " ").replace("_", " ").split():
            tokens.add(word)
    return bool(tokens & _ARCHIVAL_KEYWORDS)


def _enrich_with_change_rates(
    cw_client,
    volumes: list[EC2Volume],
    region: str,
    tracker: "DenialTracker | None" = None,
) -> None:
    """Populate write-rate metrics on each volume in-place.

    Queries 90 days of daily VolumeWriteBytes via get_metric_data (free EBS
    built-in metrics, up to 500 volumes per API call). Sets:
      - avg_daily_write_gib: rolling 90-day average
      - change_rate_pct: avg daily write as % of volume size
      - monthly_write_trend_gib: [month1_avg, month2_avg, month3_avg] oldest→newest
      - write_growth_pct: MoM growth from month2→month3 annualised (% per year)

    Volumes that look archival are flagged and excluded from Rubrik sizing.
    Failures are non-fatal — the fields stay at their zero defaults — and are recorded
    in the tracker so the gap shows in the scan errors.
    """
    if not volumes:
        return

    end = datetime.now(timezone.utc)
    start = end - timedelta(days=90)

    # Build CloudWatch queries — one per volume.
    # get_metric_data IDs must match [a-zA-Z][a-zA-Z0-9_]*, so we prefix
    # with "v" and swap hyphens for underscores.
    queries = []
    for vol in volumes:
        safe_id = "v" + vol.volume_id.replace("-", "_")
        queries.append(
            {
                "Id": safe_id,
                "MetricStat": {
                    "Metric": {
                        "Namespace": "AWS/EBS",
                        "MetricName": "VolumeWriteBytes",
                        "Dimensions": [{"Name": "VolumeId", "Value": vol.volume_id}],
                    },
                    "Period": 86400,  # daily buckets — ~90 data points per volume
                    "Stat": "Sum",
                },
                "ReturnData": True,
            }
        )

    # Build a lookup by volume_id → (volume, sorted daily timestamps+values).
    vol_map = {vol.volume_id: vol for vol in volumes}
    # Accumulate raw daily (timestamp, bytes) pairs before summarising.
    raw: dict[str, list[tuple[datetime, float]]] = {vol.volume_id: [] for vol in volumes}
    metric_errors: list[Exception] = []

    # Batch in groups of 500 (API limit).
    for i in range(0, len(queries), 500):
        batch = queries[i : i + 500]
        kwargs: dict = {"MetricDataQueries": batch, "StartTime": start, "EndTime": end}
        try:
            while True:
                resp = cw_client.get_metric_data(**kwargs)
                for result in resp.get("MetricDataResults", []):
                    vol_id = result["Id"][1:].replace("_", "-")
                    if vol_id not in raw:
                        continue
                    timestamps = result.get("Timestamps", [])
                    values = result.get("Values", [])
                    for ts, val in zip(timestamps, values):
                        raw[vol_id].append((ts, float(val)))

                next_token = resp.get("NextToken")
                if not next_token:
                    break
                kwargs["NextToken"] = next_token
        except Exception as exc:
            metric_errors.append(exc)

    record_metric_failures(tracker, region, "EBS change-rate CloudWatch metrics", metric_errors)

    # Summarise raw daily data into per-volume metrics.
    cutoffs = [end - timedelta(days=60), end - timedelta(days=30)]  # month boundaries
    for vol_id, points in raw.items():
        vol = vol_map.get(vol_id)
        if vol is None or not points:
            continue

        points_sorted = sorted(points, key=lambda p: p[0])
        all_bytes = [b for _, b in points_sorted]

        # 90-day average → avg_daily_write_gib
        avg_daily_bytes = sum(all_bytes) / len(all_bytes)
        avg_daily_gib = round(avg_daily_bytes / (1024**3), 4)
        vol.avg_daily_write_gib = avg_daily_gib
        if vol.size_gib and vol.size_gib > 0:
            vol.change_rate_pct = round(avg_daily_gib / vol.size_gib * 100, 2)

        # Split into 3 monthly buckets (oldest 30d, middle 30d, newest 30d).
        buckets: list[list[float]] = [[], [], []]
        for ts, b in points_sorted:
            if ts < cutoffs[0]:
                buckets[0].append(b)
            elif ts < cutoffs[1]:
                buckets[1].append(b)
            else:
                buckets[2].append(b)

        monthly_gib = [round(sum(bkt) / len(bkt) / (1024**3), 4) if bkt else 0.0 for bkt in buckets]
        vol.monthly_write_trend_gib = monthly_gib

        # Month-over-month growth (last two months → annualised %).
        m2, m3 = monthly_gib[1], monthly_gib[2]
        if m2 > 0:
            vol.write_growth_pct = round((m3 - m2) / m2 * 12 * 100, 1)

    # Flag archival volumes so the portal excludes them from sizing. An explicit
    # operator exclusion (tag/pattern) keeps its own, more specific reason.
    for vol in volumes:
        if vol.excluded_from_sizing:
            continue
        if _is_archival_volume(vol.name, vol.instance_name, vol.tags):
            vol.excluded_from_sizing = True
            vol.sizing_exclusion_reason = "name/tags suggest archival or log storage"


def _fetch_instance_type_specs(client, instance_types: set[str]) -> dict[str, dict]:
    """Return {instance_type: {vcpus, memory_gib}} for the given set of types."""
    specs: dict[str, dict] = {}
    types_list = list(instance_types)
    # describe_instance_types accepts up to 100 per call
    for i in range(0, len(types_list), 100):
        batch = types_list[i : i + 100]
        try:
            resp = client.describe_instance_types(InstanceTypes=batch)
            for it in resp.get("InstanceTypes", []):
                t = it.get("InstanceType", "")
                vcpus = it.get("VCpuInfo", {}).get("DefaultVCpus", 0) or 0
                mem_mib = it.get("MemoryInfo", {}).get("SizeInMiB", 0) or 0
                specs[t] = {"vcpus": vcpus, "memory_gib": round(mem_mib / 1024, 2)}
        except Exception as exc:
            logging.debug("Could not fetch instance type specs: %s", exc)
    return specs


def fetch_instances(
    session,
    region: str,
    account_id: str,
    account_alias: str,
    protected_arns: set[str],
    tracker: "DenialTracker | None" = None,
    exclusion: "VolumeExclusionEngine | None" = None,
) -> tuple[list[EC2Instance], list[EC2Volume]]:
    """Fetch all EC2 instances and their attached EBS volumes."""
    exclusion = exclusion or VolumeExclusionEngine()
    client = session.client("ec2", region_name=region)
    instances: list[EC2Instance] = []
    attached_volumes: list[EC2Volume] = []

    # Fetch once per region — O(1) per-volume lookup afterward.
    snapshotted_ids = _fetch_snapshotted_volume_ids(client, account_id)

    try:
        paginator = client.get_paginator("describe_instances")
        reservations = []
        for page in paginator.paginate():
            reservations.extend(page.get("Reservations", []))
    except Exception as exc:
        if is_scp_denial(exc):
            if tracker is not None:
                tracker.record("ec2")
            logging.debug("Could not describe EC2 instances in %s (SCP denied)", region)
        else:
            if tracker is not None:
                tracker.record_permission_error("ec2", region, exc)
            logging.warning("Could not describe EC2 instances in %s: %s", region, exc)
        return instances, attached_volumes

    # Batch-fetch all volume details for the region up front to avoid N+1 calls.
    volume_info: dict[str, dict] = {}
    try:
        vol_paginator = client.get_paginator("describe_volumes")
        for page in vol_paginator.paginate(Filters=[{"Name": "status", "Values": ["in-use"]}]):
            for v in page.get("Volumes", []):
                volume_info[v["VolumeId"]] = v
    except Exception as exc:
        if is_scp_denial(exc):
            if tracker is not None:
                tracker.record("ec2")
            logging.debug("Could not batch-fetch volumes in %s (SCP denied)", region)
        else:
            if tracker is not None:
                tracker.record_permission_error("ec2-volumes", region, exc)
            logging.warning("Could not batch-fetch volumes in %s: %s", region, exc)

    # Collect unique instance types then batch-fetch vCPUs + RAM in one call.
    all_types: set[str] = set()
    for res in reservations:
        for inst in res.get("Instances", []):
            t = inst.get("InstanceType", "")
            if t:
                all_types.add(t)
    type_specs = _fetch_instance_type_specs(client, all_types)

    for res in reservations:
        for inst in res.get("Instances", []):
            inst_id = inst.get("InstanceId", "")
            inst_arn = instance_arn(region, account_id, inst_id)
            tags = _tags_to_dict(inst.get("Tags"))
            inst_name = _name_from_tags(tags)
            inst_type = str(inst.get("InstanceType", ""))
            specs = type_specs.get(inst_type, {})

            total_gib = 0
            vol_count = 0
            all_vol_plans: set[str] = set()  # accumulates protection across all volumes

            for bdm in inst.get("BlockDeviceMappings", []):
                ebs = bdm.get("Ebs") or {}
                vol_id = ebs.get("VolumeId", "")
                if not vol_id:
                    continue

                vol = volume_info.get(vol_id, {})
                size_gib = vol.get("Size", 0)
                total_gib += size_gib
                vol_count += 1

                vol_arn = volume_arn(region, account_id, vol_id)
                vol_backup_plans = _volume_protection(
                    vol_id, vol_arn, protected_arns, snapshotted_ids
                )
                all_vol_plans |= set(vol_backup_plans)
                vol_tags = _tags_to_dict(vol.get("Tags"))

                attached_volumes.append(
                    EC2Volume(
                        account_id=account_id,
                        account_alias=account_alias,
                        volume_id=vol_id,
                        instance_id=inst_id,
                        instance_name=inst_name,
                        name=_name_from_tags(vol_tags),
                        device_name=bdm.get("DeviceName", ""),
                        size_gib=size_gib,
                        size_tb=_round_tb(size_gib),
                        size_bytes_derived=size_gib * 1024**3,
                        region=region,
                        availability_zone=vol.get("AvailabilityZone", ""),
                        volume_type=vol.get("VolumeType", ""),
                        state=vol.get("State", ""),
                        iops=vol.get("Iops") or 0,
                        throughput=vol.get("Throughput") or 0,
                        encrypted=bool(vol.get("Encrypted")),
                        in_backup_plan=bool(vol_backup_plans),
                        backup_plans=vol_backup_plans,
                        tags=vol_tags,
                    )
                )

            # Instance protection = union across all volumes + instance ARN vault check.
            inst_vault = _matching_plan_names(inst_arn, protected_arns)
            inst_backup_plans = list(all_vol_plans | set(inst_vault))

            platform_raw = inst.get("Platform", "")
            platform = "windows" if str(platform_raw).lower() == "windows" else "linux"
            state = (inst.get("State") or {}).get("Name", "unknown")

            instances.append(
                EC2Instance(
                    account_id=account_id,
                    account_alias=account_alias,
                    instance_id=inst_id,
                    name=inst_name,
                    instance_type=inst_type,
                    platform=platform,
                    state=state,
                    vcpus=specs.get("vcpus", 0),
                    memory_gib=specs.get("memory_gib", 0.0),
                    region=region,
                    volume_count=vol_count,
                    size_gib=total_gib,
                    size_tb=_round_tb(total_gib),
                    size_bytes_derived=total_gib * 1024**3,
                    in_backup_plan=bool(inst_backup_plans),
                    backup_plans=inst_backup_plans,
                    tags=tags,
                )
            )

    # Apply operator exclusions before CloudWatch enrichment so the flag never
    # depends on the metrics call succeeding.
    for vol in attached_volumes:
        reason = exclusion.evaluate(vol.name, vol.instance_name, vol.tags)
        if reason:
            vol.excluded_from_sizing = True
            vol.sizing_exclusion_reason = reason

    # Enrich attached volumes with 14-day CloudWatch write-rate data.
    if attached_volumes:
        cw_client = session.client("cloudwatch", region_name=region, config=BOTO_ADAPTIVE_CFG)
        _enrich_with_change_rates(cw_client, attached_volumes, region, tracker)

    return instances, attached_volumes


def fetch_unattached_volumes(
    session,
    region: str,
    account_id: str,
    account_alias: str,
    protected_arns: set[str],
    tracker: "DenialTracker | None" = None,
    exclusion: "VolumeExclusionEngine | None" = None,
) -> list[EC2Volume]:
    """Fetch EBS volumes in 'available' (unattached) state."""
    exclusion = exclusion or VolumeExclusionEngine()
    client = session.client("ec2", region_name=region)
    unattached: list[EC2Volume] = []
    snapshotted_ids = _fetch_snapshotted_volume_ids(client, account_id)

    try:
        paginator = client.get_paginator("describe_volumes")
        for page in paginator.paginate(Filters=[{"Name": "status", "Values": ["available"]}]):
            for v in page.get("Volumes", []):
                vol_id = v.get("VolumeId", "")
                size_gib = v.get("Size", 0)
                vol_arn = volume_arn(region, account_id, vol_id)
                vol_tags = _tags_to_dict(v.get("Tags"))
                backup_plans = _volume_protection(vol_id, vol_arn, protected_arns, snapshotted_ids)

                unattached.append(
                    EC2Volume(
                        account_id=account_id,
                        account_alias=account_alias,
                        volume_id=vol_id,
                        instance_id="",
                        instance_name="",
                        name=_name_from_tags(vol_tags),
                        device_name="",
                        size_gib=size_gib,
                        size_tb=_round_tb(size_gib),
                        size_bytes_derived=size_gib * 1024**3,
                        region=region,
                        availability_zone=v.get("AvailabilityZone", ""),
                        volume_type=v.get("VolumeType", ""),
                        state="available",
                        iops=v.get("Iops") or 0,
                        throughput=v.get("Throughput") or 0,
                        encrypted=bool(v.get("Encrypted")),
                        in_backup_plan=bool(backup_plans),
                        backup_plans=backup_plans,
                        tags=vol_tags,
                    )
                )
    except Exception as exc:
        logging.warning("Could not fetch unattached volumes in %s: %s", region, exc)

    for vol in unattached:
        reason = exclusion.evaluate(vol.name, "", vol.tags)
        if reason:
            vol.excluded_from_sizing = True
            vol.sizing_exclusion_reason = reason

    if unattached:
        cw_client = session.client("cloudwatch", region_name=region, config=BOTO_ADAPTIVE_CFG)
        _enrich_with_change_rates(cw_client, unattached, region, tracker)

    return unattached


def _matching_plan_names(arn: str, protected_arns: set[str]) -> list[str]:
    """Return a list with 'AWS Backup' if the ARN is in the protected set."""
    if arn in protected_arns:
        return ["AWS Backup"]
    return []


def _fetch_snapshotted_volume_ids(client, account_id: str, days: int = 30) -> set[str]:
    """Return volume IDs that have at least one completed EBS snapshot in the last N days.

    Called once per region before iterating instances so the check is O(1) per volume.
    Failures are non-fatal — returns empty set, volumes stay unprotected in the model.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    snapshotted: set[str] = set()
    try:
        paginator = client.get_paginator("describe_snapshots")
        for page in paginator.paginate(
            OwnerIds=[account_id],
            Filters=[{"Name": "status", "Values": ["completed"]}],
        ):
            for snap in page.get("Snapshots", []):
                start_time = snap.get("StartTime")
                if start_time and start_time >= cutoff:
                    vol_id = snap.get("VolumeId", "")
                    if vol_id:
                        snapshotted.add(vol_id)
    except Exception as exc:
        logging.warning("Could not describe snapshots: %s", exc)
    return snapshotted


def _volume_protection(
    vol_id: str, vol_arn: str, protected_arns: set[str], snapshotted_ids: set[str]
) -> list[str]:
    """Return the full protection label list for a volume."""
    plans: list[str] = []
    if vol_arn in protected_arns:
        plans.append("AWS Backup")
    if vol_id in snapshotted_ids:
        plans.append("EBS Snapshot")
    return plans
