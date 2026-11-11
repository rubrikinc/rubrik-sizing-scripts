"""GCE instance and persistent disk collector for Rubrik Discovery — GCP Edition."""

from __future__ import annotations

import logging
from typing import Optional

from models.inventory import ComputeInventory, GCEDisk, GCEInstance

from collectors.exclusion import VolumeExclusionEngine
from collectors.retry import retry_call
from collectors.utils import LabelSummary, brief_error, build_label_summary, collection_error

logger = logging.getLogger(__name__)

# GCP Windows boot disk license URL fragment
_WINDOWS_LICENSE_FRAGMENT = "windows"

# Compute Engine measures disk size in binary gigabytes: 1 GB is 2**30 bytes (a GiB).
BYTES_PER_GIB = 2**30


# Machine type URL format: zones/{zone}/machineTypes/{family}-{size}
# We extract the family prefix (e.g. n2 from n2-standard-4).
def _machine_family(machine_type_url: str) -> str:
    """Extract the machine family prefix from a machine type URL or name.

    Examples:
        ``zones/us-central1-a/machineTypes/n2-standard-4`` → ``n2``
        ``e2-medium`` → ``e2``
        ``custom-6-20480`` → ``custom``
    """
    name = machine_type_url.split("/")[-1]
    return name.split("-")[0] if "-" in name else name


def _disk_type_name(disk_type_url: str) -> str:
    """Extract the disk type name from a full URL or return the string as-is."""
    return disk_type_url.split("/")[-1] if "/" in disk_type_url else disk_type_url


def _os_type(boot_disk_licenses: list[str]) -> str:
    """Classify OS type from boot disk license URLs."""
    for lic in boot_disk_licenses:
        if _WINDOWS_LICENSE_FRAGMENT in lic.lower():
            return "windows"
    return "linux" if boot_disk_licenses else "unknown"


def _disk_key(scope: str, name: str) -> str:
    """Key a disk by its scope (``zones/z`` or ``regions/r``) plus name.

    Disk names are only unique within a scope, so name alone collides across zones.
    """
    return f"{scope}/{name}"


def _source_scope(source: str) -> str:
    """Scope segment of a disk source URL: ``.../zones/z/disks/n`` -> ``zones/z``."""
    parts = (source or "").split("/")
    return "/".join(parts[-4:-2]) if len(parts) >= 4 else ""


def _disk_scope(disk, fallback: str) -> str:
    """Scope of a listed disk, from its own ``self_link`` (same URL shape as an attached
    disk's ``source``); ``fallback`` (the aggregated-list key) when it has none."""
    link = getattr(disk, "self_link", None)
    if isinstance(link, str) and link:
        scope = _source_scope(link)
        if scope:
            return scope
    return fallback


def _encryption_key(disk) -> Optional[dict[str, str]]:
    """The disk's encryption key as gcloud's JSON shows it, or None when it has none.

    Only the fields that are set are kept, in gcloud's (alphabetical) key order. The raw key is
    never returned by the API and is not read.
    """
    key = getattr(disk, "disk_encryption_key", None)
    if key is None:
        return None
    fields = {
        "kmsKeyName": getattr(key, "kms_key_name", "") or "",
        "kmsKeyServiceAccount": getattr(key, "kms_key_service_account", "") or "",
        "sha256": getattr(key, "sha256", "") or "",
    }
    present = {name: value for name, value in fields.items() if value}
    return present or None


def _zone_to_region(zone: str) -> str:
    """Derive region from zone (e.g. us-central1-a → us-central1)."""
    from auth import zone_to_region  # deferred to avoid circular at module level

    return zone_to_region(zone)


class ComputeCollector:
    """Collect GCE instances and persistent disks for a GCP project.

    Uses ``instances.aggregatedList`` and ``disks.aggregatedList`` to fetch
    all zones in one API call each, avoiding per-zone N+1 requests.

    Credential injection rule: always receive credentials from ``main.py``;
    never instantiate ADC inside this class.
    """

    def __init__(
        self,
        project_id: str,
        credentials,
        regions: Optional[list[str]] = None,
        exclusion: Optional[VolumeExclusionEngine] = None,
    ) -> None:
        """
        Args:
            project_id: GCP project ID.
            credentials: Authenticated google.auth Credentials instance.
            regions: Optional list of regions to include; None = all regions.
            exclusion: Disk exclusion engine; None = label-only (no name patterns).
        """
        self._project_id = project_id
        self._credentials = credentials
        self._regions = regions
        self._exclusion = exclusion or VolumeExclusionEngine()
        self.errors: list[dict] = []
        self._unattached_keys: list[str] = []

    def collect(self) -> ComputeInventory:
        """Collect all GCE instances and disks for the project.

        Returns:
            ComputeInventory. On API failure, returns an empty inventory and
            logs a warning rather than raising.
        """
        from google.cloud import compute_v1  # deferred import

        try:
            disks_by_name = self._collect_disks(compute_v1)
            instances = self._collect_instances(compute_v1, disks_by_name)
            unattached = [disks_by_name[k] for k in self._unattached_keys]
        except Exception as exc:
            logger.warning(
                "Compute collection failed for project %s: %s "
                "(check roles/compute.viewer is granted)",
                self._project_id,
                brief_error(exc),
            )
            self.errors.append(collection_error("compute", exc))
            return ComputeInventory(project_id=self._project_id)

        return self._build_inventory(instances, unattached)

    def _collect_disks(self, compute_v1) -> dict[str, GCEDisk]:
        """Return a dict of ``scope/name`` → GCEDisk for all disks in the project."""
        client = compute_v1.DisksClient(credentials=self._credentials)
        disks: dict[str, GCEDisk] = {}
        self._unattached_keys = []

        try:
            request = compute_v1.AggregatedListDisksRequest(project=self._project_id)
            pages = retry_call(
                lambda: list(client.aggregated_list(request=request)),
                description=f"disks.aggregated_list({self._project_id})",
            )
            for zone_name, scoped in sorted(pages, key=lambda page: page[0]):
                if not hasattr(scoped, "disks") or not scoped.disks:
                    continue
                zone = zone_name.replace("zones/", "")
                region = _zone_to_region(zone)
                if self._regions and region not in self._regions:
                    continue
                for disk in scoped.disks:
                    size_gb = int(disk.size_gb) if disk.size_gb else 0
                    gce_disk = GCEDisk(
                        name=disk.name,
                        zone=zone,
                        region=region,
                        size_gb=size_gb,
                        disk_type=_disk_type_name(disk.type_),
                        status=disk.status or "UNKNOWN",
                        size_bytes_derived=int(size_gb * BYTES_PER_GIB),
                        size_tb=round(size_gb / 1000, 4),
                        source_image=disk.source_image or None,
                        disk_id=str(disk.id) if getattr(disk, "id", None) else None,
                        labels=dict(disk.labels) if getattr(disk, "labels", None) else {},
                        encryption_key=_encryption_key(disk),
                    )
                    gce_disk.encrypted = gce_disk.encryption_key is not None
                    # Flag, never drop, so raw totals stay intact. This sees every
                    # disk in the project, so unattached disks are covered too.
                    reason = self._exclusion.evaluate(
                        disk.name,
                        _first_user_name(disk.users),
                        dict(disk.labels) if disk.labels else {},
                    )
                    if reason:
                        gce_disk.excluded_from_sizing = True
                        gce_disk.sizing_exclusion_reason = reason
                    key = _disk_key(_disk_scope(disk, zone_name), disk.name)
                    disks[key] = gce_disk
                    if not disk.users:
                        self._unattached_keys.append(key)
            self._unattached_keys.sort()
        except Exception as exc:
            logger.warning(
                "Disk listing failed for project %s: %s — disk sizes will be missing",
                self._project_id,
                brief_error(exc),
            )
            self.errors.append(collection_error("compute_disks", exc))

        return disks

    def _collect_instances(
        self, compute_v1, disks_by_name: dict[str, GCEDisk]
    ) -> list[GCEInstance]:
        """Return a list of GCEInstance objects for all instances in the project."""
        client = compute_v1.InstancesClient(credentials=self._credentials)
        instances: list[GCEInstance] = []

        request = compute_v1.AggregatedListInstancesRequest(project=self._project_id)
        pages = retry_call(
            lambda: list(client.aggregated_list(request=request)),
            description=f"instances.aggregated_list({self._project_id})",
        )
        for zone_name, scoped in sorted(pages, key=lambda page: page[0]):
            if not hasattr(scoped, "instances") or not scoped.instances:
                continue
            zone = zone_name.replace("zones/", "")
            region = _zone_to_region(zone)
            if self._regions and region not in self._regions:
                continue

            for inst in scoped.instances:
                attached_disks, boot_licenses = self._resolve_disks(
                    inst, zone, region, disks_by_name
                )
                total_gb = sum(d.size_gb for d in attached_disks)

                gce_inst = GCEInstance(
                    name=inst.name,
                    zone=zone,
                    region=region,
                    machine_type=_machine_family_name(inst.machine_type),
                    machine_family=_machine_family(inst.machine_type),
                    status=inst.status or "UNKNOWN",
                    labels=dict(inst.labels) if inst.labels else {},
                    disks=attached_disks,
                    total_disk_gb=float(total_gb),
                    os_type=_os_type(boot_licenses),
                    total_disk_bytes_derived=float(total_gb) * BYTES_PER_GIB,
                )
                instances.append(gce_inst)

        # The API returns the zones in no fixed order, so two runs of the same project listed the
        # same VMs in different orders, and the label columns of the CSV follow the first row seen.
        instances.sort(key=lambda i: (i.zone, i.name))
        return instances

    def _resolve_disks(
        self,
        inst,
        zone: str,
        region: str,
        disks_by_name: dict[str, GCEDisk],
    ) -> tuple[list[GCEDisk], list[str]]:
        """Map attached disk references to GCEDisk objects; collect boot licenses."""
        attached: list[GCEDisk] = []
        boot_licenses: list[str] = []

        for attached_disk in inst.disks or []:
            is_boot = bool(attached_disk.boot)
            source = attached_disk.source or ""
            disk_name = source.split("/")[-1]
            disk_key = _disk_key(_source_scope(source), disk_name)

            if disk_key in disks_by_name:
                gce_disk = disks_by_name[disk_key]
                gce_disk.is_boot = is_boot
            else:
                # Disk not in our dict (e.g. different region filtered out); create stub.
                gce_disk = GCEDisk(
                    name=disk_name,
                    zone=zone,
                    region=region,
                    size_gb=0,
                    disk_type="unknown",
                    status="UNKNOWN",
                    is_boot=is_boot,
                )
                # A stub has no labels, but name patterns can still apply.
                reason = self._exclusion.evaluate(disk_name, inst.name, None)
                if reason:
                    gce_disk.excluded_from_sizing = True
                    gce_disk.sizing_exclusion_reason = reason

            attached.append(gce_disk)

            if is_boot:
                boot_licenses = [lic for lic in (attached_disk.licenses or [])]

        return attached, boot_licenses

    def _build_inventory(
        self, instances: list[GCEInstance], unattached: list[GCEDisk]
    ) -> ComputeInventory:
        os_breakdown: dict[str, int] = {}
        machine_family_breakdown: dict[str, int] = {}
        disk_type_breakdown: dict[str, int] = {}
        region_breakdown: dict[str, int] = {}
        status_breakdown: dict[str, int] = {}
        total_disk_gb = 0.0
        unattached_gb = float(sum(d.size_gb for d in unattached))

        for inst in instances:
            os_breakdown[inst.os_type] = os_breakdown.get(inst.os_type, 0) + 1
            machine_family_breakdown[inst.machine_family] = (
                machine_family_breakdown.get(inst.machine_family, 0) + 1
            )
            region_breakdown[inst.region] = region_breakdown.get(inst.region, 0) + 1
            status_breakdown[inst.status] = status_breakdown.get(inst.status, 0) + 1
            total_disk_gb += inst.total_disk_gb

            for disk in inst.disks:
                disk_type_breakdown[disk.disk_type] = disk_type_breakdown.get(disk.disk_type, 0) + 1

        label_summary: Optional[LabelSummary] = build_label_summary(
            [inst.labels for inst in instances]
        )

        logger.debug(
            "Project %s: %d GCE instances, %d unattached disks, %.1f TB total disk",
            self._project_id,
            len(instances),
            len(unattached),
            (total_disk_gb + unattached_gb) / 1000,
        )

        return ComputeInventory(
            project_id=self._project_id,
            instances=instances,
            unattached_disks=unattached,
            total_instances=len(instances),
            total_unattached_disks=len(unattached),
            total_unattached_disk_tb=round(unattached_gb / 1000, 4),
            total_disk_tb=round((total_disk_gb + unattached_gb) / 1000, 4),
            os_breakdown=os_breakdown,
            machine_family_breakdown=machine_family_breakdown,
            disk_type_breakdown=disk_type_breakdown,
            region_breakdown=region_breakdown,
            status_breakdown=status_breakdown,
            label_summary=label_summary,
        )


def _first_user_name(users) -> str:
    """Name of the first instance attached to a disk, from its users URLs."""
    for url in users or ():
        return str(url).rstrip("/").split("/")[-1]
    return ""


def _machine_family_name(machine_type_url: str) -> str:
    """Extract the short machine type name from a full URL."""
    return machine_type_url.split("/")[-1] if "/" in machine_type_url else machine_type_url
