"""Anonymization of the output files. Port of ``-Anonymize`` in ``Get-AWSSizingInfo.ps1``.

Every value of a listed field is replaced by ``<Field>-<number>`` (``InstanceId-00000``). The
mapping is shared by all files of a run, so a value that appears in several places, or in several
fields, gets one label everywhere and the files still join. Tag columns are renamed
(``Tag: TagName-00000``) and their values replaced (``TagValue-00000``); the ``BackupPlans``
column is anonymized plan by plan. A key file maps every label back to the real value.

Rules kept from the PowerShell script, checked against it with the same inputs:
  * values are matched without regard to case ("web" and "WEB" share a label);
  * an empty string is a value and is anonymized, a missing value (null) is left alone;
  * list values are anonymized item by item;
  * the tag columns of a row are moved to its end.

One rule is not kept: PowerShell writes the counter as digits that repeat from the 11th distinct
value of a field on (``InstanceId-00000`` is given to the 1st and the 11th instance, so 25
instances come out as 15 labels). Here the labels are numbered one after the other, which is the
same as PowerShell for the first ten values and unique beyond them.
"""

from __future__ import annotations

from typing import Any, Iterable

DEFAULT_FIELDS: tuple[str, ...] = (
    "Alias",
    "Arn",
    "AwsAccountAlias",
    "AwsAccountId",
    "BackupPlanArn",
    "BackupPlanId",
    "BackupPlanName",
    "BackupVaultArn",
    "BackupVaultName",
    "BucketName",
    "CidrBlock",
    "ClusterIdentifier",
    "ClusterName",
    "CreatorRequestId",
    "DBClusterIdentifier",
    "DBInstanceIdentifier",
    "DBName",
    "Description",
    "DestinationBackupVaultArn",
    "DNSName",
    "FileSystemDNSName",
    "FileSystemId",
    "FileSystemOwnerId",
    "HostedZoneId",
    "ImageId",
    "InstanceId",
    "InstanceName",
    "KeyId",
    "LoadBalancerName",
    "MasterUsername",
    "Name",
    "NodegroupArn",
    "NodegroupName",
    "NodeRole",
    "OwnerId",
    "ParentRecoveryPointArn",
    "Project",
    "RDSInstance",
    "RecoveryPointArn",
    "RequestId",
    "ResourceArn",
    "ResourceId",
    "ResourceName",
    "Resources",
    "RoleArn",
    "RuleId",
    "RuleName",
    "SnapshotArn",
    "SnapshotId",
    "SnapshotIdentifier",
    "TableArn",
    "TableBucketArn",
    "TableBucketName",
    "TableId",
    "TableName",
    "TargetBackupVaultName",
    "VersionId",
    "VolumeId",
    "VpcId",
    "WarehouseLocation",
)

# The order PowerShell anonymizes its lists in. The labels of a field are numbered in the order
# its values are first met, so the order of the files decides the numbers.
FILE_ORDER: tuple[str, ...] = (
    "aws_backup_costs",
    "aws_backup_recovery_points",
    "aws_ebs_and_ami_info",
    "aws_rds_snapshot_info",
    "aws_redshift_info",
    "aws_snapshot_storage_costs",
    "aws_DynamoDB_info",
    "aws_s3_tables_info",
    "aws_ec2_instance_info",
    "aws_ec2_attached_volume_info",
    "aws_ec2_unattached_volume_info",
    "aws_efs_info",
    "aws_eks_clusters_info",
    "aws_eks_nodegroups_info",
    "aws_fsx_filesystem_info",
    "aws_fsx_volume_info",
    "aws_kms_numbers",
    "aws_rds_info",
    "aws_s3_info",
    "aws_secrets_numbers",
    "aws_sqs_numbers",
    "aws_vpc_info",
    "aws_lb_info",
    "aws_route53_info",
    "aws_iam_info",
    "aws_glue_iceberg_info",
)

TAG_PREFIX = "Tag:"
TAG_KEY_FIELD = "TagName"
TAG_VALUE_FIELD = "TagValue"
BACKUP_PLANS_FIELD = "BackupPlans"
BACKUP_PLAN_NAME_FIELD = "BackupPlanName"
KEY_FILE_PREFIX = "aws_anonymized_keys_to_actual_values"


def _split_names(text: str) -> list[str]:
    return [name for name in (part.strip() for part in (text or "").split(",")) if name]


class Anonymizer:
    """Holds the mapping and the counters of one run."""

    def __init__(self, extra_fields: Iterable[str] = (), not_fields: Iterable[str] = ()) -> None:
        not_fields = list(not_fields)
        fields = list(DEFAULT_FIELDS)
        for field in extra_fields:
            if field.casefold() not in {f.casefold() for f in fields}:
                fields.append(field)
        skip = {f.casefold() for f in not_fields}
        self.fields = {f.casefold() for f in fields} - skip
        self.anonymize_tags = "tags" not in skip
        self._labels: dict[str, str] = {}
        self._actual: dict[str, str] = {}
        self._counters: dict[str, int] = {}

    @classmethod
    def from_options(
        cls, anonymize_fields: str = "", not_anonymize_fields: str = ""
    ) -> "Anonymizer":
        return cls(_split_names(anonymize_fields), _split_names(not_anonymize_fields))

    def _label(self, value: Any, field: str) -> str:
        text = str(value)
        key = text.casefold()
        label = self._labels.get(key)
        if label is None:
            number = self._counters.get(field, 0)
            self._counters[field] = number + 1
            label = f"{field}-{number:05d}"
            self._labels[key] = label
            self._actual[key] = text
        return label

    def pre_label(self, field: str, values: Iterable[Any]) -> None:
        """Hand out the labels for ``values`` of ``field`` now, in order.

        PowerShell anonymizes a list of its own (the backup plans) before the CSV lists, so the
        numbers follow that list's order, not the order the values first turn up in the rows.
        Does nothing for a field that is not anonymized.
        """
        if field.casefold() not in self.fields:
            return
        for value in values:
            if value is not None and value != "":
                self._label(value, field)

    def anonymize_row(self, row: dict[str, Any]) -> dict[str, Any]:
        """The row with its values replaced; tag columns are renamed and moved to the end."""
        out: dict[str, Any] = {}
        tags: dict[str, Any] = {}
        for name, value in row.items():
            if name.casefold() in self.fields:
                if value is None:
                    out[name] = None
                elif isinstance(value, (list, tuple)):
                    out[name] = [self._label(item, name) for item in value]
                else:
                    out[name] = self._label(value, name)
            elif name.casefold().startswith(TAG_PREFIX.casefold()) and self.anonymize_tags:
                key = f"{TAG_PREFIX} {self._label(name[len(TAG_PREFIX):], TAG_KEY_FIELD)}"
                tags[key] = None if value is None else self._label(value, TAG_VALUE_FIELD)
            elif name.casefold() == BACKUP_PLANS_FIELD.casefold():
                if value is not None and value != "":
                    plans = str(value).split(", ")
                    out[name] = " ,".join(self._label(p, BACKUP_PLAN_NAME_FIELD) for p in plans)
                else:
                    out[name] = value
            else:
                out[name] = value
        out.update(tags)
        return out

    def key_rows(self) -> list[tuple[str, str]]:
        """(anonymized value, actual value) for every label handed out, by label."""
        rows = [(label, self._actual[key]) for key, label in self._labels.items()]
        return sorted(rows, key=lambda r: r[0].casefold())

    def key_file_text(self) -> str:
        """The key file as CSV: every value quoted, as PowerShell's Export-Csv writes it."""

        def quote(text: str) -> str:
            return '"' + text.replace('"', '""') + '"'

        lines = ['"AnonymizedValue","ActualValue"']
        lines += [f"{quote(a)},{quote(b)}" for a, b in self.key_rows()]
        return "\n".join(lines) + "\n"


def file_rank(prefix: str) -> int:
    """Position of a file in the order PowerShell anonymizes in (unknown files go last)."""
    try:
        return FILE_ORDER.index(prefix)
    except ValueError:
        return len(FILE_ORDER)


def anonymized_log_note() -> str:
    return (
        "Anonymized file; customer has original. "
        "Request customer to sanitize and provide output log if needed\n"
    )
