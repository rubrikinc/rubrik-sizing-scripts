"""ARN builders shared by the backup merge and the CSV export, so both key on the same text."""

from __future__ import annotations


def partition(region: str) -> str:
    if region.startswith("us-gov-"):
        return "aws-us-gov"
    if region.startswith("cn-"):
        return "aws-cn"
    if region.startswith("us-isob-"):
        return "aws-iso-b"
    if region.startswith("us-iso-"):
        return "aws-iso"
    return "aws"


def dynamodb_table_arn(region: str, account_id: str, table_name: str) -> str:
    return f"arn:{partition(region)}:dynamodb:{region}:{account_id}:table/{table_name}"


def instance_arn(region: str, account_id: str, instance_id: str) -> str:
    return f"arn:{partition(region)}:ec2:{region}:{account_id}:instance/{instance_id}"


def image_arn(region: str, account_id: str, image_id: str) -> str:
    return f"arn:{partition(region)}:ec2:{region}:{account_id}:image/{image_id}"


def volume_arn(region: str, account_id: str, volume_id: str) -> str:
    return f"arn:{partition(region)}:ec2:{region}:{account_id}:volume/{volume_id}"


def snapshot_arn(region: str, snapshot_id: str) -> str:
    return f"arn:{partition(region)}:ec2:{region}::snapshot/{snapshot_id}"


def rds_db_arn(region: str, account_id: str, db_id: str) -> str:
    return f"arn:{partition(region)}:rds:{region}:{account_id}:db:{db_id}"


def rds_cluster_arn(region: str, account_id: str, cluster_id: str) -> str:
    return f"arn:{partition(region)}:rds:{region}:{account_id}:cluster:{cluster_id}"


def fsx_file_system_arn(region: str, account_id: str, file_system_id: str) -> str:
    return f"arn:{partition(region)}:fsx:{region}:{account_id}:file-system/{file_system_id}"


def fsx_volume_arn(region: str, account_id: str, volume_id: str) -> str:
    return f"arn:{partition(region)}:fsx:{region}:{account_id}:volume/{volume_id}"


def redshift_arn(region: str, account_id: str, cluster_id: str) -> str:
    return f"arn:{partition(region)}:redshift:{region}:{account_id}:cluster:{cluster_id}"


def efs_arn(region: str, account_id: str, file_system_id: str) -> str:
    return f"arn:{partition(region)}:elasticfilesystem:{region}:{account_id}:file-system/{file_system_id}"


def s3_arn(region: str, bucket: str) -> str:
    return f"arn:{partition(region)}:s3:::{bucket}"
