"""IaC (Infrastructure-as-Code) signal detection for AWS accounts.

Detects usage of CloudFormation, AWS CDK, AWS SAM, Terraform, and Pulumi by
inspecting CloudFormation stacks, S3 bucket names, DynamoDB table names, and
resource tags already collected by other collectors.

Results feed into IaCSummary which is included in the discovery JSON so the
SE can quickly assess whether Rubrik DevOps Protection is relevant.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from collectors import is_scp_denial

log = logging.getLogger(__name__)

# Tag keys that indicate Terraform management
_TERRAFORM_TAG_KEYS = frozenset(
    {
        "terraform",
        "terraform-managed",
        "managed-by-terraform",
        "created-by-terraform",
        "tf-managed",
        "provisioned-by",
    }
)
_TERRAFORM_TAG_VALUES = frozenset({"terraform", "terraform-cloud", "tofu"})

# S3 bucket name substrings that indicate Terraform remote state
_TERRAFORM_BUCKET_PATTERNS = frozenset(
    {
        "terraform-state",
        "tf-state",
        "tfstate",
        "terraform-backend",
        "tf-backend",
        "terraform-remote",
    }
)

# DynamoDB table name substrings for Terraform lock tables
_TERRAFORM_LOCK_PATTERNS = frozenset(
    {
        "terraform-lock",
        "tf-lock",
        "terraform-state-lock",
        "tfstate-lock",
        "terraform-locks",
    }
)

# S3 bucket name substrings that indicate Pulumi state
_PULUMI_BUCKET_PATTERNS = frozenset({"pulumi-state", "pulumi-backend"})


@dataclass
class CloudFormationStack:
    account_id: str
    account_alias: str
    region: str
    stack_name: str
    stack_id: str
    status: str
    description: str
    tags: dict[str, str]
    is_cdk: bool = False
    is_sam: bool = False
    is_cdk_bootstrap: bool = False


@dataclass
class IaCSummary:
    account_id: str
    account_alias: str
    has_iac: bool
    tools_detected: list[str]
    devops_opportunity: str  # "High" | "Medium" | "Low" | "None"
    cloudformation_stack_count: int = 0
    cdk_stack_count: int = 0
    cdk_bootstrap_detected: bool = False
    sam_stack_count: int = 0
    terraform_state_buckets: list[str] = field(default_factory=list)
    terraform_lock_tables: list[str] = field(default_factory=list)
    pulumi_state_buckets: list[str] = field(default_factory=list)
    tag_detected_tools: list[str] = field(default_factory=list)
    cfn_stacks: list[CloudFormationStack] = field(default_factory=list)


def fetch_cfn_stacks(
    session,
    region: str,
    account_id: str,
    account_alias: str,
) -> list[CloudFormationStack]:
    """List all non-deleted CloudFormation stacks in a region."""
    client = session.client("cloudformation", region_name=region)
    stacks: list[CloudFormationStack] = []

    try:
        paginator = client.get_paginator("list_stacks")
        # Exclude DELETE_COMPLETE — those are gone and not relevant
        active_statuses = [
            "CREATE_IN_PROGRESS",
            "CREATE_FAILED",
            "CREATE_COMPLETE",
            "ROLLBACK_IN_PROGRESS",
            "ROLLBACK_FAILED",
            "ROLLBACK_COMPLETE",
            "UPDATE_IN_PROGRESS",
            "UPDATE_COMPLETE_CLEANUP_IN_PROGRESS",
            "UPDATE_COMPLETE",
            "UPDATE_FAILED",
            "UPDATE_ROLLBACK_IN_PROGRESS",
            "UPDATE_ROLLBACK_FAILED",
            "UPDATE_ROLLBACK_COMPLETE_CLEANUP_IN_PROGRESS",
            "UPDATE_ROLLBACK_COMPLETE",
            "REVIEW_IN_PROGRESS",
            "IMPORT_IN_PROGRESS",
            "IMPORT_COMPLETE",
            "IMPORT_ROLLBACK_IN_PROGRESS",
            "IMPORT_ROLLBACK_FAILED",
            "IMPORT_ROLLBACK_COMPLETE",
        ]
        for page in paginator.paginate(StackStatusFilter=active_statuses):
            for s in page.get("StackSummaries", []):
                stack_name = s.get("StackName", "")
                tags_list = s.get("Tags") or []
                tags = {t["Key"]: t["Value"] for t in tags_list}

                # CDK detection: CDKToolkit is the bootstrap stack; other CDK stacks
                # have the aws:cdk:path tag injected by the CDK synthesizer.
                is_cdk_bootstrap = stack_name == "CDKToolkit"
                is_cdk = is_cdk_bootstrap or "aws:cdk:path" in tags

                # SAM detection: SAM transforms are marked with a ManagedBy tag or
                # the stack description commonly includes "SAM"
                description = s.get("TemplateDescription", "") or ""
                is_sam = (
                    tags.get("ManagedBy", "").upper() == "SAM"
                    or "AWS SAM" in description
                    or "serverless" in stack_name.lower()
                )

                stacks.append(
                    CloudFormationStack(
                        account_id=account_id,
                        account_alias=account_alias,
                        region=region,
                        stack_name=stack_name,
                        stack_id=s.get("StackId", ""),
                        status=s.get("StackStatus", ""),
                        description=description,
                        tags=tags,
                        is_cdk=is_cdk,
                        is_sam=is_sam,
                        is_cdk_bootstrap=is_cdk_bootstrap,
                    )
                )
    except Exception as exc:
        if is_scp_denial(exc):
            log.debug("CloudFormation list_stacks in %s (SCP denied)", region)
        else:
            log.warning("CloudFormation list_stacks failed in %s: %s", region, exc)

    return stacks


def build_iac_summary(
    account_id: str,
    account_alias: str,
    cfn_stacks: list[CloudFormationStack],
    s3_bucket_names: list[str],
    dynamodb_table_names: list[str],
    ec2_tags: list[dict[str, str]],
    rds_tags: list[dict[str, str]],
) -> IaCSummary:
    """Aggregate IaC signals across all regions into a single summary.

    Called once after all region scans complete, using the already-collected
    S3, DynamoDB, EC2, and RDS data to avoid extra API calls.
    """
    tools: set[str] = set()
    tag_tools: set[str] = set()

    # ── CloudFormation / CDK / SAM ────────────────────────────────────────────
    cfn_count = len(cfn_stacks)
    cdk_count = sum(1 for s in cfn_stacks if s.is_cdk and not s.is_cdk_bootstrap)
    sam_count = sum(1 for s in cfn_stacks if s.is_sam)
    cdk_bootstrap = any(s.is_cdk_bootstrap for s in cfn_stacks)

    if cfn_count > 0:
        tools.add("CloudFormation")
    if cdk_count > 0 or cdk_bootstrap:
        tools.add("CDK")
    if sam_count > 0:
        tools.add("SAM")

    # ── Terraform — S3 state buckets ─────────────────────────────────────────
    tf_buckets = [
        name
        for name in s3_bucket_names
        if any(pat in name.lower() for pat in _TERRAFORM_BUCKET_PATTERNS)
    ]
    if tf_buckets:
        tools.add("Terraform")

    # ── Pulumi — S3 state buckets ─────────────────────────────────────────────
    pulumi_buckets = [
        name
        for name in s3_bucket_names
        if any(pat in name.lower() for pat in _PULUMI_BUCKET_PATTERNS)
    ]
    if pulumi_buckets:
        tools.add("Pulumi")

    # ── Terraform — DynamoDB lock tables ─────────────────────────────────────
    tf_lock_tables = [
        name
        for name in dynamodb_table_names
        if any(pat in name.lower() for pat in _TERRAFORM_LOCK_PATTERNS)
    ]
    if tf_lock_tables:
        tools.add("Terraform")

    # ── Tag-based signals across EC2 + RDS ───────────────────────────────────
    for tags in ec2_tags + rds_tags:
        for key, value in tags.items():
            key_lower = key.lower()
            val_lower = value.lower()
            # Terraform managed-by tags
            if key_lower in _TERRAFORM_TAG_KEYS or val_lower in _TERRAFORM_TAG_VALUES:
                tag_tools.add("Terraform")
            # Pulumi tags
            if "pulumi" in key_lower or "pulumi" in val_lower:
                tag_tools.add("Pulumi")
            # CDK bootstrap tags injected into non-stack resources
            if key_lower.startswith("aws:cdk:"):
                tag_tools.add("CDK")

    tools |= tag_tools

    # ── DevOps opportunity score ──────────────────────────────────────────────
    if "Terraform" in tools or "Pulumi" in tools or "CDK" in tools:
        opportunity = "High"
    elif "CloudFormation" in tools or "SAM" in tools:
        opportunity = "Medium"
    elif tools:
        opportunity = "Low"
    else:
        opportunity = "None"

    return IaCSummary(
        account_id=account_id,
        account_alias=account_alias,
        has_iac=bool(tools),
        tools_detected=sorted(tools),
        devops_opportunity=opportunity,
        cloudformation_stack_count=cfn_count,
        cdk_stack_count=cdk_count,
        cdk_bootstrap_detected=cdk_bootstrap,
        sam_stack_count=sam_count,
        terraform_state_buckets=tf_buckets,
        terraform_lock_tables=tf_lock_tables,
        pulumi_state_buckets=pulumi_buckets,
        tag_detected_tools=sorted(tag_tools),
        cfn_stacks=cfn_stacks,
    )
