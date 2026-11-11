"""KMS keys: the per-region count and the per-key rows (``Get-AWSKMSInventory``)."""

from __future__ import annotations

import logging
import math
from datetime import datetime, timezone
from decimal import Decimal

from models.discovery import KMSKey, KMSRegionCount

from collectors import DenialTracker, is_scp_denial, record_metric_failures


def fetch_kms(
    session,
    region: str,
    account_id: str,
    account_alias: str,
    tracker: "DenialTracker | None" = None,
) -> KMSRegionCount:
    """Count all KMS keys in the region."""
    client = session.client("kms", region_name=region)
    count = 0
    try:
        paginator = client.get_paginator("list_keys")
        for page in paginator.paginate():
            count += len(page.get("Keys", []))
    except Exception as exc:
        if is_scp_denial(exc):
            if tracker is not None:
                tracker.record("kms")
            logging.debug("Could not list KMS keys in %s (SCP denied)", region)
        else:
            logging.warning("Could not list KMS keys in %s: %s", region, exc)
    return KMSRegionCount(
        account_id=account_id, account_alias=account_alias, region=region, key_count=count
    )


def _iso_ticks(value) -> str:
    """UTC ISO 8601 with seven fractional digits, like PowerShell's ``ToString('o')``.

    PowerShell's SDK turns the API's epoch seconds (a binary double) into 100 ns ticks by
    truncating the double's exact value, so a time of ``.941`` is written ``.9409999``. The same
    truncation is applied here so the text matches digit for digit.
    """
    if value is None:
        return ""
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    seconds, ticks = divmod(math.floor(Decimal(value.timestamp()) * 10_000_000), 10_000_000)
    stamp = datetime.fromtimestamp(seconds, timezone.utc)
    return stamp.strftime("%Y-%m-%dT%H:%M:%S") + f".{ticks:07d}Z"


def fetch_kms_inventory(
    session,
    region: str,
    account_id: str,
    account_alias: str,
    tracker: "DenialTracker | None" = None,
) -> tuple[KMSRegionCount, list[KMSKey]]:
    """Every key (AWS-managed and customer-managed) with its aliases, plus the key count.

    A key that cannot be described is skipped and recorded; one that cannot be listed for
    aliases keeps an empty alias.
    """
    client = session.client("kms", region_name=region)
    keys: list[KMSKey] = []
    key_ids: list[str] = []
    errors: list[Exception] = []
    try:
        for page in client.get_paginator("list_keys").paginate():
            key_ids.extend(k["KeyId"] for k in page.get("Keys", []))
    except Exception as exc:
        if is_scp_denial(exc):
            if tracker is not None:
                tracker.record("kms")
            logging.debug("Could not list KMS keys in %s (SCP denied)", region)
        else:
            record_metric_failures(tracker, region, "KMS list_keys", [exc], service="kms")
        count = KMSRegionCount(account_id, account_alias, region, 0)
        return count, keys

    for key_id in key_ids:
        try:
            meta = client.describe_key(KeyId=key_id)["KeyMetadata"]
        except Exception as exc:
            errors.append(exc)
            continue
        alias = ""
        try:
            aliases = [
                a["AliasName"]
                for page in client.get_paginator("list_aliases").paginate(KeyId=key_id)
                for a in page.get("Aliases", [])
            ]
            alias = "; ".join(aliases)
        except Exception as exc:
            errors.append(exc)
        keys.append(
            KMSKey(
                account_id=account_id,
                account_alias=account_alias,
                region=region,
                alias=alias,
                key_id=meta.get("KeyId", key_id),
                arn=meta.get("Arn", ""),
                key_manager=meta.get("KeyManager", ""),
                key_state=meta.get("KeyState", ""),
                creation_date=_iso_ticks(meta.get("CreationDate")),
            )
        )
    record_metric_failures(tracker, region, "KMS key details", errors, service="kms")
    return KMSRegionCount(account_id, account_alias, region, len(key_ids)), keys
