"""SQS queue count collector."""

from __future__ import annotations

import logging

from models.discovery import SQSRegionCount

from collectors import DenialTracker, is_scp_denial


def fetch_sqs(
    session,
    region: str,
    account_id: str,
    account_alias: str,
    tracker: "DenialTracker | None" = None,
) -> SQSRegionCount:
    """Count all SQS queues in the region."""
    client = session.client("sqs", region_name=region)
    count = 0
    try:
        paginator = client.get_paginator("list_queues")
        for page in paginator.paginate():
            count += len(page.get("QueueUrls", []))
    except Exception as exc:
        if is_scp_denial(exc):
            if tracker is not None:
                tracker.record("sqs")
            logging.debug("Could not list SQS queues in %s (SCP denied)", region)
        else:
            logging.warning("Could not list SQS queues in %s: %s", region, exc)
    return SQSRegionCount(
        account_id=account_id, account_alias=account_alias, region=region, queue_count=count
    )
