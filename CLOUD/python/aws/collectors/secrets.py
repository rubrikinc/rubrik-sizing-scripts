"""Secrets Manager secret count collector."""

from __future__ import annotations

import logging

from models.discovery import SecretsRegionCount

from collectors import DenialTracker, is_scp_denial


def fetch_secrets(
    session,
    region: str,
    account_id: str,
    account_alias: str,
    tracker: "DenialTracker | None" = None,
) -> SecretsRegionCount:
    """Count all Secrets Manager secrets in the region."""
    client = session.client("secretsmanager", region_name=region)
    count = 0
    try:
        paginator = client.get_paginator("list_secrets")
        for page in paginator.paginate():
            count += len(page.get("SecretList", []))
    except Exception as exc:
        if is_scp_denial(exc):
            if tracker is not None:
                tracker.record("secrets")
            logging.debug("Could not list secrets in %s (SCP denied)", region)
        else:
            logging.warning("Could not list secrets in %s: %s", region, exc)
    return SecretsRegionCount(
        account_id=account_id, account_alias=account_alias, region=region, secret_count=count
    )
