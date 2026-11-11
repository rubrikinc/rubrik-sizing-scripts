"""Subscription-wide tag names, as PowerShell's ``Get-AzTag`` lists them."""

from __future__ import annotations

import logging
from typing import Any

from azure.mgmt.resource import ResourceManagementClient
from cloud import DEFAULT_CLOUD, CloudEnvironment

logger = logging.getLogger(__name__)


def collect_tag_names(
    subscription_id: str,
    credential: Any,
    cloud: CloudEnvironment = DEFAULT_CLOUD,
) -> list[str]:
    """Return every tag name defined in the subscription, in API order.

    PowerShell adds one ``Tag: <name>`` column per name found here, whether or not any exported
    resource carries it. A failure returns an empty list so discovery continues.
    """
    try:
        client = ResourceManagementClient(credential, subscription_id, **cloud.client_kwargs())
        return [t.tag_name for t in client.tags.list() if getattr(t, "tag_name", None)]
    except Exception as exc:
        logger.warning("[%s] Could not list tag names: %s", subscription_id, exc)
        return []
