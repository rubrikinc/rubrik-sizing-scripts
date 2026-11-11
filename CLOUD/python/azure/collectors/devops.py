"""Azure DevOps repository collector for Rubrik Discovery.

Discovers Azure DevOps organizations, projects, and Git repositories using
the Azure DevOps REST API.  Authentication reuses the same
``DefaultAzureCredential`` as the rest of the tool, scoped to the Azure
DevOps resource (``499b84ac-1321-427f-aa17-267ca6975798``).

Flow:
  1. Acquire AAD token for the Azure DevOps resource.
  2. Enumerate organisations the identity belongs to (VSSPS API).
  3. For each org (or filtered subset), list projects + repos.
  4. Roll up counts and sizes.

The collector is optional — it only runs when the identity has Azure DevOps
access.  Permission failures are logged and skipped gracefully.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

import requests

logger = logging.getLogger(__name__)

_DEVOPS_RESOURCE = "499b84ac-1321-427f-aa17-267ca6975798/.default"
_VSSPS_BASE = "https://app.vssps.visualstudio.com"
_DEVOPS_API_VERSION = "7.1-preview.1"
_API_VERSION = "7.1-preview.1"


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class DevOpsRepo:
    name: str
    project_name: str
    org_name: str
    default_branch: Optional[str] = None
    size_bytes: int = 0
    url: Optional[str] = None
    is_disabled: bool = False


@dataclass
class DevOpsProject:
    name: str
    org_name: str
    project_id: str = ""
    state: str = ""
    repo_count: int = 0
    repos: list[DevOpsRepo] = field(default_factory=list)


@dataclass
class DevOpsOrg:
    name: str
    account_id: str = ""
    projects: list[DevOpsProject] = field(default_factory=list)
    total_projects: int = 0
    total_repos: int = 0
    total_repo_size_bytes: int = 0


@dataclass
class DevOpsInventory:
    orgs: list[DevOpsOrg] = field(default_factory=list)
    total_orgs: int = 0
    total_projects: int = 0
    total_repos: int = 0
    total_repo_size_gb: float = 0.0
    org_names: list[str] = field(default_factory=list)
    data_note: str = ""


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------


class DevOpsCollector:
    """Collects Azure DevOps org/project/repo inventory."""

    def __init__(
        self,
        credential,
        org_filter: Optional[list[str]] = None,
    ):
        self._credential = credential
        self._org_filter = [o.lower() for o in org_filter] if org_filter else None
        self._token: Optional[str] = None

    def _get_token(self) -> str:
        if self._token is None:
            token = self._credential.get_token(_DEVOPS_RESOURCE)
            self._token = token.token
        return self._token

    def _get(self, url: str, params: Optional[dict] = None) -> Optional[dict]:
        headers = {
            "Authorization": f"Bearer {self._get_token()}",
            "Accept": "application/json",
        }
        try:
            resp = requests.get(url, headers=headers, params=params, timeout=30)
            if resp.status_code == 401:
                logger.warning("Azure DevOps: 401 Unauthorized for %s", url)
                return None
            if resp.status_code == 403:
                logger.warning("Azure DevOps: 403 Forbidden for %s", url)
                return None
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException as exc:
            logger.warning("Azure DevOps API error: %s", exc)
            return None

    def discover_orgs(self) -> list[dict]:
        profile = self._get(
            f"{_VSSPS_BASE}/_apis/profile/profiles/me",
            params={"api-version": _API_VERSION},
        )
        if not profile:
            logger.warning("Could not fetch Azure DevOps profile — skipping org discovery.")
            return []

        member_id = profile.get("id")
        if not member_id:
            logger.warning("Azure DevOps profile has no id — skipping org discovery.")
            return []

        accounts = self._get(
            f"{_VSSPS_BASE}/_apis/accounts",
            params={"memberId": member_id, "api-version": _API_VERSION},
        )
        if not accounts:
            return []

        orgs = accounts if isinstance(accounts, list) else accounts.get("value", [])

        if self._org_filter:
            orgs = [o for o in orgs if (o.get("accountName") or "").lower() in self._org_filter]

        return orgs

    def _list_projects(self, org_name: str) -> list[dict]:
        url = f"https://dev.azure.com/{org_name}/_apis/projects"
        result = self._get(url, params={"api-version": _API_VERSION, "$top": 500})
        if not result:
            return []
        return result.get("value", [])

    def _list_repos(self, org_name: str, project_name: str) -> list[dict]:
        url = f"https://dev.azure.com/{org_name}/{project_name}/_apis/git/repositories"
        result = self._get(url, params={"api-version": _API_VERSION})
        if not result:
            return []
        return result.get("value", [])

    def collect(self) -> DevOpsInventory:
        inventory = DevOpsInventory()

        try:
            self._get_token()
        except Exception as exc:
            logger.warning(
                "Could not acquire Azure DevOps token — identity may not "
                "have DevOps access. Skipping DevOps discovery. (%s)",
                exc,
            )
            inventory.data_note = (
                "Azure DevOps token unavailable — identity may not have DevOps access."
            )
            return inventory

        raw_orgs = self.discover_orgs()
        if not raw_orgs:
            inventory.data_note = "No Azure DevOps organizations found."
            return inventory

        for raw_org in raw_orgs:
            org_name = raw_org.get("accountName", "")
            org_id = raw_org.get("accountId", "")
            if not org_name:
                continue

            org = DevOpsOrg(name=org_name, account_id=org_id)

            projects_raw = self._list_projects(org_name)
            for proj_raw in projects_raw:
                proj_name = proj_raw.get("name", "")
                proj = DevOpsProject(
                    name=proj_name,
                    org_name=org_name,
                    project_id=proj_raw.get("id", ""),
                    state=proj_raw.get("state", ""),
                )

                repos_raw = self._list_repos(org_name, proj_name)
                for repo_raw in repos_raw:
                    repo = DevOpsRepo(
                        name=repo_raw.get("name", ""),
                        project_name=proj_name,
                        org_name=org_name,
                        default_branch=repo_raw.get("defaultBranch"),
                        size_bytes=repo_raw.get("size", 0) or 0,
                        url=repo_raw.get("webUrl"),
                        is_disabled=repo_raw.get("isDisabled", False),
                    )
                    proj.repos.append(repo)

                proj.repo_count = len(proj.repos)
                org.projects.append(proj)

            org.total_projects = len(org.projects)
            org.total_repos = sum(p.repo_count for p in org.projects)
            org.total_repo_size_bytes = sum(r.size_bytes for p in org.projects for r in p.repos)
            inventory.orgs.append(org)

        inventory.total_orgs = len(inventory.orgs)
        inventory.total_projects = sum(o.total_projects for o in inventory.orgs)
        inventory.total_repos = sum(o.total_repos for o in inventory.orgs)
        inventory.total_repo_size_gb = round(
            sum(o.total_repo_size_bytes for o in inventory.orgs) / (1024**3), 3
        )
        inventory.org_names = [o.name for o in inventory.orgs]
        return inventory
