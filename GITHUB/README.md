# GitHub Sizing Instructions

Instructions for counting GitHub repositories in a customer's organization. This data is used for Rubrik sizing and capacity planning.

> **Note:** Counts include forks and archived repositories by default (everything the org owns). Use `--source` to exclude forks, `--no-archived` to exclude archived repos, or `--visibility public/private` to filter by visibility.

---

## 1. From the GitHub UI

1. Go to `https://github.com/orgs/<org-name>/repositories`
2. Browse the repository list — use the type/language filters to narrow down if needed.

> The page is paginated and filtered by default, so use the CLI method below for an accurate count.

---

## 2. From the CLI (GitHub CLI — `gh`)

The [GitHub CLI (`gh`)](https://cli.github.com/) must be installed and authenticated before running these commands.

### Count repositories for a specific user or organization

```bash
gh repo list <username_or_org> --limit 10000 | wc -l
```

Replace `<username_or_org>` with the customer's GitHub username or organization name.

**Examples:**

```bash
# Count repos for the org "acme-corp"
gh repo list acme-corp --limit 10000 | wc -l

# Count repos for a specific user
gh repo list johndoe --limit 10000 | wc -l
```

### Count repositories for the authenticated user

```bash
gh repo list --limit 10000 | wc -l
```

> **Always use `--limit 10000`.** Without it, `gh repo list` caps at 30 results — an org with 250 repos would silently report 30, understating the customer's footprint and corrupting the estimate.

---

## Prerequisites

| Method | Requirements |
|--------|-------------|
| GitHub UI | Browser access to `github.com` with org membership |
| GitHub CLI | [Install `gh`](https://cli.github.com/), then run `gh auth login` |

### Token scope for the CLI

`gh auth login` must be completed with a token that has **`repo` scope and org membership**. Without these, private repositories are invisible and won't be counted — typically the majority of a customer's repos.

To verify your token has the right scopes:

```bash
gh auth status
```

Look for `repo` in the token scopes listed. If it's missing, re-authenticate:

```bash
gh auth login --scopes repo,read:org
```
