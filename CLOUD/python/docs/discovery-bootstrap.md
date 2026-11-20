# Python Cloud Discovery — Bootstrap, Packaging and Publishing (INTERNAL)

> **This document is private by construction.** It is not on the public-mirror
> allowlist, so it never reaches `rubrikinc/rubrik-sizing-scripts`. Do not copy
> internal content (bucket names, private test paths, threat-model notes) into
> `../CLAUDE.md` or `../README.md` — those two files **are** mirrored publicly.

## Overview

Python discovery CLIs for **AWS**, **Azure** and **GCP**. A customer runs one
line in their cloud shell; the script pulls this source from GitHub at a ref,
`pip install`s it, and runs a read-only discovery that ends in a single ZIP
(raw discovery JSON + a full-DEBUG run log). The SE builds reports from that
JSON elsewhere — nothing SE-side lives in this tree.

- **Owner:** Sizing Engineering (`SIZENG` / `Cloud sizing script`)
- **Language:** Python (aws ≥ 3.9, azure/gcp ≥ 3.10) + bash bootstrap
- **Architecture:** three independent tools, no shared code, no shared deps.
  Each cloud dir is its own pip project.
- **Delivery:** "source-at-ref". The public mirror carries git content only
  (no tags, Releases or artifacts), so there is no wheel to download. The
  bootstrap streams the repo tarball for a ref and installs the extracted dir.

## Code Map

| Path | Purpose |
|------|---------|
| `aws/install.sh` | AWS bootstrap + `--org`/`--sso` orchestration. `set -uo pipefail` (no `-e`), no `die()` |
| `azure/install.sh` | Azure bootstrap. `set -euo pipefail`, has `die()` |
| `gcp/install.sh` | GCP bootstrap. `set -euo pipefail`, has `die()` |
| `<cloud>/pyproject.toml` | Packaging. Build backend pinned `setuptools==82.0.1` (newest that supports py3.9) |
| `<cloud>/main.py` | CLI entry. Console scripts: `aws-sizing`, `rubrik-discovery` (Azure), `rubrik-gcp-discovery` |
| `<cloud>/collectors/`, `models/` | One resource type per file; typed dataclasses; every call wrapped (graceful degradation) |
| `<cloud>/logging_setup.py` | Writes the always-DEBUG run `.log` that goes in the ZIP |
| `aws/iac/2-sizing-tool-spokes.yaml` | The CloudFormation template `--org` deploys as a StackSet (the spoke role) |
| `tests/bootstrap/` | Tests for the bootstrap block (see below) |
| `<cloud>/tests/` | Per-cloud unit tests (SDK calls mocked). **Never published** |

`requirements.txt` files, `*/tests/**`, `gcp/conftest.py` and everything under `docs/` are all outside the publish
surface.

## How It Works

Each bootstrap script embeds a **byte-identical** `fetch_source <cloud>` block
between `BEGIN`/`END` markers (`test_drift.py` enforces this — edit all three
together). It:

1. Streams `codeload` tarball for `RUBRIK_DISCOVERY_REF` (default `master`).
2. Extracts only `CLOUD/python/<cloud>` with Python `tarfile` (rejects
   absolute/`..` paths and symlinks).
3. If the ref is a full commit SHA, fails closed unless the tarball's pax
   global header carries that same SHA.
4. `pip install <dir>`, then runs the console script.
5. Cleans up via an `EXIT` trap (`_src_cleanup`).

Globals set for the caller: `_SRC_ROOT`, `SRC_DIR`, `_SRC_REF`, `_SRC_COMMIT`,
`_SRC_VERSION`, `_SRC_PINNED`.

| Env var | Meaning |
|---------|---------|
| `RUBRIK_DISCOVERY_REF` | Branch, tag or full SHA. Default `master`. SE engagements should pin a SHA |
| `RUBRIK_DISCOVERY_SOURCE_URL` | Tarball URL. `https` only, plus `file://` and loopback `http` for tests |
| `RUBRIK_DISCOVERY_SOURCE_SUBDIR` | Default `CLOUD/python/${cloud}`. Override when testing from this private tree |

AWS `--org` deploys the spokes StackSet with
`--template-body file://${SRC_DIR}/iac/2-sizing-tool-spokes.yaml`.
CloudFormation `--template-url` accepts **S3 URLs only**, so a GitHub URL
cannot be used there.

No token/PAT code ships. Private testing never needs one (see below).

## Publish Surface — the allowlist rule

**`sizing_scripts/cloud/python` is mirrored in full to `rubrikinc/rubrik-sizing-scripts` as `CLOUD/python`, so every file
under `python/` is public.** Nothing in it may name a bucket, an internal tool or a real customer identifier (see
`tests/bootstrap/test_deny_list.py`).

- `ci/sizing_scripts_code_mirroring/Jenkinsfile` maps `sizing_scripts/cloud` → `CLOUD/` with no `excludes`, so `python/`
  is synced with the rest of the folder. Before this, the mapping had `excludes: ['python']` and Python was not public.
- `sizing_scripts/cloud/.gitignore` is mirrored as `CLOUD/.gitignore` and ignores `*.txt`, `*.log` and `*.zip`. It
  re-includes `python/**/requirements*.txt`; without that, `git add` in the mirror job skips them and the tools cannot
  install. Any other new `.txt`, `.log` or `.zip` file under `python/` needs the same kind of exception.
- The rest of this section describes the allowlist design (a `cloud-python.rsync-filter`, a golden manifest and a
  Jenkins gate, "PR-B") that the mirror job does not use. It is kept for the review of what each published file must
  contain, not as the current publish mechanism.
- PR-B adds `cloud-python.rsync-filter` (explicit `*.py` globs, trailing
  `- *`), a golden `cloud-python.expected-manifest.txt`, and a Jenkins gate
  that compares the **git index** to the manifest and greps it against the
  deny-list before pushing.
- Check the index (`git grep --cached`), never the rsync output tree: the
  public `CLOUD/.gitignore` has `*.txt`, `*.log`, `*.zip`, so ignored files
  vanish from `git status` but are still on disk.
- `tests/bootstrap/test_deny_list.py` holds the deny regex and the per-cloud
  `PUBLISHED` dict. Keep it in step with `cloud-python.rsync-filter`.
- Adding a published file = edit filter + manifest + `PUBLISHED`, and get
  named Sizing Eng and Security sign-off on the manifest diff.
- **The AWS `PUBLISHED` list is behind the code.** It names `main.py`, `logging_setup.py`,
  `collectors/*.py` and `models/*.py`, but `main.py` also imports `accounts.py`, `anonymize.py`
  and `csv_export.py`, and since the backup plan work `csv_export.py` and `main.py` import
  `backup_plan_membership.py` and `plans_json.py` too (all are in `aws/pyproject.toml`
  `py-modules`, so the pip install is complete). A mirror built from the list as it stands
  would not run. PR-B has to add all five top-level modules to the filter, the manifest and
  `PUBLISHED`, with the sign-off above; none of them has been through the deny-list check as
  a published file (a scan of `backup_plan_membership.py`, `plans_json.py`, `csv_export.py`,
  `main.py` and `anonymize.py` found no hits).
- **The pre-flight check adds two top-level modules to each tool**, `preflight.py` and `preflight_core.py`
  (aws, azure and gcp; all six are in the `pyproject.toml` `py-modules`, and `main.py` imports `preflight`
  unconditionally). PR-B has to add them to the filter, the manifest and `PUBLISHED`, or a mirror install fails
  with an `ImportError`. They are in `PUBLISHED` in `test_deny_list.py` already, and a scan found no hits.
- **The AWS, Azure and GCP totals blocks add `totals.py`** to each tool, imported by `main.py` and listed in `py-modules`; like
  `csv_export.py` it is not in `PUBLISHED` yet, so the mirror allowlist must add it with the other modules of each tool.
- **The run log adds two more**, `runlog.py` and `runlog_core.py`, to each tool (in `py-modules`; `main.py` and
  `logging_setup.py` import them unconditionally), with the same mirror requirement and the same entries in
  `PUBLISHED`.
- **Resuming adds `checkpoint_core.py` to each tool and `resume.py` to Azure and GCP** (all in `py-modules`; `main.py`
  imports them unconditionally). The mirror publishes the whole folder, so they are public when this merges and need no
  allowlist entry. `test_no_published_python_file_contains_a_denied_string` scans every non-test `.py` under each tool,
  not only the `PUBLISHED` list, so they and any later module are covered without a list to update.
- Rollback = tighten the allowlist (filter + manifest). Emergency stop = a PR
  replacing the filter with only `- *` and emptying the manifest. **Never
  remove the folder mapping.** A manual `git rm` in the public repo is valid
  only after the cron is paused or the `- *` PR has merged.

## Testing

### Bootstrap tests

```bash
cd sizing_scripts/cloud/python
python3 -m venv /tmp/bs-venv && /tmp/bs-venv/bin/pip install pytest
/tmp/bs-venv/bin/python -m pytest tests/bootstrap -q
```

Use a venv with pytest — the default `python3` on a dev laptop may be some other
project's venv. No cloud credentials, no network: the scripts run against PATH
shims (`make_cloud_shims`, `run_script`) and a loopback tarball server.

| File | Covers |
|------|--------|
| `bootstrap_support.py` | Helpers: tarball builders, loopback `Server`, cloud shims, `run_fetch`, `run_script` |
| `test_fetch_source.py` | The block itself: ref/pin handling, tarfile safety, fail-closed paths |
| `test_bootstrap_e2e.py` | The real `install.sh` of each cloud against PATH shims |
| `test_drift.py` | Block byte-identical across the three scripts; each parses under every available bash |
| `test_deny_list.py` | Deny regex vs. the allowlisted file set |

Only the local `bash` is exercised (macOS ships 3.2). Run on Linux / newer bash
before relying on a change.

### Per-cloud suites

```bash
cd sizing_scripts/cloud/python/<cloud> && python -m pytest tests -q
```

Azure is **red on master** (5 failures + 1 collection error): the SE-side
`output/`, `analysis/`, `examples/` dirs were not migrated. Compare against that
baseline, not against green.

### Private end-to-end path (before anything is public)

Use a `git archive` tarball and `file://`; no token, no public repo needed.

```bash
git archive --format=tar.gz -o ~/src.tgz HEAD sizing_scripts/cloud/python
# upload ~/src.tgz to the cloud shell, then:
cd <upload dir>/…/aws
RUBRIK_DISCOVERY_SOURCE_URL=file://$HOME/src.tgz \
RUBRIK_DISCOVERY_SOURCE_SUBDIR=sizing_scripts/cloud/python/aws \
  bash ./install.sh --sso --role-name ReadOnlyAccess
```

Same pattern for `azure/install.sh` and `gcp/install.sh` (change the subdir).

## Common Gotchas

1. **`set -e` is ignored inside a function called in an `||` list.** Every step
   in `fetch_source` ends `|| return 1` for this reason. Don't "tidy" those
   away, and don't call `fetch_source` in a context that swallows its status.
2. **The three scripts do not share shell options.** AWS: `set -uo pipefail`,
   failure handled at the call site (`if ! fetch_source aws; then err …; exit 1`).
   Azure/GCP: `set -euo pipefail` + `fetch_source <cloud> || die "…"`. A change
   that is safe in one can abort or silently continue in another.
3. **bash 3.2 mis-parses unbalanced apostrophes inside `$(cat <<'PY' …)`.**
   The embedded Python must avoid stray `'` even in comments.
4. **One cloud per shell / venv.** The three projects expose top-level modules
   with the same names (`main`, `auth`, `config`, `logging_setup`). Installing
   two into one venv makes `rubrik-discovery` silently run GCP's `main.py`.
5. **Fetch before uninstall.** Azure/GCP fetch the new source *before*
   `pip uninstall` so a network failure doesn't leave the customer with no tool.
6. **Script/source skew.** The one-liner fetches the script from
   `raw.githubusercontent.com` (≈5 min CDN cache) while the source comes from
   the tarball — a merge landing between the two can skew them. SHA pinning
   (`RUBRIK_DISCOVERY_REF=<sha>`) removes it.
7. **Master is the release gate.** Merge to `master` → mirrored within 6 h
   (cron `0 */6 * * *`). Treat every merge touching an allowlisted file as a
   publish.
8. **Don't reintroduce `--mock` customer docs.** Azure `--mock` needs SE-side
   fixtures that are not published; `_mock_fixtures_available()` gives a
   friendly message instead of a traceback.
9. **`aws-sizing` with no credentials** prints a short message and exits 1 (a sign-in problem is explained, not
   shown as a traceback). Any other error still raises with its traceback.
10. **Customer-facing text lives in the public `../README.md` and
    `python/README.md`** — not here.

## PR Ordering

- **PR-A** (bootstrap + packaging + this doc): touches only
  `sizing_scripts/cloud/python/**` and `sizing_scripts/.plans/`. Inert publicly
  because Python is still excluded. Verify with
  `git diff --name-only origin/master` and state the result in the PR body.
- Then: private real-shell verification, publication review gate
  (sign-offs, trufflehog, deny-list clean run, `azure/config.py` decision).
- **PR-B** (mirror allowlist + public docs) merges **last**, branched from or
  rebased onto master after PR-A. The cron publishes on its next tick after
  merge; do a Jenkins dry run on the PR branch first.
- Post-publish: anonymous verification of the one-liners, then the SHA-pinned
  form before advertising the pin check.

Full plan: `sizing_scripts/.plans/github-native-python-discovery.md`.

## Quick Reference

```bash
# Bootstrap tests
cd sizing_scripts/cloud/python && /tmp/bs-venv/bin/python -m pytest tests/bootstrap -q

# What would a PR-A push touch?
git diff --name-only origin/master

# Run a cloud tool from a local checkout (dev)
cd aws   && pip install . && aws-sizing --help
cd azure && pip install . && rubrik-discovery --help
cd gcp   && pip install . && rubrik-gcp-discovery --help   # separate venv each
```
