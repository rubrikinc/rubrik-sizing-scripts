# Run guides

One HTML page per cloud that turns a few choices into a ready-to-run `run-<cloud>-sizing.sh` script. Open the page in a
browser, pick the scope and options, and copy the script it shows (or download it).

| Guide | Script it generates | Runs |
|-------|---------------------|------|
| `aws-run-guide.html` | `run-aws-sizing.sh` | the AWS tool in `../../aws` |
| `azure-run-guide.html` | `run-azure-sizing.sh` | the Azure tool in `../../azure` |
| `gcp-run-guide.html` | `run-gcp-sizing.sh` | the GCP tool in `../../gcp` |

## What a generated script does

1. Finds a `rubrik-sizing-scripts` checkout (or offers to clone `rubrikinc/rubrik-sizing-scripts` over HTTPS, sparse, `CLOUD` only).
2. Creates `.venv`, installs the requirements, and shows who it is signed in as (AWS identity, `az account show`,
   or the active gcloud account).
3. Asks `Continue? [y/N]`, then runs the tool and prints where the zip is.

The scripts never update an existing checkout. The AWS script prints the commit it will run and warns, asking whether to
go on, if the checkout is behind `master`. The Azure and GCP scripts do not check yet, so pull first:
`git -C <checkout> pull --ff-only`.

To share the tools without cloning, `../../packaging/make_cloud_zips.sh` builds one zip per cloud with the tool, its
docs and a quickstart (see `../../packaging/README.md`).

## The examples

`examples/` holds one generated script per cloud so you can read what a guide produces without opening it. They are
**templates, not runnable as they are**: each scans placeholder IDs, and its third line says which to replace.

| Example | Scans | Replace |
|---------|-------|---------|
| `run-aws-sizing.sh` | named accounts through IAM Identity Center (`--sso`) | `YOUR-ORG` in the start URL, `YOUR_PERMISSION_SET`, `ACCOUNT_ID_1,ACCOUNT_ID_2` |
| `run-azure-sizing.sh` | named subscriptions (`--subs`) | `SUBSCRIPTION_ID_1,SUBSCRIPTION_ID_2` |
| `run-gcp-sizing.sh` | named projects (`--projects`) | `PROJECT_ID_1,PROJECT_ID_2` |

Or generate your own from the guide. A script you generate holds your real account, subscription or project IDs, so
keep it local and do not commit it.

`node examples/make_examples.js` rewrites the examples from the guides; `check_guides.js` fails when an example is not
what its guide generates, so run it after changing a guide.

## Defaults the guides choose

- `--verbose` is off. It prints the full debug log of every library to the terminal; the run log in the zip is a
  transcript of the screen either way (see `../logging.md`).
- Azure: the subscription IDs it will scan are listed, and each is marked as known or not to your `az` login, before the
  `Continue?` question.
- Azure: the script installs `requirements.txt`, which has every collector's package, Backup Vaults, Defender and Purview
  included.
- AWS: `--preflight-only` is off. Ticked, the script runs only the access check in each account and looks for
  `aws_access_check_*.zip` instead of the results zip; Stage 7 suggests it as a first pass over many accounts.
- Azure and GCP: `--preflight-only` is off too. Ticked, the script checks access in each subscription or project and
  looks for `azure_access_check_*.zip` or `gcp_access_check_*.zip`.

## Changing a guide

Each page is one self-contained file; the script text is built in the `buildScript` function inside it. After an edit,
run `node check_guides.js` from this folder (it needs `node` and `bash`). It builds scripts from each guide with and
without the options that matter and checks that every one is valid bash and that `--verbose` and the optional installs
appear only when ticked. `tests/bootstrap/test_run_guides.py` runs it when `node` is available.

## These files are public

`sizing_scripts/cloud/python` is mirrored in full to the public `rubrikinc/rubrik-sizing-scripts` repository, so these
pages and scripts are public too. They clone that public repository, and `tests/bootstrap/test_run_guides.py` fails if
a guide or example names anything private (an internal repository, a real account, subscription or project ID, an email
address or a personal path).
