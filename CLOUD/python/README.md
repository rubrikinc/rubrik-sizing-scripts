# Cloud sizing tools (Python)

Read-only discovery tools for AWS, Azure and GCP. Each one scans the accounts, subscriptions or projects you choose,
writes the sizing numbers as CSV files (and a JSON record) into a single zip, and tells you before it starts what its
sign-in can and cannot read.

| Cloud | Folder | Python | Sign in with |
|-------|--------|--------|--------------|
| AWS | `aws/` | 3.9 or newer | the AWS CLI (`aws sso login`, `aws login`) or any credentials boto3 finds |
| Azure | `azure/` | 3.10 or newer | the Azure CLI (`az login`) |
| GCP | `gcp/` | 3.10 or newer | `gcloud auth application-default login` |

## Quick start

Every tool works the same way: sign in, install, run, then send the zip it writes.

```
cd aws
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python main.py --help
```

Use `azure` or `gcp` in place of `aws` for those clouds. Then sign in and run, for example:

| Cloud | Sign in | Run |
|-------|---------|-----|
| AWS | `aws sso login --profile NAME` | `AWS_PROFILE=NAME python main.py --output ./output` |
| Azure | `az login` | `python main.py --subs SUBSCRIPTION_ID --output ./output` |
| GCP | `gcloud auth application-default login` | `python main.py --projects PROJECT_ID --output ./output` |

The run guides in `docs/run-guides/` build a ready-to-run script from a few choices in a browser.

## What you get

One zip per run, named `<cloud>_sizing_results_<timestamp>.zip`:

- the CSV files (the `--no-csv` option leaves them out),
- the JSON record of the run (left out of an anonymized run, which has real names in it),
- `<cloud>_preflight_check-<timestamp>.csv`, the access check described below,
- `output_<cloud>_<timestamp>.log`, the run log.

The user guide lists every file.

## Before the scan: the access check

Before it collects anything the tool makes one small read-only call for each service it will use, and prints a table of
what its sign-in can and cannot read:

```
  SERVICE            PERMISSION               ACCESS   WHERE           FOUND          IMPACT
  -----------------  -----------------------  -------  --------------  -------------  -------------
  rds instances      rds:DescribeDBInstances  MISSING  2 of 17 regions  -             aws_rds_info
  ec2 instances      ec2:DescribeInstances    granted  all 17 regions   yes (1 of 17)  -
```

A `MISSING` row names the permission and the output files that will be empty or partial because of it. The scan still
runs. `--no-preflight` skips the check. See `docs/user-guide.md` for how to read the table.

## The run log

The log in the zip is a transcript of the screen: what you saw, in the same order, as plain text. It has a header (which
code, which options) and ends with a summary that lists each distinct problem once, with how often it happened, one
example and what to do about it. Library debug output is not in it. See `docs/logging.md`.

## When something goes wrong

Read the `Fix:` line under the problem in the run summary: it says what to do and points to a section of
`docs/troubleshooting.md`. That page also covers the problems that stop a run before the log starts.

## Documentation

| Page | For |
|------|-----|
| `docs/user-guide.md` | running a scan from start to finish, reading the screen, the output files, every option |
| `docs/troubleshooting.md` | what each error means and what to do |
| `docs/permissions.md` | the access each tool needs, and what a missing permission costs you |
| `docs/logging.md` | how the run log and the problem summary work, and how to add a fix |
| `docs/aws-vs-powershell.md` | how the AWS output and log differ from the PowerShell script's, and why |
| `docs/gcp-vs-powershell.md`, `docs/azure-vs-powershell.md` | the same for GCP and Azure |
| `docs/run-guides/` | the browser pages that generate run scripts |
| `CLAUDE.md` | notes for developers working on the code |

## Environments

Used on macOS with Python 3.13 and 3.14. Linux and the cloud shells are expected to work but have not been checked here.
Native Windows has not been tried; use WSL or a cloud shell.

## Read-only

The tools list and describe; they do not create, change or delete anything in the cloud. The one thing you can ask for
is AWS `--bucket`, which also uploads the AWS results to an S3 bucket you own.
