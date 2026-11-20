# Cloud sizing tools (Python)

Read-only discovery tools for AWS, Azure and GCP. Each one scans the accounts, subscriptions or projects you choose and
writes one zip: the sizing numbers as CSV files, a JSON record and a run log. Before it collects anything it checks what
its sign-in can and cannot read and tells you.

| Cloud | Folder | Python | Sign in with |
|-------|--------|--------|--------------|
| AWS | `aws/` | 3.9 or newer | the AWS CLI (`aws sso login`, `aws login`) or any credentials boto3 finds |
| Azure | `azure/` | 3.10 or newer | the Azure CLI (`az login`) |
| GCP | `gcp/` | 3.10 or newer | `gcloud auth application-default login` |

## Quick start: one line in a cloud shell

This is the default. Open the cloud's own shell, which already has Python and the cloud CLI, sign in if it asks, and
paste one line. It downloads the tool from GitHub, installs it, runs it and leaves one zip for you to download. Nothing
else is needed on your machine. (`bash <(...)` is used instead of `curl | bash` because the AWS script asks questions.)

AWS CloudShell, after `aws sso login`. Replace `PERMISSION_SET` with the name IAM Identity Center shows you, for example
`ReadOnlyAccess`, and type it as is, without angle brackets:

```
bash <(curl -fsSL https://raw.githubusercontent.com/rubrikinc/rubrik-sizing-scripts/master/CLOUD/python/aws/install.sh) --role-name PERMISSION_SET
```

Azure Cloud Shell, already signed in:

```
bash <(curl -fsSL https://raw.githubusercontent.com/rubrikinc/rubrik-sizing-scripts/master/CLOUD/python/azure/install.sh) --all
```

Google Cloud Shell, credentials already set up:

```
bash <(curl -fsSL https://raw.githubusercontent.com/rubrikinc/rubrik-sizing-scripts/master/CLOUD/python/gcp/install.sh) --all
```

When it finishes it prints where the zip is. Download it and send it back:

| Cloud | Where the zip is | How to download it |
|-------|------------------|--------------------|
| AWS | the folder you ran the command in (`./output` with `--single-account`) | CloudShell: **Actions > Download file** |
| Azure | `~/clouddrive`, or `~/rubrik-output` | the Cloud Shell's file download action |
| GCP | your home folder | the Cloud Shell's file download action, or `cloudshell download FILE` |

Those commands scan the default scope: every AWS account your permission set can reach through IAM Identity Center, every
Azure subscription you can read, and every GCP project you can read. To scan less, or to change anything else, add
command-line flags as described next. For a first look at what a scan would touch, add `--preflight-only` and nothing is
collected.

## Before you start

| | In a cloud shell (the quick start) | On your own machine |
|---|---|---|
| Python | already there; check it with `python3 --version` | 3.9 or newer for AWS, 3.10 or newer for Azure and GCP |
| Cloud CLI | already there and signed in (AWS needs `aws sso login` first) | `aws`, `az` or `gcloud`, signed in |
| Install | the one-liner runs `pip install` for you | `pip install -r requirements.txt` in a virtual environment |
| Network | GitHub and PyPI (hosts listed under "What the cloud shell needs to reach") | PyPI, plus the cloud's own APIs |

If the one-liner stops with `Python 3.10+ required (found 3.9)`, that shell's image has an older Python. Use another shell
or machine; `docs/troubleshooting.md` has the details. The shells are updated by their providers, so check the version in
yours instead of assuming it.

Windows: the tools have not been tested on native Windows. Use a cloud shell, which needs nothing installed, or WSL.

If a scan is interrupted, run the same command again from the same folder with `--resume` and it carries on where it
stopped: finished accounts (AWS), subscriptions (Azure) or projects (GCP) are not scanned again, and ones that finished
with gaps are. `--fresh` starts over. A single AWS account is one unit, so there is nothing to resume. All three scan in
parallel, by account on AWS, by subscription on Azure and by project on GCP (`--workers` sets how many).

## Command-line flags

A flag (also called a command-line argument or parameter) is an option that starts with `--`, such as `--regions` or
`--no-cost`, written after the command to change what it does. Some take a value (`--regions eastus,westus2`) and some
are switches with no value (`--no-cost`). They are the same whether you run the one-liner in a cloud shell or run the tool
on your own machine. There are two ways to set them, and you can mix them:

- **Type the flags.** Put them after the command. In a cloud shell that means after the closing parenthesis, and the
  installer passes on anything it does not use itself:

  ```
  bash <(curl -fsSL https://raw.githubusercontent.com/rubrikinc/rubrik-sizing-scripts/master/CLOUD/python/azure/install.sh) --subs SUBSCRIPTION_ID --regions eastus,westus2 --no-cost
  ```

- **Use the command builder.** Open the page for your cloud in a browser, tick what you want, and copy the flags it
  shows. The page runs nothing and uploads nothing; it only builds text.

  | Page | For |
  |------|-----|
  | `docs/run-guides/aws-run-guide.html` | `aws/` |
  | `docs/run-guides/azure-run-guide.html` | `azure/` |
  | `docs/run-guides/gcp-run-guide.html` | `gcp/` |

  The builder writes its command as `python main.py FLAGS`. That is the command for running on your own machine, so for
  a cloud shell copy only the `FLAGS` part and put it after the one-liner. If you pick flags the tool cannot combine,
  the page says why and turns the download off.

### The flags you will use most

| To | AWS | Azure | GCP |
|----|-----|-------|-----|
| scan specific targets | `--accounts ID,ID` | `--subs ID,ID` | `--projects ID,ID` or `--project-file FILE` |
| scan everything the sign-in can read | `--org` | `--all` | no flag needed |
| scan only the current identity | `--single-account` | no flag needed | `--current-project` |
| limit regions | `--regions a,b` or `--exclude-regions a,b` | `--regions a,b` | `--regions a,b` |
| limit what is collected | `--services ec2,rds,s3` | `--skip-vms`, `--skip-backup` and the other `--skip-*` flags | `--collectors asset,compute,storage` |
| skip the slow or billed parts | `--no-cost`, `--no-capacity` | `--no-cost`, `--no-capacity` | not needed |
| use a government cloud | `--partition govcloud` | `--cloud AzureUSGovernment` | no flag needed |
| replace names and IDs in the CSVs | `--anonymize` | `--anonymize` | `--anonymize` |
| only check access, collect nothing | `--preflight-only` | `--preflight-only` | `--preflight-only` |
| preview the scope and the API calls | not available | `--dry-run` | `--dry-run` |

`python main.py --help` lists every flag for a tool. The Options section of `docs/user-guide.md` has the full tables for
all three clouds, and the section before it explains each scope.

### AWS in a cloud shell has a few extra modes

The AWS installer starts an IAM Identity Center (`--sso`) scan unless you choose another mode, and it accepts these:

| Add | To |
|-----|----|
| `--sso-start-url URL` | name the Identity Center start URL, if it is not found in `~/.aws/config` |
| `--accounts ID,ID` | scan only these accounts |
| `--single-account` | scan only the account the current credentials belong to, with no SSO. It ignores `--accounts`, `--role-name` and `--sso-start-url` |
| `--org` | scan the organization through a read-only role it deploys with a StackSet, and remove the StackSet after the scan |
| `--org --deploy-role-only` | deploy that role and stop, so it can be reviewed before any scan. The role stays in place |
| `--org --skip-stackset` | scan an organization whose role is already deployed. It leaves the role alone |
| `--assume-role ARN` | run through a role you have already created |
| `--debug` | print more about the install |

The installer has no flag for `--cross-account-role`, `--profiles` or `--all-profiles`. If you need one of those, run the
tool on your own machine (next section) or download the script the AWS command builder writes.

### Run an exact version

An unpinned line installs whatever is on `master` today. To run one exact version, give a full 40-character commit ID in
both places, the script URL and `RUBRIK_DISCOVERY_REF`. The run stops if the downloaded source is not that commit.

```
S=PASTE_A_FULL_COMMIT_ID_HERE
RUBRIK_DISCOVERY_REF=$S bash <(curl -fsSL https://raw.githubusercontent.com/rubrikinc/rubrik-sizing-scripts/$S/CLOUD/python/azure/install.sh) --all
```

Pinning fixes this repository's code. The Python packages it needs are still downloaded from PyPI at run time.

### What the cloud shell needs to reach

`github.com`, `codeload.github.com`, `raw.githubusercontent.com`, `pypi.org` and `files.pythonhosted.org`. If the shell
blocks them, use the next section from a machine that can, or ask for a zip of the tool (`packaging/README.md`).

## Run it on your own machine instead

Use this when a cloud shell is not an option, or when you want a mode the AWS one-liner does not offer. You run `main.py`
directly, with the same flags. Install once per cloud, in its own virtual environment. Use one environment per cloud: the
three tools share top-level module names, so installing two into one environment makes the wrong one run.

```
cd aws
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python main.py --help
```

Use `azure` or `gcp` in place of `aws` for those clouds. Then sign in and run:

| Cloud | Sign in | Scan one |
|-------|---------|----------|
| AWS | `aws sso login --profile NAME` | `AWS_PROFILE=NAME python main.py --output ./output` |
| Azure | `az login` | `python main.py --subs SUBSCRIPTION_ID --output ./output` |
| GCP | `gcloud auth application-default login` | `python main.py --projects PROJECT_ID --output ./output` |

Here the whole set of flags is available, including the AWS modes the installer lacks: `--cross-account-role ROLE` with
`--accounts`, `--profiles a,b` and `--all-profiles`. AWS with IAM Identity Center needs the permission set name:
`--sso --sso-start-url URL --role-name PERMISSION_SET`. For example:

```
python main.py --sso --sso-start-url https://myorg.awsapps.com/start --role-name ReadOnlyAccess --regions us-east-1 --no-cost --output ./output
python main.py --all --regions eastus,westus2 --anonymize --output ./output
python main.py --projects my-project-1,my-project-2 --collectors asset,compute,storage --output ./output
```

Run each from its own cloud folder with that cloud's virtual environment active. The command builder's download button
writes a script that does these steps for you: it clones the repository, creates the environment, shows who you are
signed in as and asks `Continue? [y/N]` before it scans. A script you generate holds your real account, subscription or
project IDs, so keep it local and do not commit it. `docs/run-guides/README.md` explains the pages and the example
scripts.

## What you get

One zip per run, named `<cloud>_sizing_results_<timestamp>.zip`:

- the CSV files (`--no-csv` leaves them out),
- the JSON record of the run (left out of an anonymized run, which has real names in it),
- `<cloud>_preflight_check-<timestamp>.csv`, the access check described below,
- `output_<cloud>_<timestamp>.log`, the run log.

`--preflight-only` writes a smaller `<cloud>_access_check_<timestamp>.zip` instead and collects nothing. The user guide
lists every file.

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
| `docs/run-guides/README.md` | the command builder pages and the example scripts |
| `docs/troubleshooting.md` | what each error means and what to do |
| `docs/permissions.md` | the access each tool needs, and what a missing permission costs you |
| `docs/logging.md` | how the run log and the problem summary work, and how to add a fix |
| `docs/powershell-parameter-mapping.md` | each PowerShell parameter and the Python option that replaces it |
| `packaging/README.md` | building a zip of a tool to hand over without cloning |

## Read-only

The tools list and describe; they do not create, change or delete anything in the cloud. The one exception is the AWS
installer's `--org` mode, which deploys a read-only role through a StackSet (removed after a plain `--org` scan, kept by
`--deploy-role-only`).
