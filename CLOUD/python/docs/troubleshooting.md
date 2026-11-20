# Troubleshooting

What each error means and what to do about it. At the end of a run the **run summary** lists every distinct problem with a
`Fix:` line; the last line of each fix is a link to a section of this page. Commands on a line starting with `Run:` can be
copied as they are.

## Index

| You see | Section |
|---------|---------|
| the script stops at `Continue? [y/N]` and prints `Aborted.` | [Aborted at the question](#aborted-at-the-question) |
| `No rubrik-sizing-scripts checkout found`, `exists but has no`, `could not check for a newer version` | [The run script cannot get the code](#the-run-script-cannot-get-the-code) |
| the AWS script warns the checkout is behind | [The checkout is behind](#the-checkout-is-behind) |
| `Python 3.9 or newer is required` / `3.10 or newer`, or `pip install` fails | [Python and pip](#python-and-pip) |
| `ensurepip is not available`, `externally-managed-environment`, `No module named 'boto3'` (or `rich`, `azure`) | [Python and pip](#python-and-pip) |
| `usage: main.py` and `error: ...`, `Unknown services`, `Unknown collector(s)`, `Profile not found`, `Config error` | [A bad option](#a-bad-option) |
| no zip, and the log ends with a `Run ended:` line other than `scan finished`, or with no `Run ended:` line | [The run stopped before the zip](#the-run-stopped-before-the-zip) |
| you cannot find the zip, or it is not in the `--output` folder | [Where the results are](#where-the-results-are) |
| a CSV file is empty or missing, or a number is blank or 0 | [Empty files and blank numbers](#empty-files-and-blank-numbers) |
| `CERTIFICATE_VERIFY_FAILED` or `SSL validation failed` on every call, a proxy, `pip install` blocked | [Proxies and certificates](#proxies-and-certificates) |
| the Azure table shows a different subscription from the one scanned | [The subscription in the table](#the-subscription-in-the-table-is-not-the-one-scanned) |
| questions about Defender and other optional scans | [Questions about optional scans](#questions-about-optional-scans) |
| a pre-flight row says `MISSING`, `API NOT ENABLED` or `NOT CHECKED`, or `Access check could not run` | [Reading the access check](#reading-the-access-check) |
| the log is missing a detail you expected | [What is and is not in the log](#what-is-and-is-not-in-the-log) |
| `ExpiredToken`, `Your AWS sign-in has expired`, `SSOTokenLoadError`, `TokenRetrievalError` | [aws-sign-in-expired](#aws-sign-in-expired) |
| `RequestExpired`, `Signature expired`, and signing in again does not help | [aws-clock-skew](#aws-clock-skew) |
| `MissingDependencyException`, `botocore[crt]` | [aws-crt-missing](#aws-crt-missing) |
| `Unable to locate credentials`, `ProfileNotFound`, `PartialCredentialsError` | [aws-no-credentials](#aws-no-credentials) |
| `AWS rejected the credentials`, `InvalidClientTokenId`, `SignatureDoesNotMatch` | [aws-credentials-rejected](#aws-credentials-rejected) |
| `Cannot sign in to ...: cannot assume`, `Failed to assume role` | [aws-assume-role-failed](#aws-assume-role-failed) |
| `Cannot list organization accounts`, `AWSOrganizationsNotInUseException` | [aws-org-accounts-unlisted](#aws-org-accounts-unlisted) |
| `No cached SSO login`, `No valid SSO token`, `Cannot list SSO accounts`, `GetRoleCredentials` | [aws-sso](#aws-sso) |
| `Resuming from ... already complete` when you meant a fresh scan | [aws-resume](#aws-resume) |
| `Scan failed for`, `Region ... scan failed`, `Cannot sign in to ... skipping` | [aws-account-or-region-failed](#aws-account-or-region-failed) |
| `explicit deny`, `service_control_policy`, `SCP blocked read access for services` | [aws-scp-deny](#aws-scp-deny) |
| `ce:GetCostAndUsage`, Cost Explorer, `Cost data requested but none returned` | [aws-cost-explorer](#aws-cost-explorer) |
| `AccessDenied`, `UnauthorizedOperation`, `IAM permission error(s) prevented full collection` | [aws-access-denied](#aws-access-denied) |
| `OptInRequired`, `UnrecognizedClientException` for one region | [aws-region-not-enabled](#aws-region-not-enabled) |
| `Throttling`, `Rate exceeded` | [aws-throttled](#aws-throttled) |
| `Could not connect to the endpoint URL` | [aws-endpoint-unreachable](#aws-endpoint-unreachable) |
| `SSL validation failed`, `CERTIFICATE_VERIFY_FAILED` (AWS) | [aws-certificate-verify-failed](#aws-certificate-verify-failed) |
| `Recovery point listing in ... stopped after`, `BackupEnumerationTruncated` | [aws-recovery-points-truncated](#aws-recovery-points-truncated) |
| `backup plan details are missing or incomplete`, `Access denied listing backup vaults` | [aws-backup-plans-incomplete](#aws-backup-plans-incomplete) |
| `--bucket` uploaded nothing, or only JSON | [aws-bucket-upload](#aws-bucket-upload) |
| `azure-mgmt-security is not installed` | [az-optional-package-missing](#az-optional-package-missing) |
| `azure-mgmt-dataprotection is not installed` | [az-optional-package-missing](#az-optional-package-missing) |
| `Detected invalid time interval input` | [az-metrics-time-interval](#az-metrics-time-interval) |
| `MetricsDenied` | [az-metrics-denied](#az-metrics-denied) |
| `Key Vault ... could not count`, `key vault contents` denied | [az-key-vault-contents-denied](#az-key-vault-contents-denied) |
| `Blob containers of N storage account(s) could not be listed`, `Blobs of container`, `blob containers` denied | [az-blob-data-denied](#az-blob-data-denied) |
| `Used-capacity unavailable for ALL` | [az-storage-capacity-blank](#az-storage-capacity-blank) |
| `MissingSubscriptionRegistration` | [az-provider-not-registered](#az-provider-not-registered) |
| `AuthorizationFailed` | [az-authorization-failed](#az-authorization-failed) |
| `TooManyRequests` (Azure) | [az-throttled](#az-throttled) |
| `Failed to invoke the Azure CLI`, `AzureCliUnavailable` | [az-cli-unavailable](#az-cli-unavailable) |
| `az login`, `DefaultAzureCredential failed`, `Authentication failed`, `AudienceNotSupported`, `AADSTS` | [az-not-signed-in](#az-not-signed-in) |
| `No accessible subscriptions found`, `Subscription ... not accessible` | [az-no-subscriptions](#az-no-subscriptions) |
| `failed and was skipped`, `subscription(s) failed and are excluded`, `Every subscription failed` | [az-subscription-failed](#az-subscription-failed) |
| `Cost data requested but none returned` (Azure), `Cost Management 403`, `Cost Management 404` | [az-cost-management](#az-cost-management) |
| `Azure DevOps`, `Could not acquire Azure DevOps token` | [az-devops](#az-devops) |
| `Backup Vaults could not be listed`, `Unable to collect Azure Backup Vault information` | [az-backup-vaults-unlisted](#az-backup-vaults-unlisted) |
| `Unrecognised Azure cloud`, a government cloud | [az-government-cloud](#az-government-cloud) |
| `VM pricing: found 0 of N SKUs; N price request(s) failed` | [az-pricing-unreachable](#az-pricing-unreachable) |
| `VM pricing: found 0 of N SKUs; 0 price request(s) failed` | [az-pricing-no-match](#az-pricing-no-match) |
| `CERTIFICATE_VERIFY_FAILED`, `certificate verify failed` | [az-certificate-verify-failed](#az-certificate-verify-failed) |
| `Could not read the tenant`, `Could not read the display name of tenant` | [az-tenant-lookup-failed](#az-tenant-lookup-failed) |
| `Long-term retention policy could not be read` | [az-ltr-unreadable](#az-ltr-unreadable) |
| `has not been used in project X before or it is disabled`, `Quota project X has ... disabled`, `QuotaProjectServiceDisabled` | [gcp-api-disabled-in-billing-project](#gcp-api-disabled-in-billing-project) |
| `SERVICE_DISABLED` without that wording, `ServiceDisabled` in some projects only | [gcp-api-disabled](#gcp-api-disabled) |
| `Quota project X has billing disabled`, `QuotaProjectBillingDisabled` | [gcp-quota-project-billing-disabled](#gcp-quota-project-billing-disabled) |
| `BillingDisabled`, `BILLING_DISABLED`, `requires billing to be enabled` in some projects only | [gcp-billing-disabled](#gcp-billing-disabled) |
| `Operation denied by` (not followed by `[IAM permission`), `prohibited by organization` | [gcp-org-policy](#gcp-org-policy) |
| `PERMISSION_DENIED`, `Required '...' permission`, `notAuthorized`, `Missing IAM permission`, `Operation denied by [IAM permission ...]` | [gcp-permission-denied](#gcp-permission-denied) |
| `default credentials were not found` | [gcp-no-credentials](#gcp-no-credentials) |
| `RefreshError`, `invalid_grant`, `Reauthentication is needed`, `Token has been expired or revoked` | [gcp-credentials-expired](#gcp-credentials-expired) |
| `No accessible projects found`, `Project ... not accessible`, `scope.projects in the config file is not used` | [gcp-no-projects](#gcp-no-projects) |
| `USER_PROJECT_DENIED`, `charged to quota project`, `No project could be read`, `QuotaProjectDenied` | [gcp-quota-project-denied](#gcp-quota-project-denied) |
| `without a quota project`, `requires a quota project`, `NoQuotaProject` | [gcp-quota-project-warning](#gcp-quota-project-warning) |
| `RESOURCE_EXHAUSTED`, `Quota exceeded` | [gcp-rate-limited](#gcp-rate-limited) |
| `Transient GCP error`, `backing off and retrying` | [gcp-transient-retry](#gcp-transient-retry) |
| `Asset enumeration failed`, `Org-wide asset enumeration failed` | [gcp-asset-inventory](#gcp-asset-inventory) |
| `PROJECT_NOT_FOUND` | [gcp-project-not-found](#gcp-project-not-found) |
| `cannot import name`, `No module named` (GCP) | [gcp-client-library-missing](#gcp-client-library-missing) |

## Setup and script problems

### Aborted at the question

A generated script asks `Continue? [y/N]` before it scans. Anything other than `y` or `yes` (including just pressing
Enter) stops it with `Aborted.` and nothing is scanned. Read the lines above the question: they show who you are signed in as
and, for Azure with `--subs`, which subscriptions will be scanned and whether your `az` login knows each one. If that is
wrong, fix the sign-in or the script first; if it is right, run the script again and answer `y`. A script whose input is
closed (for example redirected from `/dev/null`) cannot be answered and aborts.

### The run script cannot get the code

**You see:** `No rubrik-sizing-scripts checkout found.`, then a clone that fails; or `<folder> exists but has no
CLOUD/python/<cloud> (wrong branch or not rubrik-sizing-scripts?)`; or `(could not check for a newer version; continuing)`.

**Why:** the script clones the public `rubrikinc/rubrik-sizing-scripts` repository over HTTPS, so it needs network access to
github.com (a proxy or firewall that blocks it makes the clone fail). The second message means the folder it found
(`REPO_DIR`, the folder the script is in, or the checkout your current folder is in) holds another branch or another
repository. The third means the update check could not reach GitHub; the script runs the code it has.

**What to do:** check that github.com is reachable (it prints the commit of `master` and nothing else):

Run: git ls-remote https://github.com/rubrikinc/rubrik-sizing-scripts.git master

Or clone it yourself and point the script at it with `REPO_DIR=/path/to/rubrik-sizing-scripts`. For a checkout on the wrong
branch:

Run: git -C /path/to/rubrik-sizing-scripts switch master

### The checkout is behind

The AWS script prints `WARNING: this checkout does not have the latest master.` and asks whether to run
with the code you have. Answer `N` and update:

Run: git -C /path/to/rubrik-sizing-scripts pull --ff-only

The Azure and GCP scripts do not check, so pull before running them. Fixes in this page are only in the newer code.

### Python and pip

The AWS tool needs Python 3.9 or newer; Azure and GCP need 3.10 or newer. `python3 --version` shows what you have. If
`pip install -r requirements.txt` fails, check that the virtual environment is active (`source .venv/bin/activate`) and
that the machine can reach PyPI (a proxy or an offline machine is the usual cause; see
[Proxies and certificates](#proxies-and-certificates)).

- **`ensurepip is not available`** when the virtual environment is made (Debian and Ubuntu): the `venv` part of Python is
  a separate package there. Install it (the message names the exact package, such as `python3.10-venv`), remove the
  half-made `.venv` folder and run again.

  Run: sudo apt install python3-venv

- **`error: externally-managed-environment`**: `pip` ran outside the virtual environment. Activate it first.
- **`ModuleNotFoundError: No module named 'boto3'`** (or `rich`, `azure`, `google`) when you start `main.py`: the virtual
  environment of that cloud's folder is not active in this terminal, or the requirements went into another folder's
  environment. Each cloud has its own `.venv` and its own `requirements.txt`. `which python` should end in
  `.venv/bin/python`.
- **`Python 3.10+ required (found 3.9)`** in a cloud shell: the shell's image has an older Python. Use a newer image or
  another machine.

### The subscription in the table is not the one scanned

The Azure script shows the subscription of your current `az` login in a table, then lists the IDs from `--subs` that it
will scan. They are different things on purpose. The scan reads the subscriptions in `--subs`, with the token for the
tenant the CLI is set to, so a subscription in another tenant fails with `AuthorizationFailed` even if `az account list`
shows it. See [az-authorization-failed](#az-authorization-failed).

### Questions about optional scans

On a terminal Azure asks whether to scan storage capacity, security posture (Microsoft Defender) and backup job history,
and AWS asks about cost. Each is answered by a flag (`--no-capacity`, `--no-security`, `--no-backup-jobs`, `--no-cost`),
and nothing is asked when the input is not a terminal. Defender is not offered at all when its package is not installed
([az-optional-package-missing](#az-optional-package-missing)).

### A bad option

**You see:** `usage: main.py ...` followed by `error: ...`, for example `--cross-account-role needs --accounts or
--accounts-file`, `--anonymize works on the CSV files, so it cannot be used with --no-csv`, `Unknown services: ...`,
`Profile not found: ...`, `No local AWS profiles were found`, `Only --accounts or --accounts-file can be specified, not
both.` or `Profile location not found`. GCP says `Unknown collector(s): ...`; Azure says `Config error: ...` for a
`--config` file it cannot read, or `--mock is not available in the public distribution`.

**Why:** the command line is checked before anything is scanned. Nothing is scanned and no zip is written. AWS leaves no
log for a bad option (exit code 2), because the message on the screen is all there is.

**What to do:** fix the option and run again. Every option is in the user guide (section 10) and in:

Run: python main.py --help

A warning, not an error: AWS prints `--accounts / --accounts-file only apply to --sso, --org and --cross-account-role`
and scans the current account only; add one of those modes if you meant to scan the listed accounts.

### The run stopped before the zip

**You see:** no zip, and the log `output_<cloud>_<timestamp>.log` left in the output folder (for a multi-account AWS scan
without `--output`, the current folder). Its last line says how the run ended.

**What each ending means:**

- `Run ended: failed with <Error>: <message>` and a traceback: an error the tool did not expect. Look the message up in
  the index above; if it is not there, send the log ([Still stuck](#still-stuck)).
- `Run ended: exited with code 1`: the tool stopped on purpose. The lines just above it say why, for example
  `No accessible subscriptions found`, `Every subscription failed` or `Cannot list organization accounts`.
- `Run ended: stopped by the terminal closing (SIGHUP)`: the terminal or the cloud shell session closed. Cloud shells
  end a session that has had no keyboard input for a while, even while a command runs. Keep the session active, scan
  less at a time (`--regions`, `--services`, `--subs`, `--projects`), or run from a machine that stays up.
- `Run ended: stopped by Ctrl-C (SIGINT)` or `SIGTERM`: someone or something stopped it.
- No `Run ended` line: the process was killed outright, for example by `kill -9`, by the system when it ran out of
  memory, or by the machine stopping. On Linux, `dmesg` may name the out-of-memory kill. Fewer `--workers` use less memory.

In every case run the same command again with `--resume`: a scan carries on from its progress folder and scans only what
is missing ([aws-resume](#aws-resume)). Without `--resume` or `--fresh` the run stops and tells you, rather than guessing.
The partial log is the real log and is not anonymized, whatever `--anonymize` says, so keep it to yourself unless you mean
to share names.

### Where the results are

The last lines on the screen name the zip. They are printed after the log is sealed, so they are not in the log.

| Run | The zip, the log and other files go to |
|-----|----------------------------------------|
| AWS, one account | `--output` (default `./outputs`) |
| AWS, `--org`, `--sso`, `--cross-account-role`, `--profiles`, `--all-profiles` | `--output` (default: the current folder), with the `aws-sizing-progress-*` folder |
| Azure | `--output`; else `~/clouddrive` when it exists (Azure Cloud Shell); else `./output` |
| GCP | `--output`; else `./output` |

A relative folder is relative to where the command ran. The generated run scripts take a relative output directory next
to the script itself, so their `./output` is beside the downloaded `.sh` file, in every mode; the script prints the full
path at the end. With `--anonymize` the key file and the real log are beside the zip, not in it. To get a file out of a cloud
shell, use the shell's download action (Google Cloud Shell also has `cloudshell download FILE`).

### Empty files and blank numbers

Check the access check and the run summary first: a denied call leaves its files empty or partial and says so there. If
neither shows a problem, these are expected:

- **A zero-byte CSV file** has no rows: nothing of that kind was found in the scope. PowerShell writes the same empty
  file. A few AWS files get a header line instead, as PowerShell writes them.
- **A file that is not in the zip** (Azure): `azure_postgres_info` and the three `azure_backup_data_protection_*` files
  are written only when they have rows (the Backup Vault files also need `azure-mgmt-dataprotection`), and a
  file whose collector was skipped with a `--skip-*` switch is not written.
- **A blank `...Bytes` cell with 0 in the unit columns**: the metric had no data point in the period read. AWS S3
  sizes come from CloudWatch's daily storage metrics, so a bucket created in the last day or two has none yet.
- **Cost files with only a header** (AWS): `--no-cost`, GovCloud (no Cost Explorer there) or a Cost Explorer failure
  ([aws-cost-explorer](#aws-cost-explorer)).
- **`NumberOfDatabases` of 0 in `gce_spanner_info`** (GCP) means no databases or a listing that failed; a failure is in
  the project's errors and in the run summary.
- **Fewer resources than expected**: check the scope in the banner (`--regions`, `--exclude-regions`, `--subs`,
  `--projects`) and any region the access check marked `all services in region`.

### Proxies and certificates

**You see:** `CERTIFICATE_VERIFY_FAILED`, `SSL validation failed for https://...` (AWS),
`self-signed certificate in certificate chain`, or every call timing out, for every service and not just one.

**Why:** the network sends HTTPS through a proxy, often one that re-signs the traffic with your organization's own
certificate authority. Python and the cloud libraries trust their own certificate bundle, not your system's, so they
refuse the re-signed certificate. The cloud CLIs can work while the tool fails, because each reads its own settings.

**What to do:** get your organization's certificate bundle (a PEM file) from your IT team. If a proxy must be named, set
`HTTPS_PROXY` (and `NO_PROXY` for hosts that bypass it). Then point each library at the bundle and run again:

- AWS (boto3 and the AWS CLI):

  Run: export AWS_CA_BUNDLE=/path/to/ca-bundle.pem

- Azure (the Azure SDK, the `az` CLI and the tool's own tenant and price requests):

  Run: export REQUESTS_CA_BUNDLE=/path/to/ca-bundle.pem

- GCP: `REQUESTS_CA_BUNDLE` as above, and for the Google libraries that use gRPC:

  Run: export GRPC_DEFAULT_SSL_ROOTS_FILE_PATH=/path/to/ca-bundle.pem

- `pip install`:

  Run: pip install --cert /path/to/ca-bundle.pem -r requirements.txt

Do not turn certificate verification off. Azure's tenant and price requests have their own section:
[az-certificate-verify-failed](#az-certificate-verify-failed).

## Reading the access check

The table printed before the scan (see the user guide) has one row per permission.

- **`MISSING`**: the call was denied. `PERMISSION` is what to grant; `IMPACT` is what is lost without it. The
  `Problems found` block under the table has the error as the cloud worded it and a `Fix:`.
- **`API NOT ENABLED`**: the service's API is off. The fix names the project or provider to turn it on in.
- **`NOT CHECKED`**: the call failed for a reason that is not a denial (a timeout, a throttle, an error the tool does not
  recognise). The error code is in `IMPACT`. The scan may still work; the table does not claim a loss.
- **`not requested`**: the run is not collecting it (a `--services`, `--collectors` or `--skip-*` choice, a scan you said no
  to, or `--no-cost`).

None of these stops the scan. They tell you what the numbers will lack before you wait for them.

In an AWS scan of several accounts the CSV also has a row for each account that was not scanned: `Service` `sign in`
(the scan could not enter the account) or `scan` (its scan stopped), with the error code in `Detail`. Azure and GCP add a
row for each subscription or project you named that could not be read (`Service` `subscription` or `project`) and one
for each whose scan stopped (`scan`). The end of the run lists them and why. To check access before scanning, run with
`--preflight-only` (the user guide, "Access to each account" and "Access to each subscription or project").

`Access check could not run (<code>); the scan goes on without it` means the check itself failed, not a permission. The
scan runs as with `--no-preflight`, and any missing permission shows up as warnings during the scan and in the run
summary instead.

## What is and is not in the log

The log is a transcript of the screen with a header and the run summary. It does not hold library debug output, spinners or
colour codes, and `--verbose` changes only the screen. The last lines naming the zip are printed after the log is sealed
into the zip, so they are on the screen but not in the log. A failure that stops the run before the log starts (a bad option,
no credentials) is only on the screen. With `--anonymize` the zip holds a note instead of the log, and the real log is
beside the zip. See `logging.md`.

## AWS

<a id="aws-sign-in-expired"></a>
### aws-sign-in-expired

**You see:** `ExpiredToken ... The security token included in the request is expired`, often right after the script prints
`You are about to scan with this AWS identity`. At the start of a run the tool says `Your AWS sign-in has expired (...)`
and exits with code 1; the detail in brackets can also be `ExpiredTokenException`, `RequestExpired`, `SSOTokenLoadError`,
`UnauthorizedSSOTokenError`, `TokenRetrievalError` or `credentials are still expired`.

**Why:** the sign-in has ended, or the shell still holds temporary keys from an earlier `export AWS_ACCESS_KEY_ID=...`
that have expired. Variables like those override your profile.

**What to do:** sign in again.

Run: aws sso login --profile NAME

or, if you use `aws login`:

Run: aws login

To see whether old keys are exported (names only, never values):

Run: env | grep '^AWS_' | cut -d= -f1

and clear them:

Run: unset $(env | grep '^AWS_' | cut -d= -f1)

Do not paste exported keys into a chat, a ticket or a commit.

In the middle of a multi-account scan the cause is different. `--org` and `--cross-account-role` sign in to each account
with a role session that lasts one hour, so an account whose scan takes longer than that fails with `ExpiredToken` and is
not counted. An SSO portal sign-in ends when the session length set in IAM Identity Center runs out. Sign in again if
needed and run the same command: finished accounts are kept ([aws-resume](#aws-resume)). For an account that is too big
for one hour, scan it with fewer `--regions` or `--services` at a time.

If `RequestExpired` comes back right after a fresh sign-in, see [aws-clock-skew](#aws-clock-skew).

<a id="aws-clock-skew"></a>
### aws-clock-skew

**You see:** `RequestExpired`, `Request has expired` or `Signature expired: ... is now earlier than ...`, and signing in
again does not help. At the start of a run the tool calls it an expired sign-in.

**Why:** AWS refuses a request signed more than a few minutes away from its own time, so a machine whose clock is wrong
fails every call. Virtual machines and WSL are known to drift after the computer sleeps.

**What to do:** compare the machine's time with the real time in UTC, and turn on automatic time setting.

Run: date -u

On Linux with systemd:

Run: sudo timedatectl set-ntp true

On WSL, `wsl --shutdown` from Windows resets the clock. On macOS, turn on "Set time and date automatically".

<a id="aws-crt-missing"></a>
### aws-crt-missing

**You see:** `MissingDependencyException` mentioning `botocore[crt]`. The tool stops at the start with a short message and
exit code 1 instead of a traceback.

**Why:** a session made with `aws login` is read through an extra component (`awscrt`). The current `requirements.txt` and
`pyproject.toml` install it, so you see this only in an environment set up before that, or with a package list of your own.

**What to do:** install it into the virtual environment (re-running `pip install -r requirements.txt` does the same):

Run: pip install "botocore[crt]"

Or export the credentials from the session and run again. They are temporary keys that override your profile and expire, so
clear them afterwards (see [aws-sign-in-expired](#aws-sign-in-expired)):

Run: eval "$(aws configure export-credentials --format env)"

<a id="aws-no-credentials"></a>
### aws-no-credentials

**You see:** `Unable to locate credentials`, `PartialCredentialsError` or `ProfileNotFound`.

**Why:** there is no sign-in the tool can use, or `AWS_PROFILE` names a profile that does not exist.

**What to do:** sign in, or set the profile you mean (`aws configure list-profiles` shows the names).

Run: aws sso login --profile NAME

`PartialCredentialsError` (`Some of the AWS credentials are missing`) means only part of a key pair is exported: set
`AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` together, and `AWS_SESSION_TOKEN` too for temporary keys, or unset all
three to use your profile. With `--profiles` or `--profile-location`, a profile that is not in the file stops the run
before it starts ([A bad option](#a-bad-option)).

<a id="aws-credentials-rejected"></a>
### aws-credentials-rejected

**You see:** `AWS rejected the credentials (...)` at the start of a run, with `InvalidClientTokenId` (`The security token
included in the request is invalid`), `SignatureDoesNotMatch` or `UnrecognizedClientException` in the brackets; or
`InvalidClientTokenId` or `SignatureDoesNotMatch` during a scan.

**Why:** AWS does not know the keys: they were deleted or deactivated, a character is wrong, an old `AWS_SESSION_TOKEN`
is still exported next to long-term keys, or the keys belong to the other partition (GovCloud keys used against the
commercial partition, or the reverse).

**What to do:** check what the tool will use, and look for exported keys (names only):

Run: aws sts get-caller-identity

Run: env | grep '^AWS_' | cut -d= -f1

Unset stale variables ([aws-sign-in-expired](#aws-sign-in-expired) shows how), or create new keys. For GovCloud keys, add
`--partition govcloud`.

`UnrecognizedClientException` means two things. At the start, when the tool checks who you are, it means the credentials
were rejected, and the tool says so in the message above. During a scan it usually comes from one region that is not
enabled, so the run summary links it to [aws-region-not-enabled](#aws-region-not-enabled). If every region shows it,
the credentials are the problem; follow this section.

<a id="aws-assume-role-failed"></a>
### aws-assume-role-failed

**You see:** `[n/N] Cannot sign in to ACCOUNT: cannot assume arn:aws:iam::ACCOUNT:role/ROLE: ... (AccessDenied) when
calling the AssumeRole operation ... — skipping`, in an `--org` or `--cross-account-role` scan. With `--assume-role`:
`Failed to assume role ARN: ...`, and the run stops with exit code 1.

**Why:** the identity you run as could not switch into the role in that account. Granting a read permission does not
help. The usual causes:

- the role does not exist in that account (the template that creates it was not deployed there);
- the role's trust policy does not trust the identity you run as;
- the name is wrong: `--org` uses `RubrikDiscoveryRole` unless `--role-name` says otherwise, while PowerShell's default
  for organizations is `OrganizationAccountAccessRole`;
- your identity lacks `sts:AssumeRole`, or a service control policy denies it.

**What to do:** try the switch by hand, with `ROLE_ARN` the ARN from the message. This prints only the role's ARN, never
the keys:

Run: aws sts assume-role --role-arn ROLE_ARN --role-session-name check --query AssumedRoleUser.Arn --output text

Fix the role or the trust policy (`aws/iac/` has the template for the spoke role), or pass the right `--role-name`, and
run the same command again with `--resume`. Accounts that already finished are not scanned twice
([aws-resume](#aws-resume)).

To find every account with this problem at once, run with `--preflight-only`: it tries the role in each account, collects
nothing, and lists the accounts it could not enter, which also have a `sign in` row in `aws_preflight_check-*.csv`.

<a id="aws-org-accounts-unlisted"></a>
### aws-org-accounts-unlisted

**You see:** `Cannot list organization accounts: ...` in an `--org` scan, and the run stops with exit code 1. With
`AccessDeniedException` it adds `Missing permission: organizations:ListAccounts`.

**Why:** listing accounts needs `organizations:ListAccounts`, and it works only from the organization's management account
or a delegated administrator account. `AWSOrganizationsNotInUseException` means the account is not in an organization.

**What to do:** run from the management account (or a delegated administrator) with that permission, or skip the listing
by naming the accounts with `--accounts` or `--accounts-file`. For an account that is not in an organization, scan it on
its own with no mode option, or use `--cross-account-role` with `--accounts`.

<a id="aws-sso"></a>
### aws-sso

**You see**, in an `--sso` scan, one of:

- `No cached SSO login was found. Run 'aws sso login', or pass --sso-start-url so this tool can sign in itself.`
- `Unable to start SSO authorization for URL in region REGION: ...`
- `The SSO sign-in for URL expired before it was approved.`
- `Cannot list SSO accounts: ...` and `Pass --accounts id1,id2,... to provide the list explicitly.`
- `[n/N] Cannot sign in to ACCOUNT: ... GetRoleCredentials ...` with `ForbiddenException: No access` or
  `UnauthorizedException: Session token not found or invalid`.
- the warnings `No SSO session configured for 'URL' — using session ...` or `No token cached for 'URL' — using token
  for 'OTHER URL' instead`.

**Why and what to do:**

- **No cached login**: run `aws sso login` for a profile of that start URL, or pass `--sso-start-url` and the tool signs
  in with the device flow: it prints a link and a code; open the link, check the code and approve before the time it
  shows.
- **Unable to start SSO authorization**: the start URL is wrong, or `--sso-region` is not the region of your IAM
  Identity Center instance (the default is the region of the cached login, else `us-east-1`).
- **Cannot list SSO accounts** or **`UnauthorizedException`**: the portal sign-in ended or is not valid. Sign in again and
  run the same command; finished accounts are kept ([aws-resume](#aws-resume)). Or pass the accounts with `--accounts`.
- **`ForbiddenException: No access`** for one account: the permission set named by `--role-name` is not assigned to you
  in that account. The AWS access portal shows which roles you have in each account. For **every** account, the name is
  probably wrong: pass the permission set exactly as the portal shows it.
- **`--sso needs --role-name`**: IAM Identity Center has no default permission set, so name yours with `--role-name`.
  The CloudShell installer asks for it when it runs in a terminal.
- **The warnings**: no login is cached for the start URL you passed, so the tool uses a login for another start URL. If
  that is the wrong organization, pass the right `--sso-start-url` or sign in to it with `aws sso login`.

<a id="aws-resume"></a>
### aws-resume

**You see:** `Cannot start: An unfinished run is in .../aws-sizing-progress-<time> (N units done, started ...)`, or
`Resuming from ... — N already complete, M remaining`, or `different options` in that message.

**Why:** a multi-account scan keeps each finished account in an `aws-sizing-progress-*` folder in its output folder (the
current folder without `--output`). The folder is removed when every account has a result, and kept when one has none: it
could not be signed in to, its scan failed or stopped, or a service control policy blocked it. A later scan in the same
folder does not continue it silently, because that could mix the old accounts into a scan they did not belong to. A run
with no terminal stops with this message. The folder records the options of the run that made it (the mode, role, account
list, regions, exclusions, services, cost and partition), and a run with other options will not resume it.

**What to do:** to carry on, run the same command again with `--resume`. To start over, add `--fresh`, which deletes the
unfinished run:

Run: aws-sizing --fresh ...

An account that finished with permission errors, or with a region it could not scan, is scanned again by `--resume`
(add `--keep-partial` to keep it as it was). The run ends by naming these accounts and the first reason for each. To scan
one account again that finished clean, delete its subfolder (named by the account ID) inside the progress folder and
resume.

A progress folder made by an older version records no options and is not resumed; it is left where it is and can be
deleted.

<a id="azure-resume"></a>
### azure-resume

**You see:** `Cannot start: An unfinished run is in .../azure-sizing-progress-<time> (N units done, started ...)`, or
`different options` in that message.

**Why:** the scan of each subscription is saved in an `azure-sizing-progress-*` folder in the output folder as it
finishes. The folder is removed when every subscription has a result, and kept when one has none (it could not be read, or
its scan failed). A run with no terminal stops here rather than resume silently, and a run with other options (regions,
cloud, scans, skips, or how the subscriptions were chosen) will not resume the folder.

**What to do:** run the same command with `--resume` to scan only the missing subscriptions, or `--fresh` to delete the
unfinished run and start over. A subscription that finished with gaps (a warning was logged for it during its scan, or
its access check found a service it could not read) is scanned again by `--resume`; add `--keep-partial` to keep it as it
was. The run ends by naming these subscriptions and the first reason for each. What is collected after the scan (tag
names, AKS, Cosmos DB, Backup Vaults, containers, Key Vaults, Defender, Purview) runs again for every subscription.

<a id="gcp-resume"></a>
### gcp-resume

**You see:** `Cannot start: An unfinished run is in .../gcp-sizing-progress-<time> (N units done, started ...)`, or
`different options` in that message.

**Why:** each finished project is saved in a `gcp-sizing-progress-*` folder in the output folder as it finishes. The folder
is removed when every project has a result, and kept when one has none: it could not be read, its collection failed, or
the run was stopped before it. A run with no terminal stops here rather than resume silently, and a run with other options
(collectors, regions, `--security`, `--org` or `--folder`, or how the projects were chosen) will not resume the folder.
The list of projects is not one of those options: a scan of all projects may see a few more or fewer the second time.

**What to do:** run the same command with `--resume` to scan only the missing projects, or `--fresh` to delete the
unfinished run and start over. A project that finished with collector errors, such as an API that was off or a time
limit that was reached, is scanned again by `--resume`; add `--keep-partial` to keep it as it was. The run ends by naming
these projects and the first reason for each. A project that ended after you pressed Ctrl-C is not saved, because BigQuery
then returns only what it had read, so it is scanned again.

<a id="aws-account-or-region-failed"></a>
### aws-account-or-region-failed

**You see:** `[n/N] Scan failed for ACCOUNT (NAME): ...`, `[n/N] Cannot sign in to NAME: ... — skipping`, or `Region
REGION scan failed: ...`.

**Why:** the text after the colon is the cause; look it up in the index. A failed or skipped account is not in the zip.
A region that failed (it raised, or it could not be reached) leaves that region's resources out of the account, and is
recorded as a `scan_errors` entry with the service `region`, so the account is one that finished with gaps: the run names
it at the end and `--resume` scans it again. A region that a service control policy denies is not a failure.

**What to do:** fix the cause and run the same command again with `--resume`. A multi-account scan retries the accounts
that failed and the ones that finished with gaps, and keeps the ones that finished cleanly. A failed region is one of
those gaps, so `--resume` scans the account again ([aws-resume](#aws-resume)). `Cannot sign in` is
covered by [aws-assume-role-failed](#aws-assume-role-failed), [aws-sso](#aws-sso) and, for `--profiles`,
[aws-no-credentials](#aws-no-credentials).

<a id="aws-scp-deny"></a>
### aws-scp-deny

**You see:** `explicit deny in a service control policy`, or `ServiceControlPolicy` in the pre-flight table.

**Why:** an organization policy blocks the call whatever the role allows. A region blocked this way shows as one row,
`all services in region`, and the scan skips it.

**What to do:** ask your AWS organization admin for an exception for the role you scan with, or leave the service or region
out: `--services`, `--exclude-regions`.

In a multi-account scan an account with a blocked service prints `SCP blocked read access for services: ...`. It is
**not** counted as finished and is left out of the zip, so that running the same command after the exception is granted
scans it again. Its access-check rows stay in `aws_preflight_check-*.csv`, and the closing box lists it. If you accept
the gap, leave the blocked services out with `--services` and run again.

<a id="aws-cost-explorer"></a>
### aws-cost-explorer

**You see:** `ce:GetCostAndUsage`, `Cost Explorer` or `DataUnavailableException`.

**Why:** cost data needs Cost Explorer turned on for the account and the `ce:GetCostAndUsage` permission. AWS bills Cost
Explorer requests, and the access check makes one per account.

**What to do:** turn Cost Explorer on in Billing and grant the permission, or run with `--no-cost`.

Cost Explorer has data only from about a day after it is turned on, so a run right after that finds none
(`Cost data requested but none returned`). In an organization, the management account can turn Cost Explorer off for
member accounts; a member account is then denied whatever its role allows. There is no Cost Explorer in GovCloud: the
cost files there are header-only, with no error.

<a id="aws-access-denied"></a>
### aws-access-denied

**You see:** `AccessDenied`, `AccessDeniedException` or `UnauthorizedOperation`, with `not authorized to perform:
<action>`.

**Why:** the role cannot make a read call the scan needs.

**What to do:** the pre-flight table already lists the permission (`PERMISSION`) and the output it affects. Grant it to the
role you scan with, or accept that those files will be empty. `permissions.md` lists them all. For a scan of a whole
organization, `aws/iac/` has the CloudFormation template for the role it uses.

`Account ACCOUNT: N IAM permission error(s) prevented full collection` is the count of such denials for one account; each
is in `scan_errors` in the JSON. A denial on `sts:AssumeRole` is not a read permission: see
[aws-assume-role-failed](#aws-assume-role-failed).

<a id="aws-region-not-enabled"></a>
### aws-region-not-enabled

**You see:** `OptInRequired`, `UnrecognizedClientException` or `AuthFailure` for one region, and the pre-flight row
`all services in region`.

**Why:** the region is an opt-in region (for example `me-south-1`) that the account has not enabled, so calls to it fail.
The scan skips it.

**What to do:** nothing, if you do not need it. To silence it, leave it out with `--exclude-regions`; to scan it, enable the
region in the account settings.

<a id="aws-throttled"></a>
### aws-throttled

**You see:** `Throttling`, `RequestLimitExceeded` or `Rate exceeded`.

**Why:** AWS is limiting the request rate, most often when several accounts are scanned at once.

**What to do:** run again in a few minutes. In a multi-account scan, lower `--workers` (the default is 8 accounts at a
time). `--workers` does not change a single-account scan, which reads up to 20 regions at a time; scan fewer regions
with `--regions` instead.

<a id="aws-endpoint-unreachable"></a>
### aws-endpoint-unreachable

**You see:** `Could not connect to the endpoint URL`, `EndpointConnectionError` or `Connect timeout`.

**Why:** the machine cannot reach the AWS endpoint of that region (a proxy, a firewall, a network outage), or the region is
disabled for the account.

**What to do:** check the network and proxy settings ([Proxies and certificates](#proxies-and-certificates)). If only one
region fails, treat it as [aws-region-not-enabled](#aws-region-not-enabled).

<a id="aws-certificate-verify-failed"></a>
### aws-certificate-verify-failed

**You see:** `SSL validation failed for https://...` with `CERTIFICATE_VERIFY_FAILED` or `certificate verify failed`.

**Why:** boto3 could not verify the AWS endpoint's certificate, usually because a proxy on your network re-signs HTTPS
traffic with your organization's own certificate authority. Signing in again does not help.

**What to do:** point boto3 (and the AWS CLI) at your organization's certificate bundle and run again. Verification is
never turned off.

Run: export AWS_CA_BUNDLE=/path/to/ca-bundle.pem

See also [Proxies and certificates](#proxies-and-certificates).

<a id="aws-recovery-points-truncated"></a>
### aws-recovery-points-truncated

**You see:** `Recovery point listing in REGION stopped after N min; sizes are lower bounds`, and
`BackupEnumerationTruncated` set on that region's rows.

**Why:** listing every AWS Backup recovery point of every vault has a time budget per region (60 minutes by default), and
a region with very many recovery points used it up. The counts and sizes of that region are what was listed by then.

**What to do:** accept lower bounds, or give it more time: add `--backup-recovery-point-timeout-minutes 180` (or more)
to the command and run again.

<a id="aws-backup-plans-incomplete"></a>
### aws-backup-plans-incomplete

**You see:** `Account ACCOUNT: backup plan details are missing or incomplete in REGION, so InBackupPlan there comes from
AWS Backup's protected resources and BackupPlans is empty`, or `Access denied listing backup vaults in REGION; skipping
recovery points`.

**Why:** a backup plan or one of its selections could not be read (denied or throttled), so the tool cannot tell which
resources the plans select there. It falls back to what AWS Backup lists as protected and leaves `BackupPlans` empty.
The second message is a denied vault listing, which leaves `aws_backup_recovery_points` without that region.

**What to do:** grant `backup:ListBackupPlans`, `backup:GetBackupPlan`, `backup:ListBackupSelections`,
`backup:GetBackupSelection`, `backup:ListBackupVaults` and `backup:ListRecoveryPointsByBackupVault` to the role you scan
with, then run again. A throttled read is not recorded as a scan error, so the account is saved as finished cleanly and
`--resume` does not scan it again: in a multi-account scan delete its subfolder first
([aws-resume](#aws-resume)), or add `--fresh`.

<a id="aws-bucket-upload"></a>
### aws-bucket-upload

**You see:** nothing in the bucket named by `--bucket`, or only JSON files there.

**Why:** `--bucket` is used only by the multi-account modes, and there it uploads each account's raw JSON (not the zip
and not the CSV files) to `s3://BUCKET/ACCOUNT_ID/aws_sizing_discovery.json`, with that account's own credentials. A
single-account run ignores it. An upload that fails is reported as `Scan failed for ACCOUNT`, and the account counts as
failed in that run although its results are kept in the progress folder.

**What to do:** copy the zip yourself after the run. For the per-account upload, the role in each account needs
`s3:PutObject` on the bucket, and a bucket in another account needs a bucket policy that allows it.

## Azure

<a id="az-optional-package-missing"></a>
### az-optional-package-missing

**You see:** `azure-mgmt-security is not installed` (or `azure-mgmt-purview`) in the access check, and no question about
Defender. Or `azure-mgmt-dataprotection is not installed` in the access check, and a yellow line at the start of the scan
saying Azure Backup for Blobs and PostgreSQL (Backup Vaults) will not be reported.

**Why:** the tool's Python environment is missing a package from `requirements.txt`, for example a virtual environment
set up before the package was listed there, or one where `pip install` was not run. The Defender and Purview data goes to
the JSON only, so nothing in the CSV files is affected. The Backup Vault package matters more: without it the three
`azure_backup_data_protection_*` files are not written, and a storage account with Blob backup and a PostgreSQL server with
backup show `-` and `False` in their backup columns, as if they were not protected.

**What to do:** run the generated script again (it installs `requirements.txt`), or install it yourself in the `azure`
folder, with the tool's virtual environment active:

Run: pip install -r requirements.txt

Azure Site Recovery is not collected at all: its collector does not work with the current package.

<a id="az-metrics-time-interval"></a>
### az-metrics-time-interval

**You see:** `(BadRequest) Detected invalid time interval input: 2026-10-11T07:43:08.151577 00:00/...` and storage capacity
`n/a` for every account.

**Why:** older versions sent Azure Monitor a time range ending in `+00:00`, which it rejects, so every capacity query
failed. Newer versions send UTC instants ending in `Z`.

**What to do:** update the checkout and run again.

Run: git pull --ff-only

<a id="az-metrics-denied"></a>
### az-metrics-denied

**You see:** `MetricsDenied` on `storage metrics (capacity)` in the access check.

**Why:** the identity cannot read Azure Monitor metrics, which is where storage capacity and object counts come from.

**What to do:** grant Monitoring Reader (or Reader) at subscription scope, or run with `--no-capacity`.

<a id="az-key-vault-contents-denied"></a>
### az-key-vault-contents-denied

**You see:** `Key Vault <name>: could not count secrets (Forbidden); left blank` with `--get-key-vault-amounts`, or
`key vault contents` denied in the access check.

**Why:** counting certificates, secrets and keys reads inside the vault (its data plane), which Reader does not cover. The
count is left blank in `azure_key_vault`, as PowerShell leaves it; a vault that holds nothing shows `0`.

**What to do:** grant Key Vault Reader on the vault or the subscription. A vault that uses access policies instead of
Azure RBAC needs the List permission on certificates, secrets and keys for this identity. A vault with a firewall also has
to allow the network you run from.

<a id="az-blob-data-denied"></a>
### az-blob-data-denied

**You see:** `Blob containers of N storage account(s) could not be listed (AuthorizationPermissionMismatch)` or `Blobs of
container <name> ... could not be listed` with `--get-container-details`, or `blob containers` denied in the access check.
The run summary counts them on one line, for example `234x in 1 subscription`.

**Why:** the tool lists blobs signed in with Entra ID, which needs a data role; Reader is not enough. PowerShell lists them
with the account key instead, so it needs `listKeys` rather than a data role. An account that cannot be listed has no rows
in `azure_storage_account_container_info`; a container whose blobs cannot be listed has a row with empty values.
When containers in 5 storage accounts are refused with `AuthorizationPermissionMismatch` and none could be read, the
role is missing for the subscription: its other containers are still listed, with empty rows, but their blobs are not
tried, which saves several seconds per container.

**What to do:** grant Storage Blob Data Reader on the storage accounts or the subscription. A storage account with a
firewall also has to allow the network you run from.

<a id="az-storage-capacity-blank"></a>
### az-storage-capacity-blank

**You see:** `Used-capacity unavailable for ALL N storage account(s): every Azure Monitor metrics query failed, so storage
capacity will be blank in the report and Explorer. Most common cause (...)`.

**Why:** not one storage account returned a capacity metric. The words in brackets are the error most of the queries
got, and they name the cause.

**What to do:** follow the section for those words: `MetricsDenied` or `AuthorizationFailed`:
[az-metrics-denied](#az-metrics-denied); `Detected invalid time interval`:
[az-metrics-time-interval](#az-metrics-time-interval); `MissingSubscriptionRegistration` for `Microsoft.Insights`:
[az-provider-not-registered](#az-provider-not-registered); a throttle or a timeout: run again later. Or skip capacity with
`--no-capacity`.

<a id="az-provider-not-registered"></a>
### az-provider-not-registered

**You see:** `MissingSubscriptionRegistration`, `NoRegisteredProviderFound` or `ResourceProviderNotRegistered`.

**Why:** the subscription has not registered a resource provider the scan calls.

**What to do:** register the provider named in the error (the example is `Microsoft.Insights`) and run again. To check one:

Run: az provider show --namespace Microsoft.Insights --query registrationState

and to register it:

Run: az provider register --namespace Microsoft.Insights

<a id="az-authorization-failed"></a>
### az-authorization-failed

**You see:** `(AuthorizationFailed) The client '...' does not have authorization to perform action
'Microsoft.Resources/subscriptions/read' over scope '/subscriptions/...' or the scope is invalid.`

**Why:** the identity has no role on that scope, **or** the Azure CLI is set to a different tenant from the subscription's.
The tool takes its token for the tenant of the CLI's current subscription, so a subscription in another tenant is refused
even though `az account list` shows it. A role that is eligible but not activated (PIM) gives the same error.

**What to do:** first see which tenant each subscription is in:

Run: az account list --all --query "[].{name:name,id:id,tenant:tenantId}" -o table

If the subscription's tenant differs from your current one, switch to it:

Run: az account set --subscription SUBSCRIPTION_ID

or sign in to that tenant:

Run: az login --tenant TENANT_ID

If the tenant is the same, assign Reader at subscription scope (plus Monitoring Reader for storage metrics and Cost
Management Reader for cost), or activate the eligible role, and run again.

<a id="az-subscription-failed"></a>
### az-subscription-failed

**You see:** `Subscription ID failed and was skipped: <Error>: <message>`, then `N of M subscription(s) failed and are
excluded from the results: ...`; or `Every subscription failed; nothing to report.` and exit code 1.

**Why:** an error that the collectors did not handle stopped one subscription's scan. The other subscriptions go on, and
the failed one is left out of every file. When all of them fail there is nothing to write, so no zip is made.

**What to do:** look up the error after the colon in the index. Once it is fixed, scan the failed subscriptions on their
own with `--subs`. `--workers 1` scans one subscription at a time, which keeps the log in order. If the error is not on
this page, send the log ([Still stuck](#still-stuck)). The failed subscription keeps its access-check rows in
`azure_preflight_check-*.csv`, with one more row, `Service` `scan`, holding the error code.

<a id="az-cost-management"></a>
### az-cost-management

**You see:** `Cost data requested but none returned` with a `Cost` line marked `⚠`, or one of
`Cost Management 403 (permission denied)`, `Cost Management 404 (provider not registered?)`,
`Cost Management still throttled after N attempts`, `Cost Management query failed (HTTP N)`.

**Why:** cost comes from Azure Cost Management, which needs its own role, a registered provider and an offer type it
supports:

- **403**: the identity has no Cost Management Reader (or Reader) on the subscription.
- **404**: the tool reads this as the `Microsoft.CostManagement` provider not being registered.
- **Throttled**: Cost Management allows few queries; the tool waits and retries, then gives up for that subscription and
  does not run the backup-cost query after it.
- **No data**: some subscription offer types are not supported by Cost Management, and a new subscription has no cost
  data for a while.

`No cost data: the subscription has no backup vaults` is not a problem: there is no backup cost to report.

**What to do:** grant Cost Management Reader at subscription scope, or register the provider:

Run: az provider register --namespace Microsoft.CostManagement

For a throttle, run again later or with fewer `--workers`. If the offer type is not supported, run with `--no-cost`. Only
the cost figures and `azure_backup_costs` are affected.

<a id="az-devops"></a>
### az-devops

**You see:** `Could not acquire Azure DevOps token — identity may not have DevOps access. Skipping DevOps discovery.`,
`Azure DevOps: 401 Unauthorized for ...`, `Azure DevOps: 403 Forbidden for ...`,
`Could not fetch Azure DevOps profile — skipping org discovery.` or `DevOps discovery skipped: ...`.

**Why:** every Azure run also looks for Azure DevOps repositories with your sign-in, unless `--no-devops` is given. Most
identities have no Azure DevOps access, or the organization does not allow it. The token message quotes the sign-in
credential, but signing in again does not help.

**What to do:** run with `--no-devops` (the generated run scripts do), or name organizations you can read with
`--devops-orgs ORG`. DevOps data goes to the JSON only; no CSV file is affected.

<a id="az-backup-vaults-unlisted"></a>
### az-backup-vaults-unlisted

**You see:** `Backup Vaults could not be listed: ...`, `Unable to collect Azure Backup Vault information: ...`,
`Failed to get Azure Backup Vault policies for vault ...`, `Failed to get Azure Backup Vault backup instances for
vault ...` or `Could not work out the resource group for Backup Vault ...`.

**Why:** Backup Vaults (Azure Backup for Blobs and PostgreSQL) are read with `azure-mgmt-dataprotection`. A denied call
or an unregistered `Microsoft.DataProtection` provider stops the listing for that subscription or vault. The three
`azure_backup_data_protection_*` files are then incomplete, and the Blob and PostgreSQL backup columns of the storage
and PostgreSQL files show `-` and `False` where the protection could not be read.

**What to do:** give the identity Reader on the subscription, check the provider
([az-provider-not-registered](#az-provider-not-registered), with `Microsoft.DataProtection`), and run again.
`Not reported (other datasource types): ...` is not an error: it counts backups of kinds these files do not cover.

<a id="az-government-cloud"></a>
### az-government-cloud

**You see:** a sign-in failure or `No accessible subscriptions found` when scanning Azure Government, or
`Unrecognised Azure cloud 'NAME' from --cloud — ignoring`.

**Why:** the tool uses the cloud named by `--cloud`, else `AZURE_CLOUD`, else the cloud the `az` CLI is set to, else the
public cloud. Signing in to one cloud and scanning another fails. A name it does not know is ignored and the next source
is used; only `AzureCloud` and `AzureUSGovernment` (and short forms such as `gov` and `public`) are known, so Azure China
is not supported.

**What to do:** point the CLI at the cloud, sign in to it and pass the same cloud to the tool:

Run: az cloud set --name AzureUSGovernment

Run: az login

Then run with `--cloud AzureUSGovernment`.

<a id="az-throttled"></a>
### az-throttled

**You see:** `TooManyRequests` or HTTP 429.

**Why:** Azure is limiting the request rate. Cost Management is the most aggressive.

**What to do:** run again in a few minutes, or lower `--workers`. A throttled access check shows `NOT CHECKED`, not a loss.

<a id="az-cli-unavailable"></a>
### az-cli-unavailable

**You see:** `Failed to invoke the Azure CLI`, or `AzureCliUnavailable` with `NOT CHECKED` in the access check.

**Why:** the tool gets its sign-in token from `az account get-access-token`, and the CLI did not answer within
60 seconds or could not start. No request reached Azure, so it says nothing about your access. A slow CLI is most
likely in Azure Cloud Shell, the first time it is used in a session.

**What to do:** run the tool again. If it repeats, check that the CLI answers quickly, and run with `--workers 1` so
fewer requests wait on it at once.

Run: az account get-access-token --output none

<a id="az-not-signed-in"></a>
### az-not-signed-in

**You see:** `Please run 'az login'`, `DefaultAzureCredential failed to retrieve a token` or `ClientAuthenticationError`.

**Why:** the Azure CLI has no sign-in, or it expired. (The long list of credentials tried before the CLI is normal.)

**What to do:**

Run: az login

The `Authentication failed` box the tool prints gives steps for where it runs. In particular:

- **Azure Cloud Shell** with `AudienceNotSupported`: the tenant's automatic Cloud Shell sign-in cannot issue the token
  the tool needs. Sign in as yourself with a device code, then run the tool again. If that is refused too, the tenant
  blocks the method and an Azure admin has to allow it.

  Run: az login --use-device-code

- **An Azure VM with a managed identity**: the identity must be turned on and have Reader on the subscriptions; for a
  user-assigned identity set `AZURE_CLIENT_ID` to its client ID.
- **A service principal**: set `AZURE_CLIENT_ID`, `AZURE_TENANT_ID` and `AZURE_CLIENT_SECRET` in the environment (never in
  a script you share).
- **An `AADSTS` code** in the message (for example a required multi-factor sign-in or an expired refresh token): run
  `az login` again, with `--tenant TENANT_ID` if the tenant needs it.
- **A government cloud**: see [az-government-cloud](#az-government-cloud).

<a id="az-no-subscriptions"></a>
### az-no-subscriptions

**You see:** `No accessible subscriptions found.`

**Why:** none of the subscriptions asked for could be read: wrong IDs in `--subs`, or the CLI is on another tenant
([az-authorization-failed](#az-authorization-failed)). Nothing is scanned and no access check is made.

**What to do:** check the IDs and the tenant:

Run: az account list --all

If access was only just granted, refresh the list first with `az account list --refresh`.

More causes, by how the subscriptions were chosen:

- **No scope option**: every enabled subscription the sign-in can read is scanned; none readable gives this message.
- **`--subscriptions`**: a name that matches no enabled subscription is left out and reported as not scanned.
- **`--management-groups`**: a group that cannot be read (needs Reader on it) is left out and reported as not scanned.
- **`--current-subscription`**: the tool asks `az account show` for the current subscription. If the `az` CLI is not
  installed or not on the `PATH`, or has no current subscription, the result is this message. Pass `--subs`, or select
  one with `az account set --subscription SUBSCRIPTION_ID`.
- **`--subs`**: each ID that cannot be read prints `Subscription ID not accessible: ... — skipping` and is left out;
  only when none is left does the run stop. `SubscriptionNotFound` in that line means a typo or another tenant. Each
  one also has a `subscription` row in `azure_preflight_check-*.csv` and is listed at the end of the run; to check a
  list of IDs without scanning, use `--preflight-only`.
- **`--all`**: only subscriptions in the `Enabled` state are scanned; disabled, warned and past-due ones are left out.

<a id="az-pricing-unreachable"></a>
### az-pricing-unreachable

**You see:** `VM pricing: found 0 of N SKUs; N price request(s) failed (first error: ...)`, with N greater than 0.

**Why:** the Azure retail prices service (`prices.azure.com`) could not be reached.

**What to do:** check outbound access to `prices.azure.com`. Only the VM cost estimate is skipped; nothing else changes.

<a id="az-pricing-no-match"></a>
### az-pricing-no-match

**You see:** `VM pricing: found 0 of N SKUs; 0 price request(s) failed (the prices service answered but had nothing for
these SKUs and regions)`.

**Why:** the prices service answered, but it has no price for those VM sizes and regions (a size it does not list, say).
Nothing failed, so there is nothing to fix on your side.

**What to do:** nothing. The VMs without a price have no cost estimate; the rest of the output is not affected.

<a id="az-certificate-verify-failed"></a>
### az-certificate-verify-failed

**You see:** `CERTIFICATE_VERIFY_FAILED` in a warning about the tenant or about VM pricing, for example
`unable to get local issuer certificate` or `self-signed certificate in certificate chain`.

**Why:** the tenant lookup and the VM price list are the two requests the tool makes without the Azure SDK. Python could
not verify the server's certificate with the certificates it used. Signing in again does not help, and the network is
not down. The wording after `certificate verify failed` tells the two causes apart:

- **`unable to get local issuer certificate`**, on a Mac with Python from python.org: that Python has no certificate
  store until its Install Certificates step has run. Only these two requests are affected, so only the `Tenant` column
  and the VM cost estimate are missing; the rest of the scan goes through the Azure SDK, which brings its own bundle.
  The current tool hands these two requests the same bundle (`certifi`), so this is seen with an older checkout or an
  environment without `certifi`.
- **`self-signed certificate in certificate chain`**: a proxy on your network re-signs HTTPS traffic with your
  organization's own certificate authority. Then the Azure SDK and the `az` CLI usually fail too, and the whole scan
  shows certificate errors, not only these two columns.

**What to do:**

- **The Mac case:** run the Install Certificates step that comes with python.org Python. The version in the path is
  yours (`python3 --version`):

  Run: open "/Applications/Python 3.12/Install Certificates.command"

- **The proxy case:** get your organization's certificate bundle (a PEM file) and point `REQUESTS_CA_BUNDLE` at it. It is
  read by the Azure SDK, the `az` CLI and these two requests, so it covers all of them:

  Run: export REQUESTS_CA_BUNDLE=/path/to/ca-bundle.pem

  `SSL_CERT_FILE` also works for these two requests, but not for the SDK or the CLI. When more than one is set, these two
  requests use the first of `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`. See also
  [Proxies and certificates](#proxies-and-certificates).

Verification is never turned off. `<VARIABLE> names <path>, which is not a file; using the default certificates` and
`Could not load the certificate bundle <path>` mean the bundle you named was not used: check the path and that the file
is PEM.

<a id="az-tenant-lookup-failed"></a>
### az-tenant-lookup-failed

**You see:** `Could not read the tenant of subscription ...` or `Could not read the display name of tenant ...`, and the
`Tenant` column blank in the CSV files (the SQL files show `unknown`).

**Why:** the tenant is read from the Azure Resource Manager API with your sign-in (`GET /subscriptions/{id}` for the
tenant id and `GET /tenants` for its name), because the SDK's subscription and tenant models do not carry them. The
warning names the reason: a denied or unauthorized call, a network problem, or a tenant that is not in the list your
sign-in can see.

**What to do:** sign in again, and check that this machine can reach the Resource Manager endpoint of your cloud.

Run: az login

The scan itself is not affected; only the `Tenant` column is.

<a id="az-ltr-unreadable"></a>
### az-ltr-unreadable

**You see:** `Long-term retention policy could not be read for N database(s); their LTR columns are blank`, followed by the
first error.

**Why:** the call that reads a SQL database's long-term retention policy failed for a reason other than "this database has
none", most often a denied call. A database that has no policy, or cannot have one, is not reported.

**What to do:** give the identity a role with read access to the SQL servers (Reader covers it) and run again. Only the four
`LTR` columns of `azure_sql_info` are affected.

## GCP

<a id="gcp-api-disabled-in-billing-project"></a>
### gcp-api-disabled-in-billing-project

**You see:** at the start of the access check, `Quota project cnp-example-1 has spanner.googleapis.com,
bigtableadmin.googleapis.com disabled; this affects all 6 projects.`, with Google's text `403 Cloud Bigtable Admin API has
not been used in project cnp-example-1 before or it is disabled`. In the table those services are `NOT CHECKED` with
`unknown (QuotaProjectServiceDisabled)`; in `gcp_preflight_check-*.csv` their `Access` is `could not be checked`, `Outcome`
`unknown` and `Detail` `QuotaProjectServiceDisabled`.

**Why:** Google charges each call to the quota project of your sign-in, not to the project being read. The tool prints it
first (`Quota project: <id> (from GOOGLE_CLOUD_QUOTA_PROJECT)` or `(from the application-default login)`). Some APIs,
Spanner, Bigtable and Cloud Asset among them, have to be on in **that** project as well. When it is off there, every
scanned project fails the same way, and the error names the quota project every time. It says nothing about the scanned
projects: they may well use the service. So those rows are "not checked", not "not enabled", and enabling the API in the
scanned projects does not help.

The tool counts an error as the quota project's when the project it names is not the scanned project and is the quota
project, or a project ID, or a project number that the errors of two or more scanned projects name. When the error names
the scanned project itself, see [gcp-api-disabled](#gcp-api-disabled).

**What to do:** enable every listed API once, in the quota project (the tool prints the command with all of them):

Run: gcloud services enable spanner.googleapis.com bigtableadmin.googleapis.com --project QUOTA_PROJECT

or charge a project where they are on:

Run: gcloud auth application-default set-quota-project OTHER_PROJECT

In Cloud Shell the quota project comes from `GOOGLE_CLOUD_QUOTA_PROJECT`; set that instead
(`export GOOGLE_CLOUD_QUOTA_PROJECT=OTHER_PROJECT`). Then run the scan again. Or leave the collector out with `--collectors`.

<a id="gcp-api-disabled"></a>
### gcp-api-disabled

**You see:** `SERVICE_DISABLED`, `accessNotConfigured` or `it is disabled`, or in the access check a service that is
`API NOT ENABLED` (`ServiceDisabled`) in some projects, each error naming its own project.

**Why:** the API is off in the scanned project itself. That project then holds nothing of that service to size, so the
rows are `not enabled` / `dropped`, and the scan skips that collector there.

**What to do:** nothing, if the project does not use the service. Otherwise enable it in each project; the tool prints one
command per project:

Run: gcloud services enable SERVICE.googleapis.com --project PROJECT

<a id="gcp-billing-disabled"></a>
### gcp-billing-disabled

**You see:** `BillingDisabled` in the access check, or `This API method requires billing to be enabled`, `BILLING_DISABLED`
or `Absent billing account`, in some projects, each naming its own project.

**Why:** the scanned project has no billing account linked. Google refuses Compute, Spanner, Bigtable and Backup and DR
calls there, and such a project holds nothing of them to size. When every project's error names the same other project,
it is the quota project instead: see [gcp-quota-project-billing-disabled](#gcp-quota-project-billing-disabled).

**What to do:** nothing, for a project that is not in use. Otherwise link a billing account to each project (the tool
prints one command per project):

Run: gcloud billing projects link PROJECT --billing-account=BILLING_ACCOUNT_ID

<a id="gcp-quota-project-billing-disabled"></a>
### gcp-quota-project-billing-disabled

**You see:** `Quota project QUOTA_PROJECT has billing disabled; this affects all N projects`, with Google's text `This API
method requires billing to be enabled. Please enable billing on project #QUOTA_PROJECT`. The services are `NOT CHECKED`
in the table and `could not be checked` with `Detail` `QuotaProjectBillingDisabled` in `gcp_preflight_check-*.csv`.

**Why:** the quota project, which Google charges every call to, has no billing account, so each call that needs billing
is refused in every scanned project. Nothing is known about the scanned projects themselves.

**What to do:** link a billing account to the quota project (in the console: Billing, then Account management, then
Link a billing account, for that project):

Run: gcloud billing projects link QUOTA_PROJECT --billing-account=BILLING_ACCOUNT_ID

or charge a project that has billing on:

Run: gcloud auth application-default set-quota-project OTHER_PROJECT

To pick one, list your projects with their billing state and how many of the APIs the tool uses they have on (the tool
prints the same loop):

```bash
for p in $(gcloud projects list --format='value(projectId)'); do b=$(gcloud billing projects describe $p --format='value(billingEnabled)'); n=$(gcloud services list --enabled --project $p --format='value(config.name)' | grep -cE '^(cloudresourcemanager|cloudasset|compute|spanner|bigtableadmin|alloydb|backupdr)[.]googleapis[.]com$'); echo "$p billing=$b apis=$n/7"; done
```

Choose one with `billing=True` and the most APIs on.

<a id="gcp-org-policy"></a>
### gcp-org-policy

**You see:** `Operation denied by org policy ...`, `Request is prohibited by organization's policy` or
`VPC_SERVICE_CONTROLS`.

**Why:** an organization policy or a VPC Service Controls perimeter blocks the call. Google also words an ordinary missing
permission as `Operation denied by [IAM permission '...' on resource ...]` (with `IAM_PERMISSION_DENIED`); that one is a
permission denial, see [gcp-permission-denied](#gcp-permission-denied).

**What to do:** ask your Google Cloud organization admin to allow the identity, or leave the project out (`--projects`).

<a id="gcp-permission-denied"></a>
### gcp-permission-denied

**You see:** `Request denied by Cloud IAM`, `Required 'compute.instances.list' permission`, `Permission '...' denied`,
`Operation denied by [IAM permission '...' ...]`, `PERMISSION_DENIED` or `notAuthorized`.

**Why:** the identity you signed in with cannot read that project. The pre-flight table shows which permission and which
output files are affected, project by project.

**What to do:** grant a role that includes the permission (Viewer on the project covers the list permissions; see
`permissions.md`), or leave the project out. To check one call by hand:

Run: gcloud compute instances list --project PROJECT

<a id="gcp-no-credentials"></a>
### gcp-no-credentials

**You see:** `Your default credentials were not found` or `DefaultCredentialsError`.

**Why:** there is no application-default login and no service account key set.

**What to do:**

Run: gcloud auth application-default login

or set `GOOGLE_APPLICATION_CREDENTIALS` to a service account key file.

`gcloud auth login` signs in the `gcloud` CLI only; the tool reads the application-default login, which is a separate
step. If `GOOGLE_APPLICATION_CREDENTIALS` is set, it wins over that login, so a path to a file that is gone gives the same
error (`File ... was not found`): fix the path or unset the variable.

<a id="gcp-credentials-expired"></a>
### gcp-credentials-expired

**You see:** `Authentication failed: Unexpected error: ...` with `RefreshError`, `invalid_grant`,
`Token has been expired or revoked` or `Reauthentication is needed`.

**Why:** the application-default login exists but can no longer be refreshed: it expired (many organizations limit how
long a Google session lasts), the password changed, or access was revoked. For a service account key, the key was
deleted or disabled.

**What to do:** sign in again, then run the tool again.

Run: gcloud auth application-default login

For a service account, create a new key or use another sign-in method. The generated run script checks this before
it starts and says `No Application Default Credentials` when the login cannot give a token.

<a id="gcp-no-projects"></a>
### gcp-no-projects

**You see:** `No accessible projects found.`, often after `Project ID not accessible: ... — skipping` or
`Failed to enumerate projects: ...`. Nothing is scanned and the run stops with exit code 1.

**Why**, by how the projects were chosen:

- **No scope option** (all projects): the tool searches for active projects, and finds only those where the identity can
  read the project itself (`resourcemanager.projects.get`). An identity with roles only on resources inside projects finds
  none.
- **`--projects` or `--project-file`**: each ID is looked up first; one that cannot be read is skipped with the warning
  above (a typo, a deleted project or no access), and the run stops only when none is left. Each one also has a
  `project` row in `gcp_preflight_check-*.csv` and is listed at the end of the run; to check a list of IDs without
  scanning, use `--preflight-only`.
- **`--current-project`**: the project comes from the application-default login, else from `gcloud config`. With neither,
  there is none.
- **`Failed to enumerate projects`** with an API that is off: the Cloud Resource Manager API is off in the project your
  calls are charged to ([gcp-api-disabled-in-billing-project](#gcp-api-disabled-in-billing-project)).

**What to do:** check what the sign-in can see, then pass the IDs, or grant Viewer (or Browser) on the projects:

Run: gcloud projects list

For `--current-project`, set the project first:

Run: gcloud config set project PROJECT_ID

`scope.projects in the config file is not used for project selection` means a `--config` file lists projects, which the
tool does not read for this; pass them with `--projects` or `--project-file`.

<a id="gcp-quota-project-denied"></a>
### gcp-quota-project-denied

**You see:** `Project <id> not checked: API calls are charged to quota project <project>, which refuses them
(USER_PROJECT_DENIED)` for every project, then `No project could be read`. Google's own text says `Caller does not have
required permission to use project <project>` and names the same project whichever project was being read.

In the access check those rows are `NOT CHECKED` with `Detail` `QuotaProjectDenied`, and the problem is reported once.

**Why:** Google charges each API call to the quota project of your sign-in, not to the project being read. In Cloud
Shell that is the current project, through the `GOOGLE_CLOUD_QUOTA_PROJECT` environment variable; elsewhere it is the
quota project of your application-default login. If you may not use services in that project (it takes
`roles/serviceusage.serviceUsageConsumer`), every call is refused, whatever access the scanned projects give.

**What to do:** stop sending that quota project, or name one where you have Service Usage Consumer, then run again.

Run: unset GOOGLE_CLOUD_QUOTA_PROJECT

Run: export GOOGLE_CLOUD_QUOTA_PROJECT=<project>

Outside Cloud Shell, set the quota project of the application-default login instead.

Run: gcloud auth application-default set-quota-project <project>

<a id="gcp-quota-project-warning"></a>
### gcp-quota-project-warning

**You see:** `Your application has authenticated using end user credentials from Google Cloud SDK without a quota
project.` Or, for Cloud Asset Inventory in every project, `The cloudasset.googleapis.com API requires a quota project,
which is not set by default`, which the access check shows as `NOT CHECKED` (`NoQuotaProject`), after `Quota project:
none`.

**Why:** the application-default login names no project to charge API calls to. The first message is a warning from
Google's library, not from the tool; some APIs, Cloud Asset Inventory among them, refuse the call outright. It is the
same setting that decides where an API has to be on
([gcp-api-disabled-in-billing-project](#gcp-api-disabled-in-billing-project)).

**What to do:** set a quota project you can use, usually one of the scanned projects:

Run: gcloud auth application-default set-quota-project PROJECT_ID

<a id="gcp-rate-limited"></a>
### gcp-rate-limited

**You see:** `RESOURCE_EXHAUSTED`, `Quota exceeded` or HTTP 429.

**Why:** Google is limiting the request rate for the project the calls are charged to. That is your quota project, not
the project being scanned, so every worker draws on the same budget. The Cloud Asset listing has one of 100 requests a
minute; the tool asks for 1000 assets per page, retries a throttled page on its own and keeps all workers under 80 a
minute, so it rarely hits it.

**What to do:** run again later, or lower `--workers` (the default is 8). If one project still shows `asset listing rate
limited`, run it on its own with `--projects`.

<a id="gcp-transient-retry"></a>
### gcp-transient-retry

**You see:** `Transient GCP error during <call>, backing off and retrying: ...`, sometimes many times, and a run that
seems to stall.

**Why:** a call failed for a reason that usually passes (a timeout, an unavailable service, a rate limit), and the tool
waits and tries again. The warnings are counted in the run summary, but they are not a loss on their own. A Spanner
database listing can retry for up to 10 minutes per instance, and instances in one project are read one after another.

**What to do:** nothing, unless the same project then shows `collection failed` for that service; then look up that
message. If a project with many Spanner instances is slow, run it on its own with `--projects`.

<a id="gcp-asset-inventory"></a>
### gcp-asset-inventory

**You see:** `Asset enumeration failed for project PROJECT: ...` or, with `--org` or `--folder`,
`Org-wide asset enumeration failed for scope organizations/N: ... — falling back to per-project asset collection`.
On the progress line the project shows `asset listing rate limited` or `asset listing could not be read`, not a count.

**Why:** if the message names a `429` or `Quota exceeded`, the listing was throttled for longer than the tool waits (2
minutes a page); see [gcp-rate-limited](#gcp-rate-limited). The counts for that project are unknown, not zero: they are
left out of `asset_counts` in the JSON, and the reason is in `collection_errors`. Otherwise, the asset inventory needs the
Cloud Asset API on in the project your calls are charged to, and `roles/cloudasset.viewer` on each project, or on the
organization or folder for `--org` and `--folder`. The org-wide sweep falls back to one call per project when it fails,
so a run with `--org` is slower but not missing anything that the per-project calls can read.

**What to do:** turn the API on in the project named in the error
([gcp-api-disabled-in-billing-project](#gcp-api-disabled-in-billing-project)) and grant the role where the scan needs it,
or leave the asset collector out with `--collectors`. Asset data is in the JSON only; no CSV file is affected.
`--security` (Security Command Center) needs `roles/securitycenter.findingsViewer` at organization level for the same
reason.

<a id="gcp-project-not-found"></a>
### gcp-project-not-found

**You see:** `PROJECT_NOT_FOUND` or `Project '...' not found`.

**Why:** the ID is misspelled, or the identity cannot see the project.

**What to do:** list what the sign-in can see and compare:

Run: gcloud projects list

<a id="gcp-client-library-missing"></a>
### gcp-client-library-missing

**You see:** `cannot import name 'backupdr_v1' from 'google.cloud'` or `No module named`.

**Why:** a Google client library is missing from the virtual environment, or an old one is installed.

**What to do:** reinstall the requirements in the active environment:

Run: pip install -r requirements.txt

## Still stuck

Send the run log (`output_<cloud>_<timestamp>.log` in the zip) and the access-check CSV. The log holds real names unless the
run was anonymized, in which case the real log is beside the zip and stays with you.

- **A run that stopped early** has no zip: send the log left in the output folder (for a multi-account AWS scan without
  `--output`, the current folder). Its header has the code version, the package versions, the Python version and the
  command line, and its last lines say how the run ended ([The run stopped before the zip](#the-run-stopped-before-the-zip)).
- **A sign-in problem or a bad option** leaves no log (AWS): copy the message from the screen.
- **Say what you expected** to see and where (account, region, resource type), and the exit code (`echo $?` right after
  the run).
- **Never send** the `*_anonymized_keys_to_actual_values-*` file, exported keys, tokens or a service account key file.
