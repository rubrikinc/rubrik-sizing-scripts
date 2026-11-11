# GCP pre-flight: quota-project attribution

**File:** `sizing_scripts/cloud/python/CLAUDE.md`, "Pre-flight access check", GCP bullet.

**Change:** added how 403s about the quota project are told apart from the scanned project's
(`auth.effective_quota_project`, `preflight.attribute`, `runlog.quota_block`), the new
`QuotaProject*` / `NoQuotaProject` Detail codes, and that the status set, the CSV columns and
`preflight_core.py` did not change.

**Why:** the bullet said only "A disabled API is reported as not enabled", which is no longer true
when the error names the quota project. A future change to the access check needs to know that
those rows are deliberately `could not be checked` (so they are not read as "the customer does not
use the service") and that the scan still runs those collectors.
