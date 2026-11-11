# Sharing the tools as zips

`make_cloud_zips.sh` builds one zip per cloud with everything needed to run a scan, and nothing else. It is an
alternative to the run guides (`../docs/run-guides/`), whose scripts clone the repository: a zip needs only Python and
the cloud's CLI, so it can be handed to a customer or uploaded to a cloud shell as it is.

## Build the zips

```bash
bash sizing_scripts/cloud/python/packaging/make_cloud_zips.sh
```

It writes `rubrik-cloud-sizing-aws-<commit>.zip`, `-azure-` and `-gcp-` to `./cloud-sizing-zips`. Arguments, all
optional: the clone to package from (default: the one the script is in), the branch, tag or commit (default:
`origin/master`, fetched first) and the output folder. The commit in each file name says which code
a zip holds, so rebuild whenever the code changes.

## What a zip holds

- The tool's committed code, as on the branch: no tests, caches or local output. Every option works as in the repo,
  except `--mock`, whose test data is not shipped.
- `QUICKSTART.md`: install, sign in, run one command, send back the results zip. The commands work in bash and in
  PowerShell on Linux, macOS, WSL and the three cloud shells; native Windows uses `.venv\Scripts\` instead of
  `.venv/bin/`.
- `docs/`: user guide, permissions, troubleshooting (every fix in the run summary links to it), the run log, the
  PowerShell parameter mapping and the tool's comparison with PowerShell.

## Message to send with a zip

> Please run the Rubrik cloud sizing tool for <cloud>. Unzip the attached file and follow its `QUICKSTART.md`: install,
> sign in, run one command. It needs Python 3.9+ (AWS) or 3.10+ (Azure, GCP) and works from a laptop or the cloud
> provider's shell, where you are already signed in. The tool only reads your inventory. It checks its access first,
> and the summary at the end lists any problem with its fix. Send us the zip it writes to `./output`.

## Before sharing outside Rubrik

- Every Python package is pinned to the exact version the tests ran on (`requirements.txt`), so each run installs the
  same packages. The run log in the results zip records which ones.
- The run log says `Code: unknown`, because a zip has no git history; the zip's file name is the version.
- The zips carry only the tools and their user docs. Publishing this folder follows the allowlist rule in
  `../docs/discovery-bootstrap.md`.
