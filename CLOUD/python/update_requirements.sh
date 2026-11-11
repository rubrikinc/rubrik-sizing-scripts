#!/usr/bin/env bash
# Regenerates the pinned requirements from the requirements.in files.
#
#   ./update_requirements.sh             keep the current pins where they still fit (after editing a .in)
#   ./update_requirements.sh --upgrade   move every package to the newest version the .in files allow
#
# Writes requirements-test.txt (everything the test suites install, for Python 3.10 and newer) and
# each tool's requirements.txt. Azure and GCP are resolved within requirements-test.txt; AWS, which
# also supports Python 3.9, is resolved for 3.9 and newer with its 3.10+ versions held to the same
# set, so the tests run on exactly the versions users install. Needs uv (https://docs.astral.sh/uv/).
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]:-$0}")"
command -v uv >/dev/null || { echo "This needs uv: pip install uv (or see https://docs.astral.sh/uv/)." >&2; exit 1; }

upgrade=()
case "${1:-}" in
  --upgrade) upgrade=(--upgrade) ;;
  "") ;;
  *) echo "Usage: $0 [--upgrade]" >&2; exit 2 ;;
esac

compile() {
  uv pip compile --quiet --universal --no-emit-index-url \
    --custom-compile-command "./update_requirements.sh" "${upgrade[@]}" "$@"
}

compile --python-version 3.10 requirements-test.in -o requirements-test.txt
compile --python-version 3.10 azure/requirements.in -c requirements-test.txt -o azure/requirements.txt
compile --python-version 3.10 gcp/requirements.in -c requirements-test.txt -o gcp/requirements.txt

# The test set applies to Python 3.10+, so it constrains only that part of the AWS resolution. The
# file has a fixed name because uv records it in requirements.txt; it is removed afterwards.
constraints="aws/test-set-for-python-3.10.txt"
trap 'rm -f "$constraints"' EXIT
python3 - requirements-test.txt "$constraints" <<'PY'
import re
import sys

source, target = sys.argv[1:]
with open(source, encoding="utf-8") as fh, open(target, "w", encoding="utf-8") as out:
    for line in fh:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        pin, _, marker = line.partition(";")
        if not re.match(r"^[A-Za-z0-9_.\-]+(\[[^\]]*\])?==", pin.strip()):
            continue
        marker = f"({marker.strip()}) and " if marker.strip() else ""
        out.write(f"{pin.strip()} ; {marker}python_full_version >= '3.10'\n")
PY
compile --python-version 3.9 aws/requirements.in -c "$constraints" -o aws/requirements.txt

echo "Updated requirements-test.txt and {aws,azure,gcp}/requirements.txt. Run the test suites, then commit them."
