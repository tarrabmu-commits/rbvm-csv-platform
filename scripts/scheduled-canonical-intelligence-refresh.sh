#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="${RBVM_INTELLIGENCE_WORK_DIR:-$HOME/.local/share/rbvm-platform/canonical-intelligence-refresh}"
API_BASE="${RBVM_API_BASE_URL:-http://127.0.0.1:8080}"

if [[ -L "$WORK_DIR" ]]; then
  echo "RBVM_INTELLIGENCE_WORK_DIR must not be a symlink" >&2
  exit 73
fi

umask 077
mkdir -p "$WORK_DIR"
chmod 700 "$WORK_DIR"
exec 9>"$WORK_DIR/.refresh.lock"
if ! flock --nonblock 9; then
  echo "canonical_intelligence_refresh=SKIPPED reason=already_running"
  exit 0
fi

staging="$(mktemp -d "$WORK_DIR/.refresh.XXXXXXXX")"
cleanup() {
  status=$?
  trap - EXIT
  rm -rf -- "$staging"
  exit "$status"
}
trap cleanup EXIT

input="$staging/current-cves.csv"
python3 "$ROOT_DIR/scripts/export-current-cves.py" "$input" --api-base "$API_BASE"

unique_cves="$(( $(wc -l < "$input") - 1 ))"
if (( unique_cves <= 0 )); then
  echo "canonical_intelligence_refresh=SKIPPED reason=no_canonical_cves"
  trap - EXIT
  rm -rf -- "$staging"
  exit 0
fi

# All three source adapters receive the exact same canonical CVE set. They retain
# independent provenance, timestamps, validation, persistence, and freshness rules.
RBVM_CVSS_INPUT="$input" "$ROOT_DIR/scripts/scheduled-cvss-v31-refresh.sh"
RBVM_EPSS_INPUT="$input" "$ROOT_DIR/scripts/scheduled-epss-refresh.sh"
RBVM_KEV_INPUT="$input" "$ROOT_DIR/scripts/scheduled-cisa-kev-refresh.sh"

printf 'canonical_intelligence_refresh=PASS unique_cves=%s sources=CVSS_V31,FIRST_EPSS,CISA_KEV\n' \
  "$unique_cves"
trap - EXIT
rm -rf -- "$staging"
