#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE="${1:-}"
API_BASE="${RBVM_API_BASE_URL:-http://127.0.0.1:8080}"
WORK_DIR="${RBVM_INTELLIGENCE_WORK_DIR:-$HOME/.local/share/rbvm-platform/canonical-intelligence-refresh}"

case "$SOURCE" in
  cvss|epss|kev) ;;
  *)
    echo "usage: scheduled-canonical-source-refresh.sh {cvss|epss|kev}" >&2
    exit 64
    ;;
esac

if [[ -L "$WORK_DIR" ]]; then
  echo "RBVM_INTELLIGENCE_WORK_DIR must not be a symlink" >&2
  exit 73
fi

umask 077
mkdir -p "$WORK_DIR"
chmod 700 "$WORK_DIR"
staging="$(mktemp -d "$WORK_DIR/.source-refresh.XXXXXXXX")"
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
  printf 'canonical_source_refresh=SKIPPED source=%s reason=no_canonical_cves\n' "$SOURCE"
  exit 0
fi

case "$SOURCE" in
  cvss)
    RBVM_CVSS_INPUT="$input" \
    RBVM_CVSS_API_KEY="${RBVM_CVSS_API_KEY:-${RBVM_INTELLIGENCE_API_KEY:-}}" \
      "$ROOT_DIR/scripts/scheduled-cvss-v31-refresh.sh"
    ;;
  epss)
    RBVM_EPSS_INPUT="$input" \
    RBVM_EPSS_API_KEY="${RBVM_EPSS_API_KEY:-${RBVM_INTELLIGENCE_API_KEY:-}}" \
      "$ROOT_DIR/scripts/scheduled-epss-refresh.sh"
    ;;
  kev)
    RBVM_KEV_INPUT="$input" \
    RBVM_KEV_API_KEY="${RBVM_KEV_API_KEY:-${RBVM_INTELLIGENCE_API_KEY:-}}" \
      "$ROOT_DIR/scripts/scheduled-cisa-kev-refresh.sh"
    ;;
esac

printf 'canonical_source_refresh=PASS source=%s unique_cves=%s\n' "$SOURCE" "$unique_cves"
