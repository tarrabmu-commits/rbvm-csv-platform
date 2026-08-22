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
    state_key="cvss_v31_refresh"
    RBVM_CVSS_INPUT="$input" \
    RBVM_CVSS_API_KEY="${RBVM_CVSS_API_KEY:-${RBVM_INTELLIGENCE_API_KEY:-}}" \
      "$ROOT_DIR/scripts/scheduled-cvss-v31-refresh.sh" | tee "$staging/source.log"
    ;;
  epss)
    state_key="epss_refresh"
    RBVM_EPSS_INPUT="$input" \
    RBVM_EPSS_API_KEY="${RBVM_EPSS_API_KEY:-${RBVM_INTELLIGENCE_API_KEY:-}}" \
      "$ROOT_DIR/scripts/scheduled-epss-refresh.sh" | tee "$staging/source.log"
    ;;
  kev)
    state_key="cisa_kev_refresh"
    RBVM_KEV_INPUT="$input" \
    RBVM_KEV_API_KEY="${RBVM_KEV_API_KEY:-${RBVM_INTELLIGENCE_API_KEY:-}}" \
      "$ROOT_DIR/scripts/scheduled-cisa-kev-refresh.sh" | tee "$staging/source.log"
    ;;
esac

source_state="$(sed -n "s/^${state_key}=\([A-Z_]*\).*/\1/p" "$staging/source.log" | tail -n 1)"
case "$source_state" in
  PASS|PARTIAL|SKIPPED) ;;
  *)
    printf 'canonical_source_refresh=FAILED source=%s reason=invalid_source_state\n' "$SOURCE" >&2
    exit 70
    ;;
esac

printf 'canonical_source_refresh=%s source=%s unique_cves=%s\n' \
  "$source_state" "$SOURCE" "$unique_cves"
