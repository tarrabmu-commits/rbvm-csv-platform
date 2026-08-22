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

source_state() {
  local log_file="$1"
  local key="$2"
  local state
  state="$(sed -n "s/^${key}=\([A-Z_]*\).*/\1/p" "$log_file" | tail -n 1)"
  case "$state" in
    PASS|PARTIAL|SKIPPED) printf '%s\n' "$state" ;;
    *)
      printf 'canonical_intelligence_refresh=FAILED reason=invalid_source_state source=%s\n' "$key" >&2
      return 70
      ;;
  esac
}

# All three source adapters receive the exact same canonical CVE set. They retain
# independent provenance, timestamps, validation, persistence, and freshness rules.
# Hardened deployments may set one umbrella API credential or narrower per-source overrides.
RBVM_CVSS_INPUT="$input" \
RBVM_CVSS_API_KEY="${RBVM_CVSS_API_KEY:-${RBVM_INTELLIGENCE_API_KEY:-}}" \
  "$ROOT_DIR/scripts/scheduled-cvss-v31-refresh.sh" | tee "$staging/cvss.log"
cvss_state="$(source_state "$staging/cvss.log" cvss_v31_refresh)"

RBVM_EPSS_INPUT="$input" \
RBVM_EPSS_API_KEY="${RBVM_EPSS_API_KEY:-${RBVM_INTELLIGENCE_API_KEY:-}}" \
  "$ROOT_DIR/scripts/scheduled-epss-refresh.sh" | tee "$staging/epss.log"
epss_state="$(source_state "$staging/epss.log" epss_refresh)"

RBVM_KEV_INPUT="$input" \
RBVM_KEV_API_KEY="${RBVM_KEV_API_KEY:-${RBVM_INTELLIGENCE_API_KEY:-}}" \
  "$ROOT_DIR/scripts/scheduled-cisa-kev-refresh.sh" | tee "$staging/kev.log"
kev_state="$(source_state "$staging/kev.log" cisa_kev_refresh)"

aggregate="PASS"
if [[ "$cvss_state" != PASS || "$epss_state" != PASS || "$kev_state" != PASS ]]; then
  aggregate="PARTIAL"
fi
printf 'canonical_intelligence_refresh=%s unique_cves=%s cvss=%s epss=%s kev=%s sources=CVSS_V31,FIRST_EPSS,CISA_KEV\n' \
  "$aggregate" "$unique_cves" "$cvss_state" "$epss_state" "$kev_state"
trap - EXIT
rm -rf -- "$staging"
