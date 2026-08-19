#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INPUT="${RBVM_CVSS_INPUT:?RBVM_CVSS_INPUT is required}"
OUTPUT_DIR="${RBVM_CVSS_OUTPUT_DIR:-$HOME/.local/share/rbvm-platform/cvss-v31}"
CACHE_DIR="${RBVM_CVSS_CACHE_DIR:-$HOME/.cache/rbvm-platform/cvss-v31}"
KEEP="${RBVM_CVSS_KEEP:-14}"
OFFLINE="${RBVM_CVSS_OFFLINE:-false}"
API_BASE="${RBVM_API_BASE_URL:-http://127.0.0.1:8080}"

[[ "$KEEP" =~ ^[0-9]+$ ]] && (( KEEP >= 2 )) || {
  echo "RBVM_CVSS_KEEP must be an integer of at least 2" >&2
  exit 64
}
[[ "$OFFLINE" == true || "$OFFLINE" == false ]] || {
  echo "RBVM_CVSS_OFFLINE must be true or false" >&2
  exit 64
}
[[ -n "${RBVM_CVSS_API_KEY:-}" ]] || {
  echo "RBVM_CVSS_API_KEY is required" >&2
  exit 64
}
[[ -f "$INPUT" && ! -L "$INPUT" ]] || {
  echo "RBVM_CVSS_INPUT must be a regular non-symlink file" >&2
  exit 66
}

umask 077
mkdir -p "$OUTPUT_DIR" "$CACHE_DIR"
chmod 700 "$OUTPUT_DIR" "$CACHE_DIR"
exec 9>"$OUTPUT_DIR/.refresh.lock"
if ! flock --nonblock 9; then
  echo "cvss_v31_refresh=SKIPPED reason=already_running"
  exit 0
fi

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
base="cvss-v31-$stamp"
staging="$OUTPUT_DIR/.$base.staging"
final="$OUTPUT_DIR/$base"
[[ "$base" =~ ^cvss-v31-[0-9]{8}T[0-9]{6}Z$ ]] || exit 70
[[ ! -e "$final" && ! -e "$staging" ]] || {
  echo "refusing to overwrite an existing CVSS v3.1 snapshot" >&2
  exit 73
}
mkdir "$staging"
cleanup() {
  status=$?
  trap - EXIT
  rm -rf -- "$staging"
  exit "$status"
}
trap cleanup EXIT

csv="$staging/evidence.csv"
collection_report="$staging/collection.json"
import_report="$staging/import.json"

collector_args=("$INPUT" "$csv" --cache-dir "$CACHE_DIR" --report "$collection_report")
if [[ "$OFFLINE" == true ]]; then
  collector_args+=(--offline)
fi
"$ROOT_DIR/scripts/collect-nvd-cvss-v31.py" "${collector_args[@]}"
(cd "$staging" && sha256sum evidence.csv > evidence.csv.sha256)

# The collector is never trusted to write to PostgreSQL directly. The generated contract is handed
# to the same authenticated HTTP importer used by operators, preserving validation and tenant/CVE
# resolution before persistence.
RBVM_CVSS_API_KEY="$RBVM_CVSS_API_KEY" \
  "$ROOT_DIR/scripts/import-cvss-v31.py" "$csv" \
    --api-base "$API_BASE" \
    --report "$import_report"

# Publish only after both collection and canonical import completed. Directory rename is atomic on
# the same filesystem, so readers never observe a half-published collection/import pair.
mv "$staging" "$final"
trap - EXIT

latest_tmp="$OUTPUT_DIR/.latest.tmp"
ln -sfn "$(basename "$final")" "$latest_tmp"
mv -Tf "$latest_tmp" "$OUTPUT_DIR/latest"

mapfile -t snapshots < <(find "$OUTPUT_DIR" -maxdepth 1 -mindepth 1 -type d \
  -name 'cvss-v31-????????T??????Z' -printf '%f\n' | sort -r)
if (( ${#snapshots[@]} > KEEP )); then
  for expired in "${snapshots[@]:KEEP}"; do
    [[ "$expired" =~ ^cvss-v31-[0-9]{8}T[0-9]{6}Z$ ]] || exit 70
    rm -rf -- "$OUTPUT_DIR/$expired"
  done
fi

quarantined="$(python3 - "$final/import.json" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as handle:
    print(int(json.load(handle).get("totalQuarantinedRows", 0)))
PY
)"
state="PASS"
if (( quarantined > 0 )); then
  state="PARTIAL"
fi
printf 'cvss_v31_refresh=%s snapshot=%s quarantined=%s retained=%s offline=%s\n' \
  "$state" "$final" "$quarantined" \
  "$(( ${#snapshots[@]} < KEEP ? ${#snapshots[@]} : KEEP ))" "$OFFLINE"
