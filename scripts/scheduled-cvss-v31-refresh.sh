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
final_csv="$OUTPUT_DIR/$base.csv"
final_collection="$OUTPUT_DIR/$base.collection.json"
final_import="$OUTPUT_DIR/$base.import.json"
final_checksum="$OUTPUT_DIR/$base.csv.sha256"

[[ "$base" =~ ^cvss-v31-[0-9]{8}T[0-9]{6}Z$ ]] || exit 70
for target in "$final_csv" "$final_collection" "$final_import" "$final_checksum"; do
  [[ ! -e "$target" ]] || {
    echo "refusing to overwrite an existing CVSS v3.1 snapshot" >&2
    exit 73
  }
done
[[ ! -e "$staging" ]] || {
  echo "staging directory already exists: $staging" >&2
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
checksum="$staging/evidence.csv.sha256"

collector_args=("$INPUT" "$csv" --cache-dir "$CACHE_DIR" --report "$collection_report")
if [[ "$OFFLINE" == true ]]; then
  collector_args+=(--offline)
fi
"$ROOT_DIR/scripts/collect-nvd-cvss-v31.py" "${collector_args[@]}"
(cd "$staging" && sha256sum evidence.csv > evidence.csv.sha256)

RBVM_CVSS_API_KEY="$RBVM_CVSS_API_KEY" \
  "$ROOT_DIR/scripts/import-cvss-v31.py" "$csv" \
    --api-base "$API_BASE" \
    --report "$import_report"

mv "$csv" "$final_csv"
mv "$collection_report" "$final_collection"
mv "$import_report" "$final_import"
mv "$checksum" "$final_checksum"

latest_csv_tmp="$OUTPUT_DIR/.latest.csv.tmp"
latest_collection_tmp="$OUTPUT_DIR/.latest.collection.json.tmp"
latest_import_tmp="$OUTPUT_DIR/.latest.import.json.tmp"
latest_checksum_tmp="$OUTPUT_DIR/.latest.csv.sha256.tmp"
ln -sfn "$(basename "$final_csv")" "$latest_csv_tmp"
ln -sfn "$(basename "$final_collection")" "$latest_collection_tmp"
ln -sfn "$(basename "$final_import")" "$latest_import_tmp"
ln -sfn "$(basename "$final_checksum")" "$latest_checksum_tmp"
mv -Tf "$latest_csv_tmp" "$OUTPUT_DIR/latest.csv"
mv -Tf "$latest_collection_tmp" "$OUTPUT_DIR/latest.collection.json"
mv -Tf "$latest_import_tmp" "$OUTPUT_DIR/latest.import.json"
mv -Tf "$latest_checksum_tmp" "$OUTPUT_DIR/latest.csv.sha256"

mapfile -t snapshots < <(find "$OUTPUT_DIR" -maxdepth 1 -type f \
  -name 'cvss-v31-????????T??????Z.csv' -printf '%f\n' | sort -r)
if (( ${#snapshots[@]} > KEEP )); then
  for expired in "${snapshots[@]:KEEP}"; do
    [[ "$expired" =~ ^cvss-v31-[0-9]{8}T[0-9]{6}Z\.csv$ ]] || exit 70
    expired_base="${expired%.csv}"
    rm -f -- \
      "$OUTPUT_DIR/$expired" \
      "$OUTPUT_DIR/$expired_base.csv.sha256" \
      "$OUTPUT_DIR/$expired_base.collection.json" \
      "$OUTPUT_DIR/$expired_base.import.json"
  done
fi

quarantined="$(python3 - "$final_import" <<'PY'
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
printf 'cvss_v31_refresh=%s file=%s quarantined=%s retained=%s offline=%s\n' \
  "$state" "$final_csv" "$quarantined" \
  "$(( ${#snapshots[@]} < KEEP ? ${#snapshots[@]} : KEEP ))" "$OFFLINE"
trap - EXIT
rmdir "$staging"
