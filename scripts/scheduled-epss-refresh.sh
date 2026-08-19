#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INPUT="${RBVM_EPSS_INPUT:?RBVM_EPSS_INPUT is required}"
OUTPUT_DIR="${RBVM_EPSS_OUTPUT_DIR:-$HOME/.local/share/rbvm-platform/epss}"
KEEP="${RBVM_EPSS_KEEP:-14}"
API_BASE="${RBVM_API_BASE_URL:-http://127.0.0.1:8080}"
OFFLINE_INPUT="${RBVM_EPSS_OFFLINE_INPUT:-}"

[[ "$KEEP" =~ ^[0-9]+$ ]] && (( KEEP >= 2 )) || {
  echo "RBVM_EPSS_KEEP must be an integer of at least 2" >&2
  exit 64
}
[[ -n "${RBVM_EPSS_API_KEY:-}" ]] || {
  echo "RBVM_EPSS_API_KEY is required" >&2
  exit 64
}
[[ -f "$INPUT" && ! -L "$INPUT" ]] || {
  echo "RBVM_EPSS_INPUT must be a regular non-symlink file" >&2
  exit 66
}
if [[ -n "$OFFLINE_INPUT" ]]; then
  [[ -f "$OFFLINE_INPUT" && ! -L "$OFFLINE_INPUT" ]] || {
    echo "RBVM_EPSS_OFFLINE_INPUT must be a regular non-symlink file when configured" >&2
    exit 66
  }
fi
if [[ -L "$OUTPUT_DIR" ]]; then
  echo "RBVM_EPSS_OUTPUT_DIR must not be a symlink" >&2
  exit 73
fi

umask 077
mkdir -p "$OUTPUT_DIR"
chmod 700 "$OUTPUT_DIR"
exec 9>"$OUTPUT_DIR/.refresh.lock"
if ! flock --nonblock 9; then
  echo "epss_refresh=SKIPPED reason=already_running"
  exit 0
fi

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
base="epss-$stamp"
staging="$OUTPUT_DIR/.$base.staging"
final="$OUTPUT_DIR/$base"
[[ "$base" =~ ^epss-[0-9]{8}T[0-9]{6}Z$ ]] || exit 70
[[ ! -e "$final" && ! -e "$staging" ]] || {
  echo "refusing to overwrite an existing EPSS snapshot" >&2
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

snapshot="$staging/first-snapshot.json"
evidence="$staging/evidence.csv"
build_report="$staging/build.json"
import_report="$staging/import.json"

fetch_args=("$INPUT" "$snapshot")
mode="online"
if [[ -n "$OFFLINE_INPUT" ]]; then
  fetch_args+=(--offline-input "$OFFLINE_INPUT")
  mode="offline"
fi
python3 "$ROOT_DIR/scripts/fetch-first-epss-snapshot.py" "${fetch_args[@]}"
(cd "$staging" && sha256sum first-snapshot.json > first-snapshot.json.sha256)

python3 "$ROOT_DIR/scripts/build-first-epss-csv.py" \
  "$snapshot" "$evidence" --report "$build_report"
(cd "$staging" && sha256sum evidence.csv > evidence.csv.sha256)

# Acquisition/build never write PostgreSQL. The exact generated EPSS_CSV_V1 is handed to the
# authenticated HTTP API so canonical validation, tenant/CVE resolution, replay/conflict semantics,
# and the transactional PostgreSQL V12 importer remain the only persistence route.
RBVM_EPSS_API_KEY="$RBVM_EPSS_API_KEY" \
  python3 "$ROOT_DIR/scripts/import-epss.py" "$evidence" \
    --api-base "$API_BASE" \
    --report "$import_report"

# Publish only after successful acquisition, full source validation, contract construction, and API
# import. Atomic directory/symlink replacement prevents readers from observing partial refreshes.
mv "$staging" "$final"
trap - EXIT

latest_tmp="$OUTPUT_DIR/.latest.tmp"
ln -sfn "$(basename "$final")" "$latest_tmp"
mv -Tf "$latest_tmp" "$OUTPUT_DIR/latest"

mapfile -t snapshots < <(find "$OUTPUT_DIR" -maxdepth 1 -mindepth 1 -type d \
  -name 'epss-????????T??????Z' -printf '%f\n' | sort -r)
if (( ${#snapshots[@]} > KEEP )); then
  for expired in "${snapshots[@]:KEEP}"; do
    [[ "$expired" =~ ^epss-[0-9]{8}T[0-9]{6}Z$ ]] || exit 70
    rm -rf -- "$OUTPUT_DIR/$expired"
  done
fi

read -r scored missing quarantined score_date model_version <<EOF
$(python3 - "$final/first-snapshot.json" "$final/import.json" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as handle:
    snapshot = json.load(handle)
with open(sys.argv[2], encoding="utf-8") as handle:
    imported = json.load(handle)
print(
    int(snapshot.get("scoredCveCount", 0)),
    int(snapshot.get("missingCveCount", 0)),
    int(imported.get("totalQuarantinedRows", 0)),
    snapshot.get("scoreDate", "unknown"),
    snapshot.get("modelVersion", "unknown"),
)
PY
)
EOF

state="PASS"
if (( quarantined > 0 )); then
  state="PARTIAL"
fi
printf 'epss_refresh=%s snapshot=%s scored=%s missing=%s quarantined=%s retained=%s mode=%s score_date=%s model=%s\n' \
  "$state" "$final" "$scored" "$missing" "$quarantined" \
  "$(( ${#snapshots[@]} < KEEP ? ${#snapshots[@]} : KEEP ))" "$mode" "$score_date" "$model_version"
