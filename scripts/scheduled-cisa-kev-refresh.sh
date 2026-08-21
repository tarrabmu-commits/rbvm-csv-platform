#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INPUT="${RBVM_KEV_INPUT:?RBVM_KEV_INPUT is required}"
OUTPUT_DIR="${RBVM_KEV_OUTPUT_DIR:-$HOME/.local/share/rbvm-platform/cisa-kev}"
KEEP="${RBVM_KEV_KEEP:-14}"
API_BASE="${RBVM_API_BASE_URL:-http://127.0.0.1:8080}"
OFFLINE_INPUT="${RBVM_KEV_OFFLINE_INPUT:-}"

[[ "$KEEP" =~ ^[0-9]+$ ]] && (( KEEP >= 2 )) || {
  echo "RBVM_KEV_KEEP must be an integer of at least 2" >&2
  exit 64
}
if [[ -z "${RBVM_KEV_API_KEY:-}" ]]; then
  case "$API_BASE" in
    http://127.0.0.1|http://127.0.0.1:*|http://localhost|http://localhost:*|https://127.0.0.1|https://127.0.0.1:*|https://localhost|https://localhost:*)
      RBVM_KEV_API_KEY="local-auth-disabled"
      ;;
    *)
      echo "RBVM_KEV_API_KEY is required for non-local or authenticated API deployments" >&2
      exit 64
      ;;
  esac
fi
[[ -f "$INPUT" && ! -L "$INPUT" ]] || {
  echo "RBVM_KEV_INPUT must be a regular non-symlink file" >&2
  exit 66
}
if [[ -n "$OFFLINE_INPUT" ]]; then
  [[ -f "$OFFLINE_INPUT" && ! -L "$OFFLINE_INPUT" ]] || {
    echo "RBVM_KEV_OFFLINE_INPUT must be a regular non-symlink file when configured" >&2
    exit 66
  }
fi
if [[ -L "$OUTPUT_DIR" ]]; then
  echo "RBVM_KEV_OUTPUT_DIR must not be a symlink" >&2
  exit 73
fi

umask 077
mkdir -p "$OUTPUT_DIR"
chmod 700 "$OUTPUT_DIR"
exec 9>"$OUTPUT_DIR/.refresh.lock"
if ! flock --nonblock 9; then
  echo "cisa_kev_refresh=SKIPPED reason=already_running"
  exit 0
fi

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
base="cisa-kev-$stamp"
staging="$OUTPUT_DIR/.$base.staging"
final="$OUTPUT_DIR/$base"
[[ "$base" =~ ^cisa-kev-[0-9]{8}T[0-9]{6}Z$ ]] || exit 70
[[ ! -e "$final" && ! -e "$staging" ]] || {
  echo "refusing to overwrite an existing CISA KEV snapshot" >&2
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

snapshot="$staging/catalog-snapshot.json"
evidence="$staging/evidence.csv"
build_report="$staging/build.json"
import_report="$staging/import.json"

fetch_args=("$snapshot")
mode="online"
if [[ -n "$OFFLINE_INPUT" ]]; then
  fetch_args+=(--offline-input "$OFFLINE_INPUT")
  mode="offline"
fi
python3 "$ROOT_DIR/scripts/fetch-cisa-kev-snapshot.py" "${fetch_args[@]}"
(cd "$staging" && sha256sum catalog-snapshot.json > catalog-snapshot.json.sha256)

python3 "$ROOT_DIR/scripts/build-cisa-kev-csv.py" \
  "$INPUT" "$snapshot" "$evidence" --report "$build_report"
(cd "$staging" && sha256sum evidence.csv > evidence.csv.sha256)

# The source adapter and CSV builder never write to PostgreSQL. The exact generated contract is
# handed to the canonical HTTP importer. Local auth-disabled deployments require no operator-managed
# token; hardened remote deployments still require an explicit credential.
RBVM_KEV_API_KEY="$RBVM_KEV_API_KEY" \
  python3 "$ROOT_DIR/scripts/import-cisa-kev.py" "$evidence" \
    --api-base "$API_BASE" \
    --report "$import_report"

# Publish only after acquisition, complete-snapshot validation, contract construction, and canonical
# import have all completed. The atomic directory rename prevents readers from observing partial runs.
mv "$staging" "$final"
trap - EXIT

latest_tmp="$OUTPUT_DIR/.latest.tmp"
ln -sfn "$(basename "$final")" "$latest_tmp"
mv -Tf "$latest_tmp" "$OUTPUT_DIR/latest"

mapfile -t snapshots < <(find "$OUTPUT_DIR" -maxdepth 1 -mindepth 1 -type d \
  -name 'cisa-kev-????????T??????Z' -printf '%f\n' | sort -r)
if (( ${#snapshots[@]} > KEEP )); then
  for expired in "${snapshots[@]:KEEP}"; do
    [[ "$expired" =~ ^cisa-kev-[0-9]{8}T[0-9]{6}Z$ ]] || exit 70
    rm -rf -- "$OUTPUT_DIR/$expired"
  done
fi

read -r listed not_listed quarantined <<EOF
$(python3 - "$final/build.json" "$final/import.json" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as handle:
    build = json.load(handle)
with open(sys.argv[2], encoding="utf-8") as handle:
    imported = json.load(handle)
print(
    int(build.get("listed", 0)),
    int(build.get("notListed", 0)),
    int(imported.get("totalQuarantinedRows", 0)),
)
PY
)
EOF

state="PASS"
if (( quarantined > 0 )); then
  state="PARTIAL"
fi
printf 'cisa_kev_refresh=%s snapshot=%s listed=%s not_listed=%s quarantined=%s retained=%s mode=%s\n' \
  "$state" "$final" "$listed" "$not_listed" "$quarantined" \
  "$(( ${#snapshots[@]} < KEEP ? ${#snapshots[@]} : KEEP ))" "$mode"
