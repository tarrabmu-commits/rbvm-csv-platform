#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INPUT="${RBVM_INTEL_INPUT:?RBVM_INTEL_INPUT is required}"
OUTPUT_DIR="${RBVM_INTEL_OUTPUT_DIR:-/home/olive/.local/share/rbvm-platform/intelligence}"
CACHE_DIR="${RBVM_INTEL_CACHE_DIR:-/home/olive/.cache/rbvm-platform/intelligence}"
KEEP="${RBVM_INTEL_KEEP:-14}"
OFFLINE="${RBVM_INTEL_OFFLINE:-false}"

[[ "$KEEP" =~ ^[0-9]+$ ]] && (( KEEP >= 2 )) || {
  echo "RBVM_INTEL_KEEP must be an integer of at least 2" >&2
  exit 64
}
[[ "$OFFLINE" == true || "$OFFLINE" == false ]] || {
  echo "RBVM_INTEL_OFFLINE must be true or false" >&2
  exit 64
}
[[ -f "$INPUT" && ! -L "$INPUT" ]] || {
  echo "RBVM_INTEL_INPUT must be a regular non-symlink file" >&2
  exit 66
}

umask 077
mkdir -p "$OUTPUT_DIR" "$CACHE_DIR"
chmod 700 "$OUTPUT_DIR" "$CACHE_DIR"
exec 9>"$OUTPUT_DIR/.refresh.lock"
if ! flock --nonblock 9; then
  echo "intelligence_refresh=SKIPPED reason=already_running"
  exit 0
fi

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
target="$OUTPUT_DIR/intelligence-$stamp.csv"
report="$OUTPUT_DIR/intelligence-$stamp.json"
[[ "$target" =~ /intelligence-[0-9]{8}T[0-9]{6}Z\.csv$ ]] || exit 70
[[ ! -e "$target" && ! -e "$report" ]] || {
  echo "refusing to overwrite an existing intelligence snapshot" >&2
  exit 73
}
cleanup_partial() {
  status=$?
  trap - EXIT
  if (( status != 0 )); then
    rm -f -- "$target" "$target.sha256" "$report"
  fi
  exit "$status"
}
trap cleanup_partial EXIT

arguments=("$INPUT" "$target" --cache-dir "$CACHE_DIR" --report "$report")
if [[ "$OFFLINE" == true ]]; then
  arguments+=(--offline)
fi
"$ROOT_DIR/scripts/enrich-wazuh-v2.py" "${arguments[@]}"
(cd "$OUTPUT_DIR" && sha256sum "$(basename "$target")" > "$(basename "$target").sha256")

latest_tmp="$OUTPUT_DIR/.latest.csv.tmp"
latest_checksum_tmp="$OUTPUT_DIR/.latest.csv.sha256.tmp"
latest_report_tmp="$OUTPUT_DIR/.latest.json.tmp"
ln -sfn "$(basename "$target")" "$latest_tmp"
ln -sfn "$(basename "$target").sha256" "$latest_checksum_tmp"
ln -sfn "$(basename "$report")" "$latest_report_tmp"
mv -Tf "$latest_tmp" "$OUTPUT_DIR/latest.csv"
mv -Tf "$latest_checksum_tmp" "$OUTPUT_DIR/latest.csv.sha256"
mv -Tf "$latest_report_tmp" "$OUTPUT_DIR/latest.json"

mapfile -t snapshots < <(find "$OUTPUT_DIR" -maxdepth 1 -type f \
  -name 'intelligence-????????T??????Z.csv' -printf '%f\n' | sort -r)
if (( ${#snapshots[@]} > KEEP )); then
  for expired in "${snapshots[@]:KEEP}"; do
    [[ "$expired" =~ ^intelligence-[0-9]{8}T[0-9]{6}Z\.csv$ ]] || exit 70
    base="${expired%.csv}"
    rm -- "$OUTPUT_DIR/$expired" "$OUTPUT_DIR/$expired.sha256" "$OUTPUT_DIR/$base.json"
  done
fi

printf 'intelligence_refresh=PASS file=%s retained=%s offline=%s\n' "$target" \
  "$(( ${#snapshots[@]} < KEEP ? ${#snapshots[@]} : KEEP ))" "$OFFLINE"
trap - EXIT
