#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNTIME_DIR="${RBVM_PUBLIC_INTEL_DIR:-$ROOT/runtime-data/public-intel}"
mkdir -p "$RUNTIME_DIR"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
CVES="$RUNTIME_DIR/current-cves-$STAMP.csv"
SNAPSHOT="$RUNTIME_DIR/public-cve-intel-$STAMP.json"
REPORT="$RUNTIME_DIR/public-cve-intel-$STAMP.report.json"

python3 "$ROOT/scripts/export-current-cves.py" "$CVES"
python3 "$ROOT/scripts/collect-public-vulnerability-intel.py" \
  "$CVES" "$SNAPSHOT" \
  --cache-dir "$ROOT/data/public-cve-intel-cache" \
  --report "$REPORT"

sha256sum "$SNAPSHOT" > "$SNAPSHOT.sha256"
printf 'snapshot=%s\nreport=%s\n' "$SNAPSHOT" "$REPORT"
