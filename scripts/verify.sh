#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
"$ROOT_DIR/scripts/compile.sh" --tests

MAIN_CLASSES="$ROOT_DIR/build/manual/main"
TEST_CLASSES="$ROOT_DIR/build/manual/test"

java -ea -cp "$MAIN_CLASSES:$TEST_CLASSES" io.rbvm.csv.PlatformSelfTest
python3 "$ROOT_DIR/scripts/verify-api.py"
python3 "$ROOT_DIR/scripts/verify-sql.py"
python3 "$ROOT_DIR/scripts/verify-web.py"
python3 "$ROOT_DIR/scripts/verify-workflows.py"
python3 "$ROOT_DIR/scripts/verify-enrichment.py"
python3 "$ROOT_DIR/scripts/verify-cvss-v31.py"
for script in "$ROOT_DIR"/scripts/*.sh; do
  bash -n "$script"
done
printf '%s\n' 'Shell script structural checks: PASS'

if [[ $# -gt 0 ]]; then
  java -cp "$MAIN_CLASSES" io.rbvm.csv.CsvContractCli "$1"
fi
