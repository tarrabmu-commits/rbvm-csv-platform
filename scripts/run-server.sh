#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
"$ROOT_DIR/scripts/compile.sh"

cd "$ROOT_DIR"
CLASSPATH="$ROOT_DIR/build/manual/main"
if [[ -n "${RBVM_POSTGRES_DRIVER_JAR:-}" ]]; then
  if [[ ! -f "$RBVM_POSTGRES_DRIVER_JAR" ]]; then
    printf 'RBVM_POSTGRES_DRIVER_JAR does not point to a file: %s\n' \
      "$RBVM_POSTGRES_DRIVER_JAR" >&2
    exit 2
  fi
  CLASSPATH="$CLASSPATH:$RBVM_POSTGRES_DRIVER_JAR"
fi
exec java -cp "$CLASSPATH" io.rbvm.csv.CsvPlatformServer
