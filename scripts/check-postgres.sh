#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DRIVER_JAR="${RBVM_POSTGRES_DRIVER_JAR:-}"
if [[ -z "$DRIVER_JAR" || ! -f "$DRIVER_JAR" ]]; then
  printf '%s\n' 'RBVM_POSTGRES_DRIVER_JAR must point to a pgJDBC JAR.' >&2
  exit 2
fi

"$ROOT_DIR/scripts/compile.sh"
exec java -cp "$ROOT_DIR/build/manual/main:$DRIVER_JAR" \
  io.rbvm.postgres.PostgresProjectionCheck
