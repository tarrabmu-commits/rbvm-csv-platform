#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PG_BIN="${RBVM_PG_BIN:-/home/olive/.local/opt/rbvm-postgresql/usr/lib/postgresql/17/bin}"
BACKUP_DIR="${RBVM_BACKUP_DIR:-$ROOT_DIR/runtime-data/backups}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
TARGET="${1:-$BACKUP_DIR/rbvm-$STAMP.dump}"

mkdir -p "$(dirname "$TARGET")"
start_ns="$(date +%s%N)"
env LD_LIBRARY_PATH=/home/olive/.local/opt/rbvm-postgresql/usr/lib/x86_64-linux-gnu \
    PGSSLMODE=verify-full \
    PGSSLROOTCERT=/home/olive/.local/share/rbvm-postgresql/tls/server.crt \
    "$PG_BIN/pg_dump" \
    --host=127.0.0.1 --port=55432 --username=rbvm_runtime \
    --dbname=rbvm --format=custom --compress=6 --file="$TARGET"
end_ns="$(date +%s%N)"
elapsed_ms="$(((end_ns - start_ns) / 1000000))"

printf 'backup=%s backup_time_ms=%s\n' "$TARGET" "$elapsed_ms"
