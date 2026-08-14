#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 || ! -f "$1" ]]; then
    printf '%s\n' 'usage: verify-backup-restore.sh /path/to/rbvm.dump' >&2
    exit 2
fi

PG_BIN="${RBVM_PG_BIN:-/home/olive/.local/opt/rbvm-postgresql/usr/lib/postgresql/17/bin}"
RESTORE_DB="rbvm_restore_validation_$$"
if [[ ! "$RESTORE_DB" =~ ^rbvm_restore_validation_[0-9]+$ ]]; then
    printf '%s\n' 'unsafe restore database name' >&2
    exit 2
fi

export LD_LIBRARY_PATH=/home/olive/.local/opt/rbvm-postgresql/usr/lib/x86_64-linux-gnu
export PGSSLMODE=verify-full
export PGSSLROOTCERT=/home/olive/.local/share/rbvm-postgresql/tls/server.crt

created=false
cleanup() {
    if [[ "$created" == true ]]; then
        "$PG_BIN/dropdb" --host=127.0.0.1 --port=55432 --username=olive "$RESTORE_DB"
    fi
}
trap cleanup EXIT

start_ns="$(date +%s%N)"
"$PG_BIN/createdb" --host=127.0.0.1 --port=55432 --username=olive \
    --owner=rbvm_app "$RESTORE_DB"
created=true
"$PG_BIN/pg_restore" --host=127.0.0.1 --port=55432 --username=olive \
    --dbname="$RESTORE_DB" --no-owner --role=rbvm_app --exit-on-error "$1"

counts="$($PG_BIN/psql --host=127.0.0.1 --port=55432 --username=olive \
    --dbname="$RESTORE_DB" --tuples-only --no-align \
    --command="select (select count(*) from rbvm.observation), (select count(*) from rbvm.vulnerability_case), (select count(*) from rbvm.case_audit_event);")"
end_ns="$(date +%s%N)"
elapsed_ms="$(((end_ns - start_ns) / 1000000))"
printf 'restored_counts=%s restore_time_ms=%s\n' "$counts" "$elapsed_ms"
