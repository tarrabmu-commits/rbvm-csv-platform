#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 || ! -f "$1" ]]; then
    printf '%s\n' 'usage: verify-postgres-disconnect.sh /path/to/rbvm.dump' >&2
    exit 2
fi

PG_BIN="${RBVM_PG_BIN:-/home/olive/.local/opt/rbvm-postgresql/usr/lib/postgresql/17/bin}"
TEST_DB="rbvm_disconnect_validation_$$"
if [[ ! "$TEST_DB" =~ ^rbvm_disconnect_validation_[0-9]+$ ]]; then
    printf '%s\n' 'unsafe test database name' >&2
    exit 2
fi

export LD_LIBRARY_PATH=/home/olive/.local/opt/rbvm-postgresql/usr/lib/x86_64-linux-gnu
export PGSSLMODE=verify-full
export PGSSLROOTCERT=/home/olive/.local/share/rbvm-postgresql/tls/server.crt

created=false
client_pid=''
cleanup() {
    if [[ -n "$client_pid" ]]; then
        kill "$client_pid" 2>/dev/null || true
        wait "$client_pid" 2>/dev/null || true
    fi
    if [[ "$created" == true ]]; then
        "$PG_BIN/dropdb" --force --host=127.0.0.1 --port=55432 --username=olive "$TEST_DB"
    fi
}
trap cleanup EXIT

"$PG_BIN/createdb" --host=127.0.0.1 --port=55432 --username=olive \
    --owner=rbvm_app "$TEST_DB"
created=true
"$PG_BIN/pg_restore" --host=127.0.0.1 --port=55432 --username=olive \
    --dbname="$TEST_DB" --no-owner --role=rbvm_app --exit-on-error "$1"

before="$($PG_BIN/psql --host=127.0.0.1 --port=55432 --username=olive \
    --dbname="$TEST_DB" --tuples-only --no-align \
    --command="select revision from rbvm.catalog_state;")"

"$PG_BIN/psql" --host=127.0.0.1 --port=55432 --username=rbvm_app \
    --dbname="$TEST_DB" --command="begin; update rbvm.vulnerability_case set decision_reason='disconnect-sentinel' where id=(select id from rbvm.vulnerability_case limit 1); update rbvm.catalog_state set revision=revision+1; select pg_sleep(30); commit;" >/dev/null 2>&1 &
client_pid="$!"

for ignored in 1 2 3 4 5 6 7 8 9 10; do
    active="$($PG_BIN/psql --host=127.0.0.1 --port=55432 --username=olive \
        --dbname="$TEST_DB" --tuples-only --no-align \
        --command="select count(*) from pg_stat_activity where datname='$TEST_DB' and pid <> pg_backend_pid() and state='active' and wait_event='PgSleep';")"
    if [[ "$active" == 1 ]]; then
        break
    fi
    sleep 0.1
done

if [[ "$active" != 1 ]]; then
    printf '%s\n' 'disconnect test transaction did not become active' >&2
    exit 1
fi

kill -KILL "$client_pid"
wait "$client_pid" 2>/dev/null || true
client_pid=''

after="$($PG_BIN/psql --host=127.0.0.1 --port=55432 --username=olive \
    --dbname="$TEST_DB" --tuples-only --no-align \
    --command="select revision, (select count(*) from rbvm.vulnerability_case where decision_reason='disconnect-sentinel') from rbvm.catalog_state;")"

if [[ "$after" != "$before|0" ]]; then
    printf 'rollback validation failed: before=%s after=%s\n' "$before" "$after" >&2
    exit 1
fi
printf 'disconnect_rollback=PASS revision=%s partial_rows=0\n' "$before"
