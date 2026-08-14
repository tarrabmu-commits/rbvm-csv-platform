#!/usr/bin/env bash
set -euo pipefail

PG_BIN="${RBVM_PG_BIN:-/home/olive/.local/opt/rbvm-postgresql/usr/lib/postgresql/17/bin}"
export LD_LIBRARY_PATH=/home/olive/.local/opt/rbvm-postgresql/usr/lib/x86_64-linux-gnu
export PGSSLMODE=verify-full
export PGSSLROOTCERT=/home/olive/.local/share/rbvm-postgresql/tls/server.crt
API_TOKEN_FILE="${RBVM_API_TOKEN_FILE:-/home/olive/.config/rbvm-platform/operator.token}"
API_TOKEN="$(tr -d '\r\n' < "$API_TOKEN_FILE")"
CURL_AUTH=(--header "Authorization: Bearer $API_TOKEN")

PSQL=("$PG_BIN/psql" --host=127.0.0.1 --port=55432 --username=rbvm_runtime \
    --dbname=rbvm --tuples-only --no-align --set=ON_ERROR_STOP=1)

schema_version="$("${PSQL[@]}" --command='select max(version) from rbvm.schema_migration;')"
[[ "$schema_version" == 5 ]]

counts="$("${PSQL[@]}" --command="select
    (select count(*) from rbvm.observation),
    (select count(*) from rbvm.asset),
    (select count(*) from rbvm.vulnerability),
    (select count(*) from rbvm.asset_component),
    (select count(*) from rbvm.exposure),
    (select count(*) from rbvm.vulnerability_case),
    (select count(*) from rbvm.exposure where severity_changed);")"
[[ "$counts" == '10001|5|2265|602|9090|7521|226' ]]

reconciliation="$("${PSQL[@]}" --command="select
    assets_without_public_id + components_without_public_id + cases_without_public_id
    + exposures_without_public_id + audit_events_without_public_id
    + unreconciled_imports + unreconciled_case_workflows
    from rbvm.postgres_projection_reconciliation;")"
[[ "$reconciliation" == 0 ]]

ssl="$("${PSQL[@]}" --command='select ssl from pg_stat_ssl where pid=pg_backend_pid();')"
[[ "$ssl" == t ]]

audit_privileges="$("${PSQL[@]}" --command="select
    has_table_privilege('rbvm_runtime', 'rbvm.case_audit_event', 'INSERT'),
    has_table_privilege('rbvm_runtime', 'rbvm.case_audit_event', 'UPDATE'),
    has_table_privilege('rbvm_runtime', 'rbvm.case_audit_event', 'DELETE');")"
[[ "$audit_privileges" == 't|f|f' ]]

health="$(curl --fail --silent --show-error "${CURL_AUTH[@]}" \
    http://127.0.0.1:8080/api/v1/health)"
grep -q '"catalogBackend": "POSTGRESQL"' <<<"$health"
grep -q '"schemaVersion": 5' <<<"$health"
grep -q '"status": "UP"' <<<"$health"

case_page="$(curl --fail --silent --show-error "${CURL_AUTH[@]}" \
    'http://127.0.0.1:8080/api/v1/cases?limit=1')"
grep -q '"catalogRevision"' <<<"$case_page"
grep -q '"nextCursor"' <<<"$case_page"
case_id="$(grep -oE '"caseId": "[a-f0-9]{64}"' <<<"$case_page" | head -1 | cut -d'"' -f4)"
[[ "$case_id" =~ ^[a-f0-9]{64}$ ]]
case_detail="$(curl --fail --silent --show-error "${CURL_AUTH[@]}" \
    "http://127.0.0.1:8080/api/v1/cases/$case_id")"
grep -q '"exposures"' <<<"$case_detail"
grep -q '"auditEvents"' <<<"$case_detail"

unauthenticated_status="$(curl --silent --output /dev/null --write-out '%{http_code}' \
    'http://127.0.0.1:8080/api/v1/cases?limit=1')"
[[ "$unauthenticated_status" == 401 ]]
metrics="$(curl --fail --silent --show-error "${CURL_AUTH[@]}" \
    'http://127.0.0.1:8080/api/v1/metrics')"
grep -q '^rbvm_up 1$' <<<"$metrics"

printf 'live_postgres=PASS schema=%s counts=%s reconciliation=%s ssl=%s audit_privileges=%s auth=%s\n' \
    "$schema_version" "$counts" "$reconciliation" "$ssl" "$audit_privileges" \
    "$unauthenticated_status"
