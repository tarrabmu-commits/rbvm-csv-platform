#!/usr/bin/env bash
set -euo pipefail

base_url="${RBVM_BASE_URL:-http://127.0.0.1:8080}"
timeout_seconds="${RBVM_RECOVERY_TIMEOUT_SECONDS:-30}"

before="$(curl --fail --silent --show-error "$base_url/api/v1/ready")"
grep -q '"status": "UP"' <<<"$before"

systemctl --user restart rbvm-postgresql.service

deadline=$((SECONDS + timeout_seconds))
while (( SECONDS < deadline )); do
  if ready="$(curl --fail --silent "$base_url/api/v1/ready" 2>/dev/null)" \
      && grep -q '"status": "UP"' <<<"$ready"; then
    printf 'postgres_restart_recovery=PASS recovery_seconds=%s\n' "$((timeout_seconds - deadline + SECONDS))"
    exit 0
  fi
  sleep 1
done

echo "service did not become ready after PostgreSQL restart" >&2
exit 1
