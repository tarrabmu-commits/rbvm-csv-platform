#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

AUTH_FROM_ENV=false
PRINT_AUTH_MODE=false
LOCAL_API=false
ENV_FILE=""

usage() {
  cat <<'EOF'
Usage: ./scripts/run-server.sh [--local-api] [--env-file PATH] [--auth-from-env] [--print-auth-mode]

Default local mode forces RBVM_AUTH_MODE=DISABLED so the browser UI works without
an in-app bearer token. Use --auth-from-env only for an intentional hardened/auth
test; in that mode RBVM_AUTH_MODE and RBVM_API_KEYS_FILE are read from the shell.

--local-api requires the PostgreSQL-backed runtime used by the real local API.
It refuses to start with RBVM_PROJECTION_BACKEND=DISABLED/LOCAL or without the
PostgreSQL JDBC settings/driver, preventing an accidentally partial local server.
If .env.local exists in the repository root it is loaded automatically.

--env-file PATH loads KEY=VALUE entries from a specific local environment file.
Values are treated literally; the file is not executed as shell code.

--print-auth-mode prints the effective launcher authentication mode and exits
before compilation. It is intended for diagnostics and repository verification.
EOF
}

load_env_file() {
  local path="$1"
  local line key value line_number=0
  if [[ ! -f "$path" ]]; then
    printf 'Environment file does not exist: %s\n' "$path" >&2
    exit 2
  fi
  while IFS= read -r line || [[ -n "$line" ]]; do
    line_number=$((line_number + 1))
    line="${line%$'\r'}"
    [[ -z "$line" || "$line" == \#* ]] && continue
    if [[ "$line" != *=* ]]; then
      printf 'Invalid environment entry at %s:%s (expected KEY=VALUE)\n' \
        "$path" "$line_number" >&2
      exit 2
    fi
    key="${line%%=*}"
    value="${line#*=}"
    if [[ ! "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
      printf 'Invalid environment key at %s:%s: %s\n' \
        "$path" "$line_number" "$key" >&2
      exit 2
    fi
    export "$key=$value"
  done < "$path"
}

require_local_postgres() {
  local backend="${RBVM_PROJECTION_BACKEND:-DISABLED}"
  case "${backend^^}" in
    POSTGRESQL|POSTGRES)
      ;;
    *)
      printf '%s\n' \
        'Local API mode requires RBVM_PROJECTION_BACKEND=POSTGRESQL.' >&2
      printf '%s\n' \
        'Create .env.local from deploy/local-api.environment.example or pass --env-file PATH.' >&2
      exit 2
      ;;
  esac

  local name
  for name in RBVM_JDBC_URL RBVM_DB_USER RBVM_POSTGRES_DRIVER_JAR; do
    if [[ -z "${!name:-}" ]]; then
      printf 'Local API mode requires %s.\n' "$name" >&2
      exit 2
    fi
  done
  if [[ ! -f "$RBVM_POSTGRES_DRIVER_JAR" ]]; then
    printf 'RBVM_POSTGRES_DRIVER_JAR does not point to a file: %s\n' \
      "$RBVM_POSTGRES_DRIVER_JAR" >&2
    exit 2
  fi
  if [[ "${RBVM_JDBC_URL:-}" != jdbc:postgresql:* ]]; then
    printf '%s\n' 'RBVM_JDBC_URL must begin with jdbc:postgresql: in local API mode.' >&2
    exit 2
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --local-api)
      LOCAL_API=true
      ;;
    --env-file)
      shift
      if [[ $# -eq 0 || -z "$1" ]]; then
        printf '%s\n' '--env-file requires a path.' >&2
        exit 2
      fi
      ENV_FILE="$1"
      ;;
    --auth-from-env)
      AUTH_FROM_ENV=true
      ;;
    --print-auth-mode)
      PRINT_AUTH_MODE=true
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      printf 'Unknown argument: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

if [[ -n "$ENV_FILE" ]]; then
  load_env_file "$ENV_FILE"
elif [[ -f "$ROOT_DIR/.env.local" ]]; then
  load_env_file "$ROOT_DIR/.env.local"
fi

if [[ "$AUTH_FROM_ENV" == false ]]; then
  # Frontend System V2 intentionally has no browser token field. This launcher is
  # the trusted-local entry point, so inherited hardened-shell auth settings must
  # not accidentally make the local SPA unusable.
  export RBVM_AUTH_MODE=DISABLED
  unset RBVM_API_KEYS_FILE || true
fi

if [[ "$PRINT_AUTH_MODE" == true ]]; then
  printf '%s\n' "${RBVM_AUTH_MODE:-DISABLED}"
  exit 0
fi

if [[ "$LOCAL_API" == true ]]; then
  require_local_postgres
fi

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

if [[ "$AUTH_FROM_ENV" == false ]]; then
  printf '%s\n' 'Local launcher authentication: DISABLED'
else
  printf 'Launcher authentication: from environment (%s)\n' "${RBVM_AUTH_MODE:-DISABLED}"
fi
if [[ "$LOCAL_API" == true ]]; then
  printf '%s\n' 'Local API runtime: POSTGRESQL_REQUIRED'
  printf 'Local API JDBC target: %s\n' "${RBVM_JDBC_URL%%\?*}"
fi

export RBVM_REPOSITORY_ROOT="${RBVM_REPOSITORY_ROOT:-$ROOT_DIR}"
exec java -cp "$CLASSPATH" io.rbvm.csv.RbvmPlatformMain
