#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

AUTH_FROM_ENV=false
case "${1:-}" in
  "")
    ;;
  --auth-from-env)
    AUTH_FROM_ENV=true
    shift
    ;;
  --help|-h)
    cat <<'EOF'
Usage: ./scripts/run-server.sh [--auth-from-env]

Default local mode forces RBVM_AUTH_MODE=DISABLED so the browser UI works without
an in-app bearer token. Use --auth-from-env only for an intentional hardened/auth
test; in that mode RBVM_AUTH_MODE and RBVM_API_KEYS_FILE are read from the shell.
EOF
    exit 0
    ;;
  *)
    printf 'Unknown argument: %s\n' "$1" >&2
    printf 'Usage: ./scripts/run-server.sh [--auth-from-env]\n' >&2
    exit 2
    ;;
esac

if [[ $# -ne 0 ]]; then
  printf 'Unexpected arguments: %s\n' "$*" >&2
  printf 'Usage: ./scripts/run-server.sh [--auth-from-env]\n' >&2
  exit 2
fi

if [[ "$AUTH_FROM_ENV" == false ]]; then
  # Frontend System V2 intentionally has no browser token field. This launcher is
  # the trusted-local entry point, so inherited hardened-shell auth settings must
  # not accidentally make the local SPA unusable.
  export RBVM_AUTH_MODE=DISABLED
  unset RBVM_API_KEYS_FILE || true
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

exec java -cp "$CLASSPATH" io.rbvm.csv.CsvPlatformServer
