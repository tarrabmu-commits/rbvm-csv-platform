#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

AUTH_FROM_ENV=false
PRINT_AUTH_MODE=false

usage() {
  cat <<'EOF'
Usage: ./scripts/run-server.sh [--auth-from-env] [--print-auth-mode]

Default local mode forces RBVM_AUTH_MODE=DISABLED so the browser UI works without
an in-app bearer token. Use --auth-from-env only for an intentional hardened/auth
test; in that mode RBVM_AUTH_MODE and RBVM_API_KEYS_FILE are read from the shell.

--print-auth-mode prints the effective launcher authentication mode and exits
before compilation. It is intended for diagnostics and repository verification.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
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

export RBVM_REPOSITORY_ROOT="${RBVM_REPOSITORY_ROOT:-$ROOT_DIR}"
exec java -cp "$CLASSPATH" io.rbvm.csv.RbvmPlatformMain
