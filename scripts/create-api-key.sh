#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 4 ]]; then
  echo "usage: $0 REGISTRY TOKEN_FILE ACTOR_ID VIEWER|OPERATOR|ADMIN" >&2
  exit 64
fi

registry="$1"
token_file="$2"
actor_id="$3"
role="${4^^}"

[[ "$actor_id" =~ ^[A-Za-z0-9][A-Za-z0-9._@:-]{0,199}$ ]] || {
  echo "actor id contains unsupported characters" >&2
  exit 64
}
[[ "$role" == VIEWER || "$role" == OPERATOR || "$role" == ADMIN ]] || {
  echo "role must be VIEWER, OPERATOR, or ADMIN" >&2
  exit 64
}
[[ ! -e "$token_file" ]] || {
  echo "refusing to overwrite existing token file: $token_file" >&2
  exit 73
}

umask 077
mkdir -p "$(dirname "$registry")" "$(dirname "$token_file")"
openssl rand -hex -out "$token_file" 32
chmod 600 "$token_file"
digest="$(tr -d '\r\n' < "$token_file" | sha256sum | cut -d' ' -f1)"
printf '%s=%s|%s\n' "$digest" "$actor_id" "$role" >> "$registry"
chmod 600 "$registry"
printf 'Created %s key for %s; raw token is stored only at %s\n' \
  "$role" "$actor_id" "$token_file"
