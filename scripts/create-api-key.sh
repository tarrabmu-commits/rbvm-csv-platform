#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 4 || $# -gt 5 ]]; then
  echo "usage: $0 REGISTRY TOKEN_FILE ACTOR_ID VIEWER|OPERATOR|ADMIN [EXPIRES_AT]" >&2
  exit 64
fi

registry="$1"
token_file="$2"
actor_id="$3"
role="${4^^}"
expires_at="${5:-}"

[[ "$actor_id" =~ ^[A-Za-z0-9][A-Za-z0-9._@:-]{0,199}$ ]] || {
  echo "actor id contains unsupported characters" >&2
  exit 64
}
[[ "$role" == VIEWER || "$role" == OPERATOR || "$role" == ADMIN ]] || {
  echo "role must be VIEWER, OPERATOR, or ADMIN" >&2
  exit 64
}
if [[ -n "$expires_at" ]]; then
  normalized_expiry="$(date -u -d "$expires_at" '+%Y-%m-%dT%H:%M:%SZ')" || {
    echo "EXPIRES_AT must be an ISO-8601 timestamp" >&2
    exit 64
  }
  (( $(date -u -d "$normalized_expiry" +%s) > $(date -u +%s) )) || {
    echo "EXPIRES_AT must be in the future" >&2
    exit 64
  }
  expires_at="$normalized_expiry"
fi
[[ ! -e "$token_file" ]] || {
  echo "refusing to overwrite existing token file: $token_file" >&2
  exit 73
}

umask 077
mkdir -p "$(dirname "$registry")" "$(dirname "$token_file")"
openssl rand -hex -out "$token_file" 32
chmod 600 "$token_file"
digest="$(tr -d '\r\n' < "$token_file" | sha256sum | cut -d' ' -f1)"
if [[ -n "$expires_at" ]]; then
  printf '%s=%s|%s|%s\n' "$digest" "$actor_id" "$role" "$expires_at" >> "$registry"
else
  printf '%s=%s|%s\n' "$digest" "$actor_id" "$role" >> "$registry"
fi
chmod 600 "$registry"
printf 'Created %s key for %s; raw token is stored only at %s\n' \
  "$role" "$actor_id" "$token_file"
