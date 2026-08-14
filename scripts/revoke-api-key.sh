#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 || ! -f "$1" || ! -f "$2" ]]; then
  echo "usage: $0 REGISTRY TOKEN_FILE" >&2
  exit 64
fi

registry="$1"
token_file="$2"
digest="$(tr -d '\r\n' < "$token_file" | sha256sum | cut -d' ' -f1)"
[[ "$digest" =~ ^[a-f0-9]{64}$ ]] || exit 70

umask 077
temporary="$(mktemp "$(dirname "$registry")/.api-keys.XXXXXX")"
cleanup() {
  if [[ -f "$temporary" ]]; then
    shred -u "$temporary" 2>/dev/null || rm -- "$temporary"
  fi
}
trap cleanup EXIT

awk -v digest="$digest" '
  index($0, digest "=") == 1 { removed++; next }
  { print }
  END { if (removed != 1) exit 42 }
' "$registry" > "$temporary" || {
  echo "registry does not contain exactly one matching key" >&2
  exit 65
}

chmod 600 "$temporary"
mv -- "$temporary" "$registry"
printf 'Revoked the key identified by %s…; restart the service to apply.\n' \
  "${digest:0:12}"
