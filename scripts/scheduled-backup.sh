#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKUP_DIR="${RBVM_BACKUP_DIR:-/home/olive/.local/share/rbvm-platform/backups}"
KEEP="${RBVM_BACKUP_KEEP:-14}"

[[ "$KEEP" =~ ^[0-9]+$ ]] && (( KEEP >= 2 )) || {
  echo "RBVM_BACKUP_KEEP must be an integer of at least 2" >&2
  exit 64
}

umask 077
mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
target="$BACKUP_DIR/rbvm-$stamp.dump"
[[ "$target" =~ /rbvm-[0-9]{8}T[0-9]{6}Z\.dump$ ]] || exit 70

"$ROOT_DIR/scripts/backup-postgres.sh" "$target"
(cd "$BACKUP_DIR" && sha256sum "$(basename "$target")" \
  > "$(basename "$target").sha256")
"$ROOT_DIR/scripts/verify-backup-restore.sh" "$target"

mapfile -t backups < <(find "$BACKUP_DIR" -maxdepth 1 -type f \
  -name 'rbvm-????????T??????Z.dump' -printf '%f\n' | sort -r)
if (( ${#backups[@]} > KEEP )); then
  for expired in "${backups[@]:KEEP}"; do
    [[ "$expired" =~ ^rbvm-[0-9]{8}T[0-9]{6}Z\.dump$ ]] || exit 70
    rm -- "$BACKUP_DIR/$expired" "$BACKUP_DIR/$expired.sha256"
  done
fi

printf 'scheduled_backup=PASS file=%s retained=%s\n' "$target" \
  "$(( ${#backups[@]} < KEEP ? ${#backups[@]} : KEEP ))"
