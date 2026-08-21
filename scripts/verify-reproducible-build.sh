#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION=0.22.0
JAR="$ROOT_DIR/dist/rbvm-csv-platform-$VERSION.jar"
CHECKSUM="$JAR.sha256"
SBOM="$ROOT_DIR/dist/rbvm-csv-platform-$VERSION.spdx.json"
temporary="$(mktemp -d)"
cleanup() {
  rm -rf -- "$temporary"
}
trap cleanup EXIT

SOURCE_DATE=2020-01-01T00:00:00Z "$ROOT_DIR/scripts/build-distribution.sh" >/dev/null
cp "$JAR" "$temporary/first.jar"
cp "$CHECKSUM" "$temporary/first.sha256"
cp "$SBOM" "$temporary/first.spdx.json"

SOURCE_DATE=2020-01-01T00:00:00Z "$ROOT_DIR/scripts/build-distribution.sh" >/dev/null
cmp --silent "$temporary/first.jar" "$JAR"
cmp --silent "$temporary/first.sha256" "$CHECKSUM"
cmp --silent "$temporary/first.spdx.json" "$SBOM"
(cd "$(dirname "$JAR")" && sha256sum --check "$(basename "$CHECKSUM")")
python3 -m json.tool "$SBOM" >/dev/null
manifest="$(unzip -p "$JAR" META-INF/MANIFEST.MF)"
grep -q '^Implementation-Version: 0.22.0' <<<"$manifest"
grep -q '^Created-By: RBVM reproducible build' <<<"$manifest"

if jar --list --file "$JAR" | grep -Eq '(^|/)(operator\.token|api-keys\.conf|runtime-data|postgresql-[0-9].*\.jar)'; then
  echo "distribution contains a forbidden runtime secret, data path, or JDBC driver" >&2
  exit 1
fi

printf 'reproducible_build=PASS sha256=%s\n' \
  "$(sha256sum "$JAR" | cut -d' ' -f1)"
