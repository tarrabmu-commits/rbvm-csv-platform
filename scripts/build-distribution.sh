#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="$ROOT_DIR/dist"
VERSION=0.23.2
JAR_PATH="$DIST_DIR/rbvm-csv-platform-$VERSION.jar"
CHECKSUM_PATH="$JAR_PATH.sha256"
SOURCE_DATE="${SOURCE_DATE:-2020-01-01T00:00:00Z}"

"$ROOT_DIR/scripts/compile.sh"
mkdir -p "$DIST_DIR"

if command -v jar >/dev/null 2>&1; then
  JAR=(jar)
else
  JAR=(java -m jdk.jartool/sun.tools.jar.Main)
fi

FILE_LIST="$ROOT_DIR/build/manual/jar-files.txt"
MANIFEST="$ROOT_DIR/build/manual/MANIFEST.MF"
printf '%s\r\n' \
  'Manifest-Version: 1.0' \
  'Main-Class: io.rbvm.csv.CsvPlatformServer' \
  'Implementation-Title: RBVM CSV Platform' \
  "Implementation-Version: $VERSION" \
  'Created-By: RBVM reproducible build' \
  '' > "$MANIFEST"
(cd "$ROOT_DIR/build/manual/main" && \
  find . -type f -printf '%P\n' | LC_ALL=C sort > "$FILE_LIST")
(cd "$ROOT_DIR/build/manual/main" && \
  "${JAR[@]}" --create --file "$JAR_PATH" --date="$SOURCE_DATE" \
    --manifest "$MANIFEST" @"$FILE_LIST")
(cd "$DIST_DIR" && sha256sum "$(basename "$JAR_PATH")" \
  > "$(basename "$CHECKSUM_PATH")")
"$ROOT_DIR/scripts/generate-sbom.sh" "$JAR_PATH"

printf '%s\n' "$JAR_PATH"
