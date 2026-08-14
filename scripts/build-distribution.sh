#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="$ROOT_DIR/dist"
JAR_PATH="$DIST_DIR/rbvm-csv-platform-0.7.0.jar"

"$ROOT_DIR/scripts/compile.sh"
mkdir -p "$DIST_DIR"

if command -v jar >/dev/null 2>&1; then
  JAR=(jar)
else
  JAR=(java -m jdk.jartool/sun.tools.jar.Main)
fi

"${JAR[@]}" --create --file "$JAR_PATH" \
  --main-class io.rbvm.csv.CsvPlatformServer \
  -C "$ROOT_DIR/build/manual/main" .

printf '%s\n' "$JAR_PATH"
