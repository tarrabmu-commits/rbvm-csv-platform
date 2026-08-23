#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="$ROOT_DIR/build/manual"
MAIN_CLASSES="$BUILD_DIR/main"
TEST_CLASSES="$BUILD_DIR/test"
WITH_TESTS="${1:-}"

rm -rf "$BUILD_DIR"
mkdir -p "$MAIN_CLASSES" "$TEST_CLASSES"

if command -v javac >/dev/null 2>&1; then
  JAVAC=(javac)
else
  JAVAC=(java -m jdk.compiler/com.sun.tools.javac.Main)
fi

find "$ROOT_DIR/src/main/java" -name '*.java' -print > "$BUILD_DIR/main-sources.txt"
"${JAVAC[@]}" --release 17 -encoding UTF-8 -Xlint:all -Werror \
  -d "$MAIN_CLASSES" @"$BUILD_DIR/main-sources.txt"

if [[ -d "$ROOT_DIR/src/main/resources" ]]; then
  cp -R "$ROOT_DIR/src/main/resources/." "$MAIN_CLASSES/"
fi
# Frontend System V2 remains one served dependency-free bundle. Keep the
# CSV-first workflow modules isolated in source, then concatenate them
# deterministically into the runtime rbvm-ui.js artifact.
if [[ -f "$ROOT_DIR/src/main/resources/web/customer-flow.js" ]]; then
  printf '\n' >> "$MAIN_CLASSES/web/rbvm-ui.js"
  cat "$ROOT_DIR/src/main/resources/web/customer-flow.js" >> "$MAIN_CLASSES/web/rbvm-ui.js"
fi
if [[ -f "$ROOT_DIR/src/main/resources/web/csv-run-review.js" ]]; then
  printf '\n' >> "$MAIN_CLASSES/web/rbvm-ui.js"
  cat "$ROOT_DIR/src/main/resources/web/csv-run-review.js" >> "$MAIN_CLASSES/web/rbvm-ui.js"
fi
if [[ -f "$ROOT_DIR/src/main/resources/web/csv-run-visuals.js" ]]; then
  printf '\n' >> "$MAIN_CLASSES/web/rbvm-ui.js"
  cat "$ROOT_DIR/src/main/resources/web/csv-run-visuals.js" >> "$MAIN_CLASSES/web/rbvm-ui.js"
fi
if [[ -f "$ROOT_DIR/src/main/resources/web/csv-run-visuals-mount.js" ]]; then
  printf '\n' >> "$MAIN_CLASSES/web/rbvm-ui.js"
  cat "$ROOT_DIR/src/main/resources/web/csv-run-visuals-mount.js" >> "$MAIN_CLASSES/web/rbvm-ui.js"
fi
if [[ -f "$ROOT_DIR/src/main/resources/web/csv-run-visuals.css" ]]; then
  printf '\n' >> "$MAIN_CLASSES/web/rbvm-ui.css"
  cat "$ROOT_DIR/src/main/resources/web/csv-run-visuals.css" >> "$MAIN_CLASSES/web/rbvm-ui.css"
fi
if [[ -f "$ROOT_DIR/src/main/resources/web/csv-run-visuals-mount.css" ]]; then
  printf '\n' >> "$MAIN_CLASSES/web/rbvm-ui.css"
  cat "$ROOT_DIR/src/main/resources/web/csv-run-visuals-mount.css" >> "$MAIN_CLASSES/web/rbvm-ui.css"
fi
if [[ -f "$ROOT_DIR/src/main/resources/web/csv-canonical-handoff.js" ]]; then
  printf '\n' >> "$MAIN_CLASSES/web/rbvm-ui.js"
  cat "$ROOT_DIR/src/main/resources/web/csv-canonical-handoff.js" >> "$MAIN_CLASSES/web/rbvm-ui.js"
fi

# Stabilization V1: exactly one dashboard enhancement module is allowed at
# runtime. Legacy V3/V4/V5 MutationObserver overlays remain in source history
# but are deliberately not bundled; stacking them caused repeated full-catalog
# reads, race-prone replacement, and an incoherent product surface.
if [[ -f "$ROOT_DIR/src/main/resources/web/rbvm-dashboard-core.js" ]]; then
  printf '\n' >> "$MAIN_CLASSES/web/rbvm-ui.js"
  cat "$ROOT_DIR/src/main/resources/web/rbvm-dashboard-core.js" >> "$MAIN_CLASSES/web/rbvm-ui.js"
fi
if [[ -f "$ROOT_DIR/src/main/resources/web/rbvm-dashboard-core.css" ]]; then
  printf '\n' >> "$MAIN_CLASSES/web/rbvm-ui.css"
  cat "$ROOT_DIR/src/main/resources/web/rbvm-dashboard-core.css" >> "$MAIN_CLASSES/web/rbvm-ui.css"
fi

mkdir -p "$MAIN_CLASSES/db/migration"
cp "$ROOT_DIR"/db/migration/*.sql "$MAIN_CLASSES/db/migration/"

if [[ "$WITH_TESTS" == "--tests" ]]; then
  find "$ROOT_DIR/src/test/java" -name '*.java' -print > "$BUILD_DIR/test-sources.txt"
  "${JAVAC[@]}" --release 17 -encoding UTF-8 -Xlint:all -Werror \
    -cp "$MAIN_CLASSES" -d "$TEST_CLASSES" @"$BUILD_DIR/test-sources.txt"
fi
