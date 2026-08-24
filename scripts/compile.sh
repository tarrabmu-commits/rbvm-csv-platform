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

# Package the standard-library-only public-intelligence source tools as JAR resources.
# Product runtime extracts fixed copies into an owner-only job directory and invokes them
# without a shell. This keeps source acquisition/bundle parsing identical to the verified
# offline contracts while the Java coordinator owns lifecycle and PostgreSQL admission.
INTEL_TOOLS="$MAIN_CLASSES/intelligence-tools/scripts"
mkdir -p "$INTEL_TOOLS"
cp "$ROOT_DIR/scripts/fetch-local-public-intelligence-source.py" "$INTEL_TOOLS/"
cp "$ROOT_DIR/scripts/build-public-intelligence-bundle-from-acquisition.py" "$INTEL_TOOLS/"
cp "$ROOT_DIR/scripts/build-public-intelligence-sync-bundle.py" "$INTEL_TOOLS/"

# Transitional stabilization: the legacy Overview renderer used allCases(),
# which crawled up to 60 pages before the new Dashboard could take ownership.
# Rewrite only that exact runtime call to a bounded first page; the transform
# fails closed if the source shape drifts.
python3 "$ROOT_DIR/scripts/stabilize-frontend-runtime.py" "$MAIN_CLASSES/web/rbvm-ui.js"

# Intelligence Sources is a native Frontend System V2 route. Integrate it into
# the compiled core bundle with exact fail-closed anchors instead of shipping
# another runtime overlay or MutationObserver-based page replacement.
python3 "$ROOT_DIR/scripts/integrate-public-intelligence-sources-ui.py" "$MAIN_CLASSES/web/rbvm-ui.js"

# Frontend System V2 remains one served dependency-free bundle. Keep the
# CSV-first workflow modules isolated in source, then concatenate them
# deterministically into the runtime rbvm-ui.js artifact.
if [[ -f "$ROOT_DIR/src/main/resources/web/customer-flow.js" ]]; then
  printf '\n' >> "$MAIN_CLASSES/web/rbvm-ui.js"
  cat "$ROOT_DIR/src/main/resources/web/customer-flow.js" >> "$MAIN_CLASSES/web/rbvm-ui.js"
  # Product UI opts into the async V1 enrichment job transport while the
  # source module retains compatibility with the legacy synchronous route.
  python3 "$ROOT_DIR/scripts/stabilize-csv-first-async-runtime.py" "$MAIN_CLASSES/web/rbvm-ui.js"
fi
if [[ -f "$ROOT_DIR/src/main/resources/web/customer-flow-local-api.js" ]]; then
  printf '\n' >> "$MAIN_CLASSES/web/rbvm-ui.js"
  cat "$ROOT_DIR/src/main/resources/web/customer-flow-local-api.js" >> "$MAIN_CLASSES/web/rbvm-ui.js"
fi
if [[ -f "$ROOT_DIR/src/main/resources/web/csv-run-review.js" ]]; then
  printf '\n' >> "$MAIN_CLASSES/web/rbvm-ui.js"
  cat "$ROOT_DIR/src/main/resources/web/csv-run-review.js" >> "$MAIN_CLASSES/web/rbvm-ui.js"
fi
if [[ -f "$ROOT_DIR/src/main/resources/web/csv-first-job-status.js" ]]; then
  printf '\n' >> "$MAIN_CLASSES/web/rbvm-ui.js"
  cat "$ROOT_DIR/src/main/resources/web/csv-first-job-status.js" >> "$MAIN_CLASSES/web/rbvm-ui.js"
fi
if [[ -f "$ROOT_DIR/src/main/resources/web/csv-first-job-status.css" ]]; then
  printf '\n' >> "$MAIN_CLASSES/web/rbvm-ui.css"
  cat "$ROOT_DIR/src/main/resources/web/csv-first-job-status.css" >> "$MAIN_CLASSES/web/rbvm-ui.css"
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

# V29 canonical priority integration is compile-time and fail-closed: it adds
# the explicit run->canonical materialization action and lazy Finding-detail
# reads without another MutationObserver runtime overlay or client-side scoring.
python3 "$ROOT_DIR/scripts/integrate-canonical-mvp-priority-ui.py" "$MAIN_CLASSES/web/rbvm-ui.js"

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
