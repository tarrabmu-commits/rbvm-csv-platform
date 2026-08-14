#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tag="${1:-${GITHUB_REF_NAME:-}}"
[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
  echo "release tag must have the form vMAJOR.MINOR.PATCH" >&2
  exit 64
}
expected="${tag#v}"
gradle_version="$(sed -n 's/^version = "\([0-9.]*\)-SNAPSHOT"$/\1/p' \
  "$ROOT_DIR/build.gradle.kts")"
openapi_version="$(sed -n 's/^  version: \([0-9.]*\)$/\1/p' \
  "$ROOT_DIR/api/openapi.yaml" | head -1)"
jar_version="$(sed -n 's/^VERSION=\([0-9.]*\)$/\1/p' \
  "$ROOT_DIR/scripts/build-distribution.sh")"

[[ "$gradle_version" == "$expected" && "$openapi_version" == "$expected" \
  && "$jar_version" == "$expected" ]] || {
  printf 'version mismatch: tag=%s gradle=%s openapi=%s jar=%s\n' \
    "$expected" "$gradle_version" "$openapi_version" "$jar_version" >&2
  exit 1
}
printf 'release_version=PASS version=%s\n' "$expected"
