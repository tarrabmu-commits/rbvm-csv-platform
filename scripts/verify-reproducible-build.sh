#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION=0.23.2
JAR="$ROOT_DIR/dist/rbvm-csv-platform-$VERSION.jar"
CHECKSUM="$JAR.sha256"
SBOM="$ROOT_DIR/dist/rbvm-csv-platform-$VERSION.spdx.json"
temporary="$(mktemp -d)"
server_pid=""
cleanup() {
  if [[ -n "${server_pid:-}" ]]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
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
grep -q '^Implementation-Version: 0.23.2' <<<"$manifest"
grep -q '^Created-By: RBVM reproducible build' <<<"$manifest"

if jar --list --file "$JAR" | grep -Eq '(^|/)(operator\.token|api-keys\.conf|runtime-data|postgresql-[0-9].*\.jar)'; then
  echo "distribution contains a forbidden runtime secret, data path, or JDBC driver" >&2
  exit 1
fi

port="$(python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
)"
mkdir -p "$temporary/runtime"
RBVM_HOST=127.0.0.1 \
RBVM_PORT="$port" \
RBVM_DATA_DIR="$temporary/runtime" \
RBVM_AUTH_MODE=DISABLED \
java -jar "$JAR" >"$temporary/server.log" 2>&1 &
server_pid=$!

python3 - "$port" <<'PY'
import sys
import time
from urllib.error import URLError
from urllib.request import Request, urlopen

port = int(sys.argv[1])
base = f"http://127.0.0.1:{port}"
css_link = '<link rel="stylesheet" href="/ui/rbvm-ui.css">'
js_link = '<script src="/ui/rbvm-ui.js" defer></script>'
pages = (
    "/",
    "/cvss",
    "/kev",
    "/epss",
    "/asset-context",
    "/reachability",
    "/business-impact",
    "/assets",
    "/asset-links",
)


def fetch(path):
    request = Request(base + path, headers={"User-Agent": "rbvm-packaged-frontend-smoke"})
    with urlopen(request, timeout=2) as response:
        return response.status, response.headers, response.read().decode("utf-8")


deadline = time.monotonic() + 12
while True:
    try:
        status, _, _ = fetch("/live")
        if status == 200:
            break
    except (URLError, TimeoutError, ConnectionError):
        pass
    if time.monotonic() >= deadline:
        raise AssertionError("packaged server did not become live before frontend smoke deadline")
    time.sleep(0.1)

for path in pages:
    status, headers, body = fetch(path)
    if status != 200:
        raise AssertionError(f"{path}: expected packaged HTTP 200, got {status}")
    if css_link not in body or js_link not in body:
        raise AssertionError(f"{path}: packaged page is missing shared frontend resources")
    if headers.get("Cache-Control") != "no-store":
        raise AssertionError(f"{path}: packaged page must remain no-store")

status, css_headers, css = fetch("/ui/rbvm-ui.css")
if status != 200 or not css_headers.get("Content-Type", "").startswith("text/css"):
    raise AssertionError("packaged shared CSS route must return text/css HTTP 200")
if "--rbvm-control-min: 44px" not in css or "system-ui" not in css:
    raise AssertionError("packaged shared CSS does not match the frontend-system contract")

status, js_headers, javascript = fetch("/ui/rbvm-ui.js")
if status != 200 or not js_headers.get("Content-Type", "").startswith("text/javascript"):
    raise AssertionError("packaged shared JavaScript route must return text/javascript HTTP 200")
if "RBVM_FRONTEND_SYSTEM_V1" not in javascript:
    raise AssertionError("packaged shared JavaScript contract marker is missing")

for headers in (css_headers, js_headers):
    if headers.get("Cache-Control") != "no-store":
        raise AssertionError("packaged shared frontend resources must remain no-store")
    csp = headers.get("Content-Security-Policy", "")
    for directive in (
        "default-src 'self'",
        "connect-src 'self'",
        "object-src 'none'",
        "base-uri 'none'",
        "frame-ancestors 'none'",
        "form-action 'self'",
    ):
        if directive not in csp:
            raise AssertionError(f"packaged frontend CSP missing {directive!r}")

print("packaged_frontend_smoke=PASS")
PY

kill "$server_pid" 2>/dev/null || true
wait "$server_pid" 2>/dev/null || true
server_pid=""

printf 'reproducible_build=PASS sha256=%s\n' \
  "$(sha256sum "$JAR" | cut -d' ' -f1)"
