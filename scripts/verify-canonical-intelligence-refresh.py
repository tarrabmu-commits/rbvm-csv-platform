#!/usr/bin/env python3
"""Verify the canonical-CVE intelligence refresh handoff."""

import csv
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import subprocess
import tempfile
import threading
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parent.parent
EXPORTER = ROOT / "scripts" / "export-current-cves.py"
WRAPPER = ROOT / "scripts" / "scheduled-canonical-intelligence-refresh.sh"
SERVICE = ROOT / "deploy" / "systemd" / "rbvm-intelligence-refresh.service"


class Handler(BaseHTTPRequestHandler):
    requests = []

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path != "/api/v1/cases":
            self.send_error(404)
            return
        query = parse_qs(parsed.query)
        self.__class__.requests.append(query)
        cursor = query.get("cursor", [None])[0]
        if cursor is None:
            payload = {
                "cases": [
                    {"caseId": "a", "cveId": "CVE-2026-3000"},
                    {"caseId": "b", "cveId": "cve-2025-10000"},
                ],
                "nextCursor": "page-2",
            }
        elif cursor == "page-2":
            payload = {
                "cases": [
                    {"caseId": "c", "cveId": "CVE-2026-3000"},
                    {"caseId": "d", "cveId": "CVE-2024-9999"},
                ],
                "nextCursor": None,
            }
        else:
            self.send_error(400)
            return
        encoded = __import__("json").dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, _format, *_args):
        return


def require(condition, message):
    if not condition:
        raise SystemExit(message)


def verify_exporter():
    Handler.requests = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "cves.csv"
            result = subprocess.run(
                [
                    "python3",
                    str(EXPORTER),
                    str(output),
                    "--api-base",
                    f"http://127.0.0.1:{server.server_port}",
                ],
                check=True,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={**os.environ, "RBVM_INTELLIGENCE_API_KEY": ""},
            )
            require("unique_cves=3" in result.stdout, "exporter did not report the unique CVE count")
            with output.open(encoding="utf-8", newline="") as handle:
                rows = list(csv.reader(handle))
            require(
                rows == [
                    ["CVE_ID"],
                    ["CVE-2024-9999"],
                    ["CVE-2025-10000"],
                    ["CVE-2026-3000"],
                ],
                "canonical CVE export must be normalized, unique, and deterministic",
            )
        require(len(Handler.requests) == 2, "exporter did not follow Cases API pagination")
        require(Handler.requests[0].get("limit") == ["100"], "exporter must request the bounded page size")
        require(Handler.requests[1].get("cursor") == ["page-2"], "exporter lost the pagination cursor")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def verify_handoff():
    wrapper = WRAPPER.read_text(encoding="utf-8")
    service = SERVICE.read_text(encoding="utf-8")
    require("export-current-cves.py" in wrapper, "refresh wrapper must derive canonical CVEs")
    require(
        'RBVM_CVSS_INPUT="$input"' in wrapper
        and 'RBVM_EPSS_INPUT="$input"' in wrapper
        and 'RBVM_KEV_INPUT="$input"' in wrapper,
        "all intelligence sources must receive the exact same canonical CVE artifact",
    )
    for source in ("CVSS", "EPSS", "KEV"):
        expected = (
            f'RBVM_{source}_API_KEY="${{RBVM_{source}_API_KEY:-'
            '${RBVM_INTELLIGENCE_API_KEY:-}}"'
        )
        require(expected in wrapper, f"{source} importer must inherit the umbrella API key unless overridden")
    require("scheduled-cvss-v31-refresh.sh" in wrapper, "canonical wrapper must invoke CVSS v3.1 refresh")
    require("scheduled-epss-refresh.sh" in wrapper, "canonical wrapper must invoke FIRST EPSS refresh")
    require("scheduled-cisa-kev-refresh.sh" in wrapper, "canonical wrapper must invoke CISA KEV refresh")
    require(
        "scheduled-canonical-intelligence-refresh.sh" in service,
        "umbrella systemd service must use the canonical evidence refresh",
    )
    require(
        "scheduled-intelligence-refresh.sh" not in service,
        "umbrella systemd service must not invoke the legacy embedded-intelligence refresh",
    )


def main():
    verify_exporter()
    verify_handoff()
    print("Canonical intelligence refresh checks: PASS")


if __name__ == "__main__":
    main()
