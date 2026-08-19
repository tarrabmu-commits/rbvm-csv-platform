#!/usr/bin/env python3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading

ROOT = Path(__file__).resolve().parent.parent
IMPORTER = ROOT / "scripts/import-cvss-v31.py"
SCHEDULER = ROOT / "scripts/scheduled-cvss-v31-refresh.sh"
SERVICE = ROOT / "deploy/systemd/rbvm-cvss-v31-refresh.service"
TIMER = ROOT / "deploy/systemd/rbvm-cvss-v31-refresh.timer"


class ImportHandler(BaseHTTPRequestHandler):
    received = None

    def do_POST(self):
        assert self.path == "/api/v1/cvss-v31-imports"
        assert self.headers.get("Authorization") == "Bearer test-secret"
        assert self.headers.get("Content-Type", "").startswith("text/csv")
        length = int(self.headers.get("Content-Length", "0"))
        ImportHandler.received = self.rfile.read(length)
        payload = json.dumps({
            "contractId": "CVSS_V31_CSV_V1",
            "semantics": "CVE_SCOPED_CVSS_V31_BASE_EVIDENCE",
            "insertedEvidence": 1,
            "replayedEvidence": 0,
            "totalQuarantinedRows": 0,
        }).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format, *args):
        pass


def importer_handoff_is_authenticated_and_contract_bound():
    server = ThreadingHTTPServer(("127.0.0.1", 0), ImportHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory() as temporary:
            temporary = Path(temporary)
            evidence = temporary / "cvss.csv"
            report = temporary / "import.json"
            evidence.write_text(
                "CVE_ID,CVSS_Version,CVSS_Base_Score,CVSS_Vector,CVSS_Source,CVSS_Observed_At\r\n"
                "CVE-2026-25087,3.1,9.8,CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H,"
                "https://nvd.nist.gov/vuln/detail/CVE-2026-25087,2026-08-19T09:00:00Z\r\n",
                encoding="utf-8",
            )
            environment = dict(os.environ)
            environment["RBVM_CVSS_API_KEY"] = "test-secret"
            result = subprocess.run(
                [
                    sys.executable,
                    str(IMPORTER),
                    str(evidence),
                    "--api-base",
                    f"http://127.0.0.1:{server.server_port}",
                    "--report",
                    str(report),
                ],
                cwd=ROOT,
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )
            assert result.returncode == 0, result.stderr
            assert "cvss_import=COMPLETE" in result.stdout
            assert ImportHandler.received == evidence.read_bytes()
            imported = json.loads(report.read_text(encoding="utf-8"))
            assert imported["contractId"] == "CVSS_V31_CSV_V1"
            assert imported["semantics"] == "CVE_SCOPED_CVSS_V31_BASE_EVIDENCE"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def importer_rejects_unsafe_transport_and_missing_secret():
    with tempfile.TemporaryDirectory() as temporary:
        evidence = Path(temporary) / "cvss.csv"
        evidence.write_text("header\nrow\n", encoding="utf-8")

        environment = dict(os.environ)
        environment["RBVM_CVSS_API_KEY"] = "test-secret"
        insecure = subprocess.run(
            [sys.executable, str(IMPORTER), str(evidence), "--api-base", "http://example.test:8080"],
            cwd=ROOT,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )
        assert insecure.returncode != 0
        assert "remote API base URL must use HTTPS" in insecure.stderr
        assert "test-secret" not in insecure.stderr

        environment.pop("RBVM_CVSS_API_KEY", None)
        missing = subprocess.run(
            [sys.executable, str(IMPORTER), str(evidence)],
            cwd=ROOT,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )
        assert missing.returncode != 0
        assert "RBVM_CVSS_API_KEY is required" in missing.stderr


def scheduled_flow_preserves_canonical_boundary():
    script = SCHEDULER.read_text(encoding="utf-8")
    collector = script.index('collect-nvd-cvss-v31.py')
    importer = script.index('import-cvss-v31.py')
    publish = script.index('mv "$staging" "$final"')
    latest = script.index('mv -Tf "$latest_tmp" "$OUTPUT_DIR/latest"')
    assert collector < importer < publish < latest
    assert "flock --nonblock" in script
    assert "sha256sum evidence.csv" in script
    assert "RBVM_CVSS_API_KEY is required" in script
    assert "PARTIAL" in script
    assert "psql" not in script.lower()
    assert "jdbc" not in script.lower()
    assert "enrich-wazuh-v2.py" not in script

    service = SERVICE.read_text(encoding="utf-8")
    assert "scheduled-cvss-v31-refresh.sh" in service
    assert "NoNewPrivileges=true" in service
    assert "ProtectSystem=strict" in service
    assert "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6" in service

    timer = TIMER.read_text(encoding="utf-8")
    assert "OnCalendar=daily" in timer
    assert "RandomizedDelaySec=30m" in timer
    assert "Persistent=true" in timer


def main():
    importer_handoff_is_authenticated_and_contract_bound()
    importer_rejects_unsafe_transport_and_missing_secret()
    scheduled_flow_preserves_canonical_boundary()
    print("CVSS v3.1 scheduled handoff checks: PASS")


if __name__ == "__main__":
    main()
