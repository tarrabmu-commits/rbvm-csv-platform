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
IMPORTER = ROOT / "scripts/import-cisa-kev.py"

VALID_RESPONSE = {
    "contractId": "CISA_KEV_CSV_V1",
    "semantics": "CVE_SCOPED_CISA_KEV_SNAPSHOT_MEMBERSHIP_EVIDENCE",
    "acceptedRows": 2,
    "insertedSnapshots": 1,
    "replayedSnapshots": 0,
    "snapshotConflictGroups": 0,
    "insertedEvidence": 2,
    "replayedEvidence": 0,
    "persistenceQuarantinedRows": 0,
    "contractQuarantinedRows": 0,
    "totalQuarantinedRows": 0,
    "uniqueCves": 2,
    "uniqueSnapshots": 1,
}


class ImportHandler(BaseHTTPRequestHandler):
    received = None
    response_payload = VALID_RESPONSE

    def do_POST(self):
        assert self.path == "/api/v1/cisa-kev-imports"
        assert self.headers.get("Authorization") == "Bearer test-secret"
        assert self.headers.get("Content-Type", "").startswith("text/csv")
        assert "cisa-kev-safe-handoff" in self.headers.get("User-Agent", "")
        length = int(self.headers.get("Content-Length", "0"))
        ImportHandler.received = self.rfile.read(length)
        payload = json.dumps(ImportHandler.response_payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format, *args):
        pass


def evidence_file(path):
    path.write_text(
        "CVE_ID,KEV_Status,KEV_Catalog_Version,KEV_Catalog_SHA256,KEV_Catalog_Count,"
        "KEV_Source,KEV_Observed_At,KEV_Date_Added,KEV_Due_Date,Known_Ransomware_Campaign_Use\r\n"
        "CVE-2026-1000,LISTED,2026.08.19," + "a" * 64 + ",2,"
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json,"
        "2026-08-19T10:00:00Z,2026-08-01,2026-08-22,KNOWN\r\n"
        "CVE-2026-1001,NOT_LISTED,2026.08.19," + "a" * 64 + ",2,"
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json,"
        "2026-08-19T10:00:00Z,,,\r\n",
        encoding="utf-8",
    )


def run_import(evidence, api_base, environment, report=None):
    command = [sys.executable, str(IMPORTER), str(evidence), "--api-base", api_base]
    if report is not None:
        command.extend(["--report", str(report)])
    return subprocess.run(
        command,
        cwd=ROOT,
        env=environment,
        text=True,
        capture_output=True,
        check=False,
    )


def authenticated_handoff_is_contract_bound():
    ImportHandler.response_payload = VALID_RESPONSE
    ImportHandler.received = None
    server = ThreadingHTTPServer(("127.0.0.1", 0), ImportHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory() as temporary:
            temporary = Path(temporary)
            evidence = temporary / "kev.csv"
            report = temporary / "import.json"
            evidence_file(evidence)
            environment = dict(os.environ)
            environment["RBVM_KEV_API_KEY"] = "test-secret"
            result = run_import(
                evidence,
                f"http://127.0.0.1:{server.server_port}",
                environment,
                report,
            )
            assert result.returncode == 0, result.stderr
            assert "cisa_kev_import=COMPLETE" in result.stdout
            assert ImportHandler.received == evidence.read_bytes()
            imported = json.loads(report.read_text(encoding="utf-8"))
            assert imported["contractId"] == "CISA_KEV_CSV_V1"
            assert imported["semantics"] == "CVE_SCOPED_CISA_KEV_SNAPSHOT_MEMBERSHIP_EVIDENCE"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def unsafe_transport_and_missing_secret_fail_closed():
    with tempfile.TemporaryDirectory() as temporary:
        evidence = Path(temporary) / "kev.csv"
        evidence_file(evidence)
        environment = dict(os.environ)
        environment["RBVM_KEV_API_KEY"] = "test-secret"

        insecure = run_import(evidence, "http://example.test:8080", environment)
        assert insecure.returncode != 0
        assert "remote API base URL must use HTTPS" in insecure.stderr
        assert "test-secret" not in insecure.stderr

        embedded = run_import(evidence, "https://user:password@example.test", environment)
        assert embedded.returncode != 0
        assert "must not contain credentials" in embedded.stderr
        assert "password" not in embedded.stderr
        assert "test-secret" not in embedded.stderr

        environment.pop("RBVM_KEV_API_KEY", None)
        missing = run_import(evidence, "http://127.0.0.1:8080", environment)
        assert missing.returncode != 0
        assert "RBVM_KEV_API_KEY is required" in missing.stderr


def response_accounting_and_contract_mismatch_are_rejected():
    server = ThreadingHTTPServer(("127.0.0.1", 0), ImportHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory() as temporary:
            evidence = Path(temporary) / "kev.csv"
            evidence_file(evidence)
            environment = dict(os.environ)
            environment["RBVM_KEV_API_KEY"] = "test-secret"
            api_base = f"http://127.0.0.1:{server.server_port}"

            ImportHandler.response_payload = {**VALID_RESPONSE, "contractId": "WRONG"}
            mismatch = run_import(evidence, api_base, environment)
            assert mismatch.returncode != 0
            assert "contractId does not match" in mismatch.stderr

            ImportHandler.response_payload = {**VALID_RESPONSE, "acceptedRows": 3}
            accounting = run_import(evidence, api_base, environment)
            assert accounting.returncode != 0
            assert "acceptedRows accounting is inconsistent" in accounting.stderr
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def input_and_code_preserve_boundary():
    with tempfile.TemporaryDirectory() as temporary:
        temporary = Path(temporary)
        target = temporary / "real.csv"
        link = temporary / "linked.csv"
        evidence_file(target)
        link.symlink_to(target)
        environment = dict(os.environ)
        environment["RBVM_KEV_API_KEY"] = "test-secret"
        symlink = run_import(link, "http://127.0.0.1:8080", environment)
        assert symlink.returncode != 0
        assert "regular non-symlink file" in symlink.stderr

    script = IMPORTER.read_text(encoding="utf-8").lower()
    assert "/api/v1/cisa-kev-imports" in script
    assert "rbvm_kev_api_key" in script
    assert "psql" not in script
    assert "jdbc" not in script
    assert "postgres" not in script
    assert "priority" not in script
    assert "risk score" not in script
    assert "epss" not in script


def main():
    authenticated_handoff_is_contract_bound()
    unsafe_transport_and_missing_secret_fail_closed()
    response_accounting_and_contract_mismatch_are_rejected()
    input_and_code_preserve_boundary()
    print("CISA KEV safe handoff checks: PASS")


if __name__ == "__main__":
    main()
