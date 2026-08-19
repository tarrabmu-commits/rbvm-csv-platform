#!/usr/bin/env python3
"""Dependency-free verification for the canonical EPSS CSV-to-API handoff."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading

ROOT = Path(__file__).resolve().parent.parent
IMPORTER = ROOT / "scripts/import-epss.py"
SOURCE = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
SHA = "a" * 64

VALID_RESPONSE = {
    "contractId": "EPSS_CSV_V1",
    "semantics": "CVE_SCOPED_FIRST_EPSS_PROBABILITY_EVIDENCE",
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
        assert self.path == "/api/v1/epss-imports"
        assert self.headers.get("Authorization") == "Bearer test-secret"
        assert self.headers.get("Content-Type", "").startswith("text/csv")
        assert "epss-safe-handoff" in self.headers.get("User-Agent", "")
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
        "CVE_ID,EPSS_Probability,EPSS_Percentile,EPSS_Model_Version,EPSS_Score_Date,"
        "EPSS_Source,EPSS_Observed_At,EPSS_Source_SHA256\r\n"
        "CVE-2026-10001,0.125,0.875,2025.03.14,2026-08-19,"
        f"{SOURCE},2026-08-19T10:00:00Z,{SHA}\r\n"
        "CVE-2026-10002,0.5001,0.9500,2025.03.14,2026-08-19,"
        f"{SOURCE},2026-08-19T10:00:00Z,{SHA}\r\n",
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
            evidence = temporary / "epss.csv"
            report = temporary / "import.json"
            evidence_file(evidence)
            environment = dict(os.environ)
            environment["RBVM_EPSS_API_KEY"] = "test-secret"
            result = run_import(
                evidence,
                f"http://127.0.0.1:{server.server_port}",
                environment,
                report,
            )
            assert result.returncode == 0, result.stderr
            assert "epss_import=COMPLETE" in result.stdout
            assert ImportHandler.received == evidence.read_bytes()
            imported = json.loads(report.read_text(encoding="utf-8"))
            assert imported["contractId"] == "EPSS_CSV_V1"
            assert imported["semantics"] == "CVE_SCOPED_FIRST_EPSS_PROBABILITY_EVIDENCE"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def malformed_evidence_fails_before_network():
    with tempfile.TemporaryDirectory() as temporary:
        temporary = Path(temporary)
        environment = dict(os.environ)
        environment["RBVM_EPSS_API_KEY"] = "test-secret"

        bad_probability = temporary / "bad-probability.csv"
        evidence_file(bad_probability)
        bad_probability.write_text(
            bad_probability.read_text(encoding="utf-8").replace("0.125,0.875", "1.5,0.875"),
            encoding="utf-8",
        )
        result = run_import(bad_probability, "http://127.0.0.1:1", environment)
        assert result.returncode != 0
        assert "EPSS_Probability must be between 0 and 1" in result.stderr
        assert "connection failed" not in result.stderr

        extra_header = temporary / "extra-header.csv"
        evidence_file(extra_header)
        text = extra_header.read_text(encoding="utf-8")
        lines = text.splitlines()
        lines[0] += ",Priority"
        lines[1] += ",HIGH"
        lines[2] += ",LOW"
        extra_header.write_text("\n".join(lines) + "\n", encoding="utf-8")
        result = run_import(extra_header, "http://127.0.0.1:1", environment)
        assert result.returncode != 0
        assert "headers must exactly match EPSS_CSV_V1" in result.stderr

        wrong_source = temporary / "wrong-source.csv"
        evidence_file(wrong_source)
        wrong_source.write_text(
            wrong_source.read_text(encoding="utf-8").replace(SOURCE, "https://example.test/epss.csv"),
            encoding="utf-8",
        )
        result = run_import(wrong_source, "http://127.0.0.1:1", environment)
        assert result.returncode != 0
        assert "EPSS_Source must be the pinned FIRST bulk feed" in result.stderr


def unsafe_transport_and_missing_secret_fail_closed():
    with tempfile.TemporaryDirectory() as temporary:
        evidence = Path(temporary) / "epss.csv"
        evidence_file(evidence)
        environment = dict(os.environ)
        environment["RBVM_EPSS_API_KEY"] = "test-secret"

        insecure = run_import(evidence, "http://example.test:8080", environment)
        assert insecure.returncode != 0
        assert "remote API base URL must use HTTPS" in insecure.stderr
        assert "test-secret" not in insecure.stderr

        embedded = run_import(evidence, "https://user:password@example.test", environment)
        assert embedded.returncode != 0
        assert "must not contain credentials" in embedded.stderr
        assert "password" not in embedded.stderr
        assert "test-secret" not in embedded.stderr

        environment.pop("RBVM_EPSS_API_KEY", None)
        missing = run_import(evidence, "http://127.0.0.1:8080", environment)
        assert missing.returncode != 0
        assert "RBVM_EPSS_API_KEY is required" in missing.stderr


def response_accounting_and_contract_mismatch_are_rejected():
    server = ThreadingHTTPServer(("127.0.0.1", 0), ImportHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory() as temporary:
            evidence = Path(temporary) / "epss.csv"
            evidence_file(evidence)
            environment = dict(os.environ)
            environment["RBVM_EPSS_API_KEY"] = "test-secret"
            api_base = f"http://127.0.0.1:{server.server_port}"

            ImportHandler.response_payload = {**VALID_RESPONSE, "contractId": "WRONG"}
            mismatch = run_import(evidence, api_base, environment)
            assert mismatch.returncode != 0
            assert "contractId does not match" in mismatch.stderr

            ImportHandler.response_payload = {**VALID_RESPONSE, "semantics": "WRONG"}
            mismatch = run_import(evidence, api_base, environment)
            assert mismatch.returncode != 0
            assert "semantics do not match" in mismatch.stderr

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
        environment["RBVM_EPSS_API_KEY"] = "test-secret"
        symlink = run_import(link, "http://127.0.0.1:8080", environment)
        assert symlink.returncode != 0
        assert "regular non-symlink file" in symlink.stderr

    script = IMPORTER.read_text(encoding="utf-8").lower()
    assert "/api/v1/epss-imports" in script
    assert "rbvm_epss_api_key" in script
    for forbidden in (
        "psql",
        "jdbc",
        "postgres",
        "prioritytier",
        "risk score",
        "sla_days",
        "cvss_base_score",
        "known_exploited",
    ):
        assert forbidden not in script


def main():
    authenticated_handoff_is_contract_bound()
    malformed_evidence_fails_before_network()
    unsafe_transport_and_missing_secret_fail_closed()
    response_accounting_and_contract_mismatch_are_rejected()
    input_and_code_preserve_boundary()
    print("EPSS safe handoff checks: PASS")


if __name__ == "__main__":
    main()
