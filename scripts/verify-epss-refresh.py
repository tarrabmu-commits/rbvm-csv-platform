#!/usr/bin/env python3
"""Dependency-free end-to-end verification for scheduled FIRST EPSS safe refresh."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import gzip
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts/scheduled-epss-refresh.sh"


class ImportHandler(BaseHTTPRequestHandler):
    status = 200
    received = []

    def do_POST(self):
        assert self.path == "/api/v1/epss-imports"
        assert self.headers.get("Authorization") == "Bearer scheduled-test-secret"
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        ImportHandler.received.append(body)
        if self.status != 200:
            payload = b'{"error":"synthetic import failure"}'
            self.send_response(self.status)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        rows = max(0, body.count(b"\n") - 1)
        response = {
            "contractId": "EPSS_CSV_V1",
            "semantics": "CVE_SCOPED_FIRST_EPSS_PROBABILITY_EVIDENCE",
            "acceptedRows": rows,
            "insertedSnapshots": 1,
            "replayedSnapshots": 0,
            "snapshotConflictGroups": 0,
            "insertedEvidence": rows,
            "replayedEvidence": 0,
            "persistenceQuarantinedRows": 0,
            "contractQuarantinedRows": 0,
            "totalQuarantinedRows": 0,
            "uniqueCves": rows,
            "uniqueSnapshots": 1,
        }
        payload = json.dumps(response).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format, *args):
        pass


def epss_feed(path):
    text = (
        "#model_version:v2026.06.15,score_date:2026-08-18T13:30:00Z\n"
        "cve,epss,percentile\n"
        "CVE-2026-10001,0.250000000,0.810000000\n"
        "CVE-2026-10003,0.900000000,0.990000000\n"
    )
    path.write_bytes(gzip.compress(text.encode("utf-8"), mtime=0))


def input_csv(path):
    path.write_text(
        "Agent,CVE_ID,Severity,CVE_Description,Affected_Product,References,OS_name,Detected_At\n"
        "host-a,CVE-2026-10001,High,a,pkg-a,https://example.test/a,Ubuntu,2026-08-18T10:00:00Z\n"
        "host-b,CVE-2026-19999,Medium,b,pkg-b,https://example.test/b,Ubuntu,2026-08-18T10:01:00Z\n",
        encoding="utf-8",
    )


def run_refresh(input_path, feed_path, output_dir, api_base, *, expect=0):
    environment = dict(os.environ)
    environment.update({
        "RBVM_EPSS_INPUT": str(input_path),
        "RBVM_EPSS_OUTPUT_DIR": str(output_dir),
        "RBVM_EPSS_KEEP": "2",
        "RBVM_API_BASE_URL": api_base,
        "RBVM_EPSS_API_KEY": "scheduled-test-secret",
        "RBVM_EPSS_OFFLINE_INPUT": str(feed_path),
    })
    result = subprocess.run(
        ["bash", str(SCRIPT)],
        cwd=ROOT,
        env=environment,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != expect:
        raise AssertionError(
            f"refresh returned {result.returncode}, expected {expect}\n"
            f"stdout={result.stdout}\nstderr={result.stderr}"
        )
    return result


def successful_refresh_is_atomic_and_retained():
    ImportHandler.received = []
    ImportHandler.status = 200
    server = ThreadingHTTPServer(("127.0.0.1", 0), ImportHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            input_path = root / "input.csv"
            feed_path = root / "epss.csv.gz"
            output_dir = root / "output"
            input_csv(input_path)
            epss_feed(feed_path)
            output_dir.mkdir()
            (output_dir / "epss-20200101T000000Z").mkdir()
            (output_dir / "epss-20200102T000000Z").mkdir()

            api_base = f"http://127.0.0.1:{server.server_port}"
            success = run_refresh(input_path, feed_path, output_dir, api_base)
            assert "epss_refresh=PASS" in success.stdout, success.stdout
            latest = output_dir / "latest"
            assert latest.is_symlink()
            published_name = os.readlink(latest)
            published = output_dir / published_name
            assert published.is_dir()
            assert (published / "first-snapshot.json").is_file()
            assert (published / "first-snapshot.json.sha256").is_file()
            assert (published / "evidence.csv").is_file()
            assert (published / "evidence.csv.sha256").is_file()
            assert (published / "build.json").is_file()
            assert (published / "import.json").is_file()

            snapshot = json.loads((published / "first-snapshot.json").read_text(encoding="utf-8"))
            assert snapshot["acquisitionMode"] == "OFFLINE_REPLAY"
            assert snapshot["scoredCveCount"] == 1
            assert snapshot["missingCveCount"] == 1
            assert snapshot["missingCves"] == ["CVE-2026-19999"]
            evidence = (published / "evidence.csv").read_text(encoding="utf-8")
            assert "CVE-2026-10001" in evidence
            assert "CVE-2026-19999" not in evidence
            assert ImportHandler.received[-1] == (published / "evidence.csv").read_bytes()

            retained = sorted(
                path.name for path in output_dir.iterdir()
                if path.is_dir() and path.name.startswith("epss-")
            )
            assert len(retained) == 2, retained
            assert published_name in retained
            assert "epss-20200102T000000Z" in retained
            assert "epss-20200101T000000Z" not in retained

            # A later failed canonical API handoff must not publish a new snapshot or advance latest.
            time.sleep(1.1)
            ImportHandler.status = 503
            failed = run_refresh(input_path, feed_path, output_dir, api_base, expect=1)
            assert "EPSS import returned HTTP 503" in failed.stderr
            assert os.readlink(latest) == published_name
            retained_after_failure = sorted(
                path.name for path in output_dir.iterdir()
                if path.is_dir() and path.name.startswith("epss-")
            )
            assert retained_after_failure == retained
            assert not any(path.name.endswith(".staging") for path in output_dir.iterdir())
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def configuration_and_boundary_are_explicit():
    service = (ROOT / "deploy/systemd/rbvm-epss-refresh.service").read_text(encoding="utf-8")
    timer = (ROOT / "deploy/systemd/rbvm-epss-refresh.timer").read_text(encoding="utf-8")
    example = (ROOT / "deploy/epss-refresh.example").read_text(encoding="utf-8")
    script = SCRIPT.read_text(encoding="utf-8").lower()

    assert "scheduled-epss-refresh.sh" in service
    assert "NoNewPrivileges=true" in service
    assert "ProtectSystem=strict" in service
    assert "OnCalendar=daily" in timer
    assert "RandomizedDelaySec=30m" in timer
    assert "RBVM_EPSS_API_KEY" in example
    assert "RBVM_EPSS_OFFLINE_INPUT" in example
    assert "fetch-first-epss-snapshot.py" in script
    assert "build-first-epss-csv.py" in script
    assert "import-epss.py" in script
    assert "mv \"$staging\" \"$final\"" in script
    for forbidden in (
        "psql",
        "jdbc",
        "prioritytier",
        "risk score",
        "sla_days",
        "cvss_base_score",
        "known_exploited",
    ):
        assert forbidden not in script, forbidden


def main():
    successful_refresh_is_atomic_and_retained()
    configuration_and_boundary_are_explicit()
    print("EPSS scheduled safe refresh checks: PASS")


if __name__ == "__main__":
    main()
