#!/usr/bin/env python3
"""Dependency-free checks for scheduled CISA KEV collection and canonical handoff."""

import csv
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading

ROOT = Path(__file__).resolve().parent.parent
SCHEDULER = ROOT / "scripts/scheduled-cisa-kev-refresh.sh"
SERVICE = ROOT / "deploy/systemd/rbvm-cisa-kev-refresh.service"
TIMER = ROOT / "deploy/systemd/rbvm-cisa-kev-refresh.timer"
EXAMPLE = ROOT / "deploy/cisa-kev-refresh.example"


class ImportHandler(BaseHTTPRequestHandler):
    received = None

    def do_POST(self):
        assert self.path == "/api/v1/cisa-kev-imports"
        assert self.headers.get("Authorization") == "Bearer test-kev-secret"
        assert self.headers.get("Content-Type", "").startswith("text/csv")
        length = int(self.headers.get("Content-Length", "0"))
        ImportHandler.received = self.rfile.read(length)
        payload = json.dumps({
            "contractId": "CISA_KEV_CSV_V1",
            "semantics": "CVE_SCOPED_CISA_KEV_SNAPSHOT_MEMBERSHIP_EVIDENCE",
            "logicalRows": 2,
            "acceptedRows": 2,
            "listedRows": 1,
            "notListedRows": 1,
            "insertedSnapshots": 1,
            "replayedSnapshots": 0,
            "snapshotConflictGroups": 0,
            "insertedEvidence": 2,
            "replayedEvidence": 0,
            "contractDeduplicatedRows": 0,
            "persistenceQuarantinedRows": 0,
            "contractQuarantinedRows": 0,
            "totalDeduplicatedRows": 0,
            "totalQuarantinedRows": 0,
            "uniqueCves": 2,
            "uniqueSnapshots": 1,
            "contractIssues": [],
            "persistenceIssues": [],
        }).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format, *args):
        pass


def official_feed_fixture():
    return {
        "title": "CISA Catalog of Known Exploited Vulnerabilities",
        "catalogVersion": "2026.08.19",
        "dateReleased": "2026-08-19T09:00:00.000Z",
        "count": 1,
        "vulnerabilities": [
            {
                "cveID": "CVE-2026-10001",
                "dateAdded": "2026-08-18",
                "dueDate": "2026-09-01",
                "knownRansomwareCampaignUse": "Known",
            }
        ],
    }


def scheduled_flow_runs_end_to_end_without_database_shortcut():
    server = ThreadingHTTPServer(("127.0.0.1", 0), ImportHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            input_csv = root / "wazuh.csv"
            offline_feed = root / "known_exploited_vulnerabilities.json"
            output_dir = root / "published"

            input_csv.write_text(
                "Agent,CVE_ID,Severity,CVE_Description,Affected_Product,References,OS_name,Detected_At\n"
                "host-a,CVE-2026-10001,High,listed,pkg-a,https://example.test/a,Ubuntu,2026-08-19T08:00:00Z\n"
                "host-b,CVE-2026-10003,Medium,not-listed,pkg-b,https://example.test/b,Ubuntu,2026-08-19T08:01:00Z\n",
                encoding="utf-8",
            )
            offline_feed.write_text(json.dumps(official_feed_fixture()), encoding="utf-8")

            environment = dict(os.environ)
            environment.update({
                "RBVM_KEV_INPUT": str(input_csv),
                "RBVM_KEV_OUTPUT_DIR": str(output_dir),
                "RBVM_KEV_KEEP": "3",
                "RBVM_KEV_OFFLINE_INPUT": str(offline_feed),
                "RBVM_API_BASE_URL": f"http://127.0.0.1:{server.server_port}",
                "RBVM_KEV_API_KEY": "test-kev-secret",
            })
            result = subprocess.run(
                ["bash", str(SCHEDULER)],
                cwd=ROOT,
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )
            assert result.returncode == 0, result.stderr
            assert "cisa_kev_refresh=PASS" in result.stdout
            assert "listed=1" in result.stdout
            assert "not_listed=1" in result.stdout
            assert "mode=offline" in result.stdout
            assert "test-kev-secret" not in result.stdout + result.stderr

            latest = output_dir / "latest"
            assert latest.is_symlink()
            published = output_dir / os.readlink(latest)
            assert published.is_dir()
            required = {
                "catalog-snapshot.json",
                "catalog-snapshot.json.sha256",
                "evidence.csv",
                "evidence.csv.sha256",
                "build.json",
                "import.json",
            }
            assert required.issubset({path.name for path in published.iterdir()})

            snapshot = json.loads((published / "catalog-snapshot.json").read_text(encoding="utf-8"))
            assert snapshot["complete"] is True
            assert snapshot["acquisitionMode"] == "OFFLINE_REPLAY"
            assert snapshot["declaredCount"] == snapshot["parsedCount"] == 1

            build = json.loads((published / "build.json").read_text(encoding="utf-8"))
            assert build["contractId"] == "CISA_KEV_CSV_V1"
            assert build["listed"] == 1
            assert build["notListed"] == 1
            assert build["unknownRowsEmitted"] == 0

            with (published / "evidence.csv").open(encoding="utf-8", newline="") as handle:
                rows = list(csv.DictReader(handle))
            assert [row["KEV_Status"] for row in rows] == ["LISTED", "NOT_LISTED"]
            assert rows[0]["KEV_Catalog_SHA256"] == rows[1]["KEV_Catalog_SHA256"]
            assert rows[1]["KEV_Date_Added"] == ""
            assert rows[1]["KEV_Due_Date"] == ""
            assert rows[1]["Known_Ransomware_Campaign_Use"] == ""
            assert ImportHandler.received == (published / "evidence.csv").read_bytes()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def structure_preserves_evidence_boundary_and_hardening():
    script = SCHEDULER.read_text(encoding="utf-8")
    fetch = script.index("fetch-cisa-kev-snapshot.py")
    build = script.index("build-cisa-kev-csv.py")
    handoff = script.index("import-cisa-kev.py")
    publish = script.index('mv "$staging" "$final"')
    latest = script.index('mv -Tf "$latest_tmp" "$OUTPUT_DIR/latest"')
    assert fetch < build < handoff < publish < latest
    assert "flock --nonblock" in script
    assert "sha256sum catalog-snapshot.json" in script
    assert "sha256sum evidence.csv" in script
    assert "RBVM_KEV_API_KEY is required" in script
    assert "PARTIAL" in script
    assert "psql" not in script.lower()
    assert "jdbc" not in script.lower()
    assert "riskScore" not in script
    assert "priorityTier" not in script
    assert "EPSS" not in script

    service = SERVICE.read_text(encoding="utf-8")
    assert "scheduled-cisa-kev-refresh.sh" in service
    assert "NoNewPrivileges=true" in service
    assert "ProtectSystem=strict" in service
    assert "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6" in service
    assert "ReadWritePaths=-%h/.local/share/rbvm-platform/cisa-kev" in service

    timer = TIMER.read_text(encoding="utf-8")
    assert "OnCalendar=daily" in timer
    assert "RandomizedDelaySec=30m" in timer
    assert "Persistent=true" in timer

    example = EXAMPLE.read_text(encoding="utf-8")
    assert "RBVM_KEV_INPUT=" in example
    assert "RBVM_KEV_API_KEY=" in example
    assert "RBVM_API_BASE_URL=" in example
    assert "NVD_API_KEY" not in example


def main():
    scheduled_flow_runs_end_to_end_without_database_shortcut()
    structure_preserves_evidence_boundary_and_hardening()
    print("CISA KEV scheduled refresh checks: PASS")


if __name__ == "__main__":
    main()
