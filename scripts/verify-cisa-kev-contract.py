#!/usr/bin/env python3
"""Dependency-free verification for the CISA KEV CSV contract generator."""

import csv
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
SOURCE = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
SHA = "a" * 64


def run(*args, expect=0):
    result = subprocess.run(args, cwd=ROOT, text=True, capture_output=True, check=False)
    if result.returncode != expect:
        raise AssertionError(
            f"command returned {result.returncode}, expected {expect}: {args}\n"
            f"stdout={result.stdout}\nstderr={result.stderr}"
        )
    return result


def snapshot(path, *, complete=True, declared=2, parsed=2):
    value = {
        "schemaVersion": 1,
        "artifactType": "CISA_KEV_VALIDATED_SNAPSHOT",
        "source": SOURCE,
        "observedAt": "2026-08-19T10:00:00Z",
        "sha256": SHA,
        "title": "CISA Known Exploited Vulnerabilities Catalog",
        "catalogVersion": "2026.08.19",
        "dateReleased": "2026-08-19T09:00:00Z",
        "declaredCount": declared,
        "parsedCount": parsed,
        "complete": complete,
        "vulnerabilities": [
            {
                "cveId": "CVE-2026-10001",
                "dateAdded": "2026-08-18",
                "dueDate": "2026-09-01",
                "knownRansomwareCampaignUse": "KNOWN",
            },
            {
                "cveId": "CVE-2026-10003",
                "dateAdded": "2026-08-17",
                "dueDate": "2026-08-31",
                "knownRansomwareCampaignUse": "UNKNOWN",
            },
        ],
    }
    path.write_text(json.dumps(value), encoding="utf-8")


def main():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        input_csv = root / "input.csv"
        input_csv.write_text(
            "CVE_ID\nCVE-2026-10001\nCVE-2026-10002\nCVE-2026-10001\n",
            encoding="utf-8",
        )
        snapshot_json = root / "snapshot.json"
        snapshot(snapshot_json)
        output = root / "kev.csv"
        report = root / "report.json"

        run(
            "python3", "scripts/build-cisa-kev-csv.py",
            str(input_csv), str(snapshot_json), str(output), "--report", str(report),
        )
        with output.open(encoding="utf-8", newline="") as handle:
            rows = list(csv.DictReader(handle))
        assert [row["CVE_ID"] for row in rows] == ["CVE-2026-10001", "CVE-2026-10002"]
        assert rows[0]["KEV_Status"] == "LISTED"
        assert rows[0]["KEV_Date_Added"] == "2026-08-18"
        assert rows[1]["KEV_Status"] == "NOT_LISTED"
        assert rows[1]["KEV_Date_Added"] == ""
        assert rows[1]["Known_Ransomware_Campaign_Use"] == ""
        assert all(row["KEV_Catalog_SHA256"] == SHA for row in rows)

        result = json.loads(report.read_text(encoding="utf-8"))
        assert result["listed"] == 1
        assert result["notListed"] == 1
        assert result["unknownRowsEmitted"] == 0

        incomplete = root / "incomplete.json"
        snapshot(incomplete, complete=False)
        run(
            "python3", "scripts/build-cisa-kev-csv.py",
            str(input_csv), str(incomplete), str(root / "bad.csv"),
            expect=1,
        )

        mismatch = root / "mismatch.json"
        snapshot(mismatch, declared=3, parsed=2)
        run(
            "python3", "scripts/build-cisa-kev-csv.py",
            str(input_csv), str(mismatch), str(root / "bad2.csv"),
            expect=1,
        )

    source = (ROOT / "scripts/build-cisa-kev-csv.py").read_text(encoding="utf-8").lower()
    for forbidden in ("prioritytier", "riskscore", "epss", "sla_days", "knownexploited=false"):
        assert forbidden not in source
    print("CISA KEV contract generation checks: PASS")


if __name__ == "__main__":
    main()
