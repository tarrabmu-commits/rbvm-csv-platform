#!/usr/bin/env python3
"""Dependency-free verification for the EPSS_CSV_V1 generator."""

import csv
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
SOURCE = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
SHA = "a" * 64


def run(*args, expect=0):
    result = subprocess.run(args, cwd=ROOT, text=True, capture_output=True, check=False)
    if result.returncode != expect:
        raise AssertionError(
            f"command returned {result.returncode}, expected {expect}: {args}\n"
            f"stdout={result.stdout}\nstderr={result.stderr}"
        )
    return result


def snapshot(path, *, complete=True, scored=2, missing=1, duplicate=False):
    scores = [
        {"cveId": "CVE-2026-10001", "epss": "0.125000", "percentile": "0.875000"},
        {"cveId": "CVE-2026-10003", "epss": "0.500000", "percentile": "0.990000"},
    ]
    if duplicate:
        scores[1]["cveId"] = "CVE-2026-10001"
    value = {
        "schemaVersion": 1,
        "artifactType": "FIRST_EPSS_VALIDATED_SNAPSHOT",
        "source": SOURCE,
        "resolvedSource": SOURCE,
        "observedAt": "2026-08-19T10:00:00Z",
        "sourceBytesSha256": SHA,
        "compressedBytes": 1024,
        "decompressedBytes": 4096,
        "modelVersion": "2025.03.14",
        "scoreDate": "2026-08-19",
        "feedRowCount": 100,
        "inputRows": 4,
        "requestedCveCount": 3,
        "scoredCveCount": scored,
        "missingCveCount": missing,
        "completeParse": complete,
        "acquisitionMode": "OFFLINE_REPLAY",
        "scores": scores,
        "missingCves": ["CVE-2026-10002"],
    }
    path.write_text(json.dumps(value), encoding="utf-8")


def main():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        snapshot_json = root / "snapshot.json"
        snapshot(snapshot_json)
        output = root / "epss.csv"
        report = root / "report.json"

        run(
            "python3", "scripts/build-first-epss-csv.py",
            str(snapshot_json), str(output), "--report", str(report),
        )
        with output.open(encoding="utf-8", newline="") as handle:
            rows = list(csv.DictReader(handle))
        assert [row["CVE_ID"] for row in rows] == ["CVE-2026-10001", "CVE-2026-10003"]
        assert rows[0]["EPSS_Probability"] == "0.125"
        assert rows[0]["EPSS_Percentile"] == "0.875"
        assert rows[0]["EPSS_Model_Version"] == "2025.03.14"
        assert rows[0]["EPSS_Score_Date"] == "2026-08-19"
        assert rows[0]["EPSS_Source"] == SOURCE
        assert rows[0]["EPSS_Source_SHA256"] == SHA
        assert all(row["CVE_ID"] != "CVE-2026-10002" for row in rows)

        result = json.loads(report.read_text(encoding="utf-8"))
        assert result["contractId"] == "EPSS_CSV_V1"
        assert result["evidenceRows"] == 2
        assert result["missingEvidenceCves"] == 1
        assert result["unknownRowsEmitted"] == 0
        assert result["scoreDate"] == "2026-08-19"
        assert result["sourceSha256"] == SHA

        incomplete = root / "incomplete.json"
        snapshot(incomplete, complete=False)
        run(
            "python3", "scripts/build-first-epss-csv.py",
            str(incomplete), str(root / "bad.csv"), expect=1,
        )

        mismatch = root / "mismatch.json"
        snapshot(mismatch, scored=1, missing=1)
        run(
            "python3", "scripts/build-first-epss-csv.py",
            str(mismatch), str(root / "bad2.csv"), expect=1,
        )

        duplicate = root / "duplicate.json"
        snapshot(duplicate, duplicate=True)
        run(
            "python3", "scripts/build-first-epss-csv.py",
            str(duplicate), str(root / "bad3.csv"), expect=1,
        )

    source = (ROOT / "scripts/build-first-epss-csv.py").read_text(encoding="utf-8").lower()
    for forbidden in ("prioritytier", "riskscore", "risk_score", "sla_days", "cvss_", "kev_status"):
        assert forbidden not in source
    print("FIRST EPSS contract generation checks: PASS")


if __name__ == "__main__":
    main()
