#!/usr/bin/env python3
"""Offline end-to-end verification for CSV_FIRST_PUBLIC_INTELLIGENCE_ENRICHMENT_V1."""

import csv
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "enrich-uploaded-csv.py"


def snapshot_sha(value):
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def write_snapshot(path):
    vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A"
    base_metrics = {
        "AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N",
        "VC": "H", "VI": "H", "VA": "H", "SC": "N", "SI": "N", "SA": "N",
    }
    first = {
        "source": "security@example.test", "type": "Primary", "baseScore": 9.3,
        "baseSeverity": "CRITICAL", "vector": vector,
        "metrics": {"base": base_metrics, "threat": {"E": "A"}, "environmental": {}, "supplemental": {}},
    }
    second_a = {
        "source": "cna-a@example.test", "type": "Secondary", "baseScore": 7.1,
        "baseSeverity": "HIGH", "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:L/VA:L/SC:N/SI:N/SA:N",
        "metrics": {"base": {"AV": "N"}, "threat": {}, "environmental": {}, "supplemental": {}},
    }
    second_b = {
        "source": "cna-b@example.test", "type": "Secondary", "baseScore": 8.2,
        "baseSeverity": "HIGH", "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N",
        "metrics": {"base": {"AV": "N"}, "threat": {}, "environmental": {}, "supplemental": {}},
    }
    value = {
        "schemaVersion": 1,
        "contractId": "PUBLIC_CVE_INTEL_SNAPSHOT_V1",
        "semantics": "AUTOMATED_PUBLIC_VULNERABILITY_INTELLIGENCE_WITH_PROVIDER_PROVENANCE",
        "observedAt": "2026-08-23T15:00:00Z",
        "sources": {"nvd": "test", "epss": "test", "cisaKev": "test", "cveServices": "test"},
        "providerResponseSha256": {},
        "cisaKevCatalog": {"catalogVersion": "test"},
        "inputRows": 4,
        "uniqueCves": 3,
        "coverage": {"nvd": 3, "cvssV4": 2, "epss": 1, "kevListed": 1, "cveServices": 1, "cisaSsvc": 1},
        "records": [
            {
                "cveId": "CVE-2026-10001",
                "nvd": {
                    "published": "2026-01-01T00:00:00.000", "lastModified": "2026-08-20T00:00:00.000",
                    "vulnStatus": "Analyzed", "sourceIdentifier": "security@example.test",
                    "descriptions": ["Synthetic vulnerability one"], "weaknesses": ["CWE-79"],
                    "references": ["https://example.test/1"], "cpeCriteria": ["cpe:2.3:a:test:one:*:*:*:*:*:*:*:*"],
                    "cvssV4Assessments": [first], "nvdKev": None,
                },
                "epss": {"probability": "0.42", "percentile": "0.95", "scoreDate": "2026-08-23"},
                "cisaKev": {
                    "listed": True, "dateAdded": "2026-08-01", "dueDate": "2026-08-15",
                    "vendorProject": "Test", "product": "One", "vulnerabilityName": "Synthetic One",
                    "requiredAction": "Apply mitigations", "knownRansomwareCampaignUse": "Known", "notes": "test",
                },
                "cveProgram": {
                    "metadata": {"state": "PUBLISHED", "assignerShortName": "TEST-CNA"},
                    "cna": {"providerShortName": "TEST-CNA", "title": "Synthetic One"},
                    "cisaVulnrichment": {"ssvc": {
                        "version": "2.0.3", "timestamp": "2026-08-22T00:00:00Z",
                        "exploitation": "active", "automatable": "yes", "technicalImpact": "total",
                    }},
                },
                "provenance": {"cveServicesResponseSha256": "a" * 64},
            },
            {
                "cveId": "CVE-2026-10002",
                "nvd": {
                    "published": "2026-02-01T00:00:00.000", "lastModified": "2026-08-21T00:00:00.000",
                    "vulnStatus": "Analyzed", "sourceIdentifier": "security@example.test",
                    "descriptions": [], "weaknesses": [], "references": [], "cpeCriteria": [],
                    "cvssV4Assessments": [second_a, second_b], "nvdKev": None,
                },
                "epss": None, "cisaKev": {"listed": False},
                "cveProgram": {"metadata": {"state": "PUBLISHED"}, "cna": {}, "cisaVulnrichment": None},
                "provenance": {"cveServicesResponseSha256": "b" * 64},
            },
            {
                "cveId": "CVE-2026-10003",
                "nvd": {
                    "published": "2026-03-01T00:00:00.000", "lastModified": "2026-08-22T00:00:00.000",
                    "vulnStatus": "Analyzed", "sourceIdentifier": "security@example.test",
                    "descriptions": [], "weaknesses": [], "references": [], "cpeCriteria": [],
                    "cvssV4Assessments": [], "nvdKev": None,
                },
                "epss": None, "cisaKev": {"listed": False},
                "cveProgram": {"metadata": {"state": "PUBLISHED"}, "cna": {}, "cisaVulnrichment": None},
                "provenance": {"cveServicesResponseSha256": "c" * 64},
            },
        ],
    }
    value["snapshotSha256"] = snapshot_sha(value)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main():
    with tempfile.TemporaryDirectory(prefix="rbvm-csv-first-") as temporary:
        work = Path(temporary)
        source = work / "input.csv"
        output = work / "enriched.csv"
        snapshot = work / "snapshot.json"
        report = work / "report.json"

        with source.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=["Agent", "CVE_ID", "Affected_Product", "Detected_At", "Original_Note"])
            writer.writeheader()
            writer.writerows([
                {"Agent": "a", "CVE_ID": "CVE-2026-10001", "Affected_Product": "one", "Detected_At": "2026-08-01T00:00:00Z", "Original_Note": "keep-1"},
                {"Agent": "a", "CVE_ID": "CVE-2026-10001", "Affected_Product": "one2", "Detected_At": "2026-08-02T00:00:00Z", "Original_Note": "keep-2"},
                {"Agent": "b", "CVE_ID": "CVE-2026-10002", "Affected_Product": "two", "Detected_At": "2026-08-03T00:00:00Z", "Original_Note": "keep-3"},
                {"Agent": "c", "CVE_ID": "CVE-2026-10003", "Affected_Product": "three", "Detected_At": "2026-08-04T00:00:00Z", "Original_Note": "keep-4"},
            ])
        write_snapshot(snapshot)

        completed = subprocess.run(
            [sys.executable, str(SCRIPT), str(source), str(output), "--intel-snapshot", str(snapshot), "--report", str(report)],
            check=True, capture_output=True, text=True,
        )
        if not completed.stdout.strip():
            raise AssertionError("CSV-first enrichment did not emit a completion report")

        with output.open("r", encoding="utf-8", newline="") as handle:
            rows = list(csv.DictReader(handle))
        if len(rows) != 4:
            raise AssertionError("row count was not preserved")
        if [row["Original_Note"] for row in rows] != ["keep-1", "keep-2", "keep-3", "keep-4"]:
            raise AssertionError("original row values/order were not preserved")

        first = rows[0]
        if first["CVSS4_Status"] != "PRESENT" or first["CVSS4_Base_Score"] != "9.3":
            raise AssertionError("single CVSS v4 assessment was not materialized")
        if first["CVSS4_AV"] != "N" or first["CVSS4_E"] != "A":
            raise AssertionError("CVSS v4 parsed metrics were not materialized")
        if first["EPSS_Probability"] != "0.42" or first["KEV_Listed"] != "true":
            raise AssertionError("EPSS/KEV were not materialized")
        if first["CISA_Exploitation"] != "active" or first["CISA_Automatable"] != "yes" or first["CISA_Technical_Impact"] != "total":
            raise AssertionError("CISA SSVC was not materialized")
        if rows[2]["CVSS4_Status"] != "AMBIGUOUS" or rows[2]["CVSS4_Vector"]:
            raise AssertionError("ambiguous CVSS v4 incorrectly selected a winner")
        if rows[3]["CVSS4_Status"] != "MISSING" or rows[3]["CVSS4_Base_Score"]:
            raise AssertionError("missing CVSS v4 was not preserved as missing")

        value = json.loads(report.read_text(encoding="utf-8"))
        if value.get("scope") != "INPUT_CSV_ONLY" or value.get("databaseStateUsed") is not False:
            raise AssertionError("CSV-first report does not prove stateless input scope")
        if value.get("inputRows") != 4 or value.get("uniqueCves") != 3:
            raise AssertionError("CSV-first report counts are incorrect")
        if value.get("cvssV4RowStatus") != {"PRESENT": 2, "MISSING": 1, "AMBIGUOUS": 1}:
            raise AssertionError("CVSS v4 row-state counts are incorrect")

    print("CSV-first enrichment verification: PASS")


if __name__ == "__main__":
    main()
