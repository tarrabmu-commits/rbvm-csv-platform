#!/usr/bin/env python3
import csv
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile


def cache_name(cves):
    digest = hashlib.sha256(",".join(cves).encode("ascii")).hexdigest()[:24]
    return f"nvd-cvss-v31-{digest}.json"


def main():
    root = Path(__file__).resolve().parent.parent
    collector = str(root / "scripts/collect-nvd-cvss-v31.py")
    with tempfile.TemporaryDirectory(prefix="rbvm-nvd-cvss-test-") as directory:
        work = Path(directory)
        source = work / "wazuh-v1.csv"
        output = work / "cvss-v31.csv"
        report = work / "report.json"
        cache = work / "cache"
        cache.mkdir()

        cves = ["CVE-2026-4242", "CVE-2026-4243", "CVE-2026-4244"]
        source.write_text(
            "Agent,CVE_ID,Severity,CVE_Description,Affected_Product,References,OS_name,Detected_At\n"
            "agent-a,CVE-2026-4242,High,desc,openssl,https://example.test/a,Ubuntu,2026-08-01T00:00:00Z\n"
            "agent-b,CVE-2026-4243,High,desc,libxml2,https://example.test/b,Ubuntu,2026-08-01T00:00:00Z\n"
            "agent-c,CVE-2026-4244,High,desc,curl,https://example.test/c,Ubuntu,2026-08-01T00:00:00Z\n",
            encoding="utf-8",
        )

        vector_a = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        vector_b = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"
        payload = {
            "vulnerabilities": [
                {"cve": {"id": "CVE-2026-4242", "metrics": {
                    "cvssMetricV40": [{
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "cvssData": {"version": "4.0", "baseScore": 10.0, "vectorString": "CVSS:4.0/AV:N"},
                    }],
                    "cvssMetricV31": [
                        {
                            "source": "vendor@example.test",
                            "type": "Primary",
                            "cvssData": {"version": "3.1", "baseScore": 8.8, "vectorString": vector_b},
                        },
                        {
                            "source": "nvd@nist.gov",
                            "type": "Secondary",
                            "cvssData": {"version": "3.1", "baseScore": 9.8, "vectorString": vector_a},
                        },
                    ],
                }}},
                {"cve": {"id": "CVE-2026-4243", "metrics": {
                    "cvssMetricV31": [{
                        "source": "vendor@example.test",
                        "type": "Primary",
                        "cvssData": {"version": "3.1", "baseScore": 7.5, "vectorString": vector_b},
                    }],
                }}},
                {"cve": {"id": "CVE-2026-4244", "metrics": {
                    "cvssMetricV31": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {"version": "3.1", "baseScore": 9.8, "vectorString": vector_a},
                        },
                        {
                            "source": "nvd@nist.gov",
                            "type": "Secondary",
                            "cvssData": {"version": "3.1", "baseScore": 8.1, "vectorString": vector_b},
                        },
                    ],
                }}},
            ]
        }
        (cache / cache_name(cves)).write_text(json.dumps(payload), encoding="utf-8")

        result = subprocess.run([
            "python3", collector,
            str(source),
            str(output),
            "--cache-dir", str(cache),
            "--offline",
            "--observed-at", "2026-08-19T09:00:00Z",
            "--report", str(report),
        ], check=True, capture_output=True, text=True)
        assert "emitted=1" in result.stdout
        assert "missing=1" in result.stdout
        assert "ambiguous=1" in result.stdout

        with output.open(encoding="utf-8", newline="") as handle:
            rows = list(csv.DictReader(handle))
        assert len(rows) == 1
        row = rows[0]
        assert row["CVE_ID"] == "CVE-2026-4242"
        assert row["CVSS_Version"] == "3.1"
        assert row["CVSS_Base_Score"] == "9.8"
        assert row["CVSS_Vector"] == vector_a
        assert row["CVSS_Source"] == "https://nvd.nist.gov/vuln/detail/CVE-2026-4242"
        assert row["CVSS_Observed_At"] == "2026-08-19T09:00:00Z"

        metadata = json.loads(report.read_text(encoding="utf-8"))
        assert metadata["contractId"] == "CVSS_V31_CSV_V1"
        assert metadata["uniqueCves"] == 3
        assert metadata["emittedEvidence"] == 1
        assert metadata["missingExactNvdV31"] == 1
        assert metadata["ambiguousNvdV31"] == 1
        assert metadata["sourcePolicy"]["requiredMetricSource"] == "nvd@nist.gov"
        assert metadata["sourcePolicy"]["fallbackToV30"] is False
        assert metadata["sourcePolicy"]["fallbackToV40"] is False
        assert metadata["sourcePolicy"]["fallbackToOtherProvider"] is False

        changed = work / "changed.csv"
        changed.write_text(source.read_text(encoding="utf-8").replace("CVE-2026-4244", "CVE-2026-9999"), encoding="utf-8")
        missing_cache = subprocess.run([
            "python3", collector,
            str(changed),
            str(work / "bad.csv"),
            "--cache-dir", str(cache),
            "--offline",
        ], capture_output=True, text=True)
        assert missing_cache.returncode != 0
        assert "offline cache is missing" in missing_cache.stderr

    print("NVD CVSS v3.1 collector checks: PASS")


if __name__ == "__main__":
    main()
