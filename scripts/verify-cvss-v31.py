#!/usr/bin/env python3
import csv
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile


def cache_name(cves):
    digest = hashlib.sha256(",".join(cves).encode("ascii")).hexdigest()[:24]
    return f"nvd-{digest}.json"


def main():
    root = Path(__file__).resolve().parent.parent
    with tempfile.TemporaryDirectory(prefix="rbvm-cvss-v31-test-") as directory:
        work = Path(directory)
        cache = work / "cache"
        cache.mkdir()
        cve_v31 = "CVE-2026-4242"
        cve_v4_only = "CVE-2026-9999"
        cves = sorted([cve_v31, cve_v4_only])
        source = work / "source.csv"
        source.write_text(
            "Agent,Agent_ID,CVE_ID,Severity,CVE_Description,Affected_Product,"
            "Package_Version,Package_Architecture,References,OS_name,Finding_Status,"
            "Detected_At,Resolved_At\n"
            f"agent,agent-1,{cve_v31},Critical,description,openssl,3.0.2,amd64,"
            "https://example.test/evidence,Ubuntu,ACTIVE,2026-08-01T00:00:00Z,\n"
            f"agent,agent-1,{cve_v4_only},High,description,curl,8.0.0,amd64,"
            "https://example.test/evidence,Ubuntu,ACTIVE,2026-08-01T00:00:01Z,\n",
            encoding="utf-8",
        )
        (cache / cache_name(cves)).write_text(json.dumps({
            "vulnerabilities": [
                {"cve": {"id": cve_v31, "metrics": {
                    "cvssMetricV40": [{"type": "Primary", "cvssData": {
                        "version": "4.0", "baseScore": 8.7,
                        "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
                    }}],
                    "cvssMetricV31": [{"type": "Primary", "cvssData": {
                        "version": "3.1", "baseScore": 9.8,
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                    }}]
                }}},
                {"cve": {"id": cve_v4_only, "metrics": {
                    "cvssMetricV40": [{"type": "Primary", "cvssData": {
                        "version": "4.0", "baseScore": 7.8,
                        "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:L/SC:N/SI:N/SA:N"
                    }}]
                }}},
            ]
        }), encoding="utf-8")

        enriched = work / "enriched.csv"
        report = work / "report.json"
        subprocess.run([
            "python3", str(root / "scripts/enrich-cvss-v31.py"), str(source), str(enriched),
            "--cache-dir", str(cache), "--offline", "--observed-at",
            "2026-08-18T12:00:00+00:00", "--report", str(report),
        ], check=True, capture_output=True, text=True)

        with enriched.open(encoding="utf-8", newline="") as handle:
            rows = list(csv.DictReader(handle))
        assert rows[0]["CVSS_Version"] == "3.1"
        assert rows[0]["CVSS_Base_Score"] == "9.8"
        assert rows[0]["CVSS_Vector"].startswith("CVSS:3.1/")
        assert rows[0]["Intel_Source_References"] == "https://services.nvd.nist.gov/rest/json/cves/2.0"
        assert rows[0]["Intel_Observed_At"] == "2026-08-18T12:00:00Z"

        # A CVE that only has CVSS v4.0 must not be silently substituted or converted.
        assert rows[1]["CVSS_Version"] == ""
        assert rows[1]["CVSS_Base_Score"] == ""
        assert rows[1]["CVSS_Vector"] == ""
        assert rows[1]["Intel_Observed_At"] == ""
        assert rows[1]["Intel_Source_References"] == ""

        result = json.loads(report.read_text(encoding="utf-8"))
        assert result["stage"] == "CVSS_V31_BASE"
        assert result["cvssV31Cves"] == 1
        assert result["rowsWithoutCvssV31"] == 1
        assert "do not convert" in result["policy"]

    print("CVSS v3.1 enrichment checks: PASS")


if __name__ == "__main__":
    main()
