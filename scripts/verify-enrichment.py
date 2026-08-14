#!/usr/bin/env python3
import csv
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile


def cache_name(source, cves):
    digest = hashlib.sha256(",".join(cves).encode("ascii")).hexdigest()[:24]
    return f"{source}-{digest}.json"


def main():
    root = Path(__file__).resolve().parent.parent
    with tempfile.TemporaryDirectory(prefix="rbvm-intel-test-") as directory:
        work = Path(directory)
        cache = work / "cache"
        output = work / "output"
        cache.mkdir()
        cve = "CVE-2026-4242"
        source = work / "source.csv"
        source.write_text(
            "Agent,Agent_ID,CVE_ID,Severity,CVE_Description,Affected_Product,"
            "Package_Version,Package_Architecture,References,OS_name,Finding_Status,"
            "Detected_At,Resolved_At\n"
            f"agent,agent-1,{cve},High,description,openssl,3.0.2,amd64,"
            "https://example.test/evidence,Ubuntu,ACTIVE,2026-08-01T00:00:00Z,\n",
            encoding="utf-8",
        )
        (cache / cache_name("nvd", [cve])).write_text(json.dumps({
            "vulnerabilities": [{"cve": {"id": cve, "metrics": {"cvssMetricV31": [{
                "type": "Primary", "cvssData": {"version": "3.1", "baseScore": 9.8,
                "vectorString": "CVSS:3.1/AV:N"}}]}}}]
        }), encoding="utf-8")
        (cache / cache_name("epss", [cve])).write_text(json.dumps({
            "data": [{"cve": cve, "epss": "0.500000", "percentile": "0.990000"}]
        }), encoding="utf-8")
        (cache / "cisa-kev.json").write_text(json.dumps({
            "vulnerabilities": [{"cveID": cve, "dateAdded": "2026-08-02",
                                 "dueDate": "2026-08-23"}]
        }), encoding="utf-8")

        enriched = work / "enriched.csv"
        report = work / "report.json"
        subprocess.run([
            str(root / "scripts/enrich-wazuh-v2.py"), str(source), str(enriched),
            "--cache-dir", str(cache), "--offline", "--observed-at",
            "2026-08-14T12:00:00+00:00", "--report", str(report),
        ], check=True, capture_output=True, text=True)
        with enriched.open(encoding="utf-8", newline="") as handle:
            row = next(csv.DictReader(handle))
        assert row["Intel_Observed_At"] == "2026-08-14T12:00:00Z"
        assert row["Known_Exploited"] == "true"
        assert row["CVSS_Base_Score"] == "9.8"
        result = json.loads(report.read_text(encoding="utf-8"))
        assert result["status"] == "COMPLETE"
        assert result["priorityDistribution"]["IMMEDIATE"] == 1

        environment = os.environ.copy()
        environment.update({
            "RBVM_INTEL_INPUT": str(source),
            "RBVM_INTEL_OUTPUT_DIR": str(output),
            "RBVM_INTEL_CACHE_DIR": str(cache),
            "RBVM_INTEL_OFFLINE": "true",
            "RBVM_INTEL_KEEP": "2",
        })
        subprocess.run([str(root / "scripts/scheduled-intelligence-refresh.sh")],
                       env=environment, check=True, capture_output=True, text=True)
        assert (output / "latest.csv").resolve().is_file()
        assert (output / "latest.csv.sha256").resolve().is_file()
        assert (output / "latest.json").resolve().is_file()
        assert len(list(output.glob("intelligence-*.csv.sha256"))) == 1

        changed = work / "changed.csv"
        changed.write_text(source.read_text(encoding="utf-8").replace(cve, "CVE-2026-9999"),
                           encoding="utf-8")
        rejected = subprocess.run([
            str(root / "scripts/enrich-wazuh-v2.py"), str(changed), str(work / "bad.csv"),
            "--cache-dir", str(cache), "--offline",
        ], capture_output=True, text=True)
        assert rejected.returncode != 0
        assert "offline cache is missing" in rejected.stderr
        failed_output = work / "failed-output"
        failed_environment = environment | {
            "RBVM_INTEL_INPUT": str(changed),
            "RBVM_INTEL_OUTPUT_DIR": str(failed_output),
        }
        failed_refresh = subprocess.run(
            [str(root / "scripts/scheduled-intelligence-refresh.sh")],
            env=failed_environment, capture_output=True, text=True)
        assert failed_refresh.returncode != 0
        assert not list(failed_output.glob("intelligence-*.csv"))
        assert not list(failed_output.glob("intelligence-*.json"))

    print("Enrichment scheduling checks: PASS")


if __name__ == "__main__":
    main()
