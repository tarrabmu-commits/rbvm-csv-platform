#!/usr/bin/env python3
"""Run a deterministic 6000-row CSV-first RBVM scale benchmark.

This benchmark intentionally replays a generated PUBLIC_CVE_INTEL_SNAPSHOT_V1
instead of calling the network. It measures application work — CSV enrichment,
contextual CVSS, method admission, and frozen Pareto treatment priority — while
the separate live benchmark continues to validate real public providers.
"""

from __future__ import annotations

import csv
import hashlib
import json
import os
from pathlib import Path
import resource
import shutil
import subprocess
import sys
import time

from cvss_v4_official import score_record

ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / "build/scale-6000"
ROWS = 6000
ASSETS = 60
UNIQUE_CVES = 300
EXPECTED_METHOD_SHA = "88d5cdb8702c6c0ed2c033c3df6b8abbe1aa392f44f4507685b54082a16dc388"
BASE_VECTOR = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
BASE_KEYS = ("AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA")


def canonical_sha(value):
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def parse_base(vector):
    values = {}
    for token in vector.split("/")[1:]:
        key, value = token.split(":", 1)
        if key in BASE_KEYS:
            values[key] = value
    return values


def write_input(path, cves):
    headers = ["Agent", "Agent_ID", "CVE_ID", "Severity", "Affected_Product", "Detected_At"]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=headers)
        writer.writeheader()
        for index in range(ROWS):
            asset_index = index % ASSETS
            occurrence = index // ASSETS
            cve_index = (asset_index * 37 + occurrence * 13) % UNIQUE_CVES
            writer.writerow({
                "Agent": f"host-{asset_index:03d}",
                "Agent_ID": f"asset-{asset_index:03d}",
                "CVE_ID": cves[cve_index],
                "Severity": ("Critical", "High", "Medium", "Low")[cve_index % 4],
                "Affected_Product": f"product-{cve_index % 25:02d}",
                "Detected_At": f"2026-08-{1 + (index % 20):02d}T12:00:00Z",
            })


def write_snapshot(path, cves):
    scored = score_record(BASE_VECTOR)
    base_metrics = parse_base(BASE_VECTOR)
    assessment = {
        "source": "scale-benchmark@nvd.example",
        "type": "Primary",
        "baseScore": scored["score"],
        "baseSeverity": scored["severity"],
        "vector": BASE_VECTOR,
        "metrics": {"base": base_metrics, "threat": {}, "environmental": {}, "supplemental": {}},
    }
    records = []
    for index, cve in enumerate(cves):
        probability = (index + 1) / (UNIQUE_CVES + 1)
        listed = index % 17 == 0
        records.append({
            "cveId": cve,
            "nvd": {
                "published": "2026-01-01T00:00:00.000",
                "lastModified": "2026-08-20T00:00:00.000",
                "vulnStatus": "Analyzed",
                "sourceIdentifier": "scale-benchmark@nvd.example",
                "descriptions": [f"Synthetic deterministic scale record for {cve}."],
                "weaknesses": [f"CWE-{79 + index % 5}"],
                "references": [],
                "cpeCriteria": [],
                "cvssV4Assessments": [assessment],
                "nvdKev": None,
            },
            "epss": {
                "probability": f"{probability:.6f}",
                "percentile": f"{min(0.999999, probability + 0.0005):.6f}",
                "scoreDate": "2026-08-24",
            },
            "cisaKev": {
                "listed": listed,
                "dateAdded": "2026-08-01" if listed else None,
                "dueDate": "2026-08-22" if listed else None,
            },
            "cveProgram": None,
            "provenance": {"cveServicesResponseSha256": None},
        })
    snapshot = {
        "schemaVersion": 1,
        "contractId": "PUBLIC_CVE_INTEL_SNAPSHOT_V1",
        "semantics": "AUTOMATED_PUBLIC_VULNERABILITY_INTELLIGENCE_WITH_PROVIDER_PROVENANCE",
        "observedAt": "2026-08-24T00:00:00Z",
        "sources": {
            "nvd": "SYNTHETIC_SCALE_REPLAY",
            "epss": "SYNTHETIC_SCALE_REPLAY",
            "cisaKev": "SYNTHETIC_SCALE_REPLAY",
            "cveServices": None,
        },
        "providerResponseSha256": {"nvd": [], "epss": [], "cisaKev": None, "cveServices": {}},
        "cisaKevCatalog": {"catalogVersion": "scale-replay", "dateReleased": "2026-08-24", "count": sum(1 for row in records if row["cisaKev"]["listed"])},
        "inputRows": ROWS,
        "uniqueCves": UNIQUE_CVES,
        "coverage": {
            "nvd": UNIQUE_CVES,
            "cvssV4": UNIQUE_CVES,
            "epss": UNIQUE_CVES,
            "kevListed": sum(1 for row in records if row["cisaKev"]["listed"]),
            "cveServices": 0,
            "cisaSsvc": 0,
        },
        "records": records,
    }
    snapshot["snapshotSha256"] = canonical_sha(snapshot)
    path.write_text(json.dumps(snapshot, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_bundle(path):
    criticalities = ("LOW", "MODERATE", "HIGH", "MISSION_CRITICAL")
    requirements = (("X", "X", "X"), ("L", "L", "L"), ("M", "M", "M"), ("H", "H", "H"))
    assets = []
    for index in range(ASSETS):
        cr, ir, ar = requirements[index % len(requirements)]
        assets.append({
            "customerAssetKey": f"asset-{index:03d}",
            "displayName": f"host-{index:03d}",
            "assetCriticality": criticalities[index % len(criticalities)],
            "internetFacing": "YES" if index % 3 == 0 else "NO",
            "cvssConfidentialityRequirement": cr,
            "cvssIntegrityRequirement": ir,
            "cvssAvailabilityRequirement": ar,
        })
    bundle = {
        "contractId": "RBVM_CUSTOMER_ASSET_BUNDLE_V3",
        "schemaVersion": 3,
        "createdAt": "2026-08-24T00:00:00Z",
        "sourceFileName": "scale-6000.csv",
        "assets": assets,
    }
    path.write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def run_stage(name, command, timings):
    started = time.perf_counter()
    subprocess.run(command, cwd=ROOT, check=True, stdout=subprocess.DEVNULL)
    timings[name] = round(time.perf_counter() - started, 3)


def row_count(path):
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return sum(1 for _ in csv.DictReader(handle))


def unique_priority_vectors(path):
    fields = ("KEV_Listed", "Internet_Facing", "Asset_Criticality", "EPSS_Probability", "CVSS4_Context_Score")
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return len({tuple(row.get(field, "") for field in fields) for row in csv.DictReader(handle)})


def peak_rss_mib():
    value = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    if sys.platform == "darwin":
        return value / (1024 * 1024)
    return value / 1024


def main():
    if BUILD.exists():
        shutil.rmtree(BUILD)
    BUILD.mkdir(parents=True)
    cves = [f"CVE-2026-{10000 + index}" for index in range(UNIQUE_CVES)]
    source = BUILD / "input.csv"
    snapshot = BUILD / "public-intel.json"
    bundle = BUILD / "customer-bundle.json"
    enriched = BUILD / "enriched.csv"
    enrich_report = BUILD / "enrichment-report.json"
    analysis = BUILD / "analysis.csv"
    analysis_summary = BUILD / "analysis-summary.json"
    admission = BUILD / "method-admission.json"
    ranked = BUILD / "priority.csv"
    priority_report = BUILD / "priority-report.json"

    write_input(source, cves)
    write_snapshot(snapshot, cves)
    write_bundle(bundle)

    timings = {}
    total_started = time.perf_counter()
    run_stage("enrichSeconds", [
        sys.executable, str(ROOT / "scripts/enrich-uploaded-csv.py"),
        str(source), str(enriched), "--intel-snapshot", str(snapshot), "--report", str(enrich_report),
    ], timings)
    run_stage("analysisSeconds", [
        sys.executable, str(ROOT / "scripts/analyze-csv-run-evidence.py"),
        str(enriched), str(analysis), str(analysis_summary), "--customer-bundle", str(bundle),
    ], timings)
    run_stage("admissionSeconds", [
        sys.executable, str(ROOT / "scripts/evaluate-rbvm-v2-method-candidates.py"),
        str(analysis), str(admission),
    ], timings)
    run_stage("prioritySeconds", [
        sys.executable, str(ROOT / "scripts/rank-rbvm-mvp-priority.py"),
        str(analysis), str(ranked), str(priority_report),
    ], timings)
    total_seconds = round(time.perf_counter() - total_started, 3)

    if row_count(source) != ROWS or row_count(enriched) != ROWS or row_count(analysis) != ROWS or row_count(ranked) != ROWS:
        raise RuntimeError("6000-row scale benchmark lost or duplicated rows")
    priority = json.loads(priority_report.read_text(encoding="utf-8"))
    if priority.get("methodId") != "RBVM_MVP_PRIORITY_POLICY_V1" or priority.get("methodSha256") != EXPECTED_METHOD_SHA:
        raise RuntimeError("scale benchmark priority method identity drift")
    if priority.get("rows") != ROWS or priority.get("rankedRows") != ROWS or priority.get("unrankableRows") != 0:
        raise RuntimeError("scale benchmark priority coverage drift")
    if priority.get("organizationalRiskComputed") is not False or priority.get("riskStatus") != "NON_COMPUTABLE":
        raise RuntimeError("scale benchmark must not claim Organizational Risk")

    rss_mib = round(peak_rss_mib(), 1)
    max_seconds = float(os.environ.get("RBVM_SCALE_MAX_SECONDS", "90"))
    max_rss_mib = float(os.environ.get("RBVM_SCALE_MAX_RSS_MIB", "768"))
    metrics = {
        "contractId": "RBVM_6000_ROW_SCALE_BENCHMARK_V1",
        "status": "PASS",
        "rows": ROWS,
        "assets": ASSETS,
        "uniqueCves": UNIQUE_CVES,
        "uniquePriorityVectors": unique_priority_vectors(analysis),
        "timings": {**timings, "totalSeconds": total_seconds},
        "peakChildRssMiB": rss_mib,
        "guardrails": {"maxSeconds": max_seconds, "maxRssMiB": max_rss_mib},
        "priority": {
            "rankedRows": priority["rankedRows"],
            "unrankableRows": priority["unrankableRows"],
            "frontCounts": priority["frontCounts"],
            "methodSha256": priority["methodSha256"],
            "organizationalRisk": priority["riskStatus"],
        },
    }
    if total_seconds > max_seconds:
        metrics["status"] = "FAIL_RUNTIME_GUARDRAIL"
    if rss_mib > max_rss_mib:
        metrics["status"] = "FAIL_MEMORY_GUARDRAIL"
    metrics_path = BUILD / "metrics.json"
    metrics_path.write_text(json.dumps(metrics, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(metrics, sort_keys=True))
    if metrics["status"] != "PASS":
        raise SystemExit(metrics["status"])


if __name__ == "__main__":
    main()
