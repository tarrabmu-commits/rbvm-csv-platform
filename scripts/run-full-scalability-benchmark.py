#!/usr/bin/env python3
"""Run the PostgreSQL-backed CSV-first RBVM scalability/capacity benchmark.

The standard progression is 1K -> 5K -> 10K -> 25K -> 50K -> 100K Findings.
10K is a regression checkpoint, not a platform limit. With --stress, sizes double
past the largest requested tier until a measured bottleneck/failure is observed or
an explicit run-safety ceiling is reached. Reaching the safety ceiling is reported
as CAPACITY_NOT_REACHED, never as platform capacity.

Synthetic public-intelligence setup is measured separately from the upload hot path.
The benchmark bridge refuses non-local PostgreSQL targets.
"""

from __future__ import annotations

import argparse
import csv
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SIZES = (1_000, 5_000, 10_000, 25_000, 50_000, 100_000)
EXPECTED_METHOD_SHA = "88d5cdb8702c6c0ed2c033c3df6b8abbe1aa392f44f4507685b54082a16dc388"
BRIDGE_CLASS = "io.rbvm.postgres.PostgresFullScalabilityBenchmarkBridge"


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--sizes",
        default=",".join(str(value) for value in DEFAULT_SIZES),
        help="comma-separated Finding counts; default: 1000,5000,10000,25000,50000,100000",
    )
    parser.add_argument(
        "--unique-cve-ratio",
        type=float,
        default=0.05,
        help="unique CVEs / Findings. Standard profile is 0.05; use 1.0 for lookup worst-case",
    )
    parser.add_argument("--stress", action="store_true", help="double tiers beyond the largest requested size")
    parser.add_argument(
        "--stress-max-rows",
        type=int,
        default=1_600_000,
        help="run-safety ceiling only; reaching it does not establish platform capacity",
    )
    parser.add_argument(
        "--tier-timeout-seconds",
        type=int,
        default=1800,
        help="timeout for each individual subprocess stage; timeout is recorded as a measured bottleneck",
    )
    parser.add_argument(
        "--output-directory",
        type=Path,
        default=ROOT / "build/full-scalability",
    )
    parser.add_argument(
        "--classpath",
        default=None,
        help="Java classpath. Defaults to build/manual/main:build/manual/test:$RBVM_POSTGRES_DRIVER_JAR",
    )
    parser.add_argument(
        "--keep-database-between-tiers",
        action="store_true",
        help="do not reset the local benchmark schema between tiers; standard runs isolate tiers",
    )
    return parser.parse_args()


def parse_sizes(value):
    result = []
    for token in value.split(","):
        token = token.strip().replace("_", "")
        if not token:
            continue
        parsed = int(token)
        if parsed <= 0:
            raise ValueError("benchmark sizes must be positive")
        result.append(parsed)
    result = sorted(set(result))
    if not result:
        raise ValueError("at least one benchmark size is required")
    return result


def benchmark_sizes(base, stress, safety):
    values = list(base)
    if not stress:
        return values
    current = values[-1]
    while current < safety:
        next_value = current * 2
        if next_value > safety:
            next_value = safety
        if next_value == current:
            break
        values.append(next_value)
        current = next_value
    return values


def java_classpath(args):
    if args.classpath:
        return args.classpath
    driver = os.environ.get("RBVM_POSTGRES_DRIVER_JAR", "").strip()
    if not driver:
        raise RuntimeError("RBVM_POSTGRES_DRIVER_JAR is required unless --classpath is supplied")
    return os.pathsep.join([
        str(ROOT / "build/manual/main"),
        str(ROOT / "build/manual/test"),
        driver,
    ])


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_input(path, rows, assets, unique_cves, tier_index):
    cve_base = 10_000_000 + tier_index * 2_000_000
    cves = [f"CVE-2088-{cve_base + index}" for index in range(unique_cves)]
    start = datetime(2089, 1, 1, tzinfo=timezone.utc)
    headers = [
        "Agent", "Agent_ID", "CVE_ID", "Severity", "CVE_Description",
        "Affected_Product", "References", "OS_name", "Detected_At",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=headers)
        writer.writeheader()
        for index in range(rows):
            asset = index % assets
            occurrence = index // assets
            cve_index = (asset * 37 + occurrence * 13) % unique_cves
            cve = cves[cve_index]
            writer.writerow({
                "Agent": f"host-{asset:06d}",
                "Agent_ID": f"asset-{asset:06d}",
                "CVE_ID": cve,
                "Severity": ("Critical", "High", "Medium", "Low")[cve_index % 4],
                "CVE_Description": f"Deterministic capacity finding for {cve}",
                "Affected_Product": f"product-{cve_index % max(25, min(unique_cves, 1000)):04d}",
                "References": f"https://benchmark.invalid/{cve}",
                "OS_name": "Linux",
                "Detected_At": (start + timedelta(seconds=index)).isoformat().replace("+00:00", "Z"),
            })
    return cves


def write_customer_bundle(path, assets, source_name):
    criticalities = ("LOW", "MODERATE", "HIGH", "MISSION_CRITICAL")
    requirements = (("X", "X", "X"), ("L", "L", "L"), ("M", "M", "M"), ("H", "H", "H"))
    values = []
    for index in range(assets):
        cr, ir, ar = requirements[index % len(requirements)]
        values.append({
            "customerAssetKey": f"asset-{index:06d}",
            "displayName": f"host-{index:06d}",
            "assetCriticality": criticalities[index % len(criticalities)],
            "internetFacing": "YES" if index % 3 == 0 else "NO",
            "cvssConfidentialityRequirement": cr,
            "cvssIntegrityRequirement": ir,
            "cvssAvailabilityRequirement": ar,
        })
    payload = {
        "contractId": "RBVM_CUSTOMER_ASSET_BUNDLE_V3",
        "schemaVersion": 3,
        "createdAt": "2090-01-01T00:00:00Z",
        "sourceFileName": source_name,
        "assets": values,
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def parse_time_v(path):
    if not path.is_file():
        return {}
    mapping = {
        "User time (seconds)": "userCpuSeconds",
        "System time (seconds)": "systemCpuSeconds",
        "Percent of CPU this job got": "cpuPercentText",
        "Elapsed (wall clock) time (h:mm:ss or m:ss)": "elapsedText",
        "Maximum resident set size (kbytes)": "peakRssKiB",
        "Major (requiring I/O) page faults": "majorPageFaults",
        "Minor (reclaiming a frame) page faults": "minorPageFaults",
        "Voluntary context switches": "voluntaryContextSwitches",
        "Involuntary context switches": "involuntaryContextSwitches",
        "File system inputs": "fileSystemInputs",
        "File system outputs": "fileSystemOutputs",
    }
    result = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip()
        for prefix, key in mapping.items():
            marker = prefix + ":"
            if stripped.startswith(marker):
                value = stripped[len(marker):].strip()
                if key in {"userCpuSeconds", "systemCpuSeconds"}:
                    result[key] = float(value)
                elif key in {
                    "peakRssKiB", "majorPageFaults", "minorPageFaults",
                    "voluntaryContextSwitches", "involuntaryContextSwitches",
                    "fileSystemInputs", "fileSystemOutputs",
                }:
                    result[key] = int(value)
                else:
                    result[key] = value
                break
    if "peakRssKiB" in result:
        result["peakRssMiB"] = round(result["peakRssKiB"] / 1024.0, 2)
    return result


def run_stage(name, command, tier_dir, timeout, env=None):
    time_file = tier_dir / f"time-{name}.txt"
    stdout_file = tier_dir / f"stdout-{name}.log"
    stderr_file = tier_dir / f"stderr-{name}.log"
    timer = Path("/usr/bin/time")
    wrapped = [str(timer), "-v", "-o", str(time_file), *command] if timer.is_file() else command
    started = time.perf_counter()
    try:
        with stdout_file.open("w", encoding="utf-8") as stdout, stderr_file.open("w", encoding="utf-8") as stderr:
            completed = subprocess.run(
                wrapped,
                cwd=ROOT,
                env=env,
                stdout=stdout,
                stderr=stderr,
                text=True,
                timeout=timeout,
                check=False,
            )
        wall = time.perf_counter() - started
        stderr_tail = tail(stderr_file) if completed.returncode != 0 else ""
status = "PASS"
if completed.returncode != 0:
    resource_failure = completed.returncode in {137, -9}
    marker = "SQLState="
    if marker in stderr_tail:
        sqlstate = stderr_tail.split(marker, 1)[1][:5]
        resource_failure = resource_failure or sqlstate.startswith("53")
    status = "RESOURCE_EXHAUSTION" if resource_failure else "FAILED"
metrics = {
    "status": status,
            "returnCode": completed.returncode,
            "wallSeconds": round(wall, 3),
            **parse_time_v(time_file),
        }
        if stderr_tail:
            metrics["stderrTail"] = stderr_tail
        return metrics
    except subprocess.TimeoutExpired:
        wall = time.perf_counter() - started
        return {
            "status": "TIMEOUT",
            "wallSeconds": round(wall, 3),
            "timeoutSeconds": timeout,
            "stderrTail": tail(stderr_file),
        }


def tail(path, lines=30):
    if not path.is_file():
        return ""
    return "\n".join(path.read_text(encoding="utf-8", errors="replace").splitlines()[-lines:])


def load_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def row_count(path):
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return sum(1 for _ in csv.DictReader(handle))


def directory_sizes(tier_dir):
    output = {}
    for path in sorted(tier_dir.rglob("*")):
        if path.is_file():
            output[str(path.relative_to(tier_dir))] = path.stat().st_size
    return output


def system_identity():
    def command(*args):
        try:
            return subprocess.check_output(args, cwd=ROOT, text=True, stderr=subprocess.DEVNULL).strip()
        except Exception:
            return None

    memory_mib = None
    meminfo = Path("/proc/meminfo")
    if meminfo.is_file():
        for line in meminfo.read_text(encoding="utf-8").splitlines():
            if line.startswith("MemTotal:"):
                memory_mib = round(int(line.split()[1]) / 1024.0, 1)
                break
    return {
        "gitCommit": command("git", "rev-parse", "HEAD"),
        "python": sys.version.split()[0],
        "java": command("java", "-version"),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "cpuCount": os.cpu_count(),
        "memoryMiB": memory_mib,
        "postgresJdbcUrlSanitized": sanitize_jdbc(os.environ.get("RBVM_JDBC_URL")),
    }


def sanitize_jdbc(value):
    if not value:
        return None
    return value.split("?", 1)[0]


def bridge_command(classpath, *args):
    return ["java", "-ea", "-cp", classpath, BRIDGE_CLASS, *map(str, args)]


def stage_failed(stages):
    for name, metrics in stages.items():
        if metrics.get("status") != "PASS":
            return name, metrics.get("status")
    return None


def run_tier(args, classpath, rows, tier_index, identity):
    tier_dir = args.output_directory / f"rows-{rows:09d}"
    if tier_dir.exists():
        shutil.rmtree(tier_dir)
    tier_dir.mkdir(parents=True)

    unique_cves = max(1, min(rows, int(round(rows * args.unique_cve_ratio))))
    assets = max(10, min(rows, max(10, rows // 100)))
    benchmark_id = f"rows-{rows}-cves-{unique_cves}-tier-{tier_index}"

    input_csv = tier_dir / "input.csv"
    bundle = tier_dir / "customer-bundle.json"
    export_dir = tier_dir / "local-public-intelligence"
    snapshot = tier_dir / "public-intel.json"
    snapshot_report = tier_dir / "snapshot-report.json"
    enriched = tier_dir / "enriched.csv"
    enrichment_report = tier_dir / "enrichment-report.json"
    analysis = tier_dir / "analysis.csv"
    analysis_summary = tier_dir / "analysis-summary.json"
    admission = tier_dir / "method-admission.json"
    manifest = tier_dir / "canonical-finding-manifest.csv"
    priority = tier_dir / "priority.csv"
    priority_report = tier_dir / "priority-report.json"
    reset_metrics = tier_dir / "postgres-reset.json"
    seed_metrics = tier_dir / "postgres-seed-export.json"
    projection_metrics = tier_dir / "postgres-project-manifest.json"
    priority_db_metrics = tier_dir / "postgres-priority-read.json"

    write_input(input_csv, rows, assets, unique_cves, tier_index)
    write_customer_bundle(bundle, assets, input_csv.name)

    env = dict(os.environ)
    env["RBVM_SCALABILITY_BENCHMARK_MODE"] = "true"

    stages = {}
    if not args.keep_database_between_tiers:
        stages["postgresReset"] = run_stage(
            "postgres-reset",
            bridge_command(classpath, "reset-schema", reset_metrics),
            tier_dir,
            args.tier_timeout_seconds,
            env,
        )
        failure = stage_failed(stages)
        if failure:
            return failure_result(rows, unique_cves, assets, benchmark_id, identity, stages, tier_dir, failure)

    stages["publicIntelligenceSeedExport"] = run_stage(
        "public-intelligence-seed-export",
        bridge_command(classpath, "seed-export", input_csv, export_dir, seed_metrics, benchmark_id),
        tier_dir,
        args.tier_timeout_seconds,
        env,
    )
    failure = stage_failed(stages)
    if failure:
        return failure_result(rows, unique_cves, assets, benchmark_id, identity, stages, tier_dir, failure)

    stages["localSnapshot"] = run_stage(
        "local-snapshot",
        [
            sys.executable,
            str(ROOT / "scripts/build-local-public-intelligence-snapshot.py"),
            str(export_dir),
            str(snapshot),
            "--report", str(snapshot_report),
            "--observed-at", "2090-01-01T01:00:00Z",
        ],
        tier_dir,
        args.tier_timeout_seconds,
        env,
    )
    stages["enrichment"] = run_stage(
        "enrichment",
        [
            sys.executable,
            str(ROOT / "scripts/enrich-uploaded-csv-local.py"),
            str(input_csv),
            str(enriched),
            "--intel-snapshot", str(snapshot),
            "--report", str(enrichment_report),
        ],
        tier_dir,
        args.tier_timeout_seconds,
        env,
    )
    stages["contextualAnalysis"] = run_stage(
        "contextual-analysis",
        [
            sys.executable,
            str(ROOT / "scripts/analyze-csv-run-evidence.py"),
            str(enriched),
            str(analysis),
            str(analysis_summary),
            "--customer-bundle", str(bundle),
        ],
        tier_dir,
        args.tier_timeout_seconds,
        env,
    )
    stages["methodAdmission"] = run_stage(
        "method-admission",
        [
            sys.executable,
            str(ROOT / "scripts/evaluate-rbvm-v2-method-candidates.py"),
            str(analysis),
            str(admission),
        ],
        tier_dir,
        args.tier_timeout_seconds,
        env,
    )
    failure = stage_failed(stages)
    if failure:
        return failure_result(rows, unique_cves, assets, benchmark_id, identity, stages, tier_dir, failure)

    source_profile = f"full-scalability-{rows}-{tier_index}"
    stages["canonicalProjectionManifest"] = run_stage(
        "canonical-projection-manifest",
        bridge_command(
            classpath,
            "project-manifest",
            input_csv,
            manifest,
            projection_metrics,
            source_profile,
            benchmark_id,
        ),
        tier_dir,
        args.tier_timeout_seconds,
        env,
    )
    stages["mvpPriority"] = run_stage(
        "mvp-priority",
        [
            sys.executable,
            str(ROOT / "scripts/rank-rbvm-mvp-priority.py"),
            str(analysis),
            str(priority),
            str(priority_report),
        ],
        tier_dir,
        args.tier_timeout_seconds,
        env,
    )
    failure = stage_failed(stages)
    if failure:
        return failure_result(rows, unique_cves, assets, benchmark_id, identity, stages, tier_dir, failure)

    projection = load_json(projection_metrics)
    stages["canonicalPriorityPersistenceRead"] = run_stage(
        "canonical-priority-persistence-read",
        bridge_command(
            classpath,
            "priority-read",
            priority,
            projection["importId"],
            projection["sourceCsvSha256"],
            priority_db_metrics,
            benchmark_id,
        ),
        tier_dir,
        args.tier_timeout_seconds,
        env,
    )
    failure = stage_failed(stages)
    if failure:
        return failure_result(rows, unique_cves, assets, benchmark_id, identity, stages, tier_dir, failure)

    validate_artifacts(rows, input_csv, enriched, analysis, priority, priority_report)
    seed = load_json(seed_metrics)
    priority_db = load_json(priority_db_metrics)
    hot_path_stage_names = [
        "publicIntelligenceSeedExport",
        "localSnapshot",
        "enrichment",
        "contextualAnalysis",
        "methodAdmission",
        "canonicalProjectionManifest",
        "mvpPriority",
        "canonicalPriorityPersistenceRead",
    ]
    # Synthetic DB seeding is setup, not upload-hot-path work. Remove its setupSeedSeconds and use
    # only localLookupExportSeconds for the actual product acquisition path.
    hot_path_seconds = seed["localLookupExportSeconds"]
    for name in hot_path_stage_names[1:]:
        hot_path_seconds += stages[name]["wallSeconds"]

    peak_rss = max(
        (metrics.get("peakRssMiB", 0) or 0) for metrics in stages.values()
    )
    result = {
        "contractId": "RBVM_FULL_SCALABILITY_TIER_RESULT_V1",
        "status": "PASS",
        "benchmarkId": benchmark_id,
        "rows": rows,
        "assets": assets,
        "uniqueCves": unique_cves,
        "uniqueCveRatio": round(unique_cves / rows, 6),
        "system": identity,
        "stages": stages,
        "setup": {
            "syntheticPublicIntelligenceSeedSeconds": seed["setupSeedSeconds"],
            "seedRecords": seed["seedRecords"],
        },
        "hotPath": {
            "totalSeconds": round(hot_path_seconds, 3),
            "rowsPerSecond": round(rows / hot_path_seconds, 2) if hot_path_seconds else None,
            "localLookupExportSeconds": seed["localLookupExportSeconds"],
            "localLookupCvesPerSecond": seed["localLookupCvesPerSecond"],
            "peakProcessRssMiB": round(peak_rss, 2),
        },
        "postgres": {
            "seedDelta": seed["dbSeedDelta"],
            "lookupExportDelta": seed["dbLookupExportDelta"],
            "projectionDelta": projection["dbProjectionDelta"],
            "manifestAndReadDelta": projection["dbManifestAndReadDelta"],
            "priorityMaterializeDelta": priority_db["dbPriorityMaterializeDelta"],
            "priorityReadDelta": priority_db["dbPriorityReadDelta"],
        },
        "canonical": {
            "manifestRows": projection["manifestRows"],
            "canonicalFindings": priority_db["canonicalFindings"],
            "priorityMappedSourceRows": priority_db["sourceRows"],
            "prioritySampleReadCount": priority_db["prioritySampleReadCount"],
        },
        "artifacts": directory_sizes(tier_dir),
    }
    write_json(tier_dir / "tier-result.json", result)
    return result


def validate_artifacts(rows, input_csv, enriched, analysis, priority, priority_report):
    counts = {
        "input": row_count(input_csv),
        "enriched": row_count(enriched),
        "analysis": row_count(analysis),
        "priority": row_count(priority),
    }
    if any(value != rows for value in counts.values()):
        raise RuntimeError(f"benchmark row-count drift: expected={rows} actual={counts}")
    report = load_json(priority_report)
    if report.get("methodId") != "RBVM_MVP_PRIORITY_POLICY_V1":
        raise RuntimeError("benchmark priority method identity drift")
    if report.get("methodSha256") != EXPECTED_METHOD_SHA:
        raise RuntimeError("benchmark priority method SHA drift")
    if report.get("rows") != rows or report.get("rankedRows") != rows or report.get("unrankableRows") != 0:
        raise RuntimeError("benchmark priority coverage drift")
    if report.get("organizationalRiskComputed") is not False or report.get("riskStatus") != "NON_COMPUTABLE":
        raise RuntimeError("benchmark must not fabricate Organizational Risk")


def failure_result(rows, unique_cves, assets, benchmark_id, identity, stages, tier_dir, failure):
    stage, failure_type = failure
    result = {
        "contractId": "RBVM_FULL_SCALABILITY_TIER_RESULT_V1",
        "status": "BOTTLENECK_OR_FAILURE",
        "benchmarkId": benchmark_id,
        "rows": rows,
        "assets": assets,
        "uniqueCves": unique_cves,
        "uniqueCveRatio": round(unique_cves / rows, 6),
        "system": identity,
        "failure": {"stage": stage, "type": failure_type},
        "stages": stages,
        "artifacts": directory_sizes(tier_dir),
    }
    write_json(tier_dir / "tier-result.json", result)
    return result


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_summary_csv(path, tiers):
    fields = [
        "rows", "uniqueCves", "status", "hotPathSeconds", "rowsPerSecond",
        "localLookupSeconds", "localLookupCvesPerSecond", "peakProcessRssMiB",
        "failureStage", "failureType",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for tier in tiers:
            hot = tier.get("hotPath", {})
            failure = tier.get("failure", {})
            writer.writerow({
                "rows": tier["rows"],
                "uniqueCves": tier["uniqueCves"],
                "status": tier["status"],
                "hotPathSeconds": hot.get("totalSeconds"),
                "rowsPerSecond": hot.get("rowsPerSecond"),
                "localLookupSeconds": hot.get("localLookupExportSeconds"),
                "localLookupCvesPerSecond": hot.get("localLookupCvesPerSecond"),
                "peakProcessRssMiB": hot.get("peakProcessRssMiB"),
                "failureStage": failure.get("stage"),
                "failureType": failure.get("type"),
            })


def main():
    args = arguments()
    if not 0 < args.unique_cve_ratio <= 1:
        raise SystemExit("--unique-cve-ratio must be in (0, 1]")
    base_sizes = parse_sizes(args.sizes)
    if args.stress_max_rows < base_sizes[-1]:
        raise SystemExit("--stress-max-rows cannot be below the largest requested size")
    sizes = benchmark_sizes(base_sizes, args.stress, args.stress_max_rows)
    classpath = java_classpath(args)
    identity = system_identity()

    if args.output_directory.exists():
        shutil.rmtree(args.output_directory)
    args.output_directory.mkdir(parents=True)
    tiers = []
    capacity_status = "STANDARD_PROGRESSION_COMPLETE"
    measured_bottleneck = None

    for tier_index, rows in enumerate(sizes):
        print(f"[rbvm-scalability] rows={rows} uniqueCveRatio={args.unique_cve_ratio:.4f}", flush=True)
        tier = run_tier(args, classpath, rows, tier_index, identity)
        tiers.append(tier)
        if tier["status"] != "PASS":
            measured_bottleneck = {
                "rows": rows,
                "stage": tier.get("failure", {}).get("stage"),
                "type": tier.get("failure", {}).get("type"),
            }
            capacity_status = "MEASURED_BOTTLENECK_OR_FAILURE"
            break

    if args.stress and measured_bottleneck is None:
        if tiers and tiers[-1]["rows"] >= args.stress_max_rows:
            capacity_status = "CAPACITY_NOT_REACHED_AT_RUN_SAFETY_CEILING"
        else:
            capacity_status = "CAPACITY_NOT_REACHED"

    summary = {
        "contractId": "RBVM_FULL_SCALABILITY_BENCHMARK_V1",
        "status": "PASS" if measured_bottleneck is None else "BOTTLENECK_OR_FAILURE_OBSERVED",
        "capacityStatus": capacity_status,
        "standardCheckpoints": list(DEFAULT_SIZES),
        "tenThousandIsPlatformLimit": False,
        "sizesRequested": base_sizes,
        "sizesExecuted": [tier["rows"] for tier in tiers],
        "stress": args.stress,
        "stressSafetyCeilingRows": args.stress_max_rows if args.stress else None,
        "uniqueCveRatio": args.unique_cve_ratio,
        "system": identity,
        "measuredBottleneck": measured_bottleneck,
        "tiers": tiers,
    }
    write_json(args.output_directory / "summary.json", summary)
    write_summary_csv(args.output_directory / "summary.csv", tiers)
    print(json.dumps({
        "contractId": summary["contractId"],
        "status": summary["status"],
        "capacityStatus": summary["capacityStatus"],
        "sizesExecuted": summary["sizesExecuted"],
        "measuredBottleneck": measured_bottleneck,
    }, sort_keys=True))

    # A non-timeout subprocess failure is a correctness regression, not a valid capacity result.
    if measured_bottleneck and measured_bottleneck.get("type") == "FAILED":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
