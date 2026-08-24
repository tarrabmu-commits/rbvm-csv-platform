#!/usr/bin/env python3
"""Run FULL_SCALABILITY_BENCHMARK_V1 with isolated local-lookup process metrics.

The base harness owns dataset generation, correctness checks, stage orchestration, summary
contracts, and stress progression. This entrypoint replaces only the synthetic seed/export stage:
fixture seeding remains setup, while a second Java process performs the exact V30 lookup/export.
This makes lookup wall/CPU/RSS measurements independent of synthetic fixture construction.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[1]
BASE_PATH = ROOT / "scripts/run-full-scalability-benchmark.py"
LOCAL_EXPORT_CLASS = "io.rbvm.postgres.PostgresFullScalabilityLocalExportProbe"


def load_base():
    spec = importlib.util.spec_from_file_location("rbvm_full_scalability_base", BASE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load base full-scalability benchmark")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


base = load_base()
_original_run_stage = base.run_stage


def isolated_run_stage(name, command, tier_dir, timeout, env=None):
    if name != "public-intelligence-seed-export":
        return _original_run_stage(name, command, tier_dir, timeout, env)

    if len(command) < 10 or command[5] != "seed-export":
        raise RuntimeError("unexpected public-intelligence seed command shape")

    input_csv = Path(command[6])
    measured_export_dir = Path(command[7])
    seed_metrics_path = Path(command[8])
    benchmark_id = command[9]
    classpath = command[3]
    warmup_export_dir = Path(tier_dir) / "synthetic-seed-warmup-export"
    probe_metrics_path = Path(tier_dir) / "postgres-local-export-probe.json"

    warmup_command = list(command)
    warmup_command[7] = str(warmup_export_dir)
    setup_process = _original_run_stage(
        "synthetic-public-intelligence-setup",
        warmup_command,
        tier_dir,
        timeout,
        env,
    )
    if setup_process.get("status") != "PASS":
        setup_process["measurementBoundary"] = "SYNTHETIC_SETUP_FAILED_BEFORE_LOCAL_LOOKUP_PROBE"
        return setup_process

    probe_command = [
        "java", "-ea", "-cp", classpath,
        LOCAL_EXPORT_CLASS,
        str(input_csv),
        str(measured_export_dir),
        str(probe_metrics_path),
    ]
    lookup_process = _original_run_stage(
        "isolated-local-lookup-export",
        probe_command,
        tier_dir,
        timeout,
        env,
    )
    if lookup_process.get("status") != "PASS":
        lookup_process["setupStatus"] = setup_process.get("status")
        lookup_process["setupWallSeconds"] = setup_process.get("wallSeconds")
        lookup_process["measurementBoundary"] = "ISOLATED_LOCAL_LOOKUP_EXPORT_PROCESS"
        return lookup_process

    seed_metrics = json.loads(seed_metrics_path.read_text(encoding="utf-8"))
    probe_metrics = json.loads(probe_metrics_path.read_text(encoding="utf-8"))
    cold_lookup_seconds = seed_metrics.get("localLookupExportSeconds")
    seed_metrics["coldSetupProcessLookupExportSeconds"] = cold_lookup_seconds
    seed_metrics["localLookupExportSeconds"] = probe_metrics["localLookupExportSeconds"]
    seed_metrics["localLookupCvesPerSecond"] = probe_metrics["localLookupCvesPerSecond"]
    seed_metrics["dbLookupExportDelta"] = probe_metrics["dbLookupExportDelta"]
    seed_metrics["exportBytes"] = probe_metrics["exportBytes"]
    seed_metrics["lookupMeasurementContractId"] = probe_metrics["contractId"]
    seed_metrics["lookupMeasurementProcess"] = "ISOLATED_LOCAL_EXPORT_PROBE"
    seed_metrics_path.write_text(
        json.dumps(seed_metrics, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    shutil.rmtree(warmup_export_dir, ignore_errors=True)
    lookup_process["setupStatus"] = setup_process.get("status")
    lookup_process["setupWallSeconds"] = setup_process.get("wallSeconds")
    lookup_process["setupPeakRssMiB"] = setup_process.get("peakRssMiB")
    lookup_process["coldSetupProcessLookupExportSeconds"] = cold_lookup_seconds
    lookup_process["measurementBoundary"] = "ISOLATED_LOCAL_LOOKUP_EXPORT_PROCESS"
    lookup_process["benchmarkId"] = benchmark_id
    return lookup_process


base.run_stage = isolated_run_stage

if __name__ == "__main__":
    base.main()
