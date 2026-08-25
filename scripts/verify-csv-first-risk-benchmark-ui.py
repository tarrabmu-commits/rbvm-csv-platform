#!/usr/bin/env python3
"""Verify the CSV-first risk benchmark UI remains server-backed and descriptive only."""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src/main/resources/web/csv-run-risk-benchmark-ui.js"
COMPILE = ROOT / "scripts/compile.sh"
RUNTIME = ROOT / "build/manual/main/web/rbvm-ui.js"
MODULE_MARKER = "const CONTRACT = 'CSV_FIRST_RISK_BENCHMARK_UI_V1';"

REQUIRED = [
    "CSV_FIRST_RISK_BENCHMARK_UI_V1",
    "CSV_FIRST_RISK_BENCHMARK_HTTP_V1",
    "CSV_FIRST_RISK_METHOD_BENCHMARK_V1",
    "CSV_FIRST_CONTEXTUAL_ANALYSIS_HTTP_V1",
    "/api/v1/csv-first-risk-benchmarks/",
    "Compare risk methods",
    "Risk Method Comparison",
    "spearmanRankCorrelation",
    "kendallTauB",
    "topOverlap",
    "rankPercentileGap",
    "commonComputedRows",
    "benchmarkExecutionSha256",
    "benchmarkReport",
    "sourceAnalysisSha256",
    "DESCRIPTIVE_COMPARISON_ONLY_NO_METHOD_SELECTION",
    "native",
    "analysisByRun.set(String(payload.runId), payload)",
    "payload.immutable === true",
    "previousFetch(path, {...options, cache: 'no-store'})",
]

FORBIDDEN = [
    "localStorage",
    "sessionStorage",
    "normalizedScore",
    "averageScore",
    "recommendedMethod",
    "selectedMethod",
    "winner",
    "Math.sqrt",
    "Math.pow",
    "0.3 *",
    "0.4 *",
    "EPSS_Probability",
    "KEV_Listed",
    "Asset_Criticality",
    "Internet_Facing",
]


def require(text: str, token: str, label: str) -> None:
    if token not in text:
        raise AssertionError(f"missing {label}: {token}")


def forbid(text: str, token: str, label: str) -> None:
    if token in text:
        raise AssertionError(f"forbidden {label}: {token}")


def extract_compiled_module(runtime: str) -> str:
    marker = runtime.find(MODULE_MARKER)
    if marker < 0:
        raise AssertionError("compiled risk benchmark UI marker is missing")
    start = runtime.rfind("(() => {", 0, marker)
    if start < 0:
        raise AssertionError("compiled risk benchmark UI IIFE start is missing")
    end_marker = "\n})();"
    end = runtime.find(end_marker, marker)
    if end < 0:
        raise AssertionError("compiled risk benchmark UI IIFE end is missing")
    end += len(end_marker)
    module = runtime[start:end]
    if module.count(MODULE_MARKER) != 1:
        raise AssertionError("compiled risk benchmark UI module marker is ambiguous")
    return module


def verify_ui(text: str, label: str) -> None:
    for token in REQUIRED:
        require(text, token, f"{label} benchmark UI contract")
    for token in FORBIDDEN:
        forbid(text, token, f"{label} client-side decision/scoring semantics")
    require(text, "{method: 'POST'}", f"{label} server-side benchmark materialization")
    require(text, "await api(execution.benchmarkReport)", f"{label} immutable report read")
    require(text, "execution.semantics !== EXECUTION_SEMANTICS", f"{label} descriptive execution semantics guard")
    require(text, "does not select a risk method", f"{label} no-selection wording")
    require(text, "does not select a risk method, average methods, normalize their native scales", f"{label} explicit descriptive semantics")
    require(text, "data-csv-risk-benchmark-ui", f"{label} dedicated comparison mount")
    require(text, "data-csv-risk-method-ui", f"{label} independent placement after risk selector")


def main() -> None:
    if not SOURCE.is_file():
        raise AssertionError("risk benchmark UI source is missing")
    if not RUNTIME.is_file():
        raise AssertionError("compiled runtime bundle is missing; run compile.sh first")

    source = SOURCE.read_text(encoding="utf-8")
    runtime = RUNTIME.read_text(encoding="utf-8")
    compiled_module = extract_compiled_module(runtime)
    compile_script = COMPILE.read_text(encoding="utf-8")

    verify_ui(source, "source")
    verify_ui(compiled_module, "compiled module")

    bundle_token = 'cat "$ROOT_DIR/src/main/resources/web/csv-run-risk-benchmark-ui.js" >> "$MAIN_CLASSES/web/rbvm-ui.js"'
    require(compile_script, bundle_token, "benchmark UI bundle step")
    risk_token = 'cat "$ROOT_DIR/src/main/resources/web/csv-run-risk-method-ui.js" >> "$MAIN_CLASSES/web/rbvm-ui.js"'
    activity_token = 'cat "$ROOT_DIR/src/main/resources/web/csv-run-activity.js" >> "$MAIN_CLASSES/web/rbvm-ui.js"'
    if compile_script.index(activity_token) >= compile_script.index(risk_token):
        raise AssertionError("run activity must load before the risk method UI")
    if compile_script.index(risk_token) >= compile_script.index(bundle_token):
        raise AssertionError("risk benchmark UI must load after risk method UI")

    if source.count("window.fetch = async") != 1:
        raise AssertionError("risk benchmark UI must have exactly one passive fetch observer")
    if "input.type = 'radio'" in source or "checked = true" in source:
        raise AssertionError("risk benchmark UI must not mutate selected risk method state")

    print("CSV-first risk benchmark UI verification: PASS")


if __name__ == "__main__":
    main()
