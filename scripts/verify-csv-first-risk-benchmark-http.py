#!/usr/bin/env python3
"""Structural verification for immutable CSV-first risk benchmark HTTP transport."""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HANDLER = ROOT / "src/main/java/io/rbvm/csv/CsvFirstRiskBenchmarkHttpHandler.java"
LAUNCHER = ROOT / "src/main/java/io/rbvm/csv/RbvmPlatformMain.java"
BENCHMARK = ROOT / "scripts/benchmark-csv-first-risk-methods.py"
EVALUATOR = ROOT / "scripts/evaluate-csv-first-risk.py"
ACTIVE = ROOT / "docs/fixtures/csv-first-risk-methods-active"

EXPECTED_FIXTURES = {
    "BRINQA_STYLE_CSV_V1.json",
    "JUPITERONE_STYLE_CSV_V2.json",
    "RBVM_CSV_BOUNDED_RISK_V3.json",
    "SERVICENOW_STYLE_CSV_V1.json",
}


def require(text: str, token: str, label: str) -> None:
    if token not in text:
        raise AssertionError(f"missing {label}: {token}")


def forbid(text: str, token: str, label: str) -> None:
    if token in text:
        raise AssertionError(f"forbidden {label}: {token}")


def main() -> None:
    handler = HANDLER.read_text(encoding="utf-8")
    launcher = LAUNCHER.read_text(encoding="utf-8")
    benchmark = BENCHMARK.read_text(encoding="utf-8")

    require(handler, 'public static final String ROOT = "/api/v1/csv-first-risk-benchmarks"', "benchmark route")
    require(handler, 'CSV_FIRST_RISK_BENCHMARK_HTTP_V1', "HTTP contract")
    require(handler, 'ApiRole.OPERATOR', "operator materialization authorization")
    require(handler, 'ApiRole.VIEWER', "viewer artifact authorization")
    require(handler, '"POST".equals(verb)', "POST-only materialization")
    require(handler, '"GET".equals(verb)', "GET report artifact")
    require(handler, 'sourceAnalysisSha256', "exact source analysis binding")
    require(handler, 'benchmarkExecutionSha256', "benchmark execution identity")
    require(handler, 'sha256File(benchmarkScript)', "benchmark script identity binding")
    require(handler, 'sha256File(evaluatorScript)', "risk evaluator identity binding")
    require(handler, 'StandardCopyOption.ATOMIC_MOVE', "atomic publication")
    require(handler, 'RISK_BENCHMARK_ARTIFACT_CONFLICT', "incomplete target fail-closed behavior")
    require(handler, 'ATOMIC_RISK_BENCHMARK_PUBLICATION_UNAVAILABLE', "atomic filesystem fail-closed behavior")
    require(handler, 'builder.environment().clear()', "restricted subprocess environment")
    require(handler, 'DESCRIPTIVE_COMPARISON_ONLY_NO_METHOD_SELECTION', "non-decision semantics")
    require(handler, 'risk-benchmarks', "append-only benchmark artifact namespace")

    for name in sorted(EXPECTED_FIXTURES):
        require(handler, f'"{name}"', f"active fixture pin {name}")
    actual = {path.name for path in ACTIVE.glob("*.json") if path.is_file() and not path.is_symlink()}
    if actual != EXPECTED_FIXTURES:
        raise AssertionError(f"active risk fixture drift: {sorted(actual)}")

    require(launcher, 'server.createContext(\n                CsvFirstRiskBenchmarkHttpHandler.ROOT,', "launcher route registration")
    require(launcher, 'new CsvFirstRiskBenchmarkHttpHandler(dataDirectory, authenticator)', "launcher handler construction")
    require(launcher, 'CSV-first risk benchmark API:', "launcher startup visibility")

    require(benchmark, 'CSV_FIRST_RISK_METHOD_BENCHMARK_V1', "benchmark payload contract")
    require(benchmark, 'INTERSECTION_OF_ROWS_COMPUTABLE_BY_BOTH_METHODS', "pairwise comparison population")
    require(benchmark, 'PRESERVED_NOT_NORMALIZED_ACROSS_METHODS', "native scale preservation")
    forbid(handler, 'localStorage', "browser persistence")
    forbid(handler, 'sessionStorage', "browser persistence")
    forbid(handler, 'normalizedScore', "cross-method normalized score")
    forbid(handler, 'winner', "automatic benchmark winner")

    if not EVALUATOR.is_file():
        raise AssertionError("risk evaluator script is missing")

    print("CSV-first risk benchmark HTTP verification: PASS")


if __name__ == "__main__":
    main()
