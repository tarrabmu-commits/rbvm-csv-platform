#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HANDLER = (ROOT / "src/main/java/io/rbvm/csv/CsvFirstMvpPriorityHttpHandler.java").read_text(encoding="utf-8")
LAUNCHER = (ROOT / "src/main/java/io/rbvm/csv/RbvmPlatformMain.java").read_text(encoding="utf-8")
POLICY = (ROOT / "scripts/rank-rbvm-mvp-priority.py").read_text(encoding="utf-8")

SHA = "88d5cdb8702c6c0ed2c033c3df6b8abbe1aa392f44f4507685b54082a16dc388"

required = [
    "CSV_FIRST_MVP_PRIORITY_HTTP_V1",
    "RBVM_MVP_PRIORITY_POLICY_V1",
    SHA,
    "/api/v1/csv-first-priorities",
    "scripts/rank-rbvm-mvp-priority.py",
    "analysis.csv",
    "priority.csv",
    "priority-report.json",
    "RELATIVE_TREATMENT_PRIORITY_PARETO_FRONT_WITHIN_INPUT_SET",
    "RBVM_POLICY",
    "sourceAnalysisImmutable",
    "derivedArtifactsImmutable",
    "organizationalRisk",
    "NON_COMPUTABLE",
    "StandardCopyOption.ATOMIC_MOVE",
    "AtomicMoveNotSupportedException",
    "PRIORITY_ARTIFACT_CONFLICT",
    "ApiRole.OPERATOR",
    "ApiRole.VIEWER",
    "Files.isSymbolicLink(source)",
    "Files.isSymbolicLink(priorityScript)",
    "replayed",
]
for token in required:
    if token not in HANDLER:
        raise AssertionError(f"CSV-first MVP priority handler missing {token}")

for forbidden in [
    "REPLACE_EXISTING",
    "CVSS4_Base_Score *",
    "EPSS_Probability *",
    "riskScore",
    "priorityScore",
    "Critical",
    "High risk",
    "bash -c",
    "sh -c",
    "Runtime.getRuntime().exec",
]:
    if forbidden in HANDLER:
        raise AssertionError(f"CSV-first MVP priority handler contains forbidden mutation/scoring/execution logic: {forbidden}")

if 'new CsvFirstMvpPriorityHttpHandler(dataDirectory, authenticator)' not in LAUNCHER:
    raise AssertionError("MVP priority handler is not registered by the product launcher")
if '"/api/v1/csv-first-priorities"' not in LAUNCHER:
    raise AssertionError("MVP priority API context is missing from the product launcher")
if SHA not in POLICY or 'EXPECTED_METHOD_SHA256' not in POLICY:
    raise AssertionError("HTTP boundary is not bound to the pinned priority-policy implementation SHA")
if 'weights": []' not in POLICY or 'thresholds": []' not in POLICY:
    raise AssertionError("MVP priority policy must remain weight-free and threshold-free")
if 'Files.move(staging, target, StandardCopyOption.ATOMIC_MOVE)' not in HANDLER:
    raise AssertionError("derived priority artifacts must publish as one atomic directory revision")
if 'deleteTree(staging);' not in HANDLER:
    raise AssertionError("failed/racing priority staging artifacts must be cleaned")

print("CSV-first MVP priority HTTP structural checks: PASS")
