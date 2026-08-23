#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HANDLER = (ROOT / "src/main/java/io/rbvm/csv/CsvFirstCanonicalEvidenceHttpHandler.java").read_text(encoding="utf-8")
LAUNCHER = (ROOT / "src/main/java/io/rbvm/csv/RbvmPlatformMain.java").read_text(encoding="utf-8")
UI = (ROOT / "src/main/resources/web/csv-canonical-handoff.js").read_text(encoding="utf-8")

for token in [
    "CSV_FIRST_CANONICAL_PUBLIC_EVIDENCE_HTTP_V1",
    "/api/v1/csv-first-canonical-evidence/",
    "ApiRole.OPERATOR",
    'run.resolve("input.csv")',
    'fetch-first-epss-snapshot.py',
    'build-first-epss-csv.py',
    'fetch-cisa-kev-snapshot.py',
    'build-cisa-kev-csv.py',
    "EpssImporter",
    "CisaKevImporter",
    "importFile(epssCsv)",
    "importFile(kevCsv)",
    'resolve("canonical-evidence")',
    "UUID evidenceId = UUID.randomUUID()",
    'cvssV4ToV31Conversion", false',
    'organizationalRisk", "NON_COMPUTABLE"',
    "ProcessBuilder",
]:
    if token not in HANDLER:
        raise AssertionError(f"Canonical public evidence handler missing {token}")

for forbidden in [
    "sessionStorage", "localStorage", "Runtime.getRuntime().exec", "/bin/sh", "cmd.exe",
    "EPSS_Probability *", "CVSS4_Base_Score *", "riskScore", "priorityScore",
]:
    if forbidden in HANDLER:
        raise AssertionError(f"Canonical public evidence handler contains forbidden behavior {forbidden}")

for token in [
    '"/api/v1/csv-first-canonical-evidence"',
    "new CsvFirstCanonicalEvidenceHttpHandler",
    "runtime.epssImporter()",
    "runtime.cisaKevImporter()",
]:
    if token not in LAUNCHER:
        raise AssertionError(f"Launcher missing canonical evidence registration {token}")

for token in [
    "CSV_FIRST_CANONICAL_PUBLIC_EVIDENCE_HTTP_V1",
    "Persist canonical EPSS + KEV",
    "/api/v1/csv-first-canonical-evidence/",
    "FIRST daily bulk feed",
    "exact source SHA",
    "not relabeled",
    "Decision Input readiness",
    "EXPLICIT ASSESSMENT REQUIRED",
    "CUSTOMER-CONFIRMED LINK REQUIRED",
    "RBVM V2 primary method",
    "NOT ADMITTED",
    "Internet Facing is not treated as exact reachability or MAV",
    "Asset Criticality is not converted to CR/IR/AR",
    "No applicability state is inferred",
]:
    if token not in UI:
        raise AssertionError(f"Canonical handoff UI missing {token}")

for forbidden in [
    "autoApplicability", "AUTO_APPLICABILITY", "AUTO_LINK", "INFERRED_LINK",
    "EPSS_Probability *", "CVSS4_Base_Score *", "riskScore", "priorityScore",
    "localStorage", "sessionStorage",
]:
    if forbidden in UI:
        raise AssertionError(f"Canonical handoff UI contains forbidden behavior {forbidden}")

print("CSV-first canonical public evidence + Decision Input readiness checks: PASS")
