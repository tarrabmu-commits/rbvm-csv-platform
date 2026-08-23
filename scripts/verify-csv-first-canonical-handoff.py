#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src/main/java/io/rbvm/csv/CsvFirstSourceHttpHandler.java").read_text(encoding="utf-8")
LAUNCHER = (ROOT / "src/main/java/io/rbvm/csv/RbvmPlatformMain.java").read_text(encoding="utf-8")
UI = (ROOT / "src/main/resources/web/csv-canonical-handoff.js").read_text(encoding="utf-8")
COMPILE = (ROOT / "scripts/compile.sh").read_text(encoding="utf-8")

for token in [
    "CSV_FIRST_SOURCE_ARTIFACT_HTTP_V1",
    "/api/v1/csv-first-sources",
    "input.csv",
    "ApiRole.VIEWER",
    "X-RBVM-Source-SHA256",
    "Content-Disposition",
]:
    if token not in SOURCE:
        raise AssertionError(f"CSV-first source transport missing {token}")
for forbidden in ["enriched.csv", "POST", "DELETE", "PUT"]:
    if forbidden in SOURCE:
        raise AssertionError(f"CSV-first source transport must be original-source read-only: {forbidden}")

for token in [
    "new CsvFirstSourceHttpHandler",
    '"/api/v1/csv-first-sources"',
]:
    if token not in LAUNCHER:
        raise AssertionError(f"Launcher missing source transport registration {token}")

for token in [
    "CSV_FIRST_CANONICAL_HANDOFF_UI_V1",
    "/api/v1/csv-first-sources/",
    "/api/v1/csv-imports",
    "X-Source-Profile-Id",
    "X-CSV-Contract",
    "Idempotency-Key",
    "WAZUH_CSV_V1",
    "WAZUH_CSV_V2",
    "Create canonical preview",
    "Confirm canonical import",
    "/confirm",
    "exact original uploaded CSV",
    "never the enriched CSV",
]:
    if token not in UI:
        raise AssertionError(f"Canonical handoff UI missing {token}")
for forbidden in [
    "enrichedCsv",
    "autoConfirm",
    "AUTO_CONFIRM",
    "riskScore",
    "priorityScore",
    "EPSS_Probability *",
    "CVSS4_Base_Score *",
    "localStorage",
    "sessionStorage",
]:
    if forbidden in UI:
        raise AssertionError(f"Canonical handoff UI contains forbidden behavior {forbidden}")

if "confirm.disabled = true" not in UI:
    raise AssertionError("Canonical confirmation must begin disabled until preview succeeds")
if "activeImport = data" not in UI:
    raise AssertionError("Canonical confirmation must bind to the previewed import identity")
if "csv-canonical-handoff.js" not in COMPILE:
    raise AssertionError("Canonical handoff UI is not included in the runtime bundle")

print("CSV-first canonical Finding handoff checks: PASS")
