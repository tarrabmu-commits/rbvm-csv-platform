#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src/main/java/io/rbvm/csv/CsvFirstSourceHttpHandler.java").read_text(encoding="utf-8")
MANIFEST_HANDLER = (ROOT / "src/main/java/io/rbvm/csv/CanonicalImportFindingHttpHandler.java").read_text(encoding="utf-8")
MANIFEST_EXPORTER = (ROOT / "src/main/java/io/rbvm/postgres/PostgresCanonicalImportFindingExporter.java").read_text(encoding="utf-8")
MANIFEST_FACTORY = (ROOT / "src/main/java/io/rbvm/postgres/CanonicalImportFindingRuntimeFactory.java").read_text(encoding="utf-8")
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
    "CANONICAL_IMPORT_FINDING_MANIFEST_HTTP_V1",
    "/api/v1/canonical-imports/",
    "findings\\.csv",
    "ApiRole.VIEWER",
    "X-RBVM-Import-Id",
    "COMPLETED_IMPORT_NOT_FOUND",
    "GET",
]:
    if token not in MANIFEST_HANDLER:
        raise AssertionError(f"Canonical Finding manifest handler missing {token}")
for forbidden in ["POST", "DELETE", "PUT", "riskScore", "priorityScore"]:
    if forbidden in MANIFEST_HANDLER:
        raise AssertionError(f"Canonical Finding manifest handler must remain read-only: {forbidden}")

for token in [
    "rbvm.import_observation",
    "rbvm.observation",
    "rbvm.exposure_observation",
    "rbvm.exposure",
    "io.import_id = ?",
    "e.id AS finding_id",
    "MIN(io.source_row_number)",
    "ir.status = 'COMPLETED'",
    "Finding_ID",
    "Source_Row_Number",
    "Source_Profile_Key",
]:
    if token not in MANIFEST_EXPORTER:
        raise AssertionError(f"Exact import-scoped Finding exporter missing {token}")
for forbidden in [
    "LIKE",
    "ILIKE",
    "normalized_observed_name =",
    "cve_id = ?",
    "observed_product_name = ?",
    "hostname",
    "AUTO_MATCH",
]:
    if forbidden in MANIFEST_EXPORTER:
        raise AssertionError(f"Finding manifest must not infer/match identity: {forbidden}")

for token in [
    "PostgresProjectionSettings.fromEnvironment",
    "PostgresCanonicalImportFindingExporter",
    "installedVersion < 1",
]:
    if token not in MANIFEST_FACTORY:
        raise AssertionError(f"Canonical Finding manifest runtime factory missing {token}")

for token in [
    "new CsvFirstSourceHttpHandler",
    '"/api/v1/csv-first-sources"',
    "CanonicalImportFindingRuntimeFactory.fromEnvironment",
    "new CanonicalImportFindingHttpHandler",
    '"/api/v1/canonical-imports"',
]:
    if token not in LAUNCHER:
        raise AssertionError(f"Launcher missing exact handoff transport registration {token}")

for token in [
    "CSV_FIRST_CANONICAL_HANDOFF_UI_V2",
    "CANONICAL_IMPORT_FINDING_MANIFEST_HTTP_V1",
    "/api/v1/csv-first-sources/",
    "/api/v1/csv-imports",
    "/api/v1/canonical-imports/",
    "findings.csv",
    "X-Source-Profile-Id",
    "X-CSV-Contract",
    "Idempotency-Key",
    "WAZUH_CSV_V1",
    "WAZUH_CSV_V2",
    "Create canonical preview",
    "Confirm canonical import",
    "Download exact Finding manifest",
    "/confirm",
    "exact original uploaded CSV",
    "never the enriched CSV",
    "import_observation → observation → exposure",
    "rbvm:canonical-import-complete",
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

print("CSV-first canonical handoff + exact import-scoped Finding manifest checks: PASS")
