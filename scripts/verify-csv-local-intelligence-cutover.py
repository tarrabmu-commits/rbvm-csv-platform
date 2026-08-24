#!/usr/bin/env python3
from pathlib import Path
import base64
import csv
import json
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
main = (ROOT / "src/main/java/io/rbvm/csv/RbvmPlatformMain.java").read_text(encoding="utf-8")
executor = (ROOT / "src/main/java/io/rbvm/csv/CsvFirstLocalEnrichmentExecutor.java").read_text(encoding="utf-8")
exporter = (ROOT / "src/main/java/io/rbvm/postgres/PostgresCsvFirstLocalIntelligenceSnapshotExporter.java").read_text(encoding="utf-8")
cisa_validation = (ROOT / "src/main/java/io/rbvm/postgres/PostgresCisaKevCatalogValidationReader.java").read_text(encoding="utf-8")
builder = ROOT / "scripts/build-local-public-intelligence-snapshot.py"
local_enricher = ROOT / "scripts/enrich-uploaded-csv-local.py"

assert "new CsvFirstLocalEnrichmentHttpHandler" in main
assert "new CsvFirstLocalEnrichmentJobHttpHandler" in main
assert "new CsvFirstEnrichmentHttpHandler(dataDirectory, maximumUploadBytes, authenticator)" not in main
assert "new CsvFirstEnrichmentJobHttpHandler(dataDirectory, maximumUploadBytes, authenticator)" not in main
assert "CsvFirstLocalIntelligenceRuntimeFactory.fromEnvironment(environment)" in main

assert "LOOKUP_BATCH_SIZE = 1_000" in exporter
assert "intelligence.lookupCurrent(batch)" in exporter
assert "status.readStatus()" in exporter
assert "latestSuccessId()" in exporter
assert "Safe_Negative_Absence" in exporter
assert "cisaCatalogValidation.isCompleteValidatedCatalog" in exporter
assert "Payload_Base64" in exporter
assert "public_intelligence_sync_job" in cisa_validation
assert "j.status = 'COMPLETE'" in cisa_validation
assert "j.stage = 'COMPLETE'" in cisa_validation
assert "r.status = 'COMPLETE'" in cisa_validation
assert "known_exploited_vulnerabilities.json" in cisa_validation

assert 'resolve("scripts/enrich-uploaded-csv-local.py")' in executor
assert 'resolve("scripts/build-local-public-intelligence-snapshot.py")' in executor
assert "target.clear()" in executor
for secret in ("RBVM_DB_PASSWORD", "NVD_API_KEY", "RBVM_DB_USER", "RBVM_JDBC_URL"):
    assert secret not in executor
assert "collect-public-vulnerability-intel.py" not in executor

builder_text = builder.read_text(encoding="utf-8")
assert "collector.nvd_normalized" in builder_text
assert "collector.cve_program_normalized" in builder_text
assert '"LOCAL_V30_STORE"' in builder_text
assert "NOT_LISTED_ONLY_AFTER_COMPLETE_VALIDATED_CATALOG" in builder_text
assert 'status["CISA_KEV"]["safeNegativeAbsence"]' in builder_text
assert "urlopen" not in builder_text and "urllib.request" not in builder_text

local_text = local_enricher.read_text(encoding="utf-8")
assert '"--intel-snapshot"' in local_text
assert 'report["providerNetworkIoUsed"] = False' in local_text
assert 'report["tenantDatabaseStateUsed"] = False' in local_text
assert "urlopen" not in local_text and "urllib.request" not in local_text

STATUS_HEADER = [
    "Provider", "Has_Success", "Safe_Negative_Absence", "Success_ID", "Sync_Mode", "Source_URI",
    "Source_Version", "Source_SHA256", "Source_Published_At", "Observed_At",
    "Completed_At", "Record_Count",
]
RECORD_HEADER = [
    "CVE_ID", "Provider", "Payload_Base64", "Record_SHA256", "Source_Modified_At",
    "Source_Published_At", "Record_Observed_At", "Sync_Run_ID", "Sync_Mode", "Source_URI",
    "Source_Version", "Source_SHA256", "Run_Observed_At", "Run_Completed_At",
]
PROVIDERS = ("NVD", "FIRST_EPSS", "CISA_KEV", "CVE_PROGRAM")
SHA = "a" * 64
SOURCE_SHA = "b" * 64


def b64(payload):
    return base64.b64encode(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).decode("ascii")


def write_export(directory, cisa_success, cisa_safe):
    if cisa_safe and not cisa_success:
        raise AssertionError("fixture cannot mark CISA negative-safe without a successful source")
    cves = ["CVE-2024-0001", "CVE-2024-0002"]
    (directory / "requested-cves.txt").write_text("\n".join(cves) + "\n", encoding="utf-8")
    (directory / "export.properties").write_text(
        "contractId=CSV_FIRST_LOCAL_PUBLIC_INTELLIGENCE_EXPORT_V1\n"
        "uniqueCves=2\nproviderRecords=3\ncvesWithoutActiveProviderRecords=1\n"
        f"providersWithSuccessfulSnapshot={3 if cisa_success else 2}\n",
        encoding="utf-8",
    )
    with (directory / "provider-status.tsv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=STATUS_HEADER, delimiter="\t", lineterminator="\n")
        writer.writeheader()
        for provider in PROVIDERS:
            has_success = provider in {"NVD", "FIRST_EPSS"} or (provider == "CISA_KEV" and cisa_success)
            safe_negative = provider == "CISA_KEV" and cisa_safe
            writer.writerow({
                "Provider": provider,
                "Has_Success": str(has_success).lower(),
                "Safe_Negative_Absence": str(safe_negative).lower(),
                "Success_ID": "11111111-1111-1111-1111-111111111111" if has_success else "",
                "Sync_Mode": "INCREMENTAL" if has_success else "",
                "Source_URI": f"https://example.invalid/{provider}" if has_success else "",
                "Source_Version": "fixture-v1" if has_success else "",
                "Source_SHA256": SOURCE_SHA if has_success else "",
                "Source_Published_At": "2026-08-24T00:00:00Z" if has_success else "",
                "Observed_At": "2026-08-24T00:01:00Z" if has_success else "",
                "Completed_At": "2026-08-24T00:02:00Z" if has_success else "",
                "Record_Count": "1" if has_success else "",
            })
    rows = [
        ("CVE-2024-0001", "NVD", {
            "id": "CVE-2024-0001", "published": "2024-01-01T00:00:00.000",
            "lastModified": "2024-01-02T00:00:00.000", "vulnStatus": "Analyzed",
            "sourceIdentifier": "fixture", "descriptions": [{"lang": "en", "value": "fixture"}],
            "metrics": {}, "weaknesses": [], "references": [], "configurations": [],
        }),
        ("CVE-2024-0001", "FIRST_EPSS", {
            "cve": "CVE-2024-0001", "epss": "0.25", "percentile": "0.75",
            "modelVersion": "2026.08.24", "scoreDate": "2026-08-24",
        }),
        ("CVE-2024-0001", "CISA_KEV", {
            "cveID": "CVE-2024-0001", "dateAdded": "2026-08-20", "dueDate": "2026-09-10",
            "vendorProject": "Fixture", "product": "Fixture", "vulnerabilityName": "Fixture",
            "requiredAction": "Fixture", "knownRansomwareCampaignUse": "Unknown", "notes": "",
        }),
    ]
    if not cisa_success:
        rows = rows[:2]
    with (directory / "records.tsv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=RECORD_HEADER, delimiter="\t", lineterminator="\n")
        writer.writeheader()
        for cve, provider, payload in rows:
            writer.writerow({
                "CVE_ID": cve, "Provider": provider, "Payload_Base64": b64(payload),
                "Record_SHA256": SHA, "Source_Modified_At": "", "Source_Published_At": "",
                "Record_Observed_At": "2026-08-24T00:01:00Z",
                "Sync_Run_ID": "22222222-2222-2222-2222-222222222222",
                "Sync_Mode": "INCREMENTAL", "Source_URI": f"https://example.invalid/{provider}",
                "Source_Version": "fixture-v1", "Source_SHA256": SOURCE_SHA,
                "Run_Observed_At": "2026-08-24T00:01:00Z", "Run_Completed_At": "2026-08-24T00:02:00Z",
            })


def build_case(cisa_success, cisa_safe):
    with tempfile.TemporaryDirectory(prefix="rbvm-local-intel-cutover-") as tmp:
        root = Path(tmp)
        export = root / "export"
        export.mkdir()
        write_export(export, cisa_success, cisa_safe)
        output = root / "snapshot.json"
        report = root / "report.json"
        subprocess.run([
            "python3", str(builder), str(export), str(output), "--report", str(report),
            "--observed-at", "2026-08-24T01:00:00Z",
        ], check=True, capture_output=True, text=True)
        snapshot = json.loads(output.read_text(encoding="utf-8"))
        assert snapshot["contractId"] == "PUBLIC_CVE_INTEL_SNAPSHOT_V1"
        assert snapshot["acquisition"]["mode"] == "LOCAL_V30_STORE"
        assert snapshot["cisaKevCatalog"]["completeValidatedCatalogAvailable"] is cisa_safe
        assert len(snapshot["snapshotSha256"]) == 64
        by_cve = {row["cveId"]: row for row in snapshot["records"]}
        assert by_cve["CVE-2024-0001"]["nvd"]["vulnStatus"] == "Analyzed"
        assert by_cve["CVE-2024-0001"]["epss"]["probability"] == "0.25"
        if cisa_success:
            assert by_cve["CVE-2024-0001"]["cisaKev"]["listed"] is True
        else:
            assert by_cve["CVE-2024-0001"]["cisaKev"] is None
        if cisa_safe:
            assert by_cve["CVE-2024-0002"]["cisaKev"] == {"listed": False}
        else:
            assert by_cve["CVE-2024-0002"]["cisaKev"] is None


build_case(True, True)
build_case(True, False)
build_case(False, False)
print("CSV local public-intelligence cutover checks: PASS")
