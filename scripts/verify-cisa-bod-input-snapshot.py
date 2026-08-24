#!/usr/bin/env python3
import csv
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
BUILDER = ROOT / "scripts/build-cisa-bod-input-snapshot.py"
DOC = (ROOT / "docs/CISA_BOD_26_04_PRIORITY_INPUT_SNAPSHOT_V1.md").read_text(encoding="utf-8")
METHOD_SHA = "64066ae687fd98c6db48fa224316446dc579737ff6c16321f155de69c5f0e9ff"


def file_sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_builder(analysis, summary, kev, output):
    subprocess.run([
        sys.executable, str(BUILDER), str(analysis), str(summary), str(kev), str(output),
        "--created-at", "2026-08-24T12:00:00Z",
    ], check=True, stdout=subprocess.DEVNULL)
    return json.loads(output.read_text(encoding="utf-8"))


with tempfile.TemporaryDirectory(prefix="rbvm-bod-input-") as tmp:
    tmp = Path(tmp)
    analysis = tmp / "analysis.csv"
    summary = tmp / "summary.json"
    kev = tmp / "validated-kev.json"
    output1 = tmp / "bod-input-1.json"
    output2 = tmp / "bod-input-2.json"

    response_sha = "1" * 64
    public_sha = "2" * 64
    headers = [
        "Agent", "CVE_ID", "Affected_Product",
        "Publicly_Exposed", "KEV_Listed",
        "CISA_Automatable", "CISA_Technical_Impact",
        "CISA_SSVC_Version", "CISA_SSVC_Timestamp",
        "CVE_Services_Response_SHA256", "Public_Intel_Snapshot_SHA256", "Intel_Observed_At",
        "CVSS4_Context_Score", "EPSS_Probability", "Asset_Criticality", "Internet_Facing",
    ]
    with analysis.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=headers)
        writer.writeheader()
        writer.writerow({
            "Agent": "asset-a", "CVE_ID": "CVE-2026-10001", "Affected_Product": "pkg-a",
            "Publicly_Exposed": "YES", "KEV_Listed": "false",
            "CISA_Automatable": "yes", "CISA_Technical_Impact": "total",
            "CISA_SSVC_Version": "2.0.3", "CISA_SSVC_Timestamp": "2026-08-24T09:00:00Z",
            "CVE_Services_Response_SHA256": response_sha, "Public_Intel_Snapshot_SHA256": public_sha,
            "Intel_Observed_At": "2026-08-24T09:05:00Z",
            "CVSS4_Context_Score": "10.0", "EPSS_Probability": "0.99", "Asset_Criticality": "MISSION_CRITICAL", "Internet_Facing": "YES",
        })
        writer.writerow({
            "Agent": "asset-b", "CVE_ID": "CVE-2026-10002", "Affected_Product": "pkg-b",
            "Publicly_Exposed": "NO", "KEV_Listed": "true",
            "CISA_Automatable": "no", "CISA_Technical_Impact": "partial",
            "CISA_SSVC_Version": "2.0.3", "CISA_SSVC_Timestamp": "2026-08-24T09:00:00Z",
            "CVE_Services_Response_SHA256": response_sha, "Public_Intel_Snapshot_SHA256": public_sha,
            "Intel_Observed_At": "2026-08-24T09:05:00Z",
            "CVSS4_Context_Score": "1.0", "EPSS_Probability": "0.01", "Asset_Criticality": "LOW", "Internet_Facing": "NO",
        })
        writer.writerow({
            "Agent": "asset-c", "CVE_ID": "CVE-2026-10003", "Affected_Product": "pkg-c",
            "Publicly_Exposed": "UNKNOWN", "KEV_Listed": "false",
            "CISA_Automatable": "UNKNOWN", "CISA_Technical_Impact": "total",
            "CISA_SSVC_Version": "2.0.3", "CISA_SSVC_Timestamp": "2026-08-24T09:00:00Z",
            "CVE_Services_Response_SHA256": "", "Public_Intel_Snapshot_SHA256": public_sha,
            "Intel_Observed_At": "2026-08-24T09:05:00Z",
            "CVSS4_Context_Score": "9.9", "EPSS_Probability": "0.88", "Asset_Criticality": "HIGH", "Internet_Facing": "YES",
        })

    bundle_sha = "3" * 64
    summary.write_text(json.dumps({
        "contractId": "CSV_RUN_EVIDENCE_ANALYSIS_V3",
        "source": {
            "customerBundleContractId": "RBVM_CUSTOMER_ASSET_BUNDLE_V4",
            "customerBundleSchemaVersion": 4,
            "customerBundleSha256": bundle_sha,
        },
        "scope": {"findingRows": 3},
    }), encoding="utf-8")

    # Complete validated catalog contains only CVE-2026-10001. Absence of the
    # other CVEs therefore gives canonical InKEV=N. This intentionally conflicts
    # with row-2 KEV_Listed=true to prove the convenience CSV column is not used.
    kev.write_text(json.dumps({
        "schemaVersion": 1,
        "artifactType": "CISA_KEV_VALIDATED_SNAPSHOT",
        "source": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "observedAt": "2026-08-24T08:00:00Z",
        "sha256": "4" * 64,
        "catalogVersion": "2026.08.24",
        "declaredCount": 1,
        "parsedCount": 1,
        "complete": True,
        "vulnerabilities": [{"cveId": "CVE-2026-10001"}],
    }), encoding="utf-8")

    result1 = run_builder(analysis, summary, kev, output1)
    result2 = run_builder(analysis, summary, kev, output2)

    if result1["contractId"] != "CISA_BOD_26_04_PRIORITY_INPUT_SNAPSHOT_V1" or result1["schemaVersion"] != 1:
        raise AssertionError("BOD input snapshot contract mismatch")
    if result1["method"] != {"methodId": "CISA_BOD_26_04_REMEDIATION_PRIORITY_METHOD_V1", "methodSha256": METHOD_SHA}:
        raise AssertionError("BOD input snapshot method binding mismatch")
    if result1["snapshotSha256"] != result2["snapshotSha256"]:
        raise AssertionError("same exact evidence must produce deterministic BOD snapshot SHA")
    unhashed = dict(result1)
    claimed = unhashed.pop("snapshotSha256")
    canonical = json.dumps(unhashed, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if hashlib.sha256(canonical).hexdigest() != claimed:
        raise AssertionError("BOD input snapshot canonical SHA verification failed")

    rows = result1["findingRows"]
    if len(rows) != 3 or result1["coverage"] != {"totalRows": 3, "completeRows": 2, "incompleteRows": 1}:
        raise AssertionError("BOD input snapshot coverage mismatch")

    first, second, third = rows
    if first["inputs"]["inKev"]["value"] != "Y" or first["inputs"]["inKev"]["raw"] != "LISTED":
        raise AssertionError("validated complete KEV membership was not resolved to Y")
    if second["inputs"]["inKev"]["value"] != "N" or second["inputs"]["inKev"]["raw"] != "NOT_LISTED":
        raise AssertionError("absence from complete validated KEV snapshot was not resolved to N")
    if second["inputs"]["inKev"]["value"] == "Y":
        raise AssertionError("analysis KEV_Listed convenience value must not override validated KEV snapshot")
    if first["inputs"]["publiclyExposed"]["value"] != "Y" or second["inputs"]["publiclyExposed"]["value"] != "N":
        raise AssertionError("explicit Publicly Exposed values were not resolved")
    if first["inputs"]["automatable"]["value"] != "Y" or first["inputs"]["technicalImpact"]["value"] != "T":
        raise AssertionError("CISA SSVC values were not normalized")
    if first["inputs"]["automatable"]["provenance"]["cveServicesResponseSha256"] != response_sha:
        raise AssertionError("CISA SSVC exact response provenance was not retained")
    if first["inputs"]["publiclyExposed"]["provenance"]["customerBundleSha256"] != bundle_sha:
        raise AssertionError("customer Publicly Exposed exact bundle provenance was not retained")
    if third["status"] != "INCOMPLETE":
        raise AssertionError("missing evidence must keep the row incomplete")
    if "PUBLICLY_EXPOSED_MISSING" not in third["blockers"] or "AUTOMATABLE_MISSING" not in third["blockers"]:
        raise AssertionError("missing BOD blockers were not preserved")
    if "TECHNICAL_IMPACT_PROVENANCE_MISSING" not in third["blockers"]:
        raise AssertionError("present SSVC without exact response provenance must be invalid/incomplete")

    if result1["sourceArtifacts"]["analysisCsv"]["sha256"] != file_sha(analysis):
        raise AssertionError("analysis CSV SHA provenance mismatch")
    if result1["sourceArtifacts"]["validatedKevSnapshot"]["fileSha256"] != file_sha(kev):
        raise AssertionError("validated KEV snapshot file SHA provenance mismatch")

    rendered = json.dumps(result1, sort_keys=True)
    for forbidden in (
        "CVSS4_Context_Score", "EPSS_Probability", "Asset_Criticality", "Business_Impact", "Internet_Facing",
        "LOW", "MEDIUM", "HIGH", "CRITICAL", "CISA_Exploitation",
    ):
        if forbidden in rendered:
            raise AssertionError(f"non-BOD dimension leaked into canonical BOD input snapshot: {forbidden}")

    # Complete=false must make negative KEV membership unusable instead of N.
    invalid_kev = tmp / "invalid-kev.json"
    invalid = json.loads(kev.read_text(encoding="utf-8"))
    invalid["complete"] = False
    invalid_kev.write_text(json.dumps(invalid), encoding="utf-8")
    failed = subprocess.run([
        sys.executable, str(BUILDER), str(analysis), str(summary), str(invalid_kev), str(tmp / "invalid-out.json"),
        "--created-at", "2026-08-24T12:00:00Z",
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if failed.returncode == 0:
        raise AssertionError("incomplete KEV snapshot must be rejected")

for token in (
    "exactly four decision points",
    "absence from validated complete CISA snapshot = N",
    "Legacy `Internet_Facing` is not read",
    "CVE_Services_Response_SHA256",
    "COMPLETE",
    "INCOMPLETE",
    "does **not** calculate an outcome",
    "CVSS-B/CVSS-BT/CVSS-BE/CVSS-BTE",
    "EPSS probability/percentile",
):
    if token not in DOC:
        raise AssertionError(f"BOD input snapshot documentation missing boundary: {token}")

print("CISA BOD 26-04 immutable input snapshot V1: PASS")
