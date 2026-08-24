#!/usr/bin/env python3
"""Build immutable CISA BOD 26-04 input snapshots from run-scoped evidence.

The builder deliberately does not calculate a BOD outcome. It binds exactly the
four BOD decision points to immutable source artifacts so a later decision engine
can consume a reproducible, fail-closed input.

KEV negative membership is resolved only from a validated complete CISA KEV
snapshot. The enriched CSV's KEV_Listed column is not used to infer InKEV=N.
"""

from __future__ import annotations

import argparse
import csv
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re

from cisa_bod_26_04 import (
    METHOD_ID,
    METHOD_SHA256,
    IN_KEV_ID,
    PUBLICLY_EXPOSED_ID,
    AUTOMATABLE_ID,
    TECHNICAL_IMPACT_ID,
    resolve_automatable,
    resolve_publicly_exposed,
    resolve_technical_impact,
)

CONTRACT_ID = "CISA_BOD_26_04_PRIORITY_INPUT_SNAPSHOT_V1"
SCHEMA_VERSION = 1
CVE_PATTERN = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
SUPPORTED_ANALYSIS_CONTRACTS = {"CSV_RUN_EVIDENCE_ANALYSIS_V3"}


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("analysis_csv", type=Path)
    parser.add_argument("analysis_summary", type=Path)
    parser.add_argument("validated_kev_snapshot", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--created-at", help="fixed ISO-8601 timestamp for deterministic replay/testing")
    return parser.parse_args()


def utc_timestamp(value=None):
    if value:
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError as error:
            raise RuntimeError("--created-at must be an ISO-8601 timestamp") from error
        if parsed.tzinfo is None:
            raise RuntimeError("--created-at must include a timezone")
        return parsed.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_bytes(value):
    return hashlib.sha256(value).hexdigest()


def sha256_file(path):
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"expected regular non-symlink file: {path}")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def canonical_sha(value):
    return sha256_bytes(canonical_bytes(value))


def read_json(path, label):
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"{label} must be a regular non-symlink file")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError(f"{label} must contain valid UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise RuntimeError(f"{label} root must be a JSON object")
    return value


def load_analysis_summary(path):
    value = read_json(path, "analysis summary")
    contract = value.get("contractId")
    if contract not in SUPPORTED_ANALYSIS_CONTRACTS:
        raise RuntimeError(
            "BOD snapshot requires CSV_RUN_EVIDENCE_ANALYSIS_V3 with explicit Publicly_Exposed evidence"
        )
    source = value.get("source")
    if not isinstance(source, dict):
        raise RuntimeError("analysis summary source metadata is missing")
    return value


def load_kev_snapshot(path):
    value = read_json(path, "validated KEV snapshot")
    if value.get("artifactType") != "CISA_KEV_VALIDATED_SNAPSHOT" or value.get("schemaVersion") != 1:
        raise RuntimeError("expected CISA_KEV_VALIDATED_SNAPSHOT schemaVersion 1")
    if value.get("complete") is not True:
        raise RuntimeError("CISA KEV snapshot is not marked complete")
    declared = value.get("declaredCount")
    parsed = value.get("parsedCount")
    vulnerabilities = value.get("vulnerabilities")
    if isinstance(declared, bool) or not isinstance(declared, int) or declared <= 0:
        raise RuntimeError("validated KEV declaredCount must be a positive integer")
    if parsed != declared or not isinstance(vulnerabilities, list) or len(vulnerabilities) != declared:
        raise RuntimeError("validated KEV snapshot completeness invariant failed")
    source_sha = str(value.get("sha256") or "")
    if not SHA256_PATTERN.fullmatch(source_sha):
        raise RuntimeError("validated KEV snapshot source sha256 is invalid")
    members = set()
    for index, entry in enumerate(vulnerabilities):
        if not isinstance(entry, dict):
            raise RuntimeError(f"validated KEV vulnerabilities[{index}] must be an object")
        cve = str(entry.get("cveId") or "").strip().upper()
        if not CVE_PATTERN.fullmatch(cve) or cve in members:
            raise RuntimeError("validated KEV snapshot contains invalid or duplicate CVE IDs")
        members.add(cve)
    return value, members


def read_analysis_csv(path):
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("analysis CSV must be a regular non-symlink file")
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        headers = list(reader.fieldnames or [])
        required = {
            "CVE_ID",
            "Publicly_Exposed",
            "CISA_Automatable",
            "CISA_Technical_Impact",
            "CISA_SSVC_Version",
            "CISA_SSVC_Timestamp",
            "CVE_Services_Response_SHA256",
            "Public_Intel_Snapshot_SHA256",
            "Intel_Observed_At",
        }
        missing = sorted(required - set(headers))
        if missing:
            raise RuntimeError("analysis CSV missing BOD evidence columns: " + ", ".join(missing))
        rows = list(reader)
    if not rows:
        raise RuntimeError("analysis CSV must contain at least one finding row")
    return headers, rows


def nonblank(row, keys):
    for key in keys:
        value = str(row.get(key) or "").strip()
        if value:
            return value
    return ""


def finding_scope(row, row_number):
    return {
        "rowNumber": row_number,
        "cveId": str(row.get("CVE_ID") or "").strip().upper(),
        "assetKey": nonblank(row, ("Agent_ID", "Asset_ID")),
        "assetName": nonblank(row, ("Agent", "Asset_Name", "Hostname")),
        "component": nonblank(row, ("Affected_Product", "Product", "Package_Name")),
    }


def input_value(resolved, provenance):
    return {
        "semanticId": resolved.semantic_id,
        "status": resolved.status,
        "value": resolved.value,
        "raw": resolved.raw,
        "blocker": resolved.blocker,
        "provenance": provenance,
    }


def in_kev_value(cve, kev_members, kev_snapshot, kev_file_sha):
    listed = cve in kev_members
    return {
        "semanticId": IN_KEV_ID,
        "status": "PRESENT",
        "value": "Y" if listed else "N",
        "raw": "LISTED" if listed else "NOT_LISTED",
        "blocker": None,
        "provenance": {
            "artifactType": "CISA_KEV_VALIDATED_SNAPSHOT",
            "snapshotFileSha256": kev_file_sha,
            "sourceSha256": kev_snapshot["sha256"],
            "source": kev_snapshot.get("source"),
            "observedAt": kev_snapshot.get("observedAt"),
            "catalogVersion": kev_snapshot.get("catalogVersion"),
            "declaredCount": kev_snapshot.get("declaredCount"),
            "parsedCount": kev_snapshot.get("parsedCount"),
            "complete": True,
        },
    }


def ssvc_provenance(row, public_snapshot_sha, response_sha):
    return {
        "source": "CISA_VULNERABILITY_ENRICHMENT_CISA_ADP",
        "publicIntelSnapshotSha256": public_snapshot_sha,
        "cveServicesResponseSha256": response_sha or None,
        "ssvcVersion": str(row.get("CISA_SSVC_Version") or "").strip() or None,
        "ssvcTimestamp": str(row.get("CISA_SSVC_Timestamp") or "").strip() or None,
        "intelObservedAt": str(row.get("Intel_Observed_At") or "").strip() or None,
    }


def ensure_present_ssvc_provenance(resolved, response_sha, label):
    if not resolved.present:
        return resolved
    if not SHA256_PATTERN.fullmatch(response_sha):
        return type(resolved)("INVALID", None, resolved.raw, resolved.semantic_id, f"{label}_PROVENANCE_MISSING")
    return resolved


def build_row(row, row_number, kev_members, kev_snapshot, kev_file_sha, customer_source):
    cve = str(row.get("CVE_ID") or "").strip().upper()
    if not CVE_PATTERN.fullmatch(cve):
        raise RuntimeError(f"analysis row {row_number} has invalid CVE_ID")

    public_snapshot_sha = str(row.get("Public_Intel_Snapshot_SHA256") or "").strip().lower()
    if not SHA256_PATTERN.fullmatch(public_snapshot_sha):
        raise RuntimeError(f"analysis row {row_number} has invalid Public_Intel_Snapshot_SHA256")
    response_sha = str(row.get("CVE_Services_Response_SHA256") or "").strip().lower()

    publicly_exposed = resolve_publicly_exposed(row.get("Publicly_Exposed"))
    automatable = ensure_present_ssvc_provenance(
        resolve_automatable(row.get("CISA_Automatable")), response_sha, "AUTOMATABLE"
    )
    technical_impact = ensure_present_ssvc_provenance(
        resolve_technical_impact(row.get("CISA_Technical_Impact")), response_sha, "TECHNICAL_IMPACT"
    )

    public_input = input_value(publicly_exposed, customer_source)
    auto_input = input_value(automatable, ssvc_provenance(row, public_snapshot_sha, response_sha))
    impact_input = input_value(technical_impact, ssvc_provenance(row, public_snapshot_sha, response_sha))
    kev_input = in_kev_value(cve, kev_members, kev_snapshot, kev_file_sha)
    inputs = {
        "inKev": kev_input,
        "publiclyExposed": public_input,
        "automatable": auto_input,
        "technicalImpact": impact_input,
    }
    blockers = [value["blocker"] for value in inputs.values() if value.get("status") != "PRESENT" and value.get("blocker")]
    scope = finding_scope(row, row_number)
    return {
        "scope": scope,
        "findingRowSha256": canonical_sha(row),
        "status": "COMPLETE" if not blockers else "INCOMPLETE",
        "blockers": sorted(set(blockers)),
        "inputs": inputs,
    }


def main():
    args = arguments()
    created_at = utc_timestamp(args.created_at)
    summary = load_analysis_summary(args.analysis_summary)
    _, rows = read_analysis_csv(args.analysis_csv)
    kev_snapshot, kev_members = load_kev_snapshot(args.validated_kev_snapshot)

    scope = summary.get("scope") if isinstance(summary.get("scope"), dict) else {}
    if scope.get("findingRows") != len(rows):
        raise RuntimeError("analysis summary findingRows does not match analysis CSV")

    source = summary["source"]
    bundle_sha = str(source.get("customerBundleSha256") or "").lower()
    bundle_contract = source.get("customerBundleContractId")
    bundle_schema = source.get("customerBundleSchemaVersion")
    if not SHA256_PATTERN.fullmatch(bundle_sha):
        raise RuntimeError("analysis summary is missing a valid customerBundleSha256")
    if (bundle_contract, bundle_schema) != ("RBVM_CUSTOMER_ASSET_BUNDLE_V4", 4):
        raise RuntimeError("BOD snapshot requires RBVM_CUSTOMER_ASSET_BUNDLE_V4 schemaVersion 4")

    customer_source = {
        "source": "CUSTOMER_DECLARED_CISA_PUBLICLY_EXPOSED",
        "customerBundleContractId": bundle_contract,
        "customerBundleSchemaVersion": bundle_schema,
        "customerBundleSha256": bundle_sha,
    }
    analysis_csv_sha = sha256_file(args.analysis_csv)
    analysis_summary_file_sha = sha256_file(args.analysis_summary)
    kev_file_sha = sha256_file(args.validated_kev_snapshot)

    snapshot = {
        "schemaVersion": SCHEMA_VERSION,
        "contractId": CONTRACT_ID,
        "method": {"methodId": METHOD_ID, "methodSha256": METHOD_SHA256},
        "createdAt": created_at,
        "semantics": "IMMUTABLE_EXACT_FOUR_INPUT_CISA_BOD_26_04_PRIORITY_EVIDENCE_NO_OUTCOME",
        "sourceArtifacts": {
            "analysisCsv": {"name": args.analysis_csv.name, "sha256": analysis_csv_sha},
            "analysisSummary": {"name": args.analysis_summary.name, "sha256": analysis_summary_file_sha},
            "customerBundle": {
                "contractId": bundle_contract,
                "schemaVersion": bundle_schema,
                "sha256": bundle_sha,
            },
            "validatedKevSnapshot": {
                "name": args.validated_kev_snapshot.name,
                "fileSha256": kev_file_sha,
                "sourceSha256": kev_snapshot["sha256"],
            },
        },
        "findingRows": [
            build_row(row, index, kev_members, kev_snapshot, kev_file_sha, customer_source)
            for index, row in enumerate(rows, 1)
        ],
    }
    complete = sum(item["status"] == "COMPLETE" for item in snapshot["findingRows"])
    snapshot["coverage"] = {
        "totalRows": len(snapshot["findingRows"]),
        "completeRows": complete,
        "incompleteRows": len(snapshot["findingRows"]) - complete,
    }
    snapshot["snapshotSha256"] = canonical_sha(snapshot)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_suffix(args.output.suffix + ".tmp")
    temporary.write_text(json.dumps(snapshot, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
    temporary.replace(args.output)
    print(json.dumps({
        "contractId": CONTRACT_ID,
        "snapshotSha256": snapshot["snapshotSha256"],
        **snapshot["coverage"],
        "output": str(args.output),
    }, sort_keys=True))


if __name__ == "__main__":
    main()
