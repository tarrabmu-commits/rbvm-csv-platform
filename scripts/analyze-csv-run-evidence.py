#!/usr/bin/env python3
"""Analyze one enriched CSV run without inventing organizational-risk math.

Inputs:
- enriched CSV produced by enrich-uploaded-csv.py
- optional RBVM_CUSTOMER_ASSET_BUNDLE_V2, V3, or V4 JSON

Outputs:
- row-preserving evidence/benchmark CSV
- deterministic coverage/readiness JSON

CVSS technical severity, EPSS probability, KEV/SSVC threat signals, and customer
context remain separate. Public CVSS-B/CVSS-BT values are consumed as severity
evidence. V3/V4 customer bundles may declare CVSS v4 CR/IR/AR directly using
native X/L/M/H metric values; these declarations can produce CVSS-BE/CVSS-BTE
contextual technical severity. V4 additionally carries explicit CISA Publicly
Exposed evidence. Asset Criticality is never converted to CR/IR/AR, asset-level
Internet Facing is never converted to MAV, and Internet Facing is never converted
to CISA Publicly Exposed.
"""

import argparse
import csv
import hashlib
import json
from collections import Counter
from pathlib import Path

from cvss_v4_official import CvssV4Error, score_record

CRITICALITY = {"MISSION_CRITICAL", "HIGH", "MODERATE", "LOW"}
INTERNET = {"YES", "NO"}
PUBLICLY_EXPOSED = {"YES", "NO"}
SECURITY_REQUIREMENT = {"X", "L", "M", "H"}
BUNDLE_V4 = "RBVM_CUSTOMER_ASSET_BUNDLE_V4"
BUNDLE_V3 = "RBVM_CUSTOMER_ASSET_BUNDLE_V3"
BUNDLE_V2 = "RBVM_CUSTOMER_ASSET_BUNDLE_V2"
ENV_SOURCE = "CUSTOMER_DECLARED_CVSS_V4_SECURITY_REQUIREMENTS"
PUBLICLY_EXPOSED_SOURCE = "CUSTOMER_DECLARED_CISA_PUBLICLY_EXPOSED"

ANALYSIS_COLUMNS = [
    "Customer_Context_Status", "Asset_Criticality", "Internet_Facing", "Publicly_Exposed",
    "CVSS4_Threat_E_Status", "CVSS4_Threat_E_Resolved",
    "CVSS4_CR_Resolved", "CVSS4_IR_Resolved", "CVSS4_AR_Resolved", "CVSS4_MAV_Resolved",
    "CVSS4_Environmental_Requirement_Status", "CVSS4_Environmental_Requirement_Source",
    "CVSS4_Context_Mode", "CVSS4_Context_Score_Status", "CVSS4_Context_Nomenclature",
    "CVSS4_Context_Vector", "CVSS4_Context_Score", "CVSS4_Context_Severity",
    "RBVM_V2_Status", "RBVM_V2_Blockers",
]


def args():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("enriched_csv", type=Path)
    p.add_argument("analysis_csv", type=Path)
    p.add_argument("summary_json", type=Path)
    p.add_argument("--customer-bundle", type=Path)
    return p.parse_args()


def canonical_sha(value):
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def norm(value):
    return str(value or "").strip().casefold()


def read_csv(path):
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        headers = list(reader.fieldnames or [])
        required = {"CVE_ID", "CVSS4_Status", "EPSS_Probability", "KEV_Listed"}
        missing = sorted(required - set(headers))
        if missing:
            raise RuntimeError("enriched CSV missing required columns: " + ", ".join(missing))
        collisions = sorted(set(headers) & set(ANALYSIS_COLUMNS))
        if collisions:
            raise RuntimeError("analysis columns already exist: " + ", ".join(collisions))
        return headers, list(reader)


def requirement(asset, field, index, enabled):
    if not enabled:
        return "X"
    value = str(asset.get(field) or "X").strip().upper()
    if value not in SECURITY_REQUIREMENT:
        raise RuntimeError(f"customer asset {index} has invalid {field}; expected X/L/M/H")
    return value


def customer_binary(asset, field, index, enabled, allowed, label):
    if not enabled:
        return "UNKNOWN"
    value = str(asset.get(field) or "UNKNOWN").strip().upper()
    if value != "UNKNOWN" and value not in allowed:
        raise RuntimeError(f"customer asset {index} has invalid {label}; expected UNKNOWN/YES/NO")
    return value


def load_bundle(path):
    if not path:
        return [], None, None, None
    value = json.loads(path.read_text(encoding="utf-8"))
    contract_id = value.get("contractId")
    schema_version = value.get("schemaVersion")
    supported = {(BUNDLE_V4, 4), (BUNDLE_V3, 3), (BUNDLE_V2, 2)}
    if (contract_id, schema_version) not in supported:
        raise RuntimeError("expected RBVM_CUSTOMER_ASSET_BUNDLE_V4 schemaVersion 4, V3 schemaVersion 3, or legacy V2 schemaVersion 2")
    environmental_enabled = contract_id in {BUNDLE_V4, BUNDLE_V3}
    publicly_exposed_enabled = contract_id == BUNDLE_V4
    assets = value.get("assets")
    if not isinstance(assets, list):
        raise RuntimeError("customer bundle assets must be an array")
    normalized = []
    for index, asset in enumerate(assets, 1):
        if not isinstance(asset, dict):
            raise RuntimeError(f"customer asset {index} must be an object")
        key = str(asset.get("customerAssetKey") or "").strip()
        name = str(asset.get("displayName") or "").strip()
        criticality = str(asset.get("assetCriticality") or "UNKNOWN").upper()
        internet = str(asset.get("internetFacing") or "UNKNOWN").upper()
        if criticality != "UNKNOWN" and criticality not in CRITICALITY:
            raise RuntimeError(f"customer asset {index} has invalid criticality")
        if internet != "UNKNOWN" and internet not in INTERNET:
            raise RuntimeError(f"customer asset {index} has invalid internetFacing")
        publicly_exposed = customer_binary(
            asset, "publiclyExposed", index, publicly_exposed_enabled, PUBLICLY_EXPOSED, "publiclyExposed"
        )
        normalized.append({
            "customerAssetKey": key,
            "displayName": name,
            "assetCriticality": criticality,
            "internetFacing": internet,
            "publiclyExposed": publicly_exposed,
            "cvssConfidentialityRequirement": requirement(asset, "cvssConfidentialityRequirement", index, environmental_enabled),
            "cvssIntegrityRequirement": requirement(asset, "cvssIntegrityRequirement", index, environmental_enabled),
            "cvssAvailabilityRequirement": requirement(asset, "cvssAvailabilityRequirement", index, environmental_enabled),
        })
    return normalized, canonical_sha(value), contract_id, schema_version


def build_asset_indexes(assets):
    by_key, by_name, duplicate_names = {}, {}, set()
    for asset in assets:
        if asset["customerAssetKey"]:
            by_key[asset["customerAssetKey"]] = asset
        name = norm(asset["displayName"])
        if name:
            if name in by_name:
                duplicate_names.add(name)
            else:
                by_name[name] = asset
    for name in duplicate_names:
        by_name[name] = None
    return by_key, by_name


def match_asset(row, by_key, by_name):
    for key_field in ("Agent_ID", "Asset_ID"):
        value = str(row.get(key_field) or "").strip()
        if value and value in by_key:
            return by_key[value], "MATCHED_KEY"
    for name_field in ("Agent", "Asset_Name", "Hostname"):
        name = norm(row.get(name_field))
        if name and name in by_name:
            asset = by_name[name]
            return (asset, "MATCHED_NAME") if asset else (None, "AMBIGUOUS_NAME")
    return None, "MISSING"


def is_true(value):
    return str(value or "").strip().lower() in {"true", "1", "yes", "listed"}


def resolve_threat_e(row):
    if row.get("CVSS4_Status") != "PRESENT":
        return "MISSING_BASE", ""
    published = str(row.get("CVSS4_E") or "").strip().upper()
    kev = is_true(row.get("KEV_Listed"))
    if published and published != "X":
        if kev and published != "A":
            return "AMBIGUOUS_CONFLICT", ""
        return "PRESENT_PUBLISHED", published
    if kev:
        return "PRESENT_KEV_ATTESTED", "A"
    return "NOT_DEFINED", "X"


def environmental_requirements(asset):
    if not asset:
        return "X", "X", "X", "NO_MATCHED_CUSTOMER_CONTEXT", ""
    cr = asset["cvssConfidentialityRequirement"]
    ir = asset["cvssIntegrityRequirement"]
    ar = asset["cvssAvailabilityRequirement"]
    defined = [value for value in (cr, ir, ar) if value != "X"]
    if not defined:
        return cr, ir, ar, "NOT_DEFINED", ""
    status = "COMPLETE" if len(defined) == 3 else "PARTIAL"
    return cr, ir, ar, status, ENV_SOURCE


def append_environmental(vector, cr, ir, ar):
    result = str(vector or "").strip()
    for key, value in (("CR", cr), ("IR", ir), ("AR", ar)):
        if value != "X":
            result += f"/{key}:{value}"
    return result


def score_context(row, cr, ir, ar, environmental_status):
    public_status = str(row.get("CVSS4_Calculated_Status") or "")
    if public_status == "AMBIGUOUS_THREAT_CONFLICT":
        return {
            "CVSS4_Context_Score_Status": "AMBIGUOUS_THREAT_CONFLICT",
            "CVSS4_Context_Nomenclature": "", "CVSS4_Context_Vector": "",
            "CVSS4_Context_Score": "", "CVSS4_Context_Severity": "",
        }
    if public_status != "CALCULATED":
        return {
            "CVSS4_Context_Score_Status": public_status or "NOT_APPLICABLE",
            "CVSS4_Context_Nomenclature": "", "CVSS4_Context_Vector": "",
            "CVSS4_Context_Score": "", "CVSS4_Context_Severity": "",
        }

    public_vector = str(row.get("CVSS4_Calculated_Vector") or "").strip()
    if environmental_status in {"NOT_DEFINED", "NO_MATCHED_CUSTOMER_CONTEXT"}:
        return {
            "CVSS4_Context_Score_Status": "CALCULATED_FIRST_REFERENCE_COMPATIBLE",
            "CVSS4_Context_Nomenclature": str(row.get("CVSS4_Calculated_Nomenclature") or ""),
            "CVSS4_Context_Vector": public_vector,
            "CVSS4_Context_Score": str(row.get("CVSS4_Calculated_Score") or ""),
            "CVSS4_Context_Severity": str(row.get("CVSS4_Calculated_Severity") or ""),
        }

    contextual_vector = append_environmental(public_vector, cr, ir, ar)
    try:
        calculated = score_record(contextual_vector)
    except CvssV4Error:
        return {
            "CVSS4_Context_Score_Status": "ENGINE_REJECTED_ENVIRONMENTAL_VECTOR",
            "CVSS4_Context_Nomenclature": "", "CVSS4_Context_Vector": contextual_vector,
            "CVSS4_Context_Score": "", "CVSS4_Context_Severity": "",
        }
    return {
        "CVSS4_Context_Score_Status": "CALCULATED_FIRST_REFERENCE_COMPATIBLE",
        "CVSS4_Context_Nomenclature": calculated["nomenclature"],
        "CVSS4_Context_Vector": calculated["vector"],
        "CVSS4_Context_Score": str(calculated["score"]),
        "CVSS4_Context_Severity": calculated["severity"],
    }


def context_mode(score):
    nomenclature = score.get("CVSS4_Context_Nomenclature")
    return {
        "CVSS-B": "B_ONLY",
        "CVSS-BT": "BT",
        "CVSS-BE": "BE",
        "CVSS-BTE": "BTE",
    }.get(nomenclature, "UNAVAILABLE")


def analyze_row(row, asset, context_status):
    threat_status, threat_e = resolve_threat_e(row)
    criticality = asset["assetCriticality"] if asset else "UNKNOWN"
    internet = asset["internetFacing"] if asset else "UNKNOWN"
    publicly_exposed = asset["publiclyExposed"] if asset else "UNKNOWN"
    cr, ir, ar, environmental_status, environmental_source = environmental_requirements(asset)
    mav = "X"
    score = score_context(row, cr, ir, ar, environmental_status)
    mode = context_mode(score)

    blockers = ["ORGANIZATIONAL_RISK_COMPOSITION_POLICY_NOT_APPROVED"]
    if row.get("CVSS4_Status") != "PRESENT": blockers.append("CVSS4_BASE_NOT_PRESENT")
    if not str(row.get("EPSS_Probability") or "").strip(): blockers.append("EPSS_MISSING")
    if context_status not in {"MATCHED_KEY", "MATCHED_NAME"}: blockers.append("CUSTOMER_CONTEXT_NOT_MATCHED")
    if criticality == "UNKNOWN": blockers.append("ASSET_CRITICALITY_UNKNOWN")
    if internet == "UNKNOWN": blockers.append("INTERNET_FACING_UNKNOWN")
    if environmental_status in {"NOT_DEFINED", "NO_MATCHED_CUSTOMER_CONTEXT"}: blockers.append("CVSS4_SECURITY_REQUIREMENTS_NOT_DEFINED")
    blockers.append("INTERNET_FACING_NOT_EQUIVALENT_TO_MAV")

    result = {
        "Customer_Context_Status": context_status,
        "Asset_Criticality": criticality,
        "Internet_Facing": internet,
        "Publicly_Exposed": publicly_exposed,
        "CVSS4_Threat_E_Status": threat_status,
        "CVSS4_Threat_E_Resolved": threat_e,
        "CVSS4_CR_Resolved": cr,
        "CVSS4_IR_Resolved": ir,
        "CVSS4_AR_Resolved": ar,
        "CVSS4_MAV_Resolved": mav,
        "CVSS4_Environmental_Requirement_Status": environmental_status,
        "CVSS4_Environmental_Requirement_Source": environmental_source,
        "CVSS4_Context_Mode": mode,
        "RBVM_V2_Status": "NON_COMPUTABLE",
        "RBVM_V2_Blockers": "|".join(blockers),
    }
    result.update(score)
    return result


def write_csv(path, headers, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=headers)
        writer.writeheader()
        writer.writerows(rows)


def main():
    a = args()
    headers, rows = read_csv(a.enriched_csv)
    assets, bundle_sha, bundle_contract, bundle_schema = load_bundle(a.customer_bundle)
    by_key, by_name = build_asset_indexes(assets)
    output = []
    context_counts = Counter()
    cvss_counts = Counter()
    calculated_counts = Counter()
    threat_counts = Counter()
    environmental_counts = Counter()
    publicly_exposed_counts = Counter()
    mode_counts = Counter()
    contextual_nomenclature_counts = Counter()

    for row in rows:
        asset, context_status = match_asset(row, by_key, by_name)
        extra = analyze_row(row, asset, context_status)
        joined = dict(row)
        joined.update(extra)
        output.append(joined)
        context_counts[context_status] += 1
        cvss_counts[str(row.get("CVSS4_Status") or "MISSING")] += 1
        calculated_counts[str(row.get("CVSS4_Calculated_Status") or "LEGACY_NOT_CALCULATED")] += 1
        threat_counts[extra["CVSS4_Threat_E_Status"]] += 1
        environmental_counts[extra["CVSS4_Environmental_Requirement_Status"]] += 1
        publicly_exposed_counts[extra["Publicly_Exposed"]] += 1
        mode_counts[extra["CVSS4_Context_Mode"]] += 1
        contextual_nomenclature_counts[extra["CVSS4_Context_Nomenclature"] or "NONE"] += 1

    write_csv(a.analysis_csv, headers + ANALYSIS_COLUMNS, output)
    unique_cves = len({str(row.get("CVE_ID") or "") for row in rows if row.get("CVE_ID")})
    unique_assets = len({str(row.get("Agent") or row.get("Agent_ID") or "") for row in rows if row.get("Agent") or row.get("Agent_ID")})
    epss_present = sum(bool(str(row.get("EPSS_Probability") or "").strip()) for row in rows)
    kev_listed = sum(is_true(row.get("KEV_Listed")) for row in rows)
    ssvc_present = sum(any(str(row.get(k) or "").strip() for k in ("CISA_Exploitation", "CISA_Automatable", "CISA_Technical_Impact")) for row in rows)
    complete_context = sum(
        row["Customer_Context_Status"] in {"MATCHED_KEY", "MATCHED_NAME"}
        and row["Asset_Criticality"] != "UNKNOWN"
        and row["Internet_Facing"] != "UNKNOWN"
        for row in output
    )
    environmental_defined = sum(row["CVSS4_Environmental_Requirement_Status"] in {"PARTIAL", "COMPLETE"} for row in output)
    contextual_calculated = sum(row["CVSS4_Context_Score_Status"] == "CALCULATED_FIRST_REFERENCE_COMPATIBLE" for row in output)

    summary = {
        "contractId": "CSV_RUN_EVIDENCE_ANALYSIS_V3",
        "source": {
            "enrichedCsv": a.enriched_csv.name,
            "customerBundle": a.customer_bundle.name if a.customer_bundle else None,
            "customerBundleSha256": bundle_sha,
            "customerBundleContractId": bundle_contract,
            "customerBundleSchemaVersion": bundle_schema,
        },
        "scope": {"findingRows": len(rows), "uniqueCves": unique_cves, "uniqueAssets": unique_assets},
        "coverage": {
            "cvss4Status": dict(sorted(cvss_counts.items())),
            "cvss4CalculatedStatus": dict(sorted(calculated_counts.items())),
            "epssPresentRows": epss_present,
            "kevListedRows": kev_listed,
            "cisaSsvcPresentRows": ssvc_present,
            "customerContextStatus": dict(sorted(context_counts.items())),
            "customerContextCompleteRows": complete_context,
            "publiclyExposedStatus": dict(sorted(publicly_exposed_counts.items())),
            "environmentalRequirementStatus": dict(sorted(environmental_counts.items())),
            "environmentalRequirementDefinedRows": environmental_defined,
            "contextualCvssCalculatedRows": contextual_calculated,
            "contextualNomenclature": dict(sorted(contextual_nomenclature_counts.items())),
        },
        "cisaBodCustomerContext": {
            "publiclyExposedSemanticId": "cisa:PE:1.0.0",
            "source": PUBLICLY_EXPOSED_SOURCE,
            "internetFacingMapping": "FORBIDDEN",
            "legacyBundleUpgrade": "V2/V3 -> publiclyExposed=UNKNOWN",
        },
        "cvss4Context": {
            "resolverContractId": "CVSS_V4_CONTEXT_RESOLVER_V2",
            "threatEResolutionStatus": dict(sorted(threat_counts.items())),
            "environmentalRequirementStatus": dict(sorted(environmental_counts.items())),
            "mode": dict(sorted(mode_counts.items())),
            "calculator": "FIRST_REFERENCE_COMPATIBLE_V4_0",
            "environmentalPolicy": "CR/IR/AR are accepted only as direct customer CVSS X/L/M/H declarations; Asset Criticality is not mapped; MAV remains X and Internet Facing is not mapped",
        },
        "benchmarkFields": [
            "Severity", "CVSS4_Base_Score", "CVSS4_Base_Severity", "CVSS4_Calculated_Nomenclature", "CVSS4_Calculated_Score", "CVSS4_Calculated_Severity",
            "CVSS4_CR_Resolved", "CVSS4_IR_Resolved", "CVSS4_AR_Resolved", "CVSS4_Context_Nomenclature", "CVSS4_Context_Score", "CVSS4_Context_Severity",
            "EPSS_Probability", "KEV_Listed", "CISA_Exploitation", "CISA_Automatable", "CISA_Technical_Impact", "Asset_Criticality", "Internet_Facing", "Publicly_Exposed",
        ],
        "rbvmV2": {
            "status": "NON_COMPUTABLE",
            "reason": "Contextual CVSS severity can now be calculated when direct CR/IR/AR evidence exists, but no approved authoritative composition maps contextual severity + EPSS + KEV + organization context to Organizational Risk",
            "riskComputedRows": 0,
        },
    }
    summary["analysisSha256"] = canonical_sha(summary)
    a.summary_json.parent.mkdir(parents=True, exist_ok=True)
    a.summary_json.write_text(json.dumps(summary, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    main()
