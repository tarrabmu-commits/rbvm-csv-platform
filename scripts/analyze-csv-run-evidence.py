#!/usr/bin/env python3
"""Analyze one enriched CSV run without inventing organizational-risk math.

Inputs:
- enriched CSV produced by enrich-uploaded-csv.py
- optional RBVM_CUSTOMER_ASSET_BUNDLE_V2 JSON

Outputs:
- row-preserving evidence/benchmark CSV
- deterministic coverage/readiness JSON

CVSS technical severity, EPSS probability, KEV/SSVC threat signals, and customer
context remain separate. Official CVSS-B/CVSS-BT values calculated during CSV
enrichment are consumed as severity evidence only. Asset-level Internet Facing is
not converted to MAV, and scalar Asset Criticality is not converted to CR/IR/AR.
"""

import argparse
import csv
import hashlib
import json
from collections import Counter
from pathlib import Path

CRITICALITY = {"MISSION_CRITICAL", "HIGH", "MODERATE", "LOW"}
INTERNET = {"YES", "NO"}

ANALYSIS_COLUMNS = [
    "Customer_Context_Status", "Asset_Criticality", "Internet_Facing",
    "CVSS4_Threat_E_Status", "CVSS4_Threat_E_Resolved",
    "CVSS4_CR_Resolved", "CVSS4_IR_Resolved", "CVSS4_AR_Resolved", "CVSS4_MAV_Resolved",
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


def load_bundle(path):
    if not path:
        return [], None
    value = json.loads(path.read_text(encoding="utf-8"))
    if value.get("contractId") != "RBVM_CUSTOMER_ASSET_BUNDLE_V2" or value.get("schemaVersion") != 2:
        raise RuntimeError("expected RBVM_CUSTOMER_ASSET_BUNDLE_V2 schemaVersion 2")
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
        normalized.append({"customerAssetKey": key, "displayName": name, "assetCriticality": criticality, "internetFacing": internet})
    return normalized, canonical_sha(value)


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


def score_projection(row, mode):
    status = str(row.get("CVSS4_Calculated_Status") or "")
    if status == "CALCULATED":
        return {
            "CVSS4_Context_Score_Status": "CALCULATED_FIRST_REFERENCE_COMPATIBLE",
            "CVSS4_Context_Nomenclature": str(row.get("CVSS4_Calculated_Nomenclature") or ""),
            "CVSS4_Context_Vector": str(row.get("CVSS4_Calculated_Vector") or ""),
            "CVSS4_Context_Score": str(row.get("CVSS4_Calculated_Score") or ""),
            "CVSS4_Context_Severity": str(row.get("CVSS4_Calculated_Severity") or ""),
        }
    if status == "AMBIGUOUS_THREAT_CONFLICT":
        return {
            "CVSS4_Context_Score_Status": "AMBIGUOUS_THREAT_CONFLICT",
            "CVSS4_Context_Nomenclature": "", "CVSS4_Context_Vector": "",
            "CVSS4_Context_Score": "", "CVSS4_Context_Severity": "",
        }
    return {
        "CVSS4_Context_Score_Status": "NOT_CALCULATED_OFFICIAL_ENGINE_REQUIRED" if mode == "BT_INPUT_READY" else "NOT_APPLICABLE",
        "CVSS4_Context_Nomenclature": "", "CVSS4_Context_Vector": "",
        "CVSS4_Context_Score": "", "CVSS4_Context_Severity": "",
    }


def analyze_row(row, asset, context_status):
    threat_status, threat_e = resolve_threat_e(row)
    criticality = asset["assetCriticality"] if asset else "UNKNOWN"
    internet = asset["internetFacing"] if asset else "UNKNOWN"
    cr = ir = ar = mav = "X"
    if row.get("CVSS4_Status") != "PRESENT":
        mode = "UNAVAILABLE"
    elif threat_status.startswith("PRESENT"):
        mode = "BT_INPUT_READY"
    else:
        mode = "B_ONLY"

    blockers = ["ORGANIZATIONAL_RISK_COMPOSITION_POLICY_NOT_APPROVED"]
    if row.get("CVSS4_Status") != "PRESENT": blockers.append("CVSS4_BASE_NOT_PRESENT")
    if not str(row.get("EPSS_Probability") or "").strip(): blockers.append("EPSS_MISSING")
    if context_status not in {"MATCHED_KEY", "MATCHED_NAME"}: blockers.append("CUSTOMER_CONTEXT_NOT_MATCHED")
    if criticality == "UNKNOWN": blockers.append("ASSET_CRITICALITY_UNKNOWN")
    if internet == "UNKNOWN": blockers.append("INTERNET_FACING_UNKNOWN")
    blockers.extend(["CR_IR_AR_NOT_DEFINED", "INTERNET_FACING_NOT_EQUIVALENT_TO_MAV"])

    result = {
        "Customer_Context_Status": context_status, "Asset_Criticality": criticality, "Internet_Facing": internet,
        "CVSS4_Threat_E_Status": threat_status, "CVSS4_Threat_E_Resolved": threat_e,
        "CVSS4_CR_Resolved": cr, "CVSS4_IR_Resolved": ir, "CVSS4_AR_Resolved": ar, "CVSS4_MAV_Resolved": mav,
        "CVSS4_Context_Mode": mode, "RBVM_V2_Status": "NON_COMPUTABLE", "RBVM_V2_Blockers": "|".join(blockers),
    }
    result.update(score_projection(row, mode))
    return result


def write_csv(path, headers, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=headers)
        writer.writeheader(); writer.writerows(rows)


def main():
    a = args()
    headers, rows = read_csv(a.enriched_csv)
    assets, bundle_sha = load_bundle(a.customer_bundle)
    by_key, by_name = build_asset_indexes(assets)
    output = []
    context_counts, cvss_counts, calculated_counts, threat_counts, mode_counts = Counter(), Counter(), Counter(), Counter(), Counter()
    for row in rows:
        asset, context_status = match_asset(row, by_key, by_name)
        extra = analyze_row(row, asset, context_status)
        joined = dict(row); joined.update(extra); output.append(joined)
        context_counts[context_status] += 1
        cvss_counts[str(row.get("CVSS4_Status") or "MISSING")] += 1
        calculated_counts[str(row.get("CVSS4_Calculated_Status") or "LEGACY_NOT_CALCULATED")] += 1
        threat_counts[extra["CVSS4_Threat_E_Status"]] += 1
        mode_counts[extra["CVSS4_Context_Mode"]] += 1

    write_csv(a.analysis_csv, headers + ANALYSIS_COLUMNS, output)
    unique_cves = len({str(row.get("CVE_ID") or "") for row in rows if row.get("CVE_ID")})
    unique_assets = len({str(row.get("Agent") or row.get("Agent_ID") or "") for row in rows if row.get("Agent") or row.get("Agent_ID")})
    epss_present = sum(bool(str(row.get("EPSS_Probability") or "").strip()) for row in rows)
    kev_listed = sum(is_true(row.get("KEV_Listed")) for row in rows)
    ssvc_present = sum(any(str(row.get(k) or "").strip() for k in ("CISA_Exploitation", "CISA_Automatable", "CISA_Technical_Impact")) for row in rows)
    complete_context = sum(row["Customer_Context_Status"] in {"MATCHED_KEY", "MATCHED_NAME"} and row["Asset_Criticality"] != "UNKNOWN" and row["Internet_Facing"] != "UNKNOWN" for row in output)

    summary = {
        "contractId": "CSV_RUN_EVIDENCE_ANALYSIS_V1",
        "source": {"enrichedCsv": a.enriched_csv.name, "customerBundle": a.customer_bundle.name if a.customer_bundle else None, "customerBundleSha256": bundle_sha},
        "scope": {"findingRows": len(rows), "uniqueCves": unique_cves, "uniqueAssets": unique_assets},
        "coverage": {
            "cvss4Status": dict(sorted(cvss_counts.items())), "cvss4CalculatedStatus": dict(sorted(calculated_counts.items())),
            "epssPresentRows": epss_present, "kevListedRows": kev_listed, "cisaSsvcPresentRows": ssvc_present,
            "customerContextStatus": dict(sorted(context_counts.items())), "customerContextCompleteRows": complete_context,
        },
        "cvss4Context": {
            "threatEResolutionStatus": dict(sorted(threat_counts.items())), "mode": dict(sorted(mode_counts.items())),
            "calculator": "FIRST_REFERENCE_COMPATIBLE_V4_0",
            "environmentalPolicy": "CR/IR/AR/MAV remain X; scalar criticality and asset-level Internet Facing are not mapped",
        },
        "benchmarkFields": [
            "Severity", "CVSS4_Base_Score", "CVSS4_Base_Severity", "CVSS4_Calculated_Nomenclature", "CVSS4_Calculated_Score", "CVSS4_Calculated_Severity",
            "EPSS_Probability", "KEV_Listed", "CISA_Exploitation", "CISA_Automatable", "CISA_Technical_Impact", "Asset_Criticality", "Internet_Facing",
        ],
        "rbvmV2": {
            "status": "NON_COMPUTABLE",
            "reason": "No approved authoritative composition from CVSS severity + EPSS probability + KEV + scalar asset criticality + asset-level Internet Facing to organizational risk",
            "riskComputedRows": 0,
        },
    }
    summary["analysisSha256"] = canonical_sha(summary)
    a.summary_json.parent.mkdir(parents=True, exist_ok=True)
    a.summary_json.write_text(json.dumps(summary, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    main()
