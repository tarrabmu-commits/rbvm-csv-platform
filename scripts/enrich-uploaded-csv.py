#!/usr/bin/env python3
"""Enrich one uploaded CSV from public CVE intelligence without tenant/database state.

The input CSV is the complete workload scope for one run. Every original row and
column is preserved, public intelligence is resolved only for CVE_ID values in
that file, and normalized evidence is merged back by CVE_ID. CVSS v4 scores are
recalculated with the local FIRST-reference-compatible engine; no customer
Criticality/Internet Facing values are converted into CVSS Environmental metrics.
"""

import argparse
import csv
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

from cvss_v4_official import CvssV4Error, score_record

CVE_PATTERN = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
BASE_KEYS = ("AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA")
THREAT_KEYS = ("E",)
ENV_KEYS = ("CR", "IR", "AR", "MAV", "MAC", "MAT", "MPR", "MUI", "MVC", "MVI", "MVA", "MSC", "MSI", "MSA")
SUPP_KEYS = ("S", "AU", "R", "V", "RE", "U")

ENRICHMENT_HEADERS = [
    "CVSS4_Status", "CVSS4_Assessment_Count", "CVSS4_Semantic_Assessment_Count",
    "CVSS4_Source", "CVSS4_Source_Type", "CVSS4_Vector", "CVSS4_Base_Score", "CVSS4_Base_Severity",
    "CVSS4_Base_Score_Calculated", "CVSS4_Base_Score_Validation",
    "CVSS4_Calculated_Status", "CVSS4_Calculated_Nomenclature", "CVSS4_Calculated_Vector",
    "CVSS4_Calculated_Score", "CVSS4_Calculated_Severity", "CVSS4_Calculated_Macro_Vector",
    "CVSS4_Threat_E_Resolution",
    *[f"CVSS4_{key}" for key in BASE_KEYS],
    *[f"CVSS4_{key}" for key in THREAT_KEYS],
    *[f"CVSS4_{key}" for key in ENV_KEYS],
    *[f"CVSS4_{key}" for key in SUPP_KEYS],
    "CVSS4_Assessments_JSON",
    "EPSS_Probability", "EPSS_Percentile", "EPSS_Score_Date",
    "KEV_Listed", "KEV_Date_Added", "KEV_Due_Date", "KEV_Vendor_Project",
    "KEV_Product", "KEV_Vulnerability_Name", "KEV_Known_Ransomware_Campaign_Use",
    "KEV_Required_Action", "KEV_Notes",
    "CISA_Exploitation", "CISA_Automatable", "CISA_Technical_Impact",
    "CISA_SSVC_Version", "CISA_SSVC_Timestamp",
    "NVD_Published", "NVD_Last_Modified", "NVD_Status", "NVD_Source_Identifier",
    "NVD_Description", "CWE_JSON", "CPE_Criteria_JSON", "NVD_References_JSON",
    "CVE_State", "CVE_Assigner", "CNA_Provider", "CNA_Title",
    "Intel_Observed_At", "Public_Intel_Snapshot_SHA256", "CVE_Services_Response_SHA256",
]


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="input CSV; must contain CVE_ID")
    parser.add_argument("output", type=Path, help="enriched CSV output")
    parser.add_argument("--snapshot-output", type=Path, help="public intelligence snapshot JSON")
    parser.add_argument("--report", type=Path, help="CSV-first run report JSON")
    parser.add_argument("--collector-report", type=Path, help="underlying public-intel collector report")
    parser.add_argument("--cache-dir", type=Path, default=Path("data/public-cve-intel-cache"))
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--observed-at")
    parser.add_argument("--skip-cve-services", action="store_true")
    parser.add_argument(
        "--intel-snapshot", type=Path,
        help="use an existing PUBLIC_CVE_INTEL_SNAPSHOT_V1 instead of calling providers; replay/testing only",
    )
    return parser.parse_args()


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def sha256_json(value):
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def json_cell(value):
    if value is None:
        return ""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def text(value):
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def is_true(value):
    return str(value or "").strip().lower() in {"true", "1", "yes", "listed"}


def read_input(path):
    if not path.is_file() or path.is_symlink():
        raise RuntimeError("input must be a regular non-symlink CSV file")
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        headers = list(reader.fieldnames or [])
        if "CVE_ID" not in headers:
            raise RuntimeError("input CSV must contain a CVE_ID header")
        collisions = sorted(set(headers) & set(ENRICHMENT_HEADERS))
        if collisions:
            raise RuntimeError("input already contains reserved enrichment columns: " + ", ".join(collisions))
        rows, cves, invalid = [], set(), []
        for number, row in enumerate(reader, 2):
            cve = (row.get("CVE_ID") or "").strip().upper()
            if not CVE_PATTERN.fullmatch(cve):
                invalid.append((number, cve))
            else:
                row["CVE_ID"] = cve
                cves.add(cve)
            rows.append(row)
    if invalid:
        preview = ", ".join(f"row {n}: {v or '<blank>'}" for n, v in invalid[:10])
        raise RuntimeError(f"invalid CVE_ID values: {preview}")
    return headers, rows, sorted(cves)


def default_sidecar(output, suffix):
    return output.with_name(output.name + suffix)


def run_collector(args, snapshot_path, collector_report):
    collector = Path(__file__).resolve().with_name("collect-public-vulnerability-intel.py")
    command = [sys.executable, str(collector), str(args.input), str(snapshot_path), "--cache-dir", str(args.cache_dir)]
    if collector_report:
        command.extend(["--report", str(collector_report)])
    if args.offline:
        command.append("--offline")
    if args.observed_at:
        command.extend(["--observed-at", args.observed_at])
    if args.skip_cve_services:
        command.append("--skip-cve-services")
    subprocess.run(command, check=True)


def load_snapshot(path, expected_cves):
    try:
        snapshot = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError(f"invalid public intelligence snapshot: {path}") from error
    if snapshot.get("contractId") != "PUBLIC_CVE_INTEL_SNAPSHOT_V1":
        raise RuntimeError("unexpected public intelligence snapshot contract")
    claimed_sha = snapshot.get("snapshotSha256")
    if not isinstance(claimed_sha, str) or not SHA256_PATTERN.fullmatch(claimed_sha):
        raise RuntimeError("public intelligence snapshot is missing a valid snapshotSha256")
    unhashed = dict(snapshot)
    unhashed.pop("snapshotSha256", None)
    if sha256_json(unhashed) != claimed_sha:
        raise RuntimeError("public intelligence snapshot SHA-256 verification failed")
    records = snapshot.get("records")
    if not isinstance(records, list):
        raise RuntimeError("public intelligence snapshot records must be an array")
    by_cve = {}
    for record in records:
        if not isinstance(record, dict):
            raise RuntimeError("public intelligence records must be objects")
        cve = str(record.get("cveId") or "").strip().upper()
        if not CVE_PATTERN.fullmatch(cve) or cve in by_cve:
            raise RuntimeError("public intelligence snapshot has invalid/duplicate CVE records")
        by_cve[cve] = record
    if set(by_cve) != set(expected_cves):
        missing = sorted(set(expected_cves) - set(by_cve))
        extra = sorted(set(by_cve) - set(expected_cves))
        raise RuntimeError(f"snapshot CVE scope differs from input; missing={missing[:5]} extra={extra[:5]}")
    return snapshot, by_cve


def source_assessments(record):
    values = []
    nvd = record.get("nvd") if isinstance(record.get("nvd"), dict) else {}
    cve_program = record.get("cveProgram") if isinstance(record.get("cveProgram"), dict) else {}
    for candidate in (nvd.get("cvssV4Assessments"), cve_program.get("cvssV4Assessments")):
        if isinstance(candidate, list):
            values.extend(item for item in candidate if isinstance(item, dict))
    return values


def distinct_assessments(record):
    unique = {}
    for assessment in source_assessments(record):
        canonical = json.dumps(assessment, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        unique[canonical] = assessment
    return [unique[key] for key in sorted(unique)]


def semantic_assessment_groups(assessments):
    groups = {}
    for assessment in assessments:
        key = (text(assessment.get("vector")), text(assessment.get("baseScore")), text(assessment.get("baseSeverity")))
        groups.setdefault(key, []).append(assessment)
    return groups


def cvss_columns(record):
    assessments = distinct_assessments(record)
    groups = semantic_assessment_groups(assessments)
    result = {
        "CVSS4_Assessment_Count": str(len(assessments)),
        "CVSS4_Semantic_Assessment_Count": str(len(groups)),
        "CVSS4_Assessments_JSON": json_cell(assessments),
    }
    if not groups:
        result["CVSS4_Status"] = "MISSING"
        return result
    if len(groups) > 1:
        result["CVSS4_Status"] = "AMBIGUOUS"
        return result

    equivalent = next(iter(groups.values()))
    assessment = equivalent[0]
    sources = sorted({text(item.get("source")) for item in equivalent if text(item.get("source"))})
    source_types = sorted({text(item.get("type")) for item in equivalent if text(item.get("type"))})
    result.update({
        "CVSS4_Status": "PRESENT",
        "CVSS4_Source": " | ".join(sources),
        "CVSS4_Source_Type": " | ".join(source_types),
        "CVSS4_Vector": text(assessment.get("vector")),
        "CVSS4_Base_Score": text(assessment.get("baseScore")),
        "CVSS4_Base_Severity": text(assessment.get("baseSeverity")),
    })
    metrics = assessment.get("metrics") if isinstance(assessment.get("metrics"), dict) else {}
    for family in ("base", "threat", "environmental", "supplemental"):
        values = metrics.get(family) if isinstance(metrics.get(family), dict) else {}
        for key, value in values.items():
            header = f"CVSS4_{key}"
            if header in ENRICHMENT_HEADERS:
                result[header] = text(value)
    return result


def cisa_ssvc(cve_program):
    if not isinstance(cve_program, dict):
        return {}
    cisa = cve_program.get("cisaVulnrichment")
    if not isinstance(cisa, dict):
        return {}
    ssvc = cisa.get("ssvc")
    return ssvc if isinstance(ssvc, dict) else {}


def base_vector(columns):
    values = []
    for key in BASE_KEYS:
        value = str(columns.get(f"CVSS4_{key}") or "").strip().upper()
        if not value:
            return ""
        values.append(f"{key}:{value}")
    return "CVSS:4.0/" + "/".join(values)


def calculated_cvss_columns(columns):
    result = {
        "CVSS4_Base_Score_Calculated": "", "CVSS4_Base_Score_Validation": "",
        "CVSS4_Calculated_Status": "", "CVSS4_Calculated_Nomenclature": "",
        "CVSS4_Calculated_Vector": "", "CVSS4_Calculated_Score": "",
        "CVSS4_Calculated_Severity": "", "CVSS4_Calculated_Macro_Vector": "",
        "CVSS4_Threat_E_Resolution": "",
    }
    status = str(columns.get("CVSS4_Status") or "")
    if status != "PRESENT":
        result["CVSS4_Calculated_Status"] = status or "MISSING"
        return result

    vector = base_vector(columns)
    if not vector:
        result["CVSS4_Calculated_Status"] = "INVALID_BASE_METRICS"
        return result
    try:
        base_result = score_record(vector)
    except CvssV4Error:
        result["CVSS4_Calculated_Status"] = "ENGINE_REJECTED_BASE"
        return result

    result["CVSS4_Base_Score_Calculated"] = text(base_result["score"])
    published = str(columns.get("CVSS4_Base_Score") or "").strip()
    if not published:
        result["CVSS4_Base_Score_Validation"] = "PUBLISHED_SCORE_MISSING"
    else:
        try:
            result["CVSS4_Base_Score_Validation"] = "MATCH" if float(published) == float(base_result["score"]) else "MISMATCH"
        except ValueError:
            result["CVSS4_Base_Score_Validation"] = "PUBLISHED_SCORE_INVALID"

    published_e = str(columns.get("CVSS4_E") or "").strip().upper()
    kev = is_true(columns.get("KEV_Listed"))
    scoring_vector = vector
    if published_e and published_e != "X":
        if kev and published_e != "A":
            result["CVSS4_Calculated_Status"] = "AMBIGUOUS_THREAT_CONFLICT"
            result["CVSS4_Threat_E_Resolution"] = f"PUBLISHED_{published_e}_CONFLICT_KEV"
            return result
        scoring_vector += f"/E:{published_e}"
        result["CVSS4_Threat_E_Resolution"] = "PUBLISHED"
    elif kev:
        scoring_vector += "/E:A"
        result["CVSS4_Threat_E_Resolution"] = "KEV_ATTESTED"
    else:
        result["CVSS4_Threat_E_Resolution"] = "NOT_DEFINED"

    try:
        calculated = score_record(scoring_vector)
    except CvssV4Error:
        result["CVSS4_Calculated_Status"] = "ENGINE_REJECTED_VECTOR"
        return result
    result.update({
        "CVSS4_Calculated_Status": "CALCULATED",
        "CVSS4_Calculated_Nomenclature": calculated["nomenclature"],
        "CVSS4_Calculated_Vector": calculated["vector"],
        "CVSS4_Calculated_Score": text(calculated["score"]),
        "CVSS4_Calculated_Severity": calculated["severity"],
        "CVSS4_Calculated_Macro_Vector": calculated["macroVector"],
    })
    return result


def enrichment_columns(record, snapshot):
    result = {header: "" for header in ENRICHMENT_HEADERS}
    result.update(cvss_columns(record))
    nvd = record.get("nvd") if isinstance(record.get("nvd"), dict) else {}
    epss = record.get("epss") if isinstance(record.get("epss"), dict) else {}
    kev = record.get("cisaKev") if isinstance(record.get("cisaKev"), dict) else {}
    cve_program = record.get("cveProgram") if isinstance(record.get("cveProgram"), dict) else {}
    cve_metadata = cve_program.get("metadata") if isinstance(cve_program.get("metadata"), dict) else {}
    cna = cve_program.get("cna") if isinstance(cve_program.get("cna"), dict) else {}
    ssvc = cisa_ssvc(cve_program)
    provenance = record.get("provenance") if isinstance(record.get("provenance"), dict) else {}
    descriptions = nvd.get("descriptions") if isinstance(nvd.get("descriptions"), list) else []
    result.update({
        "EPSS_Probability": text(epss.get("probability")), "EPSS_Percentile": text(epss.get("percentile")), "EPSS_Score_Date": text(epss.get("scoreDate")),
        "KEV_Listed": text(kev.get("listed")), "KEV_Date_Added": text(kev.get("dateAdded")), "KEV_Due_Date": text(kev.get("dueDate")),
        "KEV_Vendor_Project": text(kev.get("vendorProject")), "KEV_Product": text(kev.get("product")), "KEV_Vulnerability_Name": text(kev.get("vulnerabilityName")),
        "KEV_Known_Ransomware_Campaign_Use": text(kev.get("knownRansomwareCampaignUse")), "KEV_Required_Action": text(kev.get("requiredAction")), "KEV_Notes": text(kev.get("notes")),
        "CISA_Exploitation": text(ssvc.get("exploitation")), "CISA_Automatable": text(ssvc.get("automatable")), "CISA_Technical_Impact": text(ssvc.get("technicalImpact")),
        "CISA_SSVC_Version": text(ssvc.get("version")), "CISA_SSVC_Timestamp": text(ssvc.get("timestamp")),
        "NVD_Published": text(nvd.get("published")), "NVD_Last_Modified": text(nvd.get("lastModified")), "NVD_Status": text(nvd.get("vulnStatus")),
        "NVD_Source_Identifier": text(nvd.get("sourceIdentifier")), "NVD_Description": text(descriptions[0]) if descriptions else "",
        "CWE_JSON": json_cell(nvd.get("weaknesses") or []), "CPE_Criteria_JSON": json_cell(nvd.get("cpeCriteria") or []), "NVD_References_JSON": json_cell(nvd.get("references") or []),
        "CVE_State": text(cve_metadata.get("state")), "CVE_Assigner": text(cve_metadata.get("assignerShortName") or cve_metadata.get("assignerOrgId")),
        "CNA_Provider": text(cna.get("providerShortName") or cna.get("providerOrgId")), "CNA_Title": text(cna.get("title")),
        "Intel_Observed_At": text(snapshot.get("observedAt")), "Public_Intel_Snapshot_SHA256": text(snapshot.get("snapshotSha256")),
        "CVE_Services_Response_SHA256": text(provenance.get("cveServicesResponseSha256")),
    })
    result.update(calculated_cvss_columns(result))
    return result


def write_csv(path, headers, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=headers, extrasaction="raise")
        writer.writeheader()
        writer.writerows(rows)
    temporary.replace(path)


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
    temporary.replace(path)


def main():
    args = arguments()
    headers, rows, cves = read_input(args.input)
    input_sha = sha256_file(args.input)
    snapshot_path = args.snapshot_output or default_sidecar(args.output, ".public-intel.json")
    collector_report = args.collector_report or default_sidecar(args.output, ".public-intel.report.json")
    if args.intel_snapshot:
        snapshot_path = args.intel_snapshot
    else:
        run_collector(args, snapshot_path, collector_report)
    snapshot, by_cve = load_snapshot(snapshot_path, cves)
    enriched_rows = []
    cvss_status = {"PRESENT": 0, "MISSING": 0, "AMBIGUOUS": 0}
    calculated_status = {}
    base_validation = {}
    for row in rows:
        columns = enrichment_columns(by_cve[row["CVE_ID"]], snapshot)
        cvss_status[columns["CVSS4_Status"]] += 1
        calculated_status[columns["CVSS4_Calculated_Status"]] = calculated_status.get(columns["CVSS4_Calculated_Status"], 0) + 1
        validation = columns["CVSS4_Base_Score_Validation"] or "NOT_APPLICABLE"
        base_validation[validation] = base_validation.get(validation, 0) + 1
        merged = dict(row)
        merged.update(columns)
        enriched_rows.append(merged)
    write_csv(args.output, headers + ENRICHMENT_HEADERS, enriched_rows)
    report = {
        "schemaVersion": 2,
        "contractId": "CSV_FIRST_PUBLIC_INTELLIGENCE_ENRICHMENT_V1",
        "status": "COMPLETE", "input": str(args.input), "inputSha256": input_sha, "inputRows": len(rows), "uniqueCves": len(cves),
        "output": str(args.output), "outputSha256": sha256_file(args.output),
        "publicIntelSnapshot": str(snapshot_path), "publicIntelSnapshotSha256": snapshot.get("snapshotSha256"), "observedAt": snapshot.get("observedAt"),
        "cvssV4RowStatus": cvss_status, "cvssV4CalculatedStatus": dict(sorted(calculated_status.items())),
        "cvssV4BaseScoreValidation": dict(sorted(base_validation.items())),
        "cvssV4Calculator": "FIRST_REFERENCE_COMPATIBLE_V4_0", "databaseStateUsed": False, "scope": "INPUT_CSV_ONLY",
    }
    report_path = args.report or default_sidecar(args.output, ".report.json")
    write_json(report_path, report)
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
