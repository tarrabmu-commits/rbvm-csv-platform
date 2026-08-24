#!/usr/bin/env python3
"""Build PUBLIC_CVE_INTEL_SNAPSHOT_V1 from a V30 local-intelligence export.

This adapter performs no network I/O. It reuses the established collector normalization
functions so the CSV enrichment contract does not fork its NVD/CVE Program semantics.
"""

import argparse
import base64
import csv
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import re

CVE_RE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
PROVIDERS = ("NVD", "FIRST_EPSS", "CISA_KEV", "CVE_PROGRAM")
EXPORT_CONTRACT = "CSV_FIRST_LOCAL_PUBLIC_INTELLIGENCE_EXPORT_V1"
SNAPSHOT_CONTRACT = "PUBLIC_CVE_INTEL_SNAPSHOT_V1"


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("export", type=Path, help="CSV_FIRST_LOCAL_PUBLIC_INTELLIGENCE_EXPORT_V1 directory")
    parser.add_argument("output", type=Path, help="PUBLIC_CVE_INTEL_SNAPSHOT_V1 output JSON")
    parser.add_argument("--report", type=Path, help="optional local snapshot build report")
    parser.add_argument("--observed-at", help="fixed ISO-8601 snapshot observation time")
    return parser.parse_args()


def observation_time(value):
    if not value:
        return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise RuntimeError("--observed-at must include a timezone")
    return parsed.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_json(value):
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def write_json_atomic(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
    temporary.replace(path)


def load_collector():
    path = Path(__file__).resolve().with_name("collect-public-vulnerability-intel.py")
    spec = importlib.util.spec_from_file_location("rbvm_public_intel_collector", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load public-intelligence normalization module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_properties(path):
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"missing regular export manifest: {path}")
    result = {}
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        if "=" not in line:
            raise RuntimeError(f"invalid export manifest line {number}")
        key, value = line.split("=", 1)
        if not key or key in result:
            raise RuntimeError(f"invalid/duplicate export manifest key at line {number}")
        result[key] = value
    if result.get("contractId") != EXPORT_CONTRACT:
        raise RuntimeError("unexpected local public-intelligence export contract")
    return result


def load_requested_cves(path):
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("requested-cves.txt is missing")
    cves = []
    seen = set()
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        value = line.strip().upper()
        if not value:
            continue
        if not CVE_RE.fullmatch(value):
            raise RuntimeError(f"invalid requested CVE at line {number}: {value!r}")
        if value in seen:
            raise RuntimeError(f"duplicate requested CVE: {value}")
        seen.add(value)
        cves.append(value)
    if cves != sorted(cves):
        raise RuntimeError("requested CVEs must be sorted for deterministic local snapshots")
    return cves


def load_provider_status(path):
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("provider-status.tsv is missing")
    result = {}
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle, delimiter="\t")
        expected = [
            "Provider", "Has_Success", "Safe_Negative_Absence", "Success_ID", "Sync_Mode", "Source_URI",
            "Source_Version", "Source_SHA256", "Source_Published_At", "Observed_At",
            "Completed_At", "Record_Count",
        ]
        if reader.fieldnames != expected:
            raise RuntimeError("unexpected provider-status.tsv headers")
        for row in reader:
            provider = row["Provider"]
            if provider not in PROVIDERS or provider in result:
                raise RuntimeError(f"invalid/duplicate provider status: {provider!r}")
            has_success = row["Has_Success"].lower()
            safe_negative = row["Safe_Negative_Absence"].lower()
            if has_success not in {"true", "false"}:
                raise RuntimeError(f"invalid Has_Success for {provider}")
            if safe_negative not in {"true", "false"}:
                raise RuntimeError(f"invalid Safe_Negative_Absence for {provider}")
            if safe_negative == "true" and (provider != "CISA_KEV" or has_success != "true"):
                raise RuntimeError("safe negative absence is valid only for a successful validated CISA KEV catalog")
            if has_success == "true":
                if not row["Success_ID"] or not row["Source_URI"] or not row["Source_Version"]:
                    raise RuntimeError(f"successful provider {provider} is missing source identity")
                if not SHA256_RE.fullmatch(row["Source_SHA256"]):
                    raise RuntimeError(f"successful provider {provider} has invalid source SHA-256")
            result[provider] = {
                **row,
                "hasSuccess": has_success == "true",
                "safeNegativeAbsence": safe_negative == "true",
            }
    if set(result) != set(PROVIDERS):
        raise RuntimeError("provider-status.tsv must contain all four public-intelligence providers")
    return result


def decode_payload(value, cve, provider):
    try:
        raw = base64.b64decode(value, validate=True)
        payload = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError(f"invalid local payload for {provider} {cve}") from error
    if not isinstance(payload, dict):
        raise RuntimeError(f"local payload for {provider} {cve} must be a JSON object")
    return payload


def validate_payload_identity(provider, cve, payload):
    if provider == "NVD":
        claimed = payload.get("id")
    elif provider == "FIRST_EPSS":
        claimed = payload.get("cve")
    elif provider == "CISA_KEV":
        claimed = payload.get("cveID")
    else:
        metadata = payload.get("cveMetadata") if isinstance(payload.get("cveMetadata"), dict) else {}
        claimed = metadata.get("cveId")
    if str(claimed or "").strip().upper() != cve:
        raise RuntimeError(f"local payload CVE identity mismatch for {provider} {cve}")


def load_records(path, requested):
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("records.tsv is missing")
    result = {cve: {} for cve in requested}
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle, delimiter="\t")
        expected = [
            "CVE_ID", "Provider", "Payload_Base64", "Record_SHA256", "Source_Modified_At",
            "Source_Published_At", "Record_Observed_At", "Sync_Run_ID", "Sync_Mode", "Source_URI",
            "Source_Version", "Source_SHA256", "Run_Observed_At", "Run_Completed_At",
        ]
        if reader.fieldnames != expected:
            raise RuntimeError("unexpected records.tsv headers")
        for row in reader:
            cve = row["CVE_ID"].strip().upper()
            provider = row["Provider"]
            if cve not in result:
                raise RuntimeError(f"local record is outside requested CVE scope: {cve}")
            if provider not in PROVIDERS or provider in result[cve]:
                raise RuntimeError(f"invalid/duplicate local provider record: {provider} {cve}")
            if not SHA256_RE.fullmatch(row["Record_SHA256"]):
                raise RuntimeError(f"invalid record SHA-256 for {provider} {cve}")
            if not SHA256_RE.fullmatch(row["Source_SHA256"]):
                raise RuntimeError(f"invalid source SHA-256 for {provider} {cve}")
            payload = decode_payload(row["Payload_Base64"], cve, provider)
            validate_payload_identity(provider, cve, payload)
            result[cve][provider] = {"payload": payload, "metadata": row}
    return result


def normalize_epss(payload):
    return {
        "probability": payload.get("epss"),
        "percentile": payload.get("percentile"),
        "scoreDate": payload.get("scoreDate"),
    }


def normalize_kev(payload):
    return {
        "listed": True,
        "dateAdded": payload.get("dateAdded"),
        "dueDate": payload.get("dueDate"),
        "vendorProject": payload.get("vendorProject"),
        "product": payload.get("product"),
        "vulnerabilityName": payload.get("vulnerabilityName"),
        "requiredAction": payload.get("requiredAction"),
        "knownRansomwareCampaignUse": payload.get("knownRansomwareCampaignUse"),
        "notes": payload.get("notes"),
    }


def record_provenance(records):
    values = []
    for provider in PROVIDERS:
        entry = records.get(provider)
        if entry is None:
            continue
        row = entry["metadata"]
        values.append({
            "provider": provider,
            "recordSha256": row["Record_SHA256"],
            "recordObservedAt": row["Record_Observed_At"] or None,
            "syncRunId": row["Sync_Run_ID"],
            "syncMode": row["Sync_Mode"],
            "sourceUri": row["Source_URI"],
            "sourceVersion": row["Source_Version"],
            "sourceSha256": row["Source_SHA256"],
            "runObservedAt": row["Run_Observed_At"] or None,
            "runCompletedAt": row["Run_Completed_At"] or None,
        })
    return values


def main():
    args = arguments()
    export = args.export
    if export.is_symlink() or not export.is_dir():
        raise RuntimeError("local public-intelligence export must be a regular directory")
    manifest = load_properties(export / "export.properties")
    cves = load_requested_cves(export / "requested-cves.txt")
    status = load_provider_status(export / "provider-status.tsv")
    records = load_records(export / "records.tsv", set(cves))
    collector = load_collector()
    observed_at = observation_time(args.observed_at)

    coverage = {"nvd": 0, "cvssV4": 0, "epss": 0, "kevListed": 0, "cveServices": 0, "cisaSsvc": 0}
    snapshot_records = []
    source_hashes = {provider: set() for provider in PROVIDERS}

    cisa_complete = status["CISA_KEV"]["safeNegativeAbsence"]
    for cve in cves:
        local = records[cve]
        for provider, entry in local.items():
            source_hashes[provider].add(entry["metadata"]["Source_SHA256"])

        nvd_entry = local.get("NVD")
        epss_entry = local.get("FIRST_EPSS")
        kev_entry = local.get("CISA_KEV")
        cve_entry = local.get("CVE_PROGRAM")

        nvd = collector.nvd_normalized(nvd_entry["payload"]) if nvd_entry else None
        epss = normalize_epss(epss_entry["payload"]) if epss_entry else None
        if kev_entry:
            kev = normalize_kev(kev_entry["payload"])
        elif cisa_complete:
            kev = {"listed": False}
        else:
            kev = None
        cve_program = collector.cve_program_normalized(cve_entry["payload"]) if cve_entry else None

        if nvd:
            coverage["nvd"] += 1
        if epss:
            coverage["epss"] += 1
        if kev and kev.get("listed"):
            coverage["kevListed"] += 1
        if cve_program and not cve_program.get("error"):
            coverage["cveServices"] += 1
            cisa = cve_program.get("cisaVulnrichment")
            if isinstance(cisa, dict) and cisa.get("ssvc"):
                coverage["cisaSsvc"] += 1
        if bool(nvd and nvd.get("cvssV4Assessments")) or bool(
            cve_program and cve_program.get("cvssV4Assessments")
        ):
            coverage["cvssV4"] += 1

        snapshot_records.append({
            "cveId": cve,
            "nvd": nvd,
            "epss": epss,
            "cisaKev": kev,
            "cveProgram": cve_program,
            "provenance": {
                "cveServicesResponseSha256": None,
                "localPublicIntelligenceRecords": record_provenance(local),
            },
        })

    provider_status = {}
    sources = {}
    for provider in PROVIDERS:
        row = status[provider]
        provider_status[provider] = {
            "hasSuccessfulSnapshot": row["hasSuccess"],
            "safeNegativeAbsence": row["safeNegativeAbsence"],
            "successId": row["Success_ID"] or None,
            "syncMode": row["Sync_Mode"] or None,
            "sourceUri": row["Source_URI"] or None,
            "sourceVersion": row["Source_Version"] or None,
            "sourceSha256": row["Source_SHA256"] or None,
            "sourcePublishedAt": row["Source_Published_At"] or None,
            "observedAt": row["Observed_At"] or None,
            "completedAt": row["Completed_At"] or None,
            "recordCount": int(row["Record_Count"]) if row["Record_Count"] else None,
        }
        sources[provider] = row["Source_URI"] or None

    cisa_status = provider_status["CISA_KEV"]
    snapshot = {
        "schemaVersion": 1,
        "contractId": SNAPSHOT_CONTRACT,
        "semantics": "AUTOMATED_PUBLIC_VULNERABILITY_INTELLIGENCE_WITH_PROVIDER_PROVENANCE",
        "observedAt": observed_at,
        "acquisition": {
            "mode": "LOCAL_V30_STORE",
            "exportContractId": EXPORT_CONTRACT,
            "providerStatus": provider_status,
            "cisaKevNegativeSemantics": "NOT_LISTED_ONLY_AFTER_COMPLETE_VALIDATED_CATALOG",
        },
        "sources": {
            "nvd": sources["NVD"],
            "epss": sources["FIRST_EPSS"],
            "cisaKev": sources["CISA_KEV"],
            "cveServices": sources["CVE_PROGRAM"],
        },
        "providerResponseSha256": {
            "nvd": sorted(source_hashes["NVD"]),
            "epss": sorted(source_hashes["FIRST_EPSS"]),
            "cisaKev": cisa_status["sourceSha256"],
            "cveServices": {},
        },
        "cisaKevCatalog": {
            "catalogVersion": cisa_status["sourceVersion"],
            "dateReleased": cisa_status["sourcePublishedAt"],
            "count": cisa_status["recordCount"],
            "completeValidatedCatalogAvailable": cisa_complete,
        },
        "inputRows": None,
        "uniqueCves": len(cves),
        "coverage": coverage,
        "records": snapshot_records,
    }
    snapshot["snapshotSha256"] = sha256_json(snapshot)
    write_json_atomic(args.output, snapshot)

    expected_unique = int(manifest.get("uniqueCves", "-1"))
    if expected_unique != len(cves):
        raise RuntimeError(
            f"local export manifest uniqueCves={expected_unique} does not match requested scope={len(cves)}"
        )
    report = {
        "status": "COMPLETE",
        "contractId": SNAPSHOT_CONTRACT,
        "acquisitionMode": "LOCAL_V30_STORE",
        "observedAt": observed_at,
        "uniqueCves": len(cves),
        "providerRecords": int(manifest.get("providerRecords", "0")),
        "providersWithSuccessfulSnapshot": int(manifest.get("providersWithSuccessfulSnapshot", "0")),
        "coverage": coverage,
        "output": str(args.output),
        "snapshotSha256": snapshot["snapshotSha256"],
    }
    if args.report:
        write_json_atomic(args.report, report)
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
