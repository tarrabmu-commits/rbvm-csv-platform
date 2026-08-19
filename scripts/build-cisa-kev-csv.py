#!/usr/bin/env python3
"""Build CISA_KEV_CSV_V1 for input CVEs from a validated CISA KEV snapshot artifact."""

import argparse
import csv
from datetime import date, datetime
import json
from pathlib import Path
import re

CISA_KEV_JSON = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
CVE_PATTERN = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")
HEADERS = [
    "CVE_ID",
    "KEV_Status",
    "KEV_Catalog_Version",
    "KEV_Catalog_SHA256",
    "KEV_Catalog_Count",
    "KEV_Source",
    "KEV_Observed_At",
    "KEV_Date_Added",
    "KEV_Due_Date",
    "Known_Ransomware_Campaign_Use",
]


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="CSV containing a CVE_ID column")
    parser.add_argument("snapshot", type=Path, help="CISA_KEV_VALIDATED_SNAPSHOT JSON")
    parser.add_argument("output", type=Path, help="CISA_KEV_CSV_V1 output")
    parser.add_argument("--report", type=Path, help="optional atomic JSON build report")
    return parser.parse_args()


def require_regular(path, name):
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"{name} must be a regular non-symlink file")


def input_cves(path):
    require_regular(path, "input")
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if "CVE_ID" not in (reader.fieldnames or []):
            raise RuntimeError("input CSV must contain a CVE_ID header")
        logical_rows = 0
        values = set()
        invalid = []
        for row_number, row in enumerate(reader, 2):
            logical_rows += 1
            cve = (row.get("CVE_ID") or "").strip().upper()
            if not CVE_PATTERN.fullmatch(cve):
                invalid.append((row_number, cve))
                continue
            values.add(cve)
    if invalid:
        preview = ", ".join(f"row {row}: {value or '<blank>'}" for row, value in invalid[:10])
        raise RuntimeError(f"input contains invalid CVE_ID values: {preview}")
    return logical_rows, sorted(values)


def require_text(value, field):
    if not isinstance(value, str) or not value.strip():
        raise RuntimeError(f"snapshot {field} must be a non-blank string")
    return value.strip()


def require_timestamp(value, field):
    text = require_text(value, field)
    parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise RuntimeError(f"snapshot {field} must include a timezone")
    return text


def require_date(value, field):
    text = require_text(value, field)
    date.fromisoformat(text)
    return text


def validated_snapshot(path):
    require_regular(path, "snapshot")
    try:
        root = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("snapshot must be valid UTF-8 JSON") from error
    if not isinstance(root, dict):
        raise RuntimeError("snapshot root must be an object")
    if root.get("schemaVersion") != 1:
        raise RuntimeError("snapshot schemaVersion must be 1")
    if root.get("artifactType") != "CISA_KEV_VALIDATED_SNAPSHOT":
        raise RuntimeError("snapshot artifactType must be CISA_KEV_VALIDATED_SNAPSHOT")
    if root.get("complete") is not True:
        raise RuntimeError("snapshot must be marked complete")
    source = require_text(root.get("source"), "source")
    if source != CISA_KEV_JSON:
        raise RuntimeError("snapshot source must be the pinned official CISA KEV JSON feed")
    catalog_version = require_text(root.get("catalogVersion"), "catalogVersion")
    observed_at = require_timestamp(root.get("observedAt"), "observedAt")
    sha256 = require_text(root.get("sha256"), "sha256").lower()
    if not SHA256_PATTERN.fullmatch(sha256):
        raise RuntimeError("snapshot sha256 must be 64 lowercase hexadecimal characters")
    declared = root.get("declaredCount")
    parsed = root.get("parsedCount")
    vulnerabilities = root.get("vulnerabilities")
    if isinstance(declared, bool) or not isinstance(declared, int) or declared <= 0:
        raise RuntimeError("snapshot declaredCount must be a positive integer")
    if isinstance(parsed, bool) or not isinstance(parsed, int) or parsed <= 0:
        raise RuntimeError("snapshot parsedCount must be a positive integer")
    if declared != parsed:
        raise RuntimeError("snapshot declaredCount must equal parsedCount")
    if not isinstance(vulnerabilities, list) or len(vulnerabilities) != parsed:
        raise RuntimeError("snapshot vulnerabilities length must equal parsedCount")

    by_cve = {}
    for index, item in enumerate(vulnerabilities):
        if not isinstance(item, dict):
            raise RuntimeError(f"snapshot vulnerabilities[{index}] must be an object")
        cve = require_text(item.get("cveId"), f"vulnerabilities[{index}].cveId").upper()
        if not CVE_PATTERN.fullmatch(cve):
            raise RuntimeError(f"snapshot vulnerabilities[{index}].cveId is invalid")
        if cve in by_cve:
            raise RuntimeError(f"snapshot contains duplicate CVE_ID: {cve}")
        ransomware = require_text(
            item.get("knownRansomwareCampaignUse"),
            f"vulnerabilities[{index}].knownRansomwareCampaignUse",
        )
        if ransomware not in {"KNOWN", "UNKNOWN"}:
            raise RuntimeError("snapshot ransomware use must be KNOWN or UNKNOWN")
        by_cve[cve] = {
            "dateAdded": require_date(item.get("dateAdded"), f"vulnerabilities[{index}].dateAdded"),
            "dueDate": require_date(item.get("dueDate"), f"vulnerabilities[{index}].dueDate"),
            "ransomware": ransomware,
        }

    return {
        "catalogVersion": catalog_version,
        "source": source,
        "observedAt": observed_at,
        "sha256": sha256,
        "count": parsed,
        "byCve": by_cve,
    }


def evidence_rows(cves, snapshot):
    rows = []
    listed = 0
    not_listed = 0
    for cve in cves:
        item = snapshot["byCve"].get(cve)
        row = {
            "CVE_ID": cve,
            "KEV_Status": "LISTED" if item else "NOT_LISTED",
            "KEV_Catalog_Version": snapshot["catalogVersion"],
            "KEV_Catalog_SHA256": snapshot["sha256"],
            "KEV_Catalog_Count": str(snapshot["count"]),
            "KEV_Source": snapshot["source"],
            "KEV_Observed_At": snapshot["observedAt"],
            "KEV_Date_Added": item["dateAdded"] if item else "",
            "KEV_Due_Date": item["dueDate"] if item else "",
            "Known_Ransomware_Campaign_Use": item["ransomware"] if item else "",
        }
        rows.append(row)
        if item:
            listed += 1
        else:
            not_listed += 1
    return rows, listed, not_listed


def write_csv(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=HEADERS, extrasaction="raise")
        writer.writeheader()
        writer.writerows(rows)
    temporary.replace(path)


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def main():
    args = arguments()
    logical_rows, cves = input_cves(args.input)
    snapshot = validated_snapshot(args.snapshot)
    rows, listed, not_listed = evidence_rows(cves, snapshot)
    write_csv(args.output, rows)

    report = {
        "schemaVersion": 1,
        "status": "COMPLETE",
        "contractId": "CISA_KEV_CSV_V1",
        "semantics": "CVE_SCOPED_CISA_KEV_SNAPSHOT_MEMBERSHIP_EVIDENCE",
        "inputRows": logical_rows,
        "uniqueCves": len(cves),
        "listed": listed,
        "notListed": not_listed,
        "unknownRowsEmitted": 0,
        "catalogVersion": snapshot["catalogVersion"],
        "catalogSha256": snapshot["sha256"],
        "catalogCount": snapshot["count"],
        "source": snapshot["source"],
        "observedAt": snapshot["observedAt"],
    }
    if args.report:
        write_json(args.report, report)
    print(
        f"contract=CISA_KEV_CSV_V1 unique_cves={len(cves)} "
        f"listed={listed} not_listed={not_listed} output={args.output}"
    )


if __name__ == "__main__":
    main()
