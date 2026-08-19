#!/usr/bin/env python3
"""Build EPSS_CSV_V1 from a FIRST_EPSS_VALIDATED_SNAPSHOT artifact."""

import argparse
import csv
from datetime import date, datetime
from decimal import Decimal, InvalidOperation
import json
from pathlib import Path
import re
from urllib.parse import urlparse

EPSS_CURRENT_CSV_GZ = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
CVE_PATTERN = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
MODEL_VERSION_PATTERN = re.compile(r"^v?[0-9]{4}\.[0-9]{2}\.[0-9]{2}$")
SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")
HEADERS = [
    "CVE_ID",
    "EPSS_Probability",
    "EPSS_Percentile",
    "EPSS_Model_Version",
    "EPSS_Score_Date",
    "EPSS_Source",
    "EPSS_Observed_At",
    "EPSS_Source_SHA256",
]


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("snapshot", type=Path, help="FIRST_EPSS_VALIDATED_SNAPSHOT JSON")
    parser.add_argument("output", type=Path, help="EPSS_CSV_V1 output")
    parser.add_argument("--report", type=Path, help="optional atomic JSON build report")
    return parser.parse_args()


def require_regular(path, name):
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"{name} must be a regular non-symlink file")


def require_text(value, field):
    if not isinstance(value, str) or not value.strip():
        raise RuntimeError(f"snapshot {field} must be a non-blank string")
    return value.strip()


def require_timestamp(value, field):
    text = require_text(value, field)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as error:
        raise RuntimeError(f"snapshot {field} must be an ISO-8601 timestamp") from error
    if parsed.tzinfo is None:
        raise RuntimeError(f"snapshot {field} must include a timezone")
    return text


def require_date(value, field):
    text = require_text(value, field)
    try:
        date.fromisoformat(text)
    except ValueError as error:
        raise RuntimeError(f"snapshot {field} must be an ISO-8601 date") from error
    return text


def require_count(value, field, *, positive=False):
    if isinstance(value, bool) or not isinstance(value, int):
        raise RuntimeError(f"snapshot {field} must be an integer")
    if value < 0 or (positive and value <= 0):
        qualifier = "positive" if positive else "non-negative"
        raise RuntimeError(f"snapshot {field} must be a {qualifier} integer")
    return value


def probability(value, field):
    text = require_text(value, field)
    try:
        number = Decimal(text)
    except InvalidOperation as error:
        raise RuntimeError(f"snapshot {field} must be a decimal") from error
    if not number.is_finite() or number < 0 or number > 1:
        raise RuntimeError(f"snapshot {field} must be between 0 and 1")
    return format(number.normalize(), "f") if number != 0 else "0"


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
    if root.get("artifactType") != "FIRST_EPSS_VALIDATED_SNAPSHOT":
        raise RuntimeError("snapshot artifactType must be FIRST_EPSS_VALIDATED_SNAPSHOT")
    if root.get("completeParse") is not True:
        raise RuntimeError("snapshot must be marked completeParse=true")

    source = require_text(root.get("source"), "source")
    if source != EPSS_CURRENT_CSV_GZ:
        raise RuntimeError("snapshot source must be the pinned official FIRST EPSS daily feed")
    resolved_source = require_text(root.get("resolvedSource"), "resolvedSource")
    parsed_resolved = urlparse(resolved_source)
    if parsed_resolved.scheme != "https" or not parsed_resolved.hostname:
        raise RuntimeError("snapshot resolvedSource must be a valid HTTPS URL")

    observed_at = require_timestamp(root.get("observedAt"), "observedAt")
    source_sha256 = require_text(root.get("sourceBytesSha256"), "sourceBytesSha256").lower()
    if not SHA256_PATTERN.fullmatch(source_sha256):
        raise RuntimeError("snapshot sourceBytesSha256 must be 64 hexadecimal characters")

    compressed_bytes = require_count(root.get("compressedBytes"), "compressedBytes", positive=True)
    decompressed_bytes = require_count(root.get("decompressedBytes"), "decompressedBytes", positive=True)
    model_version = require_text(root.get("modelVersion"), "modelVersion")
    if not MODEL_VERSION_PATTERN.fullmatch(model_version):
        raise RuntimeError("snapshot modelVersion is invalid")
    score_date = require_date(root.get("scoreDate"), "scoreDate")
    feed_rows = require_count(root.get("feedRowCount"), "feedRowCount", positive=True)
    input_rows = require_count(root.get("inputRows"), "inputRows", positive=True)
    requested = require_count(root.get("requestedCveCount"), "requestedCveCount", positive=True)
    scored = require_count(root.get("scoredCveCount"), "scoredCveCount")
    missing = require_count(root.get("missingCveCount"), "missingCveCount")
    if requested > input_rows:
        raise RuntimeError("snapshot requestedCveCount must not exceed inputRows")
    if scored + missing != requested:
        raise RuntimeError("snapshot scoredCveCount + missingCveCount must equal requestedCveCount")
    if scored > feed_rows:
        raise RuntimeError("snapshot scoredCveCount must not exceed feedRowCount")

    acquisition_mode = require_text(root.get("acquisitionMode"), "acquisitionMode")
    if acquisition_mode not in {"OFFICIAL_HTTPS", "OFFLINE_REPLAY"}:
        raise RuntimeError("snapshot acquisitionMode is invalid")

    scores = root.get("scores")
    missing_cves = root.get("missingCves")
    if not isinstance(scores, list) or len(scores) != scored:
        raise RuntimeError("snapshot scores length must equal scoredCveCount")
    if not isinstance(missing_cves, list) or len(missing_cves) != missing:
        raise RuntimeError("snapshot missingCves length must equal missingCveCount")

    by_cve = {}
    for index, item in enumerate(scores):
        if not isinstance(item, dict):
            raise RuntimeError(f"snapshot scores[{index}] must be an object")
        cve = require_text(item.get("cveId"), f"scores[{index}].cveId").upper()
        if not CVE_PATTERN.fullmatch(cve):
            raise RuntimeError(f"snapshot scores[{index}].cveId is invalid")
        if cve in by_cve:
            raise RuntimeError(f"snapshot scores contains duplicate CVE_ID: {cve}")
        by_cve[cve] = {
            "probability": probability(item.get("epss"), f"scores[{index}].epss"),
            "percentile": probability(item.get("percentile"), f"scores[{index}].percentile"),
        }

    missing_set = set()
    for index, value in enumerate(missing_cves):
        cve = require_text(value, f"missingCves[{index}]").upper()
        if not CVE_PATTERN.fullmatch(cve):
            raise RuntimeError(f"snapshot missingCves[{index}] is invalid")
        if cve in missing_set:
            raise RuntimeError(f"snapshot missingCves contains duplicate CVE_ID: {cve}")
        if cve in by_cve:
            raise RuntimeError(f"snapshot CVE cannot be both scored and missing: {cve}")
        missing_set.add(cve)

    if len(by_cve) + len(missing_set) != requested:
        raise RuntimeError("snapshot score and missing CVE identities must cover requestedCveCount")

    return {
        "source": source,
        "resolvedSource": resolved_source,
        "observedAt": observed_at,
        "sourceSha256": source_sha256,
        "compressedBytes": compressed_bytes,
        "decompressedBytes": decompressed_bytes,
        "modelVersion": model_version,
        "scoreDate": score_date,
        "feedRowCount": feed_rows,
        "inputRows": input_rows,
        "requestedCves": requested,
        "missingCves": sorted(missing_set),
        "scores": by_cve,
        "acquisitionMode": acquisition_mode,
    }


def evidence_rows(snapshot):
    rows = []
    for cve in sorted(snapshot["scores"]):
        score = snapshot["scores"][cve]
        rows.append({
            "CVE_ID": cve,
            "EPSS_Probability": score["probability"],
            "EPSS_Percentile": score["percentile"],
            "EPSS_Model_Version": snapshot["modelVersion"],
            "EPSS_Score_Date": snapshot["scoreDate"],
            "EPSS_Source": snapshot["source"],
            "EPSS_Observed_At": snapshot["observedAt"],
            "EPSS_Source_SHA256": snapshot["sourceSha256"],
        })
    return rows


def write_csv(path, rows):
    if path.is_symlink():
        raise RuntimeError("output path must not be a symlink")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    if temporary.is_symlink():
        raise RuntimeError("temporary output path must not be a symlink")
    with temporary.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=HEADERS, extrasaction="raise")
        writer.writeheader()
        writer.writerows(rows)
    temporary.replace(path)


def write_json(path, value):
    if path.is_symlink():
        raise RuntimeError("report path must not be a symlink")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    if temporary.is_symlink():
        raise RuntimeError("temporary report path must not be a symlink")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def main():
    args = arguments()
    snapshot = validated_snapshot(args.snapshot)
    rows = evidence_rows(snapshot)
    write_csv(args.output, rows)

    report = {
        "schemaVersion": 1,
        "status": "COMPLETE",
        "contractId": "EPSS_CSV_V1",
        "semantics": "CVE_SCOPED_FIRST_EPSS_PROBABILITY_EVIDENCE",
        "inputRows": snapshot["inputRows"],
        "requestedCves": snapshot["requestedCves"],
        "evidenceRows": len(rows),
        "missingEvidenceCves": len(snapshot["missingCves"]),
        "unknownRowsEmitted": 0,
        "modelVersion": snapshot["modelVersion"],
        "scoreDate": snapshot["scoreDate"],
        "source": snapshot["source"],
        "observedAt": snapshot["observedAt"],
        "sourceSha256": snapshot["sourceSha256"],
        "acquisitionMode": snapshot["acquisitionMode"],
    }
    if args.report:
        write_json(args.report, report)
    print(
        f"contract=EPSS_CSV_V1 requested={snapshot['requestedCves']} "
        f"evidence={len(rows)} missing={len(snapshot['missingCves'])} output={args.output}"
    )


if __name__ == "__main__":
    try:
        main()
    except Exception as error:  # operational CLI boundary
        print(f"epss_csv_build=FAILED error={error}", file=__import__("sys").stderr)
        raise SystemExit(1)
