#!/usr/bin/env python3
"""Send validated EPSS_CSV_V1 evidence to the platform's canonical transactional importer."""

import argparse
import csv
from datetime import date, datetime
from decimal import Decimal, InvalidOperation
import json
import os
from pathlib import Path
import re
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

DEFAULT_API_BASE = "http://127.0.0.1:8080"
DEFAULT_MAX_BYTES = 32 * 1024 * 1024
MAX_RESPONSE_BYTES = 1024 * 1024
EXPECTED_CONTRACT = "EPSS_CSV_V1"
EXPECTED_SEMANTICS = "CVE_SCOPED_FIRST_EPSS_PROBABILITY_EVIDENCE"
EPSS_SOURCE = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
CVE_PATTERN = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
MODEL_PATTERN = re.compile(r"^v?[0-9]{4}\.[0-9]{2}\.[0-9]{2}$")
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
    parser.add_argument("input", type=Path, help="canonical EPSS_CSV_V1 file")
    parser.add_argument(
        "--api-base",
        default=os.environ.get("RBVM_API_BASE_URL", DEFAULT_API_BASE),
        help="platform origin; remote endpoints must use HTTPS",
    )
    parser.add_argument("--report", type=Path, help="write the import response atomically")
    parser.add_argument(
        "--max-bytes",
        type=int,
        default=int(os.environ.get("RBVM_EPSS_MAX_BYTES", DEFAULT_MAX_BYTES)),
    )
    return parser.parse_args()


def require_probability(value, field, row_number):
    try:
        number = Decimal(value)
    except (InvalidOperation, TypeError) as error:
        raise RuntimeError(f"row {row_number} {field} must be a decimal") from error
    if not number.is_finite() or number < 0 or number > 1:
        raise RuntimeError(f"row {row_number} {field} must be between 0 and 1")


def require_timestamp(value, field, row_number):
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise RuntimeError(f"row {row_number} {field} must be ISO-8601") from error
    if parsed.tzinfo is None:
        raise RuntimeError(f"row {row_number} {field} must include a timezone")


def validate_contract(path, max_bytes):
    if max_bytes < 1024:
        raise RuntimeError("--max-bytes must be at least 1024")
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("input must be a regular non-symlink file")
    size = path.stat().st_size
    if size <= 0:
        raise RuntimeError("input must not be empty")
    if size > max_bytes:
        raise RuntimeError(f"input exceeds configured maximum of {max_bytes} bytes")

    try:
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            if reader.fieldnames != HEADERS:
                raise RuntimeError("input headers must exactly match EPSS_CSV_V1")
            rows = 0
            for row_number, row in enumerate(reader, 2):
                rows += 1
                if None in row:
                    raise RuntimeError(f"row {row_number} contains unexpected extra fields")
                values = {field: (row.get(field) or "").strip() for field in HEADERS}
                missing = [field for field, value in values.items() if not value]
                if missing:
                    raise RuntimeError(f"row {row_number} is missing required values: {missing}")
                cve = values["CVE_ID"].upper()
                if not CVE_PATTERN.fullmatch(cve):
                    raise RuntimeError(f"row {row_number} CVE_ID is invalid")
                require_probability(values["EPSS_Probability"], "EPSS_Probability", row_number)
                require_probability(values["EPSS_Percentile"], "EPSS_Percentile", row_number)
                if not MODEL_PATTERN.fullmatch(values["EPSS_Model_Version"]):
                    raise RuntimeError(f"row {row_number} EPSS_Model_Version is invalid")
                try:
                    date.fromisoformat(values["EPSS_Score_Date"])
                except ValueError as error:
                    raise RuntimeError(
                        f"row {row_number} EPSS_Score_Date must be an ISO-8601 date"
                    ) from error
                if values["EPSS_Source"] != EPSS_SOURCE:
                    raise RuntimeError(f"row {row_number} EPSS_Source must be the pinned FIRST bulk feed")
                require_timestamp(values["EPSS_Observed_At"], "EPSS_Observed_At", row_number)
                if not SHA256_PATTERN.fullmatch(values["EPSS_Source_SHA256"]):
                    raise RuntimeError(f"row {row_number} EPSS_Source_SHA256 is invalid")
    except UnicodeDecodeError as error:
        raise RuntimeError("input must be valid UTF-8") from error
    if rows <= 0:
        raise RuntimeError("EPSS_CSV_V1 must contain at least one evidence row")
    return size, rows


def endpoint(api_base):
    parsed = urlparse(api_base)
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise RuntimeError("API base URL must not contain credentials, query, or fragment")
    if parsed.path not in {"", "/"}:
        raise RuntimeError("API base URL must be an origin without an application path")
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise RuntimeError("API base URL must be an absolute HTTP(S) URL")
    localhost = parsed.hostname.lower() in {"127.0.0.1", "localhost", "::1"}
    if parsed.scheme != "https" and not localhost:
        raise RuntimeError("remote API base URL must use HTTPS")
    return api_base.rstrip("/") + "/api/v1/epss-imports"


def write_json(path, value):
    if path.is_symlink():
        raise RuntimeError("report path must not be a symlink")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    if temporary.is_symlink():
        raise RuntimeError("temporary report path must not be a symlink")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def bounded_response(response):
    payload = response.read(MAX_RESPONSE_BYTES + 1)
    if len(payload) > MAX_RESPONSE_BYTES:
        raise RuntimeError("EPSS import response exceeds the configured safety bound")
    return payload


def require_non_negative_integer(result, field):
    value = result.get(field)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise RuntimeError(f"EPSS import response field {field} is invalid")
    return value


def validate_result(result):
    if not isinstance(result, dict):
        raise RuntimeError("EPSS import response must be a JSON object")
    if result.get("contractId") != EXPECTED_CONTRACT:
        raise RuntimeError("EPSS import response contractId does not match EPSS_CSV_V1")
    if result.get("semantics") != EXPECTED_SEMANTICS:
        raise RuntimeError("EPSS import response semantics do not match the canonical contract")

    accepted = require_non_negative_integer(result, "acceptedRows")
    inserted = require_non_negative_integer(result, "insertedEvidence")
    replayed = require_non_negative_integer(result, "replayedEvidence")
    persistence_quarantined = require_non_negative_integer(result, "persistenceQuarantinedRows")
    contract_quarantined = require_non_negative_integer(result, "contractQuarantinedRows")
    total_quarantined = require_non_negative_integer(result, "totalQuarantinedRows")
    require_non_negative_integer(result, "insertedSnapshots")
    require_non_negative_integer(result, "replayedSnapshots")
    require_non_negative_integer(result, "snapshotConflictGroups")
    require_non_negative_integer(result, "uniqueCves")
    require_non_negative_integer(result, "uniqueSnapshots")

    if accepted != inserted + replayed + persistence_quarantined:
        raise RuntimeError("EPSS import response acceptedRows accounting is inconsistent")
    if total_quarantined != contract_quarantined + persistence_quarantined:
        raise RuntimeError("EPSS import response quarantine accounting is inconsistent")
    return result


def import_evidence(path, api_base, api_key, max_bytes):
    validate_contract(path, max_bytes)
    if not api_key or not api_key.strip():
        raise RuntimeError("RBVM_EPSS_API_KEY is required")

    body = path.read_bytes()
    request = Request(
        endpoint(api_base),
        data=body,
        method="POST",
        headers={
            "Authorization": "Bearer " + api_key.strip(),
            "Content-Type": "text/csv; charset=utf-8",
            "Accept": "application/json",
            "User-Agent": "rbvm-csv-platform/0.15 epss-safe-handoff",
        },
    )
    try:
        with urlopen(request, timeout=60) as response:
            status = response.status
            payload = bounded_response(response)
    except HTTPError as error:
        raise RuntimeError(f"EPSS import returned HTTP {error.code}") from error
    except URLError as error:
        raise RuntimeError(f"EPSS import connection failed: {error.reason}") from error

    if status != 200:
        raise RuntimeError(f"EPSS import returned unexpected HTTP {status}")
    try:
        result = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("EPSS import returned invalid JSON") from error
    return validate_result(result)


def main():
    args = arguments()
    result = import_evidence(
        args.input,
        args.api_base,
        os.environ.get("RBVM_EPSS_API_KEY"),
        args.max_bytes,
    )
    if args.report:
        write_json(args.report, result)

    inserted = int(result["insertedEvidence"])
    replayed = int(result["replayedEvidence"])
    quarantined = int(result["totalQuarantinedRows"])
    snapshots = int(result["insertedSnapshots"]) + int(result["replayedSnapshots"])
    print(
        f"epss_import=COMPLETE snapshots={snapshots} inserted={inserted} "
        f"replayed={replayed} quarantined={quarantined}"
    )


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"epss_import=FAILED error={error}", file=sys.stderr)
        raise SystemExit(1)
