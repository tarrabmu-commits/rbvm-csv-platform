#!/usr/bin/env python3
"""Fetch and validate the official FIRST EPSS daily bulk feed for requested CVEs."""

import argparse
import csv
from datetime import date, datetime, timezone
from decimal import Decimal, InvalidOperation
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
from urllib.parse import urlparse
from urllib.request import Request, urlopen

EPSS_CURRENT_CSV_GZ = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
CVE_PATTERN = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
MODEL_VERSION_PATTERN = re.compile(r"^v?[0-9]{4}\.[0-9]{2}\.[0-9]{2}$")
MODEL_VERSION_FIELD = re.compile(r"(?:^|,)\s*model_version\s*[:=]\s*([^,\s]+)", re.I)
SCORE_DATE_FIELD = re.compile(r"(?:^|,)\s*score_date\s*[:=]\s*([^,\s]+)", re.I)
MAX_COMPRESSED_BYTES = 32 * 1024 * 1024
MAX_DECOMPRESSED_BYTES = 96 * 1024 * 1024
EXPECTED_HEADERS = ["cve", "epss", "percentile"]


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="CSV containing a CVE_ID column")
    parser.add_argument("output", type=Path, help="FIRST_EPSS_VALIDATED_SNAPSHOT JSON output")
    parser.add_argument("--observed-at", help="fixed ISO-8601 time for deterministic replay/testing")
    parser.add_argument(
        "--offline-input",
        type=Path,
        help="parse a local epss_scores-*.csv.gz file through the same validation path",
    )
    return parser.parse_args()


def require_regular(path, name):
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"{name} must be a regular non-symlink file")


def observation_time(value):
    if not value:
        return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise RuntimeError("--observed-at must be an ISO-8601 timestamp") from error
    if parsed.tzinfo is None:
        raise RuntimeError("--observed-at must include a timezone")
    return parsed.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


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
    if not values:
        raise RuntimeError("input contains no valid CVE_ID values")
    return logical_rows, sorted(values)


def fetch_official_bytes():
    request = Request(
        EPSS_CURRENT_CSV_GZ,
        headers={
            "Accept": "application/gzip, application/octet-stream",
            "User-Agent": "rbvm-csv-platform/0.14 first-epss-source-adapter",
        },
    )
    with urlopen(request, timeout=90) as response:  # nosec: fixed official HTTPS source
        if response.status != 200:
            raise RuntimeError(f"FIRST EPSS feed returned HTTP {response.status}")
        final_url = response.geturl()
        parsed = urlparse(final_url)
        if parsed.scheme != "https" or not parsed.hostname:
            raise RuntimeError("FIRST EPSS redirect target must remain HTTPS")
        declared_length = response.headers.get("Content-Length")
        if declared_length:
            try:
                if int(declared_length) > MAX_COMPRESSED_BYTES:
                    raise RuntimeError("FIRST EPSS compressed response exceeds configured maximum size")
            except ValueError as error:
                raise RuntimeError("FIRST EPSS Content-Length is invalid") from error
        payload = response.read(MAX_COMPRESSED_BYTES + 1)
    if len(payload) > MAX_COMPRESSED_BYTES:
        raise RuntimeError("FIRST EPSS compressed response exceeds configured maximum size")
    if not payload:
        raise RuntimeError("FIRST EPSS response is empty")
    return payload, final_url


def read_offline_bytes(path):
    require_regular(path, "--offline-input")
    size = path.stat().st_size
    if size <= 0:
        raise RuntimeError("--offline-input must not be empty")
    if size > MAX_COMPRESSED_BYTES:
        raise RuntimeError("offline FIRST EPSS input exceeds configured maximum size")
    return path.read_bytes()


def bounded_gunzip(payload):
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(payload), mode="rb") as handle:
            decompressed = handle.read(MAX_DECOMPRESSED_BYTES + 1)
    except (OSError, EOFError) as error:
        raise RuntimeError("FIRST EPSS source is not a valid gzip stream") from error
    if len(decompressed) > MAX_DECOMPRESSED_BYTES:
        raise RuntimeError("FIRST EPSS decompressed data exceeds configured maximum size")
    if not decompressed:
        raise RuntimeError("FIRST EPSS decompressed data is empty")
    return decompressed


def parse_score_date(value):
    text = value.strip()
    try:
        if len(text) == 10:
            return date.fromisoformat(text).isoformat()
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as error:
        raise RuntimeError("FIRST EPSS score_date must be an ISO-8601 date or timestamp") from error
    if parsed.tzinfo is None:
        raise RuntimeError("FIRST EPSS score_date timestamp must include a timezone")
    return parsed.astimezone(timezone.utc).date().isoformat()


def metadata_and_csv(text):
    lines = text.splitlines()
    comments = []
    header_index = None
    for index, line in enumerate(lines):
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            comments.append(stripped[1:].strip())
            continue
        header_index = index
        break
    if header_index is None:
        raise RuntimeError("FIRST EPSS feed does not contain a CSV header")
    if not comments:
        raise RuntimeError("FIRST EPSS feed is missing the model-version metadata comment")

    metadata_text = ",".join(comments)
    model_match = MODEL_VERSION_FIELD.search(metadata_text)
    date_match = SCORE_DATE_FIELD.search(metadata_text)
    if not model_match or not date_match:
        raise RuntimeError("FIRST EPSS metadata must contain model_version and score_date")
    model_version = model_match.group(1).strip()
    if not MODEL_VERSION_PATTERN.fullmatch(model_version):
        raise RuntimeError("FIRST EPSS model_version is invalid")
    score_date = parse_score_date(date_match.group(1))

    csv_text = "\n".join(lines[header_index:]) + "\n"
    return model_version, score_date, csv_text


def decimal_probability(value, field, row_number):
    text = (value or "").strip()
    try:
        number = Decimal(text)
    except InvalidOperation as error:
        raise RuntimeError(f"FIRST EPSS row {row_number} {field} is not a decimal") from error
    if not number.is_finite() or number < 0 or number > 1:
        raise RuntimeError(f"FIRST EPSS row {row_number} {field} must be between 0 and 1")
    return format(number, "f")


def parse_feed(payload, requested_cves):
    decompressed = bounded_gunzip(payload)
    try:
        text = decompressed.decode("utf-8")
    except UnicodeDecodeError as error:
        raise RuntimeError("FIRST EPSS feed must be UTF-8") from error

    model_version, score_date, csv_text = metadata_and_csv(text)
    reader = csv.DictReader(io.StringIO(csv_text, newline=""))
    headers = [header.strip() for header in (reader.fieldnames or [])]
    if headers != EXPECTED_HEADERS:
        raise RuntimeError(
            "FIRST EPSS CSV headers must be exactly: " + ",".join(EXPECTED_HEADERS)
        )

    requested = set(requested_cves)
    selected = {}
    seen = set()
    feed_rows = 0
    for row_number, row in enumerate(reader, 2):
        if None in row:
            raise RuntimeError(f"FIRST EPSS row {row_number} contains unexpected extra fields")
        feed_rows += 1
        cve = (row.get("cve") or "").strip().upper()
        if not CVE_PATTERN.fullmatch(cve):
            raise RuntimeError(f"FIRST EPSS row {row_number} contains invalid CVE ID")
        if cve in seen:
            raise RuntimeError(f"FIRST EPSS feed contains duplicate CVE ID: {cve}")
        seen.add(cve)
        epss = decimal_probability(row.get("epss"), "epss", row_number)
        percentile = decimal_probability(row.get("percentile"), "percentile", row_number)
        if cve in requested:
            selected[cve] = {
                "cveId": cve,
                "epss": epss,
                "percentile": percentile,
            }

    if feed_rows <= 0:
        raise RuntimeError("FIRST EPSS feed contains no score rows")

    scores = [selected[cve] for cve in sorted(selected)]
    missing = sorted(requested - set(selected))
    return {
        "modelVersion": model_version,
        "scoreDate": score_date,
        "feedRowCount": feed_rows,
        "decompressedBytes": len(decompressed),
        "scores": scores,
        "missingCves": missing,
    }


def write_json(path, value):
    if path.is_symlink():
        raise RuntimeError("output path must not be a symlink")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    if temporary.is_symlink():
        raise RuntimeError("temporary output path must not be a symlink")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def main():
    args = arguments()
    logical_rows, cves = input_cves(args.input)
    observed_at = observation_time(args.observed_at)
    if args.offline_input:
        payload = read_offline_bytes(args.offline_input)
        acquisition_mode = "OFFLINE_REPLAY"
        final_url = EPSS_CURRENT_CSV_GZ
    else:
        payload, final_url = fetch_official_bytes()
        acquisition_mode = "OFFICIAL_HTTPS"

    parsed = parse_feed(payload, cves)
    artifact = {
        "schemaVersion": 1,
        "artifactType": "FIRST_EPSS_VALIDATED_SNAPSHOT",
        "source": EPSS_CURRENT_CSV_GZ,
        "resolvedSource": final_url,
        "observedAt": observed_at,
        "sourceBytesSha256": hashlib.sha256(payload).hexdigest(),
        "compressedBytes": len(payload),
        "decompressedBytes": parsed["decompressedBytes"],
        "modelVersion": parsed["modelVersion"],
        "scoreDate": parsed["scoreDate"],
        "feedRowCount": parsed["feedRowCount"],
        "inputRows": logical_rows,
        "requestedCveCount": len(cves),
        "scoredCveCount": len(parsed["scores"]),
        "missingCveCount": len(parsed["missingCves"]),
        "completeParse": True,
        "acquisitionMode": acquisition_mode,
        "scores": parsed["scores"],
        "missingCves": parsed["missingCves"],
    }
    write_json(args.output, artifact)
    print(
        "first_epss_snapshot=VALID "
        f"model={artifact['modelVersion']} score_date={artifact['scoreDate']} "
        f"feed_rows={artifact['feedRowCount']} requested={artifact['requestedCveCount']} "
        f"scored={artifact['scoredCveCount']} missing={artifact['missingCveCount']} "
        f"output={args.output}"
    )


if __name__ == "__main__":
    try:
        main()
    except Exception as error:  # operational CLI boundary
        print(f"first_epss_snapshot=FAILED error={error}", file=__import__("sys").stderr)
        raise SystemExit(1)
