#!/usr/bin/env python3
"""Build PUBLIC_INTELLIGENCE_SYNC_BUNDLE_V1 from validated official-source bytes."""

import argparse
import base64
import csv
from datetime import date, datetime, timezone
from decimal import Decimal, InvalidOperation
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import zipfile

CVE_RE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
EPSS_MODEL_RE = re.compile(r"^v?[0-9]{4}\.[0-9]{2}\.[0-9]{2}$")
PROVIDERS = {"NVD", "FIRST_EPSS", "CISA_KEV", "CVE_PROGRAM"}
MODES = {"BOOTSTRAP", "INCREMENTAL"}
HEADER = [
    "CVE_ID",
    "Record_State",
    "Source_Modified_At",
    "Source_Published_At",
    "Observed_At",
    "Payload_Base64",
]


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("provider", choices=sorted(PROVIDERS))
    parser.add_argument("source", type=Path, help="downloaded official-source payload")
    parser.add_argument("output", type=Path, help="output bundle directory")
    parser.add_argument("--mode", choices=sorted(MODES), required=True)
    parser.add_argument("--source-uri", required=True)
    parser.add_argument("--source-version", required=True)
    parser.add_argument("--observed-at", required=True)
    parser.add_argument("--source-published-at")
    parser.add_argument(
        "--previous-cves",
        type=Path,
        help="newline-delimited prior current CVEs used only to emit explicit tombstones",
    )
    return parser.parse_args()


def iso8601(value, field, *, assume_utc=False):
    if value is None or value == "":
        return ""
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise RuntimeError(f"{field} must be ISO-8601") from exc
    if parsed.tzinfo is None:
        if not assume_utc:
            raise RuntimeError(f"{field} must include timezone")
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def canonical_cve(value, field):
    text = str(value or "").strip().upper()
    if not CVE_RE.fullmatch(text):
        raise RuntimeError(f"{field} is not a canonical CVE identifier: {text!r}")
    return text


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def source_bytes(path):
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("source must be a regular non-symlink file")
    return path.read_bytes()


def decompressed_json(raw, source_name):
    try:
        data = gzip.decompress(raw) if source_name.endswith(".gz") else raw
        return json.loads(data.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("source must be valid UTF-8 JSON or gzip-compressed JSON") from exc


def canonical_json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def record_line(cve_id, state, modified_at, published_at, observed_at, payload):
    encoded = "" if payload is None else base64.b64encode(
        payload.encode("utf-8")
    ).decode("ascii")
    return [
        cve_id,
        state,
        modified_at or "",
        published_at or "",
        observed_at,
        encoded,
    ]


def nvd_records(raw, source_name, observed_at):
    root = decompressed_json(raw, source_name)
    vulns = root.get("vulnerabilities")
    if not isinstance(vulns, list):
        raise RuntimeError("NVD JSON 2.0 source must contain vulnerabilities[]")
    declared = root.get("totalResults")
    if isinstance(declared, int) and declared != len(vulns):
        raise RuntimeError(
            "NVD source is not a complete requested result set: "
            f"totalResults={declared}, parsed={len(vulns)}"
        )
    seen = set()
    for index, item in enumerate(vulns):
        if not isinstance(item, dict) or not isinstance(item.get("cve"), dict):
            raise RuntimeError(f"NVD vulnerabilities[{index}] must contain cve object")
        payload = item["cve"]
        cve_id = canonical_cve(payload.get("id"), f"NVD vulnerabilities[{index}].cve.id")
        if cve_id in seen:
            raise RuntimeError(f"NVD source contains duplicate CVE: {cve_id}")
        seen.add(cve_id)
        # NVD CVE API 2.0 response timestamps are UTC but are serialized without an offset.
        modified = iso8601(
            payload.get("lastModified"), "NVD lastModified", assume_utc=True
        )
        published = iso8601(payload.get("published"), "NVD published", assume_utc=True)
        yield record_line(
            cve_id, "ACTIVE", modified, published, observed_at, canonical_json(payload)
        )


def epss_metadata_and_rows(text):
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
        raise RuntimeError("FIRST EPSS source does not contain a CSV header")
    if not comments:
        raise RuntimeError("FIRST EPSS source is missing model metadata")

    metadata = {}
    for comment in comments:
        for part in comment.split(","):
            if ":" in part:
                key, value = part.split(":", 1)
            elif "=" in part:
                key, value = part.split("=", 1)
            else:
                continue
            metadata[key.strip().lower()] = value.strip()

    model_version = metadata.get("model_version", "")
    if not EPSS_MODEL_RE.fullmatch(model_version):
        raise RuntimeError("FIRST EPSS model_version is missing or invalid")
    score_date = metadata.get("score_date", "")
    try:
        score_date = date.fromisoformat(score_date).isoformat()
    except ValueError as exc:
        raise RuntimeError("FIRST EPSS score_date must be an ISO-8601 date") from exc

    reader = csv.DictReader(io.StringIO("\n".join(lines[header_index:]) + "\n"))
    if reader.fieldnames != ["cve", "epss", "percentile"]:
        raise RuntimeError("FIRST EPSS CSV headers must be exactly cve,epss,percentile")
    return model_version, score_date, reader


def probability(value, field, row_number):
    text = str(value or "").strip()
    try:
        number = Decimal(text)
    except InvalidOperation as exc:
        raise RuntimeError(f"FIRST EPSS row {row_number} {field} is not a decimal") from exc
    if not number.is_finite() or number < 0 or number > 1:
        raise RuntimeError(f"FIRST EPSS row {row_number} {field} must be between 0 and 1")
    return format(number, "f")


def epss_records(raw, source_name, observed_at):
    try:
        data = gzip.decompress(raw) if source_name.endswith(".gz") else raw
        text = data.decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise RuntimeError("FIRST EPSS source must be UTF-8 CSV or gzip-compressed CSV") from exc

    model_version, score_date, reader = epss_metadata_and_rows(text)
    seen = set()
    row_count = 0
    for row_number, row in enumerate(reader, start=2):
        if None in row:
            raise RuntimeError(f"FIRST EPSS row {row_number} contains unexpected extra fields")
        row_count += 1
        cve_id = canonical_cve(row.get("cve"), f"FIRST EPSS row {row_number} cve")
        if cve_id in seen:
            raise RuntimeError(f"FIRST EPSS source contains duplicate CVE: {cve_id}")
        seen.add(cve_id)
        payload = {
            "cve": cve_id,
            "epss": probability(row.get("epss"), "epss", row_number),
            "percentile": probability(row.get("percentile"), "percentile", row_number),
            "modelVersion": model_version,
            "scoreDate": score_date,
        }
        yield record_line(
            cve_id, "ACTIVE", "", "", observed_at, canonical_json(payload)
        )
    if row_count == 0:
        raise RuntimeError("FIRST EPSS source contains no score rows")


def cisa_records(raw, source_name, observed_at):
    root = decompressed_json(raw, source_name)
    vulns = root.get("vulnerabilities")
    if not isinstance(vulns, list):
        raise RuntimeError("CISA KEV source must contain vulnerabilities[]")
    declared = root.get("count")
    if not isinstance(declared, int) or declared != len(vulns):
        raise RuntimeError("CISA KEV declared count must equal parsed count")
    seen = set()
    for index, payload in enumerate(vulns):
        if not isinstance(payload, dict):
            raise RuntimeError(f"CISA vulnerabilities[{index}] must be an object")
        cve_id = canonical_cve(payload.get("cveID"), f"CISA vulnerabilities[{index}].cveID")
        if cve_id in seen:
            raise RuntimeError(f"CISA KEV source contains duplicate CVE: {cve_id}")
        seen.add(cve_id)
        yield record_line(
            cve_id, "ACTIVE", "", "", observed_at, canonical_json(payload)
        )


def cve_program_json_names(names):
    selected = []
    for name in names:
        normalized = name.replace("\\", "/")
        if normalized.endswith("/") or not normalized.lower().endswith(".json"):
            continue
        parts = [part for part in normalized.split("/") if part]
        if "cves" in parts:
            selected.append(name)
    return sorted(selected)


def cve_program_payloads(path):
    if path.is_dir():
        records_root = path / "cves" if (path / "cves").is_dir() else path
        for file_path in sorted(records_root.rglob("*.json")):
            if file_path.is_symlink() or not file_path.is_file():
                continue
            try:
                payload = json.loads(file_path.read_text(encoding="utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise RuntimeError(f"invalid CVE Program JSON: {file_path}") from exc
            if isinstance(payload, dict) and isinstance(payload.get("cveMetadata"), dict):
                yield payload
        return

    raw = source_bytes(path)
    if zipfile.is_zipfile(io.BytesIO(raw)):
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            names = cve_program_json_names(archive.namelist())
            if not names:
                raise RuntimeError("CVE Program archive contains no cves/*.json records")
            for name in names:
                try:
                    payload = json.loads(archive.read(name).decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise RuntimeError(f"invalid CVE Program JSON in archive: {name}") from exc
                if not isinstance(payload, dict) or not isinstance(payload.get("cveMetadata"), dict):
                    raise RuntimeError(f"CVE Program archive record lacks cveMetadata: {name}")
                yield payload
        return

    root = decompressed_json(raw, path.name)
    if isinstance(root, list):
        yield from root
    else:
        yield root


def cve_program_records(path, observed_at):
    seen = set()
    row_count = 0
    for index, payload in enumerate(cve_program_payloads(path)):
        if not isinstance(payload, dict) or not isinstance(payload.get("cveMetadata"), dict):
            raise RuntimeError(f"CVE Program record {index} must contain cveMetadata")
        row_count += 1
        metadata = payload["cveMetadata"]
        cve_id = canonical_cve(metadata.get("cveId"), f"CVE Program record {index} cveId")
        if cve_id in seen:
            raise RuntimeError(f"CVE Program source contains duplicate CVE: {cve_id}")
        seen.add(cve_id)
        modified = iso8601(
            metadata.get("dateUpdated"), "CVE Program dateUpdated", assume_utc=True
        )
        published = iso8601(
            metadata.get("datePublished"), "CVE Program datePublished", assume_utc=True
        )
        yield record_line(
            cve_id, "ACTIVE", modified, published, observed_at, canonical_json(payload)
        )
    if row_count == 0:
        raise RuntimeError("CVE Program source contains no CVE records")


def previous_cves(path):
    if path is None:
        return set()
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("--previous-cves must be a regular non-symlink file")
    result = set()
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        result.add(canonical_cve(line, f"previous CVE line {line_number}"))
    return result


def write_properties(path, values):
    lines = []
    for key, value in values:
        text = "" if value is None else str(value)
        if "\n" in text or "\r" in text:
            raise RuntimeError(f"manifest value {key} must be single-line")
        lines.append(f"{key}={text}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def directory_source_sha(path):
    digest = hashlib.sha256()
    json_files = [
        file_path for file_path in sorted(path.rglob("*.json"))
        if file_path.is_file() and not file_path.is_symlink()
    ]
    if not json_files:
        raise RuntimeError("source directory contains no JSON files")
    for file_path in json_files:
        digest.update(file_path.relative_to(path).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(file_path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def main():
    options = parse_args()
    if not options.source_uri.startswith("https://"):
        raise RuntimeError("--source-uri must use https")
    observed_at = iso8601(options.observed_at, "observedAt")
    source_published_at = iso8601(options.source_published_at, "sourcePublishedAt")
    if options.output.exists():
        if not options.output.is_dir() or any(options.output.iterdir()):
            raise RuntimeError("output directory must not exist or must be empty")
    options.output.mkdir(parents=True, exist_ok=True)

    raw = source_bytes(options.source) if not options.source.is_dir() else b""
    source_sha = directory_source_sha(options.source) if options.source.is_dir() else sha256_bytes(raw)

    if options.provider == "NVD":
        records = nvd_records(raw, options.source.name, observed_at)
    elif options.provider == "FIRST_EPSS":
        records = epss_records(raw, options.source.name, observed_at)
    elif options.provider == "CISA_KEV":
        records = cisa_records(raw, options.source.name, observed_at)
    else:
        records = cve_program_records(options.source, observed_at)

    records_path = options.output / "records.tsv"
    active_cves = set()
    count = 0
    with records_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, delimiter="\t", lineterminator="\n")
        writer.writerow(HEADER)
        for row in records:
            if row[0] in active_cves:
                raise RuntimeError(f"source contains duplicate CVE: {row[0]}")
            active_cves.add(row[0])
            writer.writerow(row)
            count += 1

        prior = previous_cves(options.previous_cves)
        for cve_id in sorted(prior - active_cves):
            writer.writerow(record_line(cve_id, "TOMBSTONE", observed_at, "", observed_at, None))
            count += 1

    records_sha = sha256_bytes(records_path.read_bytes())
    write_properties(
        options.output / "manifest.properties",
        [
            ("artifactType", "PUBLIC_INTELLIGENCE_SYNC_BUNDLE"),
            ("schemaVersion", "1"),
            ("provider", options.provider),
            ("syncMode", options.mode),
            ("sourceUri", options.source_uri),
            ("sourceVersion", options.source_version),
            ("sourceSha256", source_sha),
            ("sourcePublishedAt", source_published_at),
            ("observedAt", observed_at),
            ("startedAt", observed_at),
            ("recordCount", count),
            ("recordsSha256", records_sha),
        ],
    )
    print(
        f"provider={options.provider} mode={options.mode} "
        f"records={count} source_sha256={source_sha} records_sha256={records_sha}"
    )


if __name__ == "__main__":
    main()
