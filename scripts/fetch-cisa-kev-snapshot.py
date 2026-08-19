#!/usr/bin/env python3
"""Fetch and validate the official CISA KEV JSON feed into a canonical snapshot artifact."""

import argparse
from datetime import date, datetime, timezone
import hashlib
import json
from pathlib import Path
import re
from urllib.request import Request, urlopen

CISA_KEV_JSON = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
CVE_PATTERN = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
MAX_RESPONSE_BYTES = 32 * 1024 * 1024
KNOWN_RANSOMWARE_VALUES = {"Known": "KNOWN", "Unknown": "UNKNOWN"}


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="validated canonical snapshot JSON output")
    parser.add_argument(
        "--observed-at",
        help="fixed ISO-8601 observation time for deterministic replay/testing",
    )
    parser.add_argument(
        "--offline-input",
        type=Path,
        help="parse local feed bytes instead of performing the official HTTPS request",
    )
    return parser.parse_args()


def observation_time(value):
    if not value:
        return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise RuntimeError("--observed-at must include a timezone")
    return parsed.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def fetch_official_bytes():
    request = Request(
        CISA_KEV_JSON,
        headers={
            "Accept": "application/json",
            "User-Agent": "rbvm-csv-platform/0.13 cisa-kev-source-adapter",
        },
    )
    with urlopen(request, timeout=60) as response:  # nosec: fixed official HTTPS endpoint
        if response.status != 200:
            raise RuntimeError(f"CISA KEV returned HTTP {response.status}")
        declared_length = response.headers.get("Content-Length")
        if declared_length and int(declared_length) > MAX_RESPONSE_BYTES:
            raise RuntimeError("CISA KEV response exceeds configured maximum size")
        payload = response.read(MAX_RESPONSE_BYTES + 1)
    if len(payload) > MAX_RESPONSE_BYTES:
        raise RuntimeError("CISA KEV response exceeds configured maximum size")
    if not payload:
        raise RuntimeError("CISA KEV response is empty")
    return payload


def read_offline_bytes(path):
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("--offline-input must be a regular non-symlink file")
    size = path.stat().st_size
    if size <= 0:
        raise RuntimeError("--offline-input must not be empty")
    if size > MAX_RESPONSE_BYTES:
        raise RuntimeError("offline CISA KEV input exceeds configured maximum size")
    return path.read_bytes()


def require_text(value, field):
    if not isinstance(value, str) or not value.strip():
        raise RuntimeError(f"{field} must be a non-blank string")
    return value.strip()


def require_date(value, field):
    text = require_text(value, field)
    try:
        date.fromisoformat(text)
    except ValueError as error:
        raise RuntimeError(f"{field} must be an ISO-8601 date") from error
    return text


def require_timestamp(value, field):
    text = require_text(value, field)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as error:
        raise RuntimeError(f"{field} must be an ISO-8601 timestamp") from error
    if parsed.tzinfo is None:
        raise RuntimeError(f"{field} must include a timezone")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def canonical_ransomware_use(value, index):
    text = require_text(value, f"vulnerabilities[{index}].knownRansomwareCampaignUse")
    if text not in KNOWN_RANSOMWARE_VALUES:
        raise RuntimeError(
            "vulnerabilities[%d].knownRansomwareCampaignUse must be Known or Unknown" % index
        )
    return KNOWN_RANSOMWARE_VALUES[text]


def parse_and_validate(payload_bytes, observed_at):
    try:
        root = json.loads(payload_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("CISA KEV response is not valid UTF-8 JSON") from error
    if not isinstance(root, dict):
        raise RuntimeError("CISA KEV root must be a JSON object")

    title = require_text(root.get("title"), "title")
    catalog_version = require_text(root.get("catalogVersion"), "catalogVersion")
    date_released = require_timestamp(root.get("dateReleased"), "dateReleased")
    count = root.get("count")
    if isinstance(count, bool) or not isinstance(count, int) or count <= 0:
        raise RuntimeError("count must be a positive integer")
    vulnerabilities = root.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        raise RuntimeError("vulnerabilities must be an array")
    if len(vulnerabilities) != count:
        raise RuntimeError(
            f"CISA KEV snapshot is incomplete: declared count {count}, parsed array {len(vulnerabilities)}"
        )

    seen = set()
    canonical = []
    for index, entry in enumerate(vulnerabilities):
        if not isinstance(entry, dict):
            raise RuntimeError(f"vulnerabilities[{index}] must be an object")
        cve_id = require_text(entry.get("cveID"), f"vulnerabilities[{index}].cveID").upper()
        if not CVE_PATTERN.fullmatch(cve_id):
            raise RuntimeError(f"vulnerabilities[{index}].cveID is invalid")
        if cve_id in seen:
            raise RuntimeError(f"duplicate CISA KEV CVE_ID: {cve_id}")
        seen.add(cve_id)
        canonical.append({
            "cveId": cve_id,
            "dateAdded": require_date(entry.get("dateAdded"), f"vulnerabilities[{index}].dateAdded"),
            "dueDate": require_date(entry.get("dueDate"), f"vulnerabilities[{index}].dueDate"),
            "knownRansomwareCampaignUse": canonical_ransomware_use(
                entry.get("knownRansomwareCampaignUse"), index
            ),
        })

    canonical.sort(key=lambda item: item["cveId"])
    digest = hashlib.sha256(payload_bytes).hexdigest()
    return {
        "schemaVersion": 1,
        "artifactType": "CISA_KEV_VALIDATED_SNAPSHOT",
        "source": CISA_KEV_JSON,
        "observedAt": observed_at,
        "sha256": digest,
        "title": title,
        "catalogVersion": catalog_version,
        "dateReleased": date_released,
        "declaredCount": count,
        "parsedCount": len(canonical),
        "complete": True,
        "vulnerabilities": canonical,
    }


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def main():
    args = arguments()
    observed_at = observation_time(args.observed_at)
    if args.offline_input:
        payload = read_offline_bytes(args.offline_input)
        acquisition = "OFFLINE_INPUT"
    else:
        payload = fetch_official_bytes()
        acquisition = "OFFICIAL_HTTPS"
    snapshot = parse_and_validate(payload, observed_at)
    snapshot["acquisitionMode"] = acquisition
    write_json(args.output, snapshot)
    print(
        "cisa_kev_snapshot=VALID "
        f"catalog_version={snapshot['catalogVersion']} "
        f"count={snapshot['parsedCount']} sha256={snapshot['sha256']} "
        f"output={args.output}"
    )


if __name__ == "__main__":
    main()
