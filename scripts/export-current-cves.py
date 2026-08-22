#!/usr/bin/env python3
"""Export the tenant's current canonical CVEs from the RBVM Cases API."""

import argparse
import csv
import json
import os
from pathlib import Path
import re
import tempfile
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen

CVE_PATTERN = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
DEFAULT_API_BASE = "http://127.0.0.1:8080"
PAGE_LIMIT = 100
MAX_PAGES = 10000


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="destination CSV containing a single CVE_ID column")
    parser.add_argument(
        "--api-base",
        default=os.environ.get("RBVM_API_BASE_URL", DEFAULT_API_BASE),
        help="RBVM API base URL (default: RBVM_API_BASE_URL or trusted-local URL)",
    )
    return parser.parse_args()


def validated_api_base(value):
    base = value.strip().rstrip("/")
    parsed = urlparse(base)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise RuntimeError("RBVM API base must be an absolute HTTP(S) URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise RuntimeError("RBVM API base must not contain credentials, query parameters, or fragments")
    return base


def request_json(url):
    headers = {
        "Accept": "application/json",
        "User-Agent": "rbvm-csv-platform canonical-intelligence-refresh",
    }
    token = os.environ.get("RBVM_INTELLIGENCE_API_KEY", "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = Request(url, headers=headers)
    with urlopen(request, timeout=60) as response:  # nosec: operator-configured RBVM endpoint
        if response.status != 200:
            raise RuntimeError(f"RBVM Cases API returned HTTP {response.status}")
        payload = response.read()
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("RBVM Cases API did not return valid JSON") from error
    if not isinstance(value, dict):
        raise RuntimeError("RBVM Cases API response root must be an object")
    return value


def canonical_cves(api_base):
    values = set()
    cursor = None
    seen_cursors = set()
    case_count = 0
    for _ in range(MAX_PAGES):
        query = {"limit": str(PAGE_LIMIT)}
        if cursor:
            query["cursor"] = cursor
        payload = request_json(f"{api_base}/api/v1/cases?{urlencode(query)}")
        cases = payload.get("cases")
        if not isinstance(cases, list):
            raise RuntimeError("RBVM Cases API response must contain a cases array")
        for item in cases:
            if not isinstance(item, dict):
                raise RuntimeError("RBVM Cases API cases must contain objects")
            case_count += 1
            cve = str(item.get("cveId") or "").strip().upper()
            if not CVE_PATTERN.fullmatch(cve):
                raise RuntimeError(f"canonical case contains invalid CVE identity: {cve or '<blank>'}")
            values.add(cve)
        next_cursor = payload.get("nextCursor")
        if next_cursor in (None, ""):
            return sorted(values), case_count
        if not isinstance(next_cursor, str) or next_cursor in seen_cursors:
            raise RuntimeError("RBVM Cases API returned an invalid or repeated pagination cursor")
        seen_cursors.add(next_cursor)
        cursor = next_cursor
    raise RuntimeError("RBVM Cases API pagination exceeded the safety limit")


def write_csv(path, cves):
    if path.is_symlink():
        raise RuntimeError("output path must not be a symlink")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent, text=True)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
            writer = csv.writer(handle, lineterminator="\n")
            writer.writerow(["CVE_ID"])
            for cve in cves:
                writer.writerow([cve])
        temporary.replace(path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def main():
    args = arguments()
    api_base = validated_api_base(args.api_base)
    cves, case_count = canonical_cves(api_base)
    write_csv(args.output, cves)
    print(
        f"canonical_cve_export=PASS cases={case_count} unique_cves={len(cves)} "
        f"output={args.output}"
    )


if __name__ == "__main__":
    try:
        main()
    except Exception as error:  # operational CLI boundary
        print(f"canonical_cve_export=FAILED error={error}", file=__import__("sys").stderr)
        raise SystemExit(1)
