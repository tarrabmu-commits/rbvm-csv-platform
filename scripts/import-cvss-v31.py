#!/usr/bin/env python3
"""Send CVSS_V31_CSV_V1 to the platform's canonical transactional importer."""

import argparse
import json
import os
from pathlib import Path
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

DEFAULT_API_BASE = "http://127.0.0.1:8080"
DEFAULT_MAX_BYTES = 16 * 1024 * 1024
EXPECTED_CONTRACT = "CVSS_V31_CSV_V1"
EXPECTED_SEMANTICS = "CVE_SCOPED_CVSS_V31_BASE_EVIDENCE"


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="CVSS_V31_CSV_V1 file")
    parser.add_argument(
        "--api-base",
        default=os.environ.get("RBVM_API_BASE_URL", DEFAULT_API_BASE),
        help="platform origin; remote endpoints must use HTTPS",
    )
    parser.add_argument("--report", type=Path, help="write the import response atomically")
    parser.add_argument(
        "--max-bytes",
        type=int,
        default=int(os.environ.get("RBVM_CVSS_MAX_BYTES", DEFAULT_MAX_BYTES)),
    )
    return parser.parse_args()


def validate_input(path, max_bytes):
    if max_bytes < 1024:
        raise RuntimeError("--max-bytes must be at least 1024")
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("input must be a regular non-symlink file")
    size = path.stat().st_size
    if size <= 0:
        raise RuntimeError("input must not be empty")
    if size > max_bytes:
        raise RuntimeError(f"input exceeds configured maximum of {max_bytes} bytes")
    return size


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
    base = api_base.rstrip("/")
    return base + "/api/v1/cvss-v31-imports"


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def import_evidence(path, api_base, api_key, max_bytes):
    validate_input(path, max_bytes)
    if not api_key or not api_key.strip():
        raise RuntimeError("RBVM_CVSS_API_KEY is required")

    body = path.read_bytes()
    request = Request(
        endpoint(api_base),
        data=body,
        method="POST",
        headers={
            "Authorization": "Bearer " + api_key.strip(),
            "Content-Type": "text/csv; charset=utf-8",
            "Accept": "application/json",
            "User-Agent": "rbvm-csv-platform/0.13 cvss-v31-safe-handoff",
        },
    )
    try:
        with urlopen(request, timeout=60) as response:
            status = response.status
            payload = response.read()
    except HTTPError as error:
        # Do not echo the remote response body. A configured endpoint has seen the bearer token and
        # must not be allowed to reflect secrets or attacker-controlled text into scheduler logs.
        raise RuntimeError(f"CVSS import returned HTTP {error.code}") from error
    except URLError as error:
        raise RuntimeError(f"CVSS import connection failed: {error.reason}") from error

    if status != 200:
        raise RuntimeError(f"CVSS import returned unexpected HTTP {status}")
    try:
        result = json.loads(payload)
    except json.JSONDecodeError as error:
        raise RuntimeError("CVSS import returned invalid JSON") from error
    if result.get("contractId") != EXPECTED_CONTRACT:
        raise RuntimeError("CVSS import response contractId does not match CVSS_V31_CSV_V1")
    if result.get("semantics") != EXPECTED_SEMANTICS:
        raise RuntimeError("CVSS import response semantics do not match the canonical contract")
    return result


def main():
    args = arguments()
    result = import_evidence(
        args.input,
        args.api_base,
        os.environ.get("RBVM_CVSS_API_KEY"),
        args.max_bytes,
    )
    if args.report:
        write_json(args.report, result)

    inserted = int(result.get("insertedEvidence", 0))
    replayed = int(result.get("replayedEvidence", 0))
    quarantined = int(result.get("totalQuarantinedRows", 0))
    print(
        f"cvss_import=COMPLETE inserted={inserted} replayed={replayed} "
        f"quarantined={quarantined}"
    )


if __name__ == "__main__":
    try:
        main()
    except Exception as error:  # operational CLI boundary
        print(f"cvss_import=FAILED error={error}", file=sys.stderr)
        raise SystemExit(1)
