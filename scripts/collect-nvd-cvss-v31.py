#!/usr/bin/env python3
"""Collect NVD-authored CVSS v3.1 Base evidence into CVSS_V31_CSV_V1."""

import argparse
import csv
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import time
from urllib.parse import urlencode
from urllib.request import Request, urlopen

NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_METRIC_SOURCE = "nvd@nist.gov"
NVD_DETAIL = "https://nvd.nist.gov/vuln/detail/"
CONTRACT_HEADERS = [
    "CVE_ID",
    "CVSS_Version",
    "CVSS_Base_Score",
    "CVSS_Vector",
    "CVSS_Source",
    "CVSS_Observed_At",
]
CVE_PATTERN = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="CSV containing a CVE_ID column")
    parser.add_argument("output", type=Path, help="CVSS_V31_CSV_V1 output path")
    parser.add_argument("--cache-dir", type=Path, default=Path("data/cvss-v31-cache"))
    parser.add_argument("--offline", action="store_true", help="read matching cache files only")
    parser.add_argument("--observed-at", help="fixed ISO-8601 collection time for replay/testing")
    parser.add_argument("--report", type=Path, help="write an atomic JSON completion report")
    return parser.parse_args()


def observation_time(value):
    if not value:
        return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise RuntimeError("--observed-at must include a timezone")
    return parsed.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def input_cves(path):
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


def chunks(values, size):
    for index in range(0, len(values), size):
        yield values[index:index + size]


def batch_cache(cache_dir, batch):
    digest = hashlib.sha256(",".join(batch).encode("ascii")).hexdigest()[:24]
    return cache_dir / f"nvd-cvss-v31-{digest}.json"


def fetch_json(url, cache, offline, api_key):
    if offline:
        if not cache.is_file():
            raise RuntimeError(f"offline cache is missing: {cache}")
        return json.loads(cache.read_text(encoding="utf-8"))

    headers = {"User-Agent": "rbvm-csv-platform/0.13 nvd-cvss-v31-collector"}
    if api_key:
        headers["apiKey"] = api_key
    request = Request(url, headers=headers)
    with urlopen(request, timeout=60) as response:  # nosec: fixed official HTTPS endpoint
        if response.status != 200:
            raise RuntimeError(f"NVD returned HTTP {response.status}")
        payload = response.read()

    cache.parent.mkdir(parents=True, exist_ok=True)
    temporary = cache.with_suffix(cache.suffix + ".tmp")
    temporary.write_bytes(payload)
    temporary.replace(cache)
    return json.loads(payload)


def nvd_url(batch):
    return NVD_CVE_API + "?" + urlencode({"cveIds": ",".join(batch)}) + "&noRejected"


def exact_nvd_v31_candidates(cve):
    candidates = []
    for metric in cve.get("metrics", {}).get("cvssMetricV31", []):
        data = metric.get("cvssData", {})
        if str(metric.get("source", "")).strip().lower() != NVD_METRIC_SOURCE:
            continue
        if str(data.get("version", "")).strip() != "3.1":
            continue
        score = data.get("baseScore")
        vector = str(data.get("vectorString", "")).strip()
        if score is None or not vector:
            candidates.append(None)
            continue
        candidates.append((str(score), vector))
    return candidates


def collect(cves, cache_dir, offline):
    api_key = os.environ.get("NVD_API_KEY")
    delay = 0.7 if api_key else 6.1
    by_cve = {}
    returned_records = 0
    batches = list(chunks(cves, 100))

    for number, batch in enumerate(batches):
        payload = fetch_json(nvd_url(batch), batch_cache(cache_dir, batch), offline, api_key)
        for wrapper in payload.get("vulnerabilities", []):
            cve = wrapper.get("cve", {})
            cve_id = str(cve.get("id", "")).strip().upper()
            if cve_id in cves:
                returned_records += 1
                by_cve[cve_id] = cve
        if not offline and number + 1 < len(batches):
            time.sleep(delay)
    return by_cve, returned_records


def evidence_rows(cves, records, observed_at):
    rows = []
    missing = []
    ambiguous = []
    malformed = []

    for cve_id in cves:
        cve = records.get(cve_id)
        if cve is None:
            missing.append(cve_id)
            continue
        candidates = exact_nvd_v31_candidates(cve)
        if any(candidate is None for candidate in candidates):
            malformed.append(cve_id)
            continue
        unique = sorted(set(candidates))
        if not unique:
            missing.append(cve_id)
            continue
        if len(unique) > 1:
            ambiguous.append({"cveId": cve_id, "candidateCount": len(unique)})
            continue
        score, vector = unique[0]
        rows.append({
            "CVE_ID": cve_id,
            "CVSS_Version": "3.1",
            "CVSS_Base_Score": score,
            "CVSS_Vector": vector,
            "CVSS_Source": NVD_DETAIL + cve_id,
            "CVSS_Observed_At": observed_at,
        })
    return rows, missing, ambiguous, malformed


def write_csv(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=CONTRACT_HEADERS, extrasaction="raise")
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
    observed_at = observation_time(args.observed_at)
    records, returned_records = collect(cves, args.cache_dir, args.offline)
    rows, missing, ambiguous, malformed = evidence_rows(cves, records, observed_at)
    write_csv(args.output, rows)

    report = {
        "schemaVersion": 1,
        "status": "COMPLETE",
        "contractId": "CVSS_V31_CSV_V1",
        "semantics": "NVD_AUTHORED_EXACT_CVSS_V31_BASE_COLLECTION",
        "inputRows": logical_rows,
        "uniqueCves": len(cves),
        "nvdRecordsReturned": returned_records,
        "emittedEvidence": len(rows),
        "missingExactNvdV31": len(missing),
        "ambiguousNvdV31": len(ambiguous),
        "malformedNvdV31": len(malformed),
        "ambiguous": ambiguous,
        "offline": args.offline,
        "observedAt": observed_at,
        "apiEndpoint": NVD_CVE_API,
        "sourcePolicy": {
            "metricObject": "cvssMetricV31",
            "requiredVersion": "3.1",
            "requiredMetricSource": NVD_METRIC_SOURCE,
            "fallbackToV30": False,
            "fallbackToV40": False,
            "fallbackToOtherProvider": False,
        },
    }
    if args.report:
        write_json(args.report, report)

    print(
        f"contract=CVSS_V31_CSV_V1 unique_cves={len(cves)} "
        f"emitted={len(rows)} missing={len(missing)} ambiguous={len(ambiguous)} "
        f"malformed={len(malformed)} output={args.output}"
    )


if __name__ == "__main__":
    main()
