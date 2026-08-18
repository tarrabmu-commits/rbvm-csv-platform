#!/usr/bin/env python3
"""Enrich WAZUH_CSV_V2 rows with NVD CVSS v3.1 Base evidence only.

This stage is intentionally narrow: it does not calculate organizational risk,
apply EPSS/KEV policy, or convert scores between CVSS versions. For each CVE it
copies an official NVD-hosted CVSS v3.1 Base score and vector when available and
records the observation time plus NVD provenance.
"""

import argparse
import csv
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import time
from urllib.parse import urlencode
from urllib.request import Request, urlopen

NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVSS_HEADERS = [
    "CVSS_Version",
    "CVSS_Base_Score",
    "CVSS_Vector",
    "Intel_Observed_At",
    "Intel_Source_References",
]


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--cache-dir", type=Path, default=Path("data/intel-cache"))
    parser.add_argument("--offline", action="store_true", help="use cache only")
    parser.add_argument("--observed-at", help="fixed ISO-8601 observation time for replay/testing")
    parser.add_argument("--report", type=Path, help="write an atomic JSON completion report")
    return parser.parse_args()


def observation_time(value):
    if not value:
        return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise RuntimeError("--observed-at must include a timezone")
    return parsed.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def validate_headers(fieldnames):
    required = {
        "Agent", "Agent_ID", "CVE_ID", "Affected_Product", "Package_Version",
        "Package_Architecture", "Finding_Status", "Detected_At",
    }
    missing = sorted(required - set(fieldnames or []))
    if missing:
        raise RuntimeError(f"input is not WAZUH_CSV_V2; missing headers: {missing}")


def chunks(values, size):
    for index in range(0, len(values), size):
        yield values[index:index + size]


def batch_cache(cache_dir, batch):
    digest = hashlib.sha256(",".join(batch).encode("ascii")).hexdigest()[:24]
    return cache_dir / f"nvd-{digest}.json"


def fetch_json(url, cache, offline=False, headers=None):
    if offline:
        if not cache.is_file():
            raise RuntimeError(f"offline cache is missing: {cache}")
        return json.loads(cache.read_text(encoding="utf-8"))
    request = Request(url, headers={"User-Agent": "rbvm-csv-platform/cvss-v31", **(headers or {})})
    with urlopen(request, timeout=60) as response:  # nosec: fixed official HTTPS endpoint
        if response.status != 200:
            raise RuntimeError(f"source returned HTTP {response.status}: {url}")
        payload = response.read()
    cache.parent.mkdir(parents=True, exist_ok=True)
    temporary = cache.with_suffix(cache.suffix + ".tmp")
    temporary.write_bytes(payload)
    temporary.replace(cache)
    return json.loads(payload)


def preferred_v31_metric(metrics):
    """Return CVSS v3.1 evidence only; never substitute v4.0 or v3.0."""
    candidates = metrics.get("cvssMetricV31", [])
    if not candidates:
        return None
    primary = next((item for item in candidates if item.get("type") == "Primary"), None)
    return primary or candidates[0]


def nvd_cvss_v31(cves, cache_dir, offline):
    output = {}
    api_key = os.environ.get("NVD_API_KEY")
    headers = {"apiKey": api_key} if api_key else {}
    delay = 0.7 if api_key else 6.1
    batches = list(chunks(cves, 100))
    for number, batch in enumerate(batches):
        cache = batch_cache(cache_dir, batch)
        url = NVD + "?" + urlencode({"cveIds": ",".join(batch), "noRejected": ""})
        payload = fetch_json(url, cache, offline, headers)
        for wrapper in payload.get("vulnerabilities", []):
            cve = wrapper.get("cve", {})
            metric = preferred_v31_metric(cve.get("metrics", {}))
            if metric is None:
                continue
            data = metric.get("cvssData", {})
            version = str(data.get("version", "")).strip()
            score = data.get("baseScore", "")
            vector = str(data.get("vectorString", "")).strip()
            if version != "3.1" or score == "" or not vector.startswith("CVSS:3.1/"):
                continue
            output[cve.get("id", "").upper()] = {
                "version": version,
                "score": score,
                "vector": vector,
            }
        if not offline and number + 1 < len(batches):
            time.sleep(delay)
    return output


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def main():
    args = arguments()
    with args.input.open("r", encoding="utf-8-sig", newline="") as source:
        reader = csv.DictReader(source)
        validate_headers(reader.fieldnames)
        rows = list(reader)
        original_headers = list(reader.fieldnames or [])

    cves = sorted({row["CVE_ID"].strip().upper() for row in rows if row["CVE_ID"].strip()})
    evidence = nvd_cvss_v31(cves, args.cache_dir, args.offline)
    observed_at = observation_time(args.observed_at)

    enriched_rows = 0
    missing_rows = 0
    for row in rows:
        cve = row["CVE_ID"].strip().upper()
        cvss = evidence.get(cve)
        if cvss is None:
            row.update({
                "CVSS_Version": "",
                "CVSS_Base_Score": "",
                "CVSS_Vector": "",
            })
            missing_rows += 1
            # No intelligence signal means provenance fields must remain empty under the V2 contract.
            if not any(row.get(name, "").strip() for name in (
                    "EPSS_Probability", "EPSS_Percentile", "Known_Exploited"
            )):
                row["Intel_Observed_At"] = ""
                row["Intel_Source_References"] = ""
            continue

        row.update({
            "CVSS_Version": cvss["version"],
            "CVSS_Base_Score": cvss["score"],
            "CVSS_Vector": cvss["vector"],
            "Intel_Observed_At": observed_at,
            "Intel_Source_References": NVD,
        })
        enriched_rows += 1

    headers = [name for name in original_headers if name not in CVSS_HEADERS] + CVSS_HEADERS
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_suffix(args.output.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="") as target:
        writer = csv.DictWriter(target, fieldnames=headers, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    temporary.replace(args.output)

    if args.report:
        write_json(args.report, {
            "schemaVersion": 1,
            "stage": "CVSS_V31_BASE",
            "status": "COMPLETE",
            "observedAt": observed_at,
            "offline": args.offline,
            "rows": len(rows),
            "uniqueCves": len(cves),
            "cvssV31Cves": len(evidence),
            "enrichedRows": enriched_rows,
            "rowsWithoutCvssV31": missing_rows,
            "source": NVD,
            "policy": "Use CVSS v3.1 Base only; do not convert or substitute another CVSS version.",
        })

    print(
        f"stage=CVSS_V31_BASE rows={len(rows)} unique_cves={len(cves)} "
        f"cvss_v31_cves={len(evidence)} output={args.output}"
    )


if __name__ == "__main__":
    main()
