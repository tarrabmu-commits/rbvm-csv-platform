#!/usr/bin/env python3
"""Enrich WAZUH_CSV_V2 with cached NVD, FIRST EPSS, and CISA KEV evidence."""

import argparse
import csv
import json
import os
from pathlib import Path
import time
from urllib.parse import urlencode
from urllib.request import Request, urlopen

NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS = "https://api.first.org/data/v1/epss"
KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
INTEL_HEADERS = [
    "CVSS_Version", "CVSS_Base_Score", "CVSS_Vector", "EPSS_Probability",
    "EPSS_Percentile", "Known_Exploited", "KEV_Date_Added", "KEV_Due_Date",
    "Intel_Observed_At", "Intel_Source_References",
]


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--cache-dir", type=Path, default=Path("data/intel-cache"))
    parser.add_argument("--offline", action="store_true", help="use cache only")
    return parser.parse_args()


def fetch_json(url, cache, offline=False, headers=None):
    if offline:
        if not cache.is_file():
            raise RuntimeError(f"offline cache is missing: {cache}")
        return json.loads(cache.read_text(encoding="utf-8"))
    request = Request(url, headers={"User-Agent": "rbvm-csv-platform/0.11", **(headers or {})})
    with urlopen(request, timeout=60) as response:  # nosec: URLs are fixed official HTTPS endpoints
        if response.status != 200:
            raise RuntimeError(f"source returned HTTP {response.status}: {url}")
        payload = response.read()
    cache.parent.mkdir(parents=True, exist_ok=True)
    temporary = cache.with_suffix(cache.suffix + ".tmp")
    temporary.write_bytes(payload)
    temporary.replace(cache)
    return json.loads(payload)


def chunks(values, size):
    for index in range(0, len(values), size):
        yield values[index:index + size]


def nvd_intelligence(cves, cache_dir, offline):
    output = {}
    api_key = os.environ.get("NVD_API_KEY")
    headers = {"apiKey": api_key} if api_key else {}
    delay = 0.7 if api_key else 6.1
    for number, batch in enumerate(chunks(cves, 100)):
        cache = cache_dir / f"nvd-{number:05d}.json"
        url = NVD + "?" + urlencode({"cveIds": ",".join(batch), "noRejected": ""})
        payload = fetch_json(url, cache, offline, headers)
        for wrapper in payload.get("vulnerabilities", []):
            cve = wrapper.get("cve", {})
            metric = preferred_metric(cve.get("metrics", {}))
            if metric:
                data = metric.get("cvssData", {})
                output[cve.get("id")] = {
                    "version": data.get("version", ""),
                    "score": data.get("baseScore", ""),
                    "vector": data.get("vectorString", ""),
                }
        if not offline and number + 1 < (len(cves) + 99) // 100:
            time.sleep(delay)
    return output


def preferred_metric(metrics):
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
        candidates = metrics.get(key, [])
        if candidates:
            primary = next((item for item in candidates if item.get("type") == "Primary"), None)
            return primary or candidates[0]
    return None


def epss_intelligence(cves, cache_dir, offline):
    output = {}
    for number, batch in enumerate(chunks(cves, 100)):
        cache = cache_dir / f"epss-{number:05d}.json"
        url = EPSS + "?" + urlencode({"cve": ",".join(batch)})
        payload = fetch_json(url, cache, offline)
        for item in payload.get("data", []):
            output[item["cve"]] = {
                "probability": item.get("epss", ""),
                "percentile": item.get("percentile", ""),
            }
    return output


def kev_intelligence(cache_dir, offline):
    payload = fetch_json(KEV, cache_dir / "cisa-kev.json", offline)
    return {item["cveID"]: item for item in payload.get("vulnerabilities", [])}


def validate_headers(fieldnames):
    required = {
        "Agent", "Agent_ID", "CVE_ID", "Affected_Product", "Package_Version",
        "Package_Architecture", "Finding_Status", "Detected_At",
    }
    missing = sorted(required - set(fieldnames or []))
    if missing:
        raise RuntimeError(f"input is not WAZUH_CSV_V2; missing headers: {missing}")


def main():
    args = arguments()
    with args.input.open("r", encoding="utf-8-sig", newline="") as source:
        reader = csv.DictReader(source)
        validate_headers(reader.fieldnames)
        rows = list(reader)
        original_headers = list(reader.fieldnames or [])
    cves = sorted({row["CVE_ID"].strip().upper() for row in rows if row["CVE_ID"].strip()})
    nvd = nvd_intelligence(cves, args.cache_dir, args.offline)
    epss = epss_intelligence(cves, args.cache_dir, args.offline)
    kev = kev_intelligence(args.cache_dir, args.offline)
    observed_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    sources = ",".join((NVD, EPSS, KEV))
    for row in rows:
        cve = row["CVE_ID"].strip().upper()
        cvss = nvd.get(cve, {})
        prediction = epss.get(cve, {})
        exploited = kev.get(cve)
        row.update({
            "CVSS_Version": cvss.get("version", ""),
            "CVSS_Base_Score": cvss.get("score", ""),
            "CVSS_Vector": cvss.get("vector", ""),
            "EPSS_Probability": prediction.get("probability", ""),
            "EPSS_Percentile": prediction.get("percentile", ""),
            "Known_Exploited": str(exploited is not None).lower(),
            "KEV_Date_Added": "" if exploited is None else exploited.get("dateAdded", ""),
            "KEV_Due_Date": "" if exploited is None else exploited.get("dueDate", ""),
            "Intel_Observed_At": observed_at,
            "Intel_Source_References": sources,
        })
    headers = [name for name in original_headers if name not in INTEL_HEADERS] + INTEL_HEADERS
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_suffix(args.output.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="") as target:
        writer = csv.DictWriter(target, fieldnames=headers, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    temporary.replace(args.output)
    print(f"enriched_rows={len(rows)} unique_cves={len(cves)} output={args.output}")


if __name__ == "__main__":
    main()
