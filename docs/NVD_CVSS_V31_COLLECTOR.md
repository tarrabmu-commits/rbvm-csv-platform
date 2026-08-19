# NVD CVSS v3.1 Collector

## Purpose

`collect-nvd-cvss-v31.py` is the first automated producer for the independent
`CVSS_V31_CSV_V1` evidence contract. It accepts any CSV containing a `CVE_ID`
column, including the current `WAZUH_CSV_V1`, and produces a separate CVSS
technical-severity evidence CSV.

It does **not** enrich or rewrite the Wazuh CSV and it does not write directly to
PostgreSQL. The generated CSV must still pass the existing CVSS contract analyzer
and transactional importer.

```text
WAZUH_CSV_V1 / other CVE reference CSV
              |
              v
       unique CVE_ID set
              |
              v
       NVD CVE API 2.0
              |
              v
 exact NVD-authored CVSS v3.1 Base only
              |
              v
       CVSS_V31_CSV_V1
              |
              v
 existing validation + transactional importer
              |
              v
 PostgreSQL CVSS evidence history
```

## Source policy

The collector intentionally has a narrow source policy:

1. API transport: `https://services.nvd.nist.gov/rest/json/cves/2.0`.
2. Metric object: `metrics.cvssMetricV31` only.
3. Metric version: `cvssData.version` must be exactly `3.1`.
4. Metric author: `metric.source` must be exactly `nvd@nist.gov`.
5. Evidence reference stored in `CVSS_Source`: the official NVD vulnerability
   detail page for the CVE.
6. `CVSS_Observed_At` is the UTC time at which this platform collected the
   evidence, not the CVE publication or last-modified time.

This is an explicit **source scope**, not a hidden source-precedence algorithm.
The collector does not choose a CNA/vendor metric merely because NVD labels it
`Primary`, and it does not compare NVD and CNA scores to choose a winner.

If a future vendor/CNA collector is added, its evidence can coexist through the
same independent CVSS evidence model instead of being collapsed into this NVD
collector.

## No fallback

The collector never substitutes:

- CVSS v4.0 for v3.1;
- CVSS v3.0 for v3.1;
- a CNA/vendor metric for an absent NVD-authored metric;
- Wazuh `Severity` for a CVSS Base score;
- a locally calculated priority or SLA.

No exact NVD-authored v3.1 metric therefore means **no emitted CVSS evidence from
this collector**. That is missing evidence, not score zero and not a lower
severity.

## Ambiguity handling

For one CVE, duplicate identical NVD v3.1 metrics collapse to one candidate. If
more than one distinct NVD-authored v3.1 Base score/vector is returned for the
same collection snapshot, the collector does not choose between them. The CVE is
omitted from the output and surfaced in the JSON report under
`ambiguousNvdV31`/`ambiguous`.

Malformed NVD-authored v3.1 candidates are likewise omitted and counted as
`malformedNvdV31`.

## NVD API behavior

The collector batches up to 100 CVE IDs per request and supports `NVD_API_KEY`.
Without a key it spaces multi-request runs by 6.1 seconds; with a key it uses a
0.7 second interval. These values keep the collector below the documented NVD
rolling-window request limits while still processing responses sequentially.

Responses are cached by the SHA-256 fingerprint of the exact sorted CVE batch.
`--offline` therefore cannot silently reuse a cache created for a different CVE
set.

NVD-required notice:

> This product uses data from the NVD API but is not endorsed or certified by the NVD.

## Usage

```bash
python3 scripts/collect-nvd-cvss-v31.py \
  wazuh-vulnerabilities.csv \
  cvss-v31.csv \
  --report cvss-v31-report.json
```

With an NVD API key:

```bash
export NVD_API_KEY='from-a-secret-manager'
python3 scripts/collect-nvd-cvss-v31.py wazuh-vulnerabilities.csv cvss-v31.csv
```

Offline replay/testing:

```bash
python3 scripts/collect-nvd-cvss-v31.py \
  wazuh-vulnerabilities.csv \
  cvss-v31.csv \
  --cache-dir data/cvss-v31-cache \
  --offline \
  --observed-at 2026-08-19T09:00:00Z \
  --report cvss-v31-report.json
```

The output columns are exactly:

```text
CVE_ID
CVSS_Version
CVSS_Base_Score
CVSS_Vector
CVSS_Source
CVSS_Observed_At
```

## RBVM boundary

This collector ends at **Technical Severity evidence acquisition**. It does not
introduce EPSS, CISA KEV, asset criticality, business impact, exposure context,
RBVM priority, risk score, treatment decision, or remediation SLA.
