# Public CVE Intelligence Automation V1

`PUBLIC_CVE_INTEL_SNAPSHOT_V1` collects every currently useful public CVE attribute that the platform can acquire automatically without asking the customer for organizational truth.

## Sources

- NVD CVE API 2.0: CVE metadata, descriptions, references, CWE, CPE criteria, all published CVSS v4 assessments, and NVD-carried CISA KEV fields.
- FIRST EPSS API v1: EPSS probability, percentile, and score date.
- CISA KEV official JSON feed: direct authoritative KEV membership and catalog attributes.
- CVE Program production CVE Services API: CNA record plus ADP containers, including CISA Vulnrichment SSVC values when present (`Exploitation`, `Automatable`, `Technical Impact`).

## CVSS v4

Every NVD `cvssMetricV40` assessment is retained independently with source/type, vector, score, severity, and parsed metric groups:

- Base: `AV AC AT PR UI VC VI VA SC SI SA`
- Threat: `E`
- Environmental: `CR IR AR MAV MAC MAT MPR MUI MVC MVI MVA MSC MSI MSA`
- Supplemental: `S AU R V RE U`

The collector does not convert CVSS v3.1 into v4 and does not choose a winning CVSS v4 assessment.

## Missing semantics

Missing API evidence stays absent. It is not converted to zero, `NOT_LISTED`, `LOW`, or any inferred customer value. The one exception is direct KEV catalog absence, which is represented as `listed=false` only because the complete CISA catalog artifact was fetched as a single provider snapshot.

## Provenance

Raw provider responses are cached under `data/public-cve-intel-cache/` and SHA-256 hashes are recorded in the normalized snapshot. The snapshot itself has a canonical SHA-256 identity.

## Runtime

Manual:

```bash
python3 scripts/collect-public-vulnerability-intel.py current-cves.csv public-intel.json \
  --report public-intel.report.json
```

`NVD_API_KEY` is used automatically when present.

Scheduled/current platform data:

```bash
scripts/scheduled-public-intel-refresh.sh
```

The wrapper exports the current canonical CVEs from the RBVM API, collects all four public sources, and writes an immutable runtime snapshot plus checksum.

## Deliberate boundary

This automation does **not** fabricate organization-specific facts. `CR`, `IR`, `AR`, actual deployment reachability, business ownership/service meaning, and business/mission consequence remain customer/internal-environment evidence unless a future authenticated customer-system connector supplies them.

This increment is acquisition only. It does not modify Formula V1, choose a source winner, derive CVSS-BTE, or calculate organizational risk.
