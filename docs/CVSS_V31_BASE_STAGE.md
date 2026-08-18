# CVSS v3.1 Base Enrichment Stage

This stage enriches an existing `WAZUH_CSV_V2` export with **CVSS v3.1 Base** evidence before any RBVM threat or organizational-context decision is applied.

## Purpose

The stage answers one narrow question:

> What is the technical severity evidence for this CVE under CVSS v3.1 Base?

It does **not** calculate organizational risk and does not use EPSS, CISA KEV, asset criticality, business impact, or remediation policy.

## Inputs

The input must satisfy the existing `WAZUH_CSV_V2` contract. CVEs are looked up through the official NVD CVE API.

## Outputs

When NVD exposes a valid CVSS v3.1 metric for a CVE, the stage populates:

- `CVSS_Version` = `3.1`
- `CVSS_Base_Score` = numeric Base score from NVD-hosted CVSS v3.1 evidence
- `CVSS_Vector` = vector beginning with `CVSS:3.1/`
- `Intel_Observed_At` = UTC observation timestamp
- `Intel_Source_References` = official NVD API endpoint

If CVSS v3.1 is not available, the CVSS fields remain empty. A CVSS v4.0 or v3.0 score is **not substituted or converted**.

## Selection policy

For `cvssMetricV31`, the stage selects a metric marked `Primary` when present; otherwise it uses the first v3.1 metric returned by NVD. It then validates that the returned version is exactly `3.1` and that the vector begins with `CVSS:3.1/`.

This makes the policy deterministic and auditable while preserving the original source evidence.

## Usage

```bash
python3 scripts/enrich-cvss-v31.py \
  input-v2.csv \
  output-v2-cvss.csv \
  --report output-v2-cvss.json
```

For NVD API rate limits, `NVD_API_KEY` is supported through the environment. `--offline` uses provenance-bound cached NVD responses already present in the cache directory.

## Pipeline position

```text
Wazuh finding evidence
        |
        v
CVSS v3.1 Base enrichment   <-- this stage
        |
        v
Technical severity evidence
        |
        v
Future threat/context stages
        |
        v
RBVM decision
```

The CVSS Base score must be interpreted as technical severity evidence, not as an organizational risk score.
