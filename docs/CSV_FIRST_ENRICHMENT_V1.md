# CSV-First Public Intelligence Enrichment V1

Contract ID: `CSV_FIRST_PUBLIC_INTELLIGENCE_ENRICHMENT_V1`

## Purpose

This is the immediate stateless workflow for evaluating one customer-supplied CSV without depending on previously persisted tenant, Case, Finding, or PostgreSQL state.

The uploaded/input CSV is the complete workload scope for the run:

```text
One input CSV
    ↓
validate CVE_ID
    ↓
deduplicate CVEs for provider collection
    ↓
PUBLIC_CVE_INTEL_SNAPSHOT_V1
    ↓
merge by CVE_ID back onto every original row
    ↓
one enriched CSV + immutable snapshot/report
```

Only `CVE_ID` is required by the public-intelligence stage. Wazuh V1/V2 rows are supported naturally because they already contain `CVE_ID`, but public enrichment does not require a prior database import or WAZUH_CSV_V2-only fields.

## Command

```bash
python3 scripts/enrich-uploaded-csv.py input.csv enriched.csv
```

Optional `NVD_API_KEY` improves NVD request throughput. Provider responses are cached under `data/public-cve-intel-cache` by default.

The run emits:

- `enriched.csv` — every original row/column plus normalized public intelligence;
- `enriched.csv.public-intel.json` — immutable `PUBLIC_CVE_INTEL_SNAPSHOT_V1`;
- `enriched.csv.public-intel.report.json` — provider-collection report;
- `enriched.csv.report.json` — CSV-first orchestration report with input/output SHA-256 and `scope=INPUT_CSV_ONLY`.

## Automated public fields

The current provider layer collects:

- NVD CVE metadata, description, CWE, CPE criteria, references, and every available CVSS v4 assessment;
- FIRST EPSS probability, percentile, and score date;
- the complete CISA KEV catalog, including explicit listed/not-listed semantics for the validated catalog snapshot;
- CVE Program CNA metadata and ADP summaries;
- CISA Vulnrichment SSVC values when present: Exploitation, Automatable, and Technical Impact.

The enriched CSV materializes convenient columns for these values while preserving the complete multi-assessment CVSS v4 payload as JSON.

## CVSS v4 selection safety

This workflow does not invent a source winner:

- zero CVSS v4 assessments → `CVSS4_Status=MISSING`;
- exactly one distinct assessment → `CVSS4_Status=PRESENT` and singular convenience columns are populated;
- two or more distinct assessments → `CVSS4_Status=AMBIGUOUS`; singular score/vector/metric columns remain blank and all assessments remain in `CVSS4_Assessments_JSON`.

There is no v3.1-to-v4 conversion, highest-score-wins behavior, or first-row selection.

## Scope and provenance

The workflow:

- preserves original row order and duplicate findings;
- deduplicates only the provider lookup CVE inventory;
- rejects enrichment-column collisions rather than silently overwriting prior values;
- binds every row to `Intel_Observed_At` and `Public_Intel_Snapshot_SHA256`;
- preserves CVE Services response SHA-256 per CVE where available;
- never queries current RBVM Cases or tenant database state to determine the run scope.

A replay/testing path may supply an already-created snapshot using `--intel-snapshot`; its CVE set must exactly equal the current input CSV CVE set.

## Deliberate boundary

Public Internet sources cannot establish organization-specific truth. This workflow therefore does not fabricate:

- CVSS v4 `CR`, `IR`, or `AR` for a customer asset;
- actual Internet/internal reachability or network segmentation;
- business service, owner, criticality, or mission consequence;
- organizational risk, treatment priority, SLA, or remediation deadline.

Those values may later be supplied from customer evidence or customer-system APIs. They are not inferred from public CVE metadata.

## Verification

`./scripts/verify.sh` now includes:

- `verify-public-vulnerability-intel.py` for offline provider-normalization semantics;
- `verify-csv-first-enrichment.py` for an offline end-to-end merge covering CVSS v4 `PRESENT`, `AMBIGUOUS`, and `MISSING`, EPSS, KEV, CISA SSVC, row preservation, and the no-database-state invariant.
