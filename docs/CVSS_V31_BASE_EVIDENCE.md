# CVSS v3.1 Base Evidence Foundation

This stage provides a dedicated CVE-scoped evidence boundary for **CVSS v3.1 Base**. It is intentionally separate from Wazuh finding evidence, applicability, EPSS, CISA KEV, asset context, remediation policy, and the legacy combined intelligence/priority model.

## Question answered by this stage

```text
For this CVE, what CVSS v3.1 Base technical-severity evidence was observed,
from which source, and when?
```

It does **not** answer:

```text
How risky is this finding to this organization?
How likely is exploitation?
What should be remediated first?
What SLA applies?
```

Those are later RBVM stages.

## Contract

`CVSS_V31_CSV_V1` has the semantics:

```text
CVE_SCOPED_CVSS_V31_BASE_EVIDENCE
```

Required headers:

```text
CVE_ID,CVSS_Version,CVSS_Base_Score,CVSS_Vector,CVSS_Source,CVSS_Observed_At
```

The contract is CVE-scoped rather than finding-scoped because CVSS Base describes the intrinsic technical characteristics of the vulnerability. Asset-specific and deployment-specific context remains outside this stage.

### Validation rules

- `CVE_ID` must be a valid CVE identifier.
- `CVSS_Version` must be exactly `3.1`.
- `CVSS_Base_Score` must be between `0.0` and `10.0`, with at most one decimal place.
- `CVSS_Vector` must begin with `CVSS:3.1/`.
- The vector must contain exactly the eight CVSS v3.1 Base metrics: `AV`, `AC`, `PR`, `UI`, `S`, `C`, `I`, and `A`.
- Metric ordering is not significant.
- Duplicate metrics are rejected.
- Invalid metric values are rejected.
- Temporal or Environmental metrics are rejected by this Base-only evidence contract rather than silently accepted into a different score type.
- The published `CVSS_Base_Score` must equal the Base score calculated from `CVSS_Vector` using the FIRST CVSS v3.1 equations, metric weights, scope-dependent Privileges Required weights, and one-decimal Roundup semantics.
- A syntactically valid score/vector pair that disagrees mathematically is quarantined as `INVALID_CVSS_BASE_SCORE`; the platform does not silently replace either value.
- `CVSS_Source` must be an HTTPS URL.
- `CVSS_Observed_At` must be an ISO-8601 timestamp with timezone.

The platform does not convert CVSS v4.0 or v3.0 into v3.1. If v3.1 Base evidence is unavailable, this stage must remain without v3.1 evidence rather than fabricate a replacement.

The score/vector consistency implementation is documented separately in [`CVSS_V31_SCORE_VALIDATION.md`](CVSS_V31_SCORE_VALIDATION.md).

## Evidence identity and history

Within a CVSS evidence file, one evidence observation is identified by:

```text
CVE_ID + CVSS_Source + CVSS_Observed_At
```

For the same key:

- semantically identical evidence is deduplicated, even when the eight Base metrics are written in a different valid order;
- a different score or vector is quarantined as conflicting same-time source evidence.

Different observation times are allowed so persistence can preserve evidence history and freshness independently from EPSS or KEV freshness.

## PostgreSQL persistence

Schema migration `V10__cvss_v31_base_persistence.sql` persists immutable CVSS observations in:

```text
rbvm.cvss_v31_base_evidence
```

The persistent grain is:

```text
Tenant + CVE + CVSS Source + Observed At
```

Tenant scope is an access/isolation boundary. It does not make CVSS Base asset-specific; the evidence remains attached to the CVE and is joined to findings only through their `vulnerability_id`.

The table stores:

```text
cvss_version
base_score
vector
cvss_source
observed_at
ingested_at
evidence_sha256
```

The runtime role receives `SELECT, INSERT` only and explicit `UPDATE`, `DELETE`, and `TRUNCATE` revocation, so CVSS history is append-only at runtime.

### Current evidence semantics

`rbvm.current_cvss_v31_base_evidence` selects the latest observation **per CVSS source** for each tenant and CVE:

```text
Tenant + CVE + CVSS Source -> latest observed evidence
```

It intentionally does **not** choose a winning source when multiple sources exist. Recency is not an authority policy.

`rbvm.finding_cvss_v31_base_evidence` joins canonical findings to all current per-source CVSS observations through the CVE. Therefore one finding may have zero, one, or multiple current CVSS source rows. This persistence layer does not turn disagreement between sources into an implicit priority or risk decision.

## Transactional import

`PostgresCvssV31Importer` is the persistence boundary for `CVSS_V31_CSV_V1`.
It first runs the dedicated contract analyzer, then persists only parser-accepted evidence inside a serializable PostgreSQL transaction.

Each accepted `CVE_ID` must already be attached to at least one canonical finding in the selected tenant. The importer resolves the CVE through tenant-scoped exposures rather than accepting a globally known CVE as sufficient local evidence. A syntactically valid row that cannot be resolved in the tenant is quarantined as:

```text
CVE_NOT_FOUND_IN_TENANT
```

For persisted evidence, the identity is:

```text
Tenant + CVE + CVSS Source + CVSS Observed At
```

The importer canonicalizes the Base vector before hashing and storage. Therefore a metric-order-only replay remains idempotent.

Persistence behavior is deterministic:

```text
same tenant + CVE + source + observed_at + same evidence
    -> REPLAYED

same tenant + CVE + source + observed_at + different evidence
    -> QUARANTINED
       CONFLICTING_PERSISTED_CVSS_EVIDENCE_TIMESTAMP

same tenant + CVE + observed_at + different source
    -> independently INSERTED
```

Different sources are preserved side by side. The importer does not create a source-precedence rule and does not overwrite one source with another.

The catalog revision changes only when new evidence is inserted. A pure replay does not create a false catalog change. Fatal database failures roll back the persistence transaction.

## Authenticated API and operator UI

The runtime exposes the dedicated CVSS evidence path only when PostgreSQL schema version 10 or newer is installed.

```text
POST /api/v1/cvss-v31-imports
GET  /api/v1/cvss-v31-evidence
GET  /cvss
```

`POST /api/v1/cvss-v31-imports` requires `OPERATOR` authorization and accepts the same CSV media types as the other evidence upload paths. It stages the body with the configured upload limit, then calls the transactional importer. The response separates parser-level and persistence-level replay/quarantine counts.

`GET /api/v1/cvss-v31-evidence` requires `VIEWER` authorization and returns the current **per-source** CVSS evidence. Supported query parameters are:

```text
limit=1..500        default 100
cve=CVE-...         optional exact identifier or prefix
```

The read path is tenant-scoped through the local tenant and reads from `rbvm.current_cvss_v31_base_evidence`. It does not join to or expose the legacy priority heuristic.

The dedicated `/cvss` page provides an operator-oriented workflow for:

1. entering the same bearer API key used by the main UI;
2. uploading `CVSS_V31_CSV_V1` evidence;
3. seeing inserted, replayed, deduplicated, and quarantined counts;
4. filtering and reviewing current per-source CVSS evidence.

The main health response now includes an explicit capability object:

```json
{
  "cvssV31": {
    "importEnabled": true,
    "evidenceReadEnabled": true
  }
}
```

If PostgreSQL V10 is unavailable, these capabilities are false and the CVSS API endpoints return `503` rather than falling back to the legacy combined intelligence model.

## Official NVD collection

`scripts/collect-nvd-cvss-v31.py` is the first automated producer for this contract. It accepts any CSV with a `CVE_ID` column, including `WAZUH_CSV_V1`, queries the NVD CVE API 2.0, and writes a separate `CVSS_V31_CSV_V1` file.

The collector is deliberately narrower than the NVD response. It emits only `metrics.cvssMetricV31` entries whose `cvssData.version` is exactly `3.1` and whose metric `source` is exactly `nvd@nist.gov`. It never falls back to v4.0, v3.0, or another provider merely because that provider is marked `Primary`.

The resulting CSV still goes through the existing contract analyzer and transactional importer; the collector does not write directly to PostgreSQL. See [`NVD_CVSS_V31_COLLECTOR.md`](NVD_CVSS_V31_COLLECTOR.md) for source policy, caching, rate-limit behavior, ambiguity handling, and usage.

## Relationship to current platform intelligence

The existing `VulnerabilityIntelligenceEvidence` and PostgreSQL V7 fields combine CVSS, EPSS, KEV, shared provenance, and a local priority heuristic. They remain compatibility/legacy behavior for now. This new evidence boundary does not call `priorityTier()` and does not use shared `Intel_Observed_At` or `Intel_Source_References` as the canonical CVSS model.

Migration away from that combined model must happen through additive, auditable migrations rather than rewriting historical migrations.

## Pipeline position

```text
Wazuh observation / canonical finding
        |
        +---- Applicability evidence
        |
        +---- CVE_ID
                |
                v
        NVD CVSS v3.1 collector
                |
                v
        CVSS_V31_CSV_V1
                |
                v
        Contract validation
        (syntax + Base score/vector consistency)
                |
                v
        Tenant/CVE resolution
                |
                v
        PostgreSQL CVSS history
                |
                v
        Authenticated API / operator UI
                |
                v
        Technical Severity
                |
                v
        later threat + organizational context
                |
                v
        RBVM decision
```

No `WAZUH_CSV_V1 -> WAZUH_CSV_V2` promotion is required to attach CVSS v3.1 Base evidence, because this contract is independent and CVE-scoped.

## Current stage boundary

Implemented:

- independent `CvssV31BaseEvidence` domain model;
- exact v3.1 Base vector validation;
- FIRST CVSS v3.1 Base-score calculation and score/vector consistency enforcement;
- dedicated `CVSS_V31_CSV_V1` contract;
- streaming RFC 4180 / strict UTF-8 analyzer;
- deterministic within-file replay/conflict handling;
- validation ledger and preview;
- PostgreSQL V10 immutable CVSS evidence history;
- current-per-source CVSS view;
- canonical finding-to-CVSS evidence view;
- runtime append-only privileges;
- transactional `CVSS_V31_CSV_V1` importer;
- tenant/CVE membership enforcement during import;
- persisted replay idempotency;
- persisted same-source/same-time conflict quarantine;
- independent coexistence of multiple CVSS sources;
- canonical vector persistence;
- catalog revision only on new evidence;
- authenticated operator import API;
- authenticated current-evidence read API;
- explicit V10 runtime capability reporting;
- dedicated operator UI at `/cvss`;
- official NVD CVSS v3.1 collector producing this contract from a CSV `CVE_ID` set;
- offline batch-fingerprint cache verification for collector replay/testing;
- collector tests proving no v4.0, v3.0, CNA/vendor, priority, risk, EPSS/KEV, or SLA fallback;
- HTTP and JDBC self-tests for the workflow;
- tests proving no priority, risk score, EPSS/KEV, or SLA is derived.

Not implemented yet:

- automatic scheduling/import of newly collected NVD CVSS evidence;
- vendor/CNA-specific CVSS collectors;
- explicit cross-source precedence policy, if one is later required;
- EPSS or CISA KEV redesign;
- RBVM priority, risk score, or SLA.

The next CVSS increment can automate scheduling and safe handoff of the generated `CVSS_V31_CSV_V1` into the existing importer without weakening validation, provenance, freshness, tenant/CVE resolution, or score/vector integrity.
