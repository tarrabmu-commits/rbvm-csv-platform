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
- `CVSS_Source` must be an HTTPS URL.
- `CVSS_Observed_At` must be an ISO-8601 timestamp with timezone.

The platform does not convert CVSS v4.0 or v3.0 into v3.1. If v3.1 Base evidence is unavailable, this stage must remain without v3.1 evidence rather than fabricate a replacement.

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
        CVSS_V31_CSV_V1
                |
                v
        Contract validation
                |
                v
        Tenant/CVE resolution
                |
                v
        PostgreSQL CVSS history
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
- tests proving no priority, risk score, EPSS/KEV, or SLA is derived.

Not implemented yet:

- API/UI workflow for CVSS evidence;
- official-source NVD fetcher feeding this canonical contract/importer;
- explicit source-precedence policy, if one is later required;
- EPSS or CISA KEV redesign;
- RBVM priority, risk score, or SLA.

The next increment should expose this importer through an authenticated operator workflow without coupling CVSS evidence back into the Wazuh CSV or the legacy priority model.
