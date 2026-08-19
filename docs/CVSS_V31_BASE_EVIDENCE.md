# CVSS v3.1 Base Evidence Foundation

This stage provides a dedicated CVE-scoped evidence boundary for **CVSS v3.1 Base**. It is intentionally separate from Wazuh finding evidence, applicability, EPSS, CISA KEV, asset context, remediation policy, and the legacy combined intelligence/priority model.

## Question answered by this stage

```text
For this CVE, what CVSS v3.1 Base technical-severity evidence was observed,
from which source, and when?
```

It does **not** answer organizational risk, exploitation probability, remediation priority, or SLA. Those are later RBVM stages.

## Contract

`CVSS_V31_CSV_V1` has semantics:

```text
CVE_SCOPED_CVSS_V31_BASE_EVIDENCE
```

Required headers:

```text
CVE_ID,CVSS_Version,CVSS_Base_Score,CVSS_Vector,CVSS_Source,CVSS_Observed_At
```

The contract is CVE-scoped because CVSS Base describes intrinsic technical vulnerability characteristics. Asset and deployment context remain outside this stage.

### Validation rules

- `CVE_ID` must be a valid CVE identifier.
- `CVSS_Version` must be exactly `3.1`.
- `CVSS_Base_Score` must be `0.0..10.0` with at most one decimal place.
- `CVSS_Vector` must contain exactly the eight Base metrics: `AV`, `AC`, `PR`, `UI`, `S`, `C`, `I`, and `A`.
- Metric ordering is not significant; duplicates and invalid values are rejected.
- Temporal and Environmental metrics are rejected by this Base-only contract.
- The supplied Base score must mathematically equal the score calculated from the vector using the FIRST CVSS v3.1 Base equations and Roundup semantics.
- Contradictory score/vector evidence is quarantined as `INVALID_CVSS_BASE_SCORE`; neither field is silently replaced.
- `CVSS_Source` must be HTTPS.
- `CVSS_Observed_At` must be an ISO-8601 timestamp with timezone.

The platform does not numerically convert CVSS v4.0 or v3.0 into v3.1. If exact v3.1 evidence is unavailable, it remains unavailable.

See [`CVSS_V31_SCORE_VALIDATION.md`](CVSS_V31_SCORE_VALIDATION.md) for the score/vector integrity boundary.

## Evidence identity and history

Within the evidence contract one observation is identified by:

```text
CVE_ID + CVSS_Source + CVSS_Observed_At
```

For the same key, semantically identical evidence is deduplicated even when Base metrics are reordered. Conflicting content is quarantined. Different observation times preserve history and freshness independently from other intelligence sources.

## PostgreSQL persistence

`V10__cvss_v31_base_persistence.sql` persists immutable history in:

```text
rbvm.cvss_v31_base_evidence
```

Persistent grain:

```text
Tenant + CVE + CVSS Source + Observed At
```

Tenant scope is an isolation boundary; it does not make CVSS Base asset-specific. Evidence is attached to the CVE and joins to findings through `vulnerability_id`.

Runtime privileges are append-only (`SELECT, INSERT`), with `UPDATE`, `DELETE`, and `TRUNCATE` revoked.

`rbvm.current_cvss_v31_base_evidence` selects the latest observation **per source** for each tenant and CVE. It does not choose a winning source. `rbvm.finding_cvss_v31_base_evidence` joins findings to all current per-source observations.

## Transactional import

`PostgresCvssV31Importer` first runs the dedicated contract analyzer and then persists only accepted evidence inside a serializable PostgreSQL transaction.

Each accepted CVE must already be attached to at least one canonical finding in the selected tenant. Otherwise it is quarantined as:

```text
CVE_NOT_FOUND_IN_TENANT
```

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

The importer canonicalizes the vector before hashing/storage. Catalog revision changes only when new evidence is inserted; pure replay does not create a false catalog change. Fatal database failures roll back the transaction.

## Authenticated API and operator UI

PostgreSQL schema V10+ exposes:

```text
POST /api/v1/cvss-v31-imports
GET  /api/v1/cvss-v31-evidence
GET  /cvss
```

The import endpoint requires `OPERATOR`. The read endpoint requires `VIEWER` and returns current **per-source** CVSS evidence. The `/cvss` page supports operator upload and review. If V10 is unavailable, the capability is reported unavailable and the endpoints return `503`; the platform does not fall back to the legacy combined intelligence model.

## Official NVD collection

`scripts/collect-nvd-cvss-v31.py` is the official-source producer for this contract. It accepts any CSV containing `CVE_ID`, including `WAZUH_CSV_V1`, queries NVD CVE API 2.0, and emits a separate `CVSS_V31_CSV_V1` file.

The collector emits only `metrics.cvssMetricV31` entries where:

```text
cvssData.version = 3.1
metric.source     = nvd@nist.gov
```

It does not fall back to v4.0, v3.0, CNA/vendor evidence, a `Primary` flag, or a highest-score rule. Multiple distinct NVD-authored v3.1 candidates remain ambiguous rather than being arbitrarily selected.

See [`NVD_CVSS_V31_COLLECTOR.md`](NVD_CVSS_V31_COLLECTOR.md).

## Scheduled safe handoff

The official collector is now connected to the canonical importer through a scheduled, authenticated evidence handoff:

```text
Configured Wazuh/CVE CSV
        |
        v
collect-nvd-cvss-v31.py
        |
        v
CVSS_V31_CSV_V1 + collection report + SHA-256
        |
        v
import-cvss-v31.py
        |
        v
POST /api/v1/cvss-v31-imports
        |
        v
same contract validation
        |
        v
same tenant/CVE resolution
        |
        v
same transactional importer
        |
        v
PostgreSQL immutable history
```

There is deliberately no NVD-to-database shortcut. The scheduler does not use JDBC, `psql`, or `enrich-wazuh-v2.py`.

`scripts/scheduled-cvss-v31-refresh.sh` stages collection and import results privately, and publishes an immutable snapshot directory only after the HTTP import completes. Publication uses a same-filesystem directory rename; then one `latest` symlink is atomically moved to the completed snapshot.

A published snapshot contains:

```text
cvss-v31-YYYYMMDDTHHMMSSZ/
    evidence.csv
    evidence.csv.sha256
    collection.json
    import.json
```

Quarantined rows produce a visible `PARTIAL` result while preserving the completed import ledger. Collection, authentication, transport, importer, or response-contract failure prevents snapshot publication and leaves `latest` unchanged.

The repository includes a daily systemd timer and hardened oneshot service. See [`CVSS_V31_AUTOMATION.md`](CVSS_V31_AUTOMATION.md) for deployment, secret separation, transport policy, retention, and replay behavior.

## Relationship to legacy intelligence

The existing `VulnerabilityIntelligenceEvidence`, PostgreSQL V7 intelligence fields, and legacy enrichment scheduler combine CVSS, EPSS, KEV, shared provenance, and a local priority heuristic. They remain compatibility/legacy behavior only. The canonical CVSS path does not call `priorityTier()` and does not use the shared legacy provenance model.

Migration away from legacy combined intelligence must remain additive and auditable; historical migrations are not rewritten.

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
        Authenticated safe handoff
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
        API / UI / current-per-source evidence
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

No `WAZUH_CSV_V1 -> WAZUH_CSV_V2` promotion is required to attach CVSS v3.1 Base evidence.

## Current stage boundary

Implemented:

- independent CVSS v3.1 Base evidence model and CSV contract;
- strict Base-vector syntax/value validation;
- FIRST Base-score calculation and score/vector consistency enforcement;
- deterministic deduplication/conflict quarantine;
- immutable PostgreSQL V10 history and current-per-source views;
- finding-to-CVSS join without source precedence;
- transactional tenant-scoped importer and replay idempotency;
- authenticated API, runtime capability reporting, and operator UI;
- official NVD-authored exact-v3.1 collector;
- collector cache/offline verification and ambiguity handling;
- authenticated safe handoff back through the canonical importer;
- atomic completed-snapshot publication, checksum, collection/import ledgers, retention, and locking;
- daily hardened systemd scheduling;
- tests proving the automated path does not bypass canonical validation/persistence boundaries.

Not implemented yet:

- vendor/CNA-specific CVSS collectors;
- explicit cross-source precedence policy, if one is later required;
- EPSS redesign;
- CISA KEV redesign;
- asset/business context;
- RBVM priority, risk score, or SLA.

The next methodology stage should leave CVSS as Technical Severity and move to independent threat evidence, starting with CISA KEV rather than extending CVSS into a risk formula.
