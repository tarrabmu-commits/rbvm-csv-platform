# Local Public Intelligence Store V1

Contract: `LOCAL_PUBLIC_INTELLIGENCE_STORE_V1`

## Purpose

V30 creates a global, non-tenant operational mirror for public vulnerability intelligence so RBVM can stop depending on thousands of provider HTTP requests during a future CSV upload. The mirror is source infrastructure only. It is not a risk score, priority method, customer evidence store, SLA policy, or applicability decision.

Supported provider identities are:

- `NVD`
- `FIRST_EPSS`
- `CISA_KEV`
- `CVE_PROGRAM`

Public source data is shared once for the platform. Customer context such as Asset Criticality, Internet Facing, direct CVSS v4 CR/IR/AR declarations, reachability, business impact, and all tenant-scoped evidence remain separate.

## V30 boundary

V30 establishes the persistence and local-lookup contract. CSV enrichment is not switched to the local store by V30. Provider download/bootstrap adapters, incremental synchronization jobs, status HTTP APIs, the Update Intelligence Now UI, scheduled refresh, and CSV local-lookup cutover are follow-up layers built on this contract.

This separation makes the persistence semantics testable before network behavior changes.

## Sync runs

`rbvm.public_intelligence_sync_run` records one exact provider source payload.

A run has one of two source scopes:

- `BOOTSTRAP`
- `INCREMENTAL`

and one lifecycle state:

- `STAGING`
- `COMPLETE`
- `FAILED`

Only COMPLETE runs are admitted to current local lookup. STAGING data is invisible to consumers. A FAILED refresh therefore cannot replace or erase the last successful provider data.

Source identity includes provider, source URI, source version, exact SHA-256, source publication time when available, and observation time. An exact non-failed provider/source SHA is replayed rather than duplicated. FAILED runs are excluded from that uniqueness boundary so the exact source can be retried.

Run source identity is immutable. The only allowed mutation is the explicit `STAGING -> COMPLETE` or `STAGING -> FAILED` terminal transition. Terminal runs cannot be edited or deleted.

## Provider records

`rbvm.public_intelligence_record` stores immutable CVE-scoped source records under one exact sync run.

Record states are:

- `ACTIVE`: carries source JSON.
- `TOMBSTONE`: carries no source JSON and explicitly states that a newer complete provider update suppresses older local state for that CVE.

Records can be inserted only while the owning run is STAGING. UPDATE and DELETE are rejected at the database layer.

A record SHA-256 binds CVE, record state, source timestamps, source JSON text, and observation time. The Java store uses bounded batch persistence and exact replay/conflict detection.

## Current-state resolution

`rbvm.latest_public_intelligence_record` first resolves the latest record independently for each `(provider, CVE)` across COMPLETE runs, including TOMBSTONE records.

`rbvm.current_public_intelligence_record` then filters that resolved state to ACTIVE records.

The order is intentional. Filtering ACTIVE records before selecting the latest provider statement would allow an older record to reappear after a newer tombstone.

`rbvm.public_intelligence_source_status` exposes both the latest synchronization attempt and the latest successful synchronization independently for all four supported providers. A future product status page can therefore distinguish:

- never synchronized;
- currently staging;
- latest attempt failed while older successful data remains usable;
- current successful source version and record count.

## Local lookup

`PostgresPublicIntelligenceStore.lookupCurrent(...)` performs a PostgreSQL local lookup for a set of CVE identifiers and returns each provider independently. It does not combine providers into a score and does not invent missing data.

One CVE may therefore have, for example, current NVD and FIRST EPSS records while having no current CISA KEV or CVE Program record. Missing provider data remains absent.

Provider-specific evidence semantics are intentionally deferred to provider adapters/materializers. In particular, absence from a partial local mirror must never be interpreted as CISA KEV `NOT_LISTED`. That status is valid only when a complete validated KEV catalog observation establishes non-membership.

## Relationship to existing tenant evidence

Existing tenant-scoped immutable stores such as `cisa_kev_catalog_snapshot`, `cisa_kev_evidence`, `epss_score_snapshot`, and `epss_evidence` remain authoritative evidence contracts for tenant decisions.

The V30 global mirror is an efficient public-source acquisition/cache layer. Follow-up code may materialize exact admitted public evidence from it, preserving source SHA, observation time, and provider semantics. It must not silently reinterpret the mirror as customer-specific evidence.

## Decision reproducibility

Refreshing the global mirror does not change historical decision artifacts. Existing contextual analyses, frozen MVP Pareto priority results, method SHA bindings, and canonical priority materializations remain bound to the exact evidence/artifact versions that produced them.

A future recalculation must create a new explicit analysis/materialization against newly admitted evidence; it must not mutate old results.

## Failure behavior

The sync contract is fail-closed:

1. provider bytes are downloaded and validated by the future adapter;
2. a STAGING run is opened for the exact validated source identity;
3. immutable records are appended;
4. the record count is verified;
5. only then does the run become COMPLETE.

If any provider download, validation, parse, or import stage fails, the run becomes FAILED. Its records remain historical but are excluded from current lookup. The last successful complete provider state stays usable.

## Next implementation layers

The next work on top of V30 is:

1. official-source bootstrap/incremental adapters for NVD, FIRST EPSS, CISA KEV, and CVE Program;
2. background synchronization job + provider-level persisted status;
3. `GET /api/v1/intelligence/status` and Operator `POST /api/v1/intelligence/sync`;
4. Intelligence Sources UI with manual **Update Intelligence Now**;
5. daily server-side scheduling and stale-source policy;
6. CSV enrichment cutover from live per-upload provider calls to `lookupCurrent(...)`;
7. 5k/6k/10k Finding PostgreSQL local-lookup benchmarks.

No change in this contract alters `RBVM_MVP_PRIORITY_POLICY_V1`, its frozen SHA, CVSS/EPSS/KEV semantics, or the intentionally `NON_COMPUTABLE` Organizational Risk state.
