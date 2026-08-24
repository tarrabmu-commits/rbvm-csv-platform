# Local Public Intelligence Store V1

Contract: `LOCAL_PUBLIC_INTELLIGENCE_STORE_V1`

## Purpose

V30 creates a global, non-tenant operational mirror for public vulnerability intelligence so RBVM does not depend on thousands of provider HTTP requests during a CSV upload. The mirror is source infrastructure only. It is not a risk score, priority method, customer evidence store, SLA policy, or applicability decision.

Supported provider identities are:

- `NVD`
- `FIRST_EPSS`
- `CISA_KEV`
- `CVE_PROGRAM`

Public source data is shared once for the platform. Customer context such as Asset Criticality, Internet Facing, direct CVSS v4 CR/IR/AR declarations, reachability, business impact, and all tenant-scoped evidence remain separate.

## V30 boundary

V30 establishes the persistence and local-lookup contract. Official-source acquisition, end-to-end synchronization lifecycle/status, operator-triggered refresh, scheduled refresh, UI, and CSV local-lookup cutover are layered on top without changing V30 provider-record semantics.

This separation makes persistence, acquisition, orchestration, and product transport independently testable.

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

`rbvm.public_intelligence_source_status` exposes V30 source-run state and the latest successful source independently for all four supported providers.

V31 adds `rbvm.public_intelligence_sync_job` and `rbvm.public_intelligence_provider_status_v1`. The V31 job begins before network acquisition, so HTTPS/metadata/archive/bundle failures that occur before a V30 run exists are durable. The unified V31 view exposes the latest end-to-end job and the last successful V30 source independently.

A product status page can therefore distinguish:

- never attempted;
- currently acquiring/building/admitting;
- latest end-to-end attempt failed before or during V30 admission;
- an older successful local source remains usable;
- current successful source version, SHA, completion time, and record count.

## Local lookup

`PostgresPublicIntelligenceStore.lookupCurrent(...)` performs a PostgreSQL local lookup for a set of CVE identifiers and returns each provider independently. It does not combine providers into a score and does not invent missing data.

One CVE may therefore have, for example, current NVD and FIRST EPSS records while having no current CISA KEV or CVE Program record. Missing provider data remains absent.

Provider-specific evidence semantics remain explicit. In particular, absence from a partial local mirror must never be interpreted as CISA KEV `NOT_LISTED`. That status is valid only when a complete validated KEV catalog observation establishes non-membership.

## CSV-first local-intelligence cutover

Product CSV enrichment uses `CSV_FIRST_LOCAL_PUBLIC_INTELLIGENCE_EXPORT_V1` to resolve only CVEs present in the uploaded CSV against the V30 current-state view. Lookups are bounded in batches rather than issuing provider requests per Finding or loading an arbitrary fixed maximum CVE count.

The local export contains:

- the exact requested CVE set;
- independent current provider records with record/source/run provenance;
- the last successful provider source state for all four providers;
- no customer or tenant context.

`build-local-public-intelligence-snapshot.py` converts that export into the established `PUBLIC_CVE_INTEL_SNAPSHOT_V1` shape. Existing NVD and CVE Program normalization functions are reused, so the acquisition cutover does not fork CVSS/CNA/ADP normalization semantics.

The product upload path then runs the established CSV enricher with `--intel-snapshot`. It does not invoke the live per-upload public-intelligence collector and does not silently fall back to provider Internet access.

The CISA KEV negative boundary is explicit:

- a current CISA KEV record means `listed=true`;
- absence after a successful complete validated CISA catalog permits `listed=false`;
- absence when no successful complete CISA catalog is available remains missing/unknown.

CSV enrichment subprocesses receive only generated local artifacts and a restricted environment allowlist. PostgreSQL credentials and provider API credentials are not inherited by the Python enrichment process.

If the V30/V31 PostgreSQL local-intelligence runtime is unavailable, the product CSV upload endpoint fails closed rather than reverting to live provider network calls.

The use of the global PostgreSQL mirror is reported as `databaseStateUsed=true` with `databaseStateScope=GLOBAL_PUBLIC_INTELLIGENCE_ONLY`; tenant database state remains explicitly unused by this acquisition stage.

## Relationship to existing tenant evidence

Existing tenant-scoped immutable stores such as `cisa_kev_catalog_snapshot`, `cisa_kev_evidence`, `epss_score_snapshot`, and `epss_evidence` remain authoritative evidence contracts for tenant decisions.

The V30 global mirror is an efficient public-source acquisition/cache layer. Follow-up code may materialize exact admitted public evidence from it, preserving source SHA, observation time, and provider semantics. It must not silently reinterpret the mirror as customer-specific evidence.

## Decision reproducibility

Refreshing the global mirror does not change historical decision artifacts. Existing contextual analyses, frozen MVP Pareto priority results, method SHA bindings, and canonical priority materializations remain bound to the exact evidence/artifact versions that produced them.

A future recalculation must create a new explicit analysis/materialization against newly admitted evidence; it must not mutate old results.

## Failure behavior

The combined V31/V30 pipeline is fail-closed:

1. a V31 end-to-end job starts in `RUNNING / ACQUIRING` before any provider request;
2. official provider bytes are acquired and validated by `PUBLIC_INTELLIGENCE_SOURCE_ACQUISITION_V1`;
3. `PUBLIC_INTELLIGENCE_SYNC_BUNDLE_V1` is built and fully validated;
4. only then is a V30 STAGING source run opened/replayed for the exact source identity;
5. immutable records are appended and the exact record count is verified;
6. the V30 run becomes COMPLETE;
7. only after the linked V30 run is COMPLETE may the V31 job become COMPLETE.

If acquisition or bundle construction fails before V30 admission, the V31 job becomes FAILED without inventing a V30 run. If V30 admission fails after a source run exists, V30 remains STAGING/FAILED according to its contract and the V31 job becomes FAILED. In every case, the last successful COMPLETE provider state stays usable.

CSV upload consumes only the last admitted current local state. A provider refresh failure therefore does not turn the upload path back into an Internet acquisition path and does not displace the last good source.

## Implemented layers above V30

`PUBLIC_INTELLIGENCE_SYNC_BUNDLE_V1` provides the deterministic provider-format-to-V30 admission boundary.

`PUBLIC_INTELLIGENCE_SOURCE_ACQUISITION_V1` provides hardened official-source acquisition for NVD, FIRST EPSS, CISA KEV, and CVE Program with exact source provenance, size bounds, provider-specific validation, and credential/redirect boundaries.

`PUBLIC_INTELLIGENCE_SYNC_JOB_V1` (V31) provides the durable end-to-end job lifecycle plus `GET /api/v1/intelligence/status`, including failures that occur before V30 admission.

Background/manual orchestration executes acquisition → bundle → V30 admission while advancing/failing V31 jobs. Operator manual synchronization is exposed through the intelligence sync API.

The native Frontend System V2 Intelligence Sources page exposes provider state and **Update Intelligence Now** without inventing progress percentages or stale thresholds.

Server-side automation provides scheduled refresh and resumable NVD annual bootstrap. The documented deployment boundary remains one automation node unless a future leader-election/lease contract is added.

CSV-first product enrichment is cut over to bounded V30 local lookup and the established `PUBLIC_CVE_INTEL_SNAPSHOT_V1` enrichment contract, with no silent per-upload provider-network fallback.

## Remaining implementation layer

Full scalability/capacity benchmarking remains progressive: 1K, 5K, 10K, 25K, 50K, 100K+ Findings and continued stress testing to the measured bottleneck. **10K is a regression checkpoint, not a platform limit.** The implementation itself does not impose a 10K Finding/CVE cap; local lookup proceeds in bounded batches across the complete uploaded scope.

No change in this contract alters `RBVM_MVP_PRIORITY_POLICY_V1`, its frozen SHA, CVSS/EPSS/KEV semantics, or the intentionally `NON_COMPUTABLE` Organizational Risk state.
