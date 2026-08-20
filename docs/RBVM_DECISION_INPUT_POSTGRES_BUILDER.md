# RBVM Decision Input Snapshot — PostgreSQL Builder

`PostgresDecisionInputSnapshotBuilder` materializes one typed `RBVM_DECISION_INPUT_SNAPSHOT_V1` from native PostgreSQL evidence history. It is an evidence-selection boundary only: it does not persist the snapshot, choose an active methodology, rank evidence values, calculate risk, assign priority/SLA/treatment, or roll findings into Cases.

## Explicit evaluation identity

Every build requires all four inputs explicitly:

`Finding_ID + methodology revision + methodology policy SHA-256 + evaluatedAt`

The requested methodology revision must already exist in the immutable V16 registry and its registered SHA-256 must exactly match the caller-supplied SHA. The builder never chooses the current, active, highest, or maximum methodology revision.

## Transaction-consistent native evidence read

The seven evidence dimensions are read under one PostgreSQL `REPEATABLE READ`, read-only transaction after the canonical tenant and Finding are resolved. This prevents a concurrent evidence import from being visible to only part of one Decision Input Snapshot.

The builder queries immutable native history relations directly and bounds admissibility by the explicit evaluation time. It does not query `current_*` or `finding_*` evidence views because those views are wall-clock/current projections and cannot reproduce a historical `evaluatedAt` snapshot.

## Native evidence mapping

| Dimension | Native history | Semantic source | Sub-grain |
|---|---|---|---|
| Applicability | `applicability_assessment` | `evidence_source` | Finding |
| Technical Severity | `cvss_v31_base_evidence` | `cvss_source` | vulnerability/CVE |
| Known Exploitation | `cisa_kev_evidence` + catalog snapshot | `kev_source` | vulnerability/CVE |
| Exploitation Probability | `epss_evidence` + score snapshot | `epss_source` | vulnerability/CVE |
| Asset Context | `asset_context_evidence` + snapshot | `context_source` | Asset |
| Network Reachability | `network_reachability_evidence` + snapshot | `evidence_source` | Asset + origin scope + normalized origin label + protocol + port |
| Business/Mission Impact | `business_impact_evidence` + snapshot | `impact_source` | Asset + normalized service + impact dimension |

Only native evidence UUID, evidence-row SHA-256, semantic source, observation/evaluation time, and sub-grain metadata enter selection. Evidence values such as CVSS score/vector, KEV membership, EPSS probability/percentile, business criticality, reachability status, or impact level are not read by the builder.

## EPSS chronology

EPSS has a native chronology that differs from local acquisition chronology. For each semantic EPSS source, the builder first restricts candidates to the latest admissible `score_date`. The shared selector then applies latest `observed_at` within that publication-date frontier, source allowlisting, ambiguity preservation, and freshness.

This prevents a later offline replay of an older FIRST score file from replacing a newer published score. EPSS probability and percentile never participate in selection.

## Output and persistence boundary

The result is an immutable typed `RbvmDecisionInputSnapshot`. Callers may persist it separately through `DecisionInputSnapshotStore.install(...)`. Keeping build and install transactions separate preserves the distinction between:

1. a transaction-consistent read of native evidence history; and
2. immutable replay/conflict handling in V17 snapshot persistence.

No evidence row is created, updated, deleted, or mutated by the builder.
