# RBVM Canonical MVP Priority Integration V1

## Purpose

`RBVM_CANONICAL_MVP_PRIORITY_INTEGRATION_V1` makes the frozen CSV-first treatment-priority result available on exact canonical Findings without changing or reimplementing `RBVM_MVP_PRIORITY_POLICY_V1`.

The frozen policy remains:

- method: `RBVM_MVP_PRIORITY_POLICY_V1`
- SHA-256: `88d5cdb8702c6c0ed2c033c3df6b8abbe1aa392f44f4507685b54082a16dc388`
- classification: `RBVM_POLICY`
- semantics: `RELATIVE_TREATMENT_PRIORITY_PARETO_FRONT_WITHIN_INPUT_SET`
- weights: none
- thresholds: none
- Organizational Risk: `NON_COMPUTABLE`

## Why materialize instead of recompute

The current canonical evidence catalog and the CSV-first contextual-analysis contract are deliberately not interchangeable. In particular, the CSV-first priority method consumes contextual CVSS v4 calculated from direct customer CR/IR/AR declarations. Canonical CVSS v3.1 evidence, Asset Criticality, or Internet Facing must not be coerced into those missing inputs.

Therefore V1 does not recompute Pareto priority from approximated canonical fields. It materializes only an already-derived immutable priority artifact onto canonical Findings through exact persisted import lineage.

## Exact association boundary

The materialization command binds one exact triple:

```text
canonical importId + CSV-first runId + analysisId
```

Before any write, the server requires:

1. the canonical import is `COMPLETED`;
2. `csv-first-enrichments/{runId}/input.csv` exists as a regular non-symlink artifact;
3. the frozen-method priority artifact exists under the exact `analysisId` and method SHA;
4. the SHA-256 of the CSV-first original input equals `rbvm.import_run.file_sha256`;
5. each canonical source row resolves only through persisted lineage:

```text
import_observation.source_row_number
        -> observation
        -> exposure_observation
        -> exposure (canonical Finding)
```

Hostname, CVE, product, filename, severity, timestamps, or name similarity are never used to associate priority results to Findings.

If several exact source rows collapse to one canonical Finding, all priority result fields and all five admitted inputs must be identical. A disagreement is an ambiguity and the whole transaction fails closed.

## Persistence

PostgreSQL V29 adds `rbvm.finding_mvp_priority_result`.

Each append-only row binds:

- canonical Finding identity;
- canonical import identity;
- CSV-first run and analysis identities;
- frozen method identity and SHA;
- original source CSV SHA;
- immutable priority CSV SHA;
- deterministic result SHA;
- ranked/unrankable state, Pareto front and dominance counts;
- blockers and deterministic `Why?` explanation;
- exact source-row numbers;
- the five admitted priority inputs as artifact-bound provenance.

The copied KEV, Internet Facing, Asset Criticality, EPSS, and contextual CVSS v4 fields are **not new canonical evidence records**. They explain the exact immutable priority artifact that was materialized. The authoritative evidence stores remain separate.

Database UPDATE and DELETE are rejected by an append-only trigger. Exact retries replay existing immutable content; conflicting content under the same materialization identity is rejected.

## HTTP contracts

Materialize, Operator-only:

```text
POST /api/v1/canonical-mvp-priorities/{importId}/{runId}/{analysisId}
```

Read latest explicitly materialized result for one Finding, Viewer:

```text
GET /api/v1/canonical-mvp-priorities/findings/{findingId}
```

The read response preserves method identity, result semantics, admitted inputs, exact source-row lineage, source/priority artifact hashes, immutable result SHA, and materialization time.

There is no endpoint that silently computes priority from current canonical evidence and no implicit fuzzy association.

## Product behavior

After an explicit canonical import and a completed CSV Finding Review, the run review exposes **Persist to canonical Findings**. The action is unavailable until the exact canonical `importId` exists.

The canonical Finding drawer then exposes a **Priority** tab. Priority reads are lazy and Finding-scoped when the drawer opens; the Findings table does not perform a catalog-wide N+1 priority load.

The UI displays `Front n` or `Unrankable` plus `Why?` and supporting admitted inputs. It never relabels the result as Organizational Risk, Critical Risk, SLA, or remediation deadline.

## Change boundary

This integration is a persistence/association/presentation change only. It must not change:

- frozen Pareto dimensions or mappings;
- dominance/fronting rules;
- missing-evidence behavior;
- method ID/SHA;
- CVSS, EPSS, KEV, SSVC, or customer-context semantics;
- Organizational Risk state.

Any semantic change to the priority policy requires a new method identity/version under the MVP freeze rules.
