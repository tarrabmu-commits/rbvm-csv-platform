# PostgreSQL Decision Input Evidence Resolver

`PostgresDecisionInputEvidenceResolver` is the native-value dereference boundary between an immutable `RBVM_DECISION_INPUT_SNAPSHOT_V1` and any later Formula Contract.

It does **not** select evidence. Selection already happened when the Decision Input Snapshot was built. The resolver only loads the exact native immutable rows named by the snapshot and verifies that persisted provenance still matches the reference.

## Transaction semantics

Resolution runs under one read-only PostgreSQL `REPEATABLE READ` transaction. The resolver first resolves the local tenant and then processes every evidence reference retained by the snapshot.

A `MISSING` dimension contains no references and therefore performs no native evidence lookup.

Any missing row, provenance mismatch, invalid persisted native value, or SQL failure rolls the transaction back. A successful complete resolution commits the read transaction and returns one `RbvmResolvedDecisionInput`.

## Exact UUID dereference

Each lookup is tenant-scoped and addressed by the native evidence UUID from the snapshot:

```text
tenant_id + evidence_id
```

The resolver never searches for a newer, current, highest, nearest, or otherwise preferred row. It does not use `current_*` or `finding_*` views and it does not re-run `DecisionInputEvidenceSelection`.

For joined snapshot-backed evidence (KEV, EPSS, Asset Context, Network Reachability, Business/Mission Impact), native evidence rows are joined only to their immutable source snapshot so source and observation provenance can be verified.

## Provenance verification

Before returning any typed value, the resolver verifies the native row against the snapshot reference:

- native evidence UUID is the UUID used by the lookup;
- evidence-row SHA-256 matches `evidenceSha256`;
- semantic evidence source matches `evidenceSource`;
- native observation/evaluation timestamp matches `observedAt`.

If any of those fields differ, resolution fails. The resolver must never substitute a different row to make resolution succeed.

## Typed native values

The resolver maps the exact native rows to the already-defined `RbvmResolvedDecisionInput` types:

- Applicability status + reason;
- CVSS v3.1 Base version + score + vector;
- CISA KEV listing status and listing metadata;
- FIRST EPSS probability + percentile + model version + score date;
- Asset Context environment + service + owner + qualitative criticality;
- scoped Network Reachability origin/endpoint + status + method;
- qualitative Business/Mission Impact service + dimension + level + method + statement.

Native value validation remains in `RbvmResolvedDecisionInput`. Resolver code does not transform these values into weights, coefficients, thresholds, scores, priority tiers, SLAs, or treatment decisions.

## Deliberate boundary

This increment introduces no:

- Formula Contract or risk equation;
- source precedence or winner selection;
- `current_*` evidence lookup;
- active/highest methodology policy inference;
- priority tier, SLA, treatment, or Case roll-up;
- monetary-loss or attack-path model;
- PostgreSQL schema migration.

The next safe integration step is to expose this resolver through the V17 Decision runtime capability. A Formula Contract should be defined only after that exact build -> install -> resolve pipeline is stable and testable.
