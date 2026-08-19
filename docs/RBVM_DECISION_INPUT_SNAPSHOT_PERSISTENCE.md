# RBVM Decision Input Snapshot PostgreSQL Persistence

V17 persists `RBVM_DECISION_INPUT_SNAPSHOT_V1` as immutable, Finding-scoped, methodology-bound evidence-selection provenance. It does not materialize native evidence values and does not calculate a risk score, priority, treatment, SLA, or Case roll-up.

## Snapshot identity and policy binding

`rbvm.decision_input_snapshot` stores one explicit evaluation of one canonical `Finding_ID` under one registered methodology policy revision at one `evaluated_at` timestamp.

The row preserves:

- canonical Finding UUID;
- exact methodology policy database identity;
- methodology revision and canonical policy SHA-256;
- snapshot contract ID and semantics;
- canonical snapshot SHA-256;
- canonical binary payload and payload-format identifier;
- evaluation and persistence timestamps.

V17 adds a composite uniqueness constraint to the immutable V16 methodology registry so the snapshot can use a database-enforced composite foreign key over `tenant + methodology_policy_id + revision + policy_sha256`. Revision/SHA strings therefore cannot be persisted independently from the registered policy row.

A canonical Finding must already exist in `rbvm.exposure`; snapshot persistence never creates findings or evidence.

## Dimension state

`rbvm.decision_input_dimension` stores exactly one persisted state row per snapshot and evidence dimension. Allowed states remain the contract states:

- `PRESENT`;
- `MISSING`;
- `AMBIGUOUS`;
- `STALE`.

The Java snapshot type validates complete seven-dimension coverage and state/reference cardinality before persistence. A `MISSING` state therefore cannot carry fabricated evidence references, while `PRESENT`/`STALE` require references and `AMBIGUOUS` requires at least two.

## Native evidence references

`rbvm.decision_input_evidence_reference` stores only immutable pointers:

- evidence dimension;
- native evidence UUID;
- native evidence-row SHA-256;
- semantic evidence source;
- evidence observation/evaluation time.

Native CVSS, EPSS, KEV, Applicability, Asset Context, Network Reachability, and Business/Mission Impact values remain in their native immutable tables. V17 deliberately does not copy those values into the snapshot tables.

The persistence store does not invent polymorphic SQL foreign keys across seven native evidence tables. Native evidence discovery and reference verification belong to the subsequent policy-aware snapshot builder, which must construct references from the native tenant-scoped evidence relations rather than accepting arbitrary external pointers.

## Replay and conflict semantics

The natural evaluation identity is:

`tenant + Finding_ID + methodology policy row + evaluated_at`.

- first valid snapshot for that identity is `INSERTED`;
- exact same canonical snapshot replay is `REPLAYED`;
- a different snapshot for the same evaluation identity is `EVALUATION_CONFLICT` and is not overwritten;
- a later `evaluated_at` is a separate immutable snapshot;
- snapshot UUIDs are deterministic from tenant + canonical snapshot SHA-256;
- installation runs at `SERIALIZABLE` isolation under a dedicated transaction advisory lock;
- snapshot persistence does not mutate the evidence catalog revision.

Reads reconstruct the typed snapshot and revalidate its canonical SHA/payload. Persisted corruption or mismatched normalized content is rejected.

## Runtime-role boundary

The runtime role receives `SELECT, INSERT` on:

- `rbvm.decision_input_snapshot`;
- `rbvm.decision_input_dimension`;
- `rbvm.decision_input_evidence_reference`.

`UPDATE`, `DELETE`, and `TRUNCATE` are explicitly revoked from all three relations.

## Deliberate boundary

V17 contains no:

- native evidence values;
- active/highest methodology policy selection;
- source precedence or winner;
- risk score or aggregate decision signal;
- priority tier;
- remediation/treatment SLA;
- weight, multiplier, coefficient, or threshold;
- monetary-loss model;
- asset-wide Internet-exposure verdict;
- attack-path score;
- Case-level roll-up.

The next isolated increment is the **policy-aware Decision Input Snapshot builder**. It must resolve the canonical Finding, load one explicit methodology revision, select native evidence as-of `evaluatedAt`, apply exact source allowlists and freshness rules, and then construct `PRESENT|MISSING|AMBIGUOUS|STALE` states without introducing a scoring formula.