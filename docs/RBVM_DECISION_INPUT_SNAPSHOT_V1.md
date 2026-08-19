# RBVM Decision Input Snapshot V1

`RBVM_DECISION_INPUT_SNAPSHOT_V1` is the immutable boundary between a selected methodology policy and any later RBVM decision formula.

It records **which evidence rows were eligible or unavailable for one canonical Finding at one explicit evaluation time**. It does not copy CVSS/EPSS/KEV/Impact values and it does not calculate risk, priority, treatment, or SLA.

## Contract

- Contract ID: `RBVM_DECISION_INPUT_SNAPSHOT_V1`
- Semantics: `FINDING_SCOPED_POLICY_BOUND_EVIDENCE_REFERENCE_SNAPSHOT`
- Canonical payload format: `RBVM_DECISION_INPUT_SNAPSHOT_CANONICAL_BINARY_V1`
- Subject: canonical `Finding_ID` UUID
- Methodology binding: explicit positive methodology revision + methodology policy SHA-256
- Evaluation time: explicit `evaluatedAt`
- Snapshot provenance: SHA-256 of deterministic canonical payload excluding `snapshotSha256` itself

The snapshot is not valid unless all seven evidence dimensions are classified explicitly.

## Dimension states

Each dimension is exactly one of:

- `PRESENT`: one or more admissible current evidence references are retained;
- `MISSING`: no admissible evidence exists; this state contains zero evidence references;
- `AMBIGUOUS`: at least two admissible evidence rows remain and cannot be reduced without a later explicit rule;
- `STALE`: one or more evidence rows exist but are ineligible by the methodology freshness rule.

A `MISSING` dimension cannot point to a fabricated evidence row. `PRESENT` and `STALE` require at least one reference. `AMBIGUOUS` requires at least two references.

The snapshot contract does not itself decide whether multiple evidence rows are semantically consistent or conflicting. That is the responsibility of the later snapshot builder applying the selected methodology policy to native evidence values.

## Evidence references

A reference contains only immutable provenance needed to point back to the native evidence row:

- evidence dimension;
- native evidence UUID;
- native evidence-row SHA-256;
- semantic evidence source;
- evidence observation/evaluation time.

The reference deliberately does **not** copy evidence values such as CVSS Base Score, EPSS probability, KEV status, Applicability status, Business Criticality, Reachability status, or Business Impact level. Those values remain in their native immutable evidence tables.

Evidence observed after `evaluatedAt` is invalid for the snapshot.

## Canonical snapshot hash

`snapshotSha256` is the SHA-256 of deterministic canonical binary bytes that exclude the hash field itself.

The payload encodes:

1. canonical payload format ID;
2. contract ID and semantics;
3. Finding UUID;
4. methodology revision and methodology policy SHA;
5. evaluation timestamp;
6. every evidence dimension in fixed enum order;
7. dimension state;
8. evidence references sorted by immutable evidence UUID.

Reference input order therefore has no semantic effect on `snapshotSha256`.

## Relationship to methodology policy

The snapshot binds to one explicit methodology revision and SHA. It does not infer the newest/highest policy revision and does not contain an `active` policy concept.

A later builder must load exactly that policy revision, apply its source allowlists and freshness rules, and then produce the seven dimension states. The snapshot persistence layer should enforce a foreign-key-like binding to the registered methodology policy rather than trusting revision/SHA strings independently.

## Missing evidence remains absence

The Evidence Foundation semantics remain unchanged:

- missing CVSS is not zero;
- missing EPSS is not probability zero;
- missing KEV is not `NOT_LISTED`;
- missing Applicability is not an explicit `UNKNOWN` assessment row;
- missing Reachability is not `NOT_REACHABLE`;
- missing Business Impact is not `LOW`, `NEGLIGIBLE`, or a fabricated `UNKNOWN` row.

`MISSING` in the Decision Input Snapshot means only that no admissible native evidence reference was available under the selected methodology policy at evaluation time.

## Deliberate non-goals

This contract contains no:

- evidence values;
- risk score;
- priority tier;
- remediation/treatment SLA;
- numeric weight, multiplier, coefficient, or threshold;
- evidence-combination formula;
- source precedence/winner;
- active-policy selection;
- Case-level roll-up;
- monetary-loss model;
- asset-wide Internet exposure verdict;
- attack-path score.

## Next increments

The safe sequence after this contract is:

1. **Decision Input Snapshot persistence/builder**: persist one immutable policy-bound snapshot and resolve native evidence references with explicit `PRESENT|MISSING|AMBIGUOUS|STALE` states.
2. **Formula contract**: only after snapshot semantics are stable, define how native values referenced by one snapshot become a decision signal.
3. **Decision persistence/explanation**: bind formula version + snapshot SHA + output and explanation.
4. **Case roll-up/treatment/SLA**: define separately rather than silently aggregating Finding decisions.

This keeps future scoring reproducible: the system can identify the exact Finding, policy revision, evaluation time, evidence UUIDs, evidence hashes, and eligibility states that preceded any decision.
