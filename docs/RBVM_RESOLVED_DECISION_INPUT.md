# RBVM Resolved Decision Input

`RbvmResolvedDecisionInput` is the typed, ephemeral value boundary between an immutable `RBVM_DECISION_INPUT_SNAPSHOT_V1` and any later formula implementation.

The snapshot remains the persisted provenance artifact. Resolution does not create a second persisted truth and does not select new evidence. It only dereferences the exact native evidence UUIDs already present in the snapshot.

## Exact reference conservation

A resolved input is valid only when every evidence dimension is represented and its resolved rows match the snapshot references exactly:

- same evidence dimension;
- same native evidence UUID;
- same evidence-row SHA-256;
- same semantic source;
- same observation/evaluation timestamp;
- no added rows;
- no omitted rows;
- no duplicate native UUIDs.

`MISSING` therefore resolves to an empty list. `PRESENT`, `AMBIGUOUS`, and `STALE` resolve the references already retained by the snapshot; resolution does not change the dimension state.

Resolved rows are ordered by native evidence UUID for deterministic downstream processing. This ordering is not source precedence.

## Typed native values

The contract represents the native semantic values required by a later formula without combining them:

- Applicability: `APPLICABLE|NOT_APPLICABLE|UNKNOWN` + reason;
- Technical Severity: CVSS v3.1 Base score + vector;
- Known Exploitation: `LISTED|NOT_LISTED` + KEV listing metadata when listed;
- Exploitation Probability: EPSS probability + percentile + model version + score date;
- Asset Context: environment + business service + owner + qualitative criticality;
- Network Reachability: origin scope/label + protocol/port/service + status + evidence method;
- Business/Mission Impact: service + normalized service + impact dimension + qualitative level + method + statement.

The value records enforce the same basic domains/ranges as native persistence, but they do not derive or compare values across evidence rows.

## Why this exists before the formula

`RBVM_DECISION_INPUT_SNAPSHOT_V1` intentionally persists references rather than copied values. A formula must therefore dereference those exact immutable rows before evaluating them. A generic `DecisionInputEvidenceResolver` boundary makes that operation explicit and testable.

A PostgreSQL resolver is a later implementation step. It must verify each returned row against the full snapshot reference identity before constructing `RbvmResolvedDecisionInput`.

## Non-goals

This contract does not define:

- a risk equation or numeric score;
- source ranking or winner selection;
- priority tier;
- remediation/treatment SLA;
- thresholds, weights, multipliers, or coefficients;
- active/highest methodology selection;
- Case roll-up;
- monetary-loss or attack-path models.

Those remain Formula/Decision concerns after exact native-value resolution is available.
