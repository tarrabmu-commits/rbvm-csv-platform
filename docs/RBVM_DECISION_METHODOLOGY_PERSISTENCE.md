# RBVM Decision Methodology PostgreSQL Persistence

V16 persists `RBVM_DECISION_METHODOLOGY_V1` as an immutable tenant-scoped policy registry. It stores methodology configuration provenance only. It does not select an active policy, build decision-input snapshots, calculate a score, assign priority, or derive an SLA.

## Tables

`rbvm.decision_methodology_policy` stores one immutable methodology revision:

- contract ID and semantics;
- positive revision;
- canonical non-self-referential policy SHA-256;
- canonical payload format `RBVM_DECISION_METHODOLOGY_CANONICAL_BINARY_V1`;
- exact canonical binary payload bytes;
- fixed Finding scope;
- explicit missing, ambiguity, and legacy-priority handling;
- installation time.

`rbvm.decision_methodology_evidence_policy` stores exactly one source-selection/freshness rule per evidence dimension.

`rbvm.decision_methodology_source_allowlist` stores exact source identifiers for dimensions using `EXPLICIT_ALLOWLIST`. It contains no ordering column because an allowlist is a set and row order has no precedence semantic.

## Revision identity and replay

The canonical payload includes the policy revision. Installation identity is therefore tenant + contract + revision.

- new revision -> `INSERTED`;
- exact same revision + same canonical SHA/payload -> `REPLAYED`;
- same revision + different canonical policy -> `REVISION_CONFLICT`;
- a later revision with otherwise identical selection rules is valid and has a different canonical SHA because revision is part of the payload.

The store never overwrites an existing revision.

## Canonical provenance verification

On write, `RbvmDecisionMethodologyPolicy` has already verified that `policySha256` equals SHA-256 of its canonical payload.

On read, the PostgreSQL store reconstructs all seven evidence-selection policies, rebuilds the typed methodology policy, and then verifies:

1. reconstructed policy SHA matches the stored SHA;
2. reconstructed canonical bytes match stored canonical bytes;
3. stored semantics and canonical payload format match the contract constants.

Corrupt or inconsistent persisted policy data is rejected rather than normalized silently.

## Transaction and authorization boundary

Installation runs at PostgreSQL `SERIALIZABLE` isolation under a dedicated transaction advisory lock. Parent policy, seven evidence-policy rows, and allowlist rows commit atomically.

The runtime role receives `SELECT, INSERT` on the three V16 registry tables and explicit `REVOKE UPDATE, DELETE, TRUNCATE`. The registry is append-only.

Policy installation deliberately does not increment `rbvm.catalog_state`: installing methodology configuration does not change canonical vulnerability evidence.

## No implicit active/current policy

V16 intentionally creates no `current_*` or `active_*` methodology view and does not infer `max(revision)` as the selected policy.

A higher revision being present does not mean it is active. Policy activation is a later explicit control-plane decision and must itself be auditable. This prevents a database read from silently changing RBVM behavior when a new policy revision is merely registered.

## Decision boundary

V16 contains no:

- decision-input snapshot;
- evidence winner/arbitration;
- risk score;
- priority tier;
- remediation/treatment SLA;
- numeric evidence weight, threshold, multiplier, or coefficient;
- aggregate Business Impact score or monetary-loss model;
- asset-wide Internet exposure verdict or attack-path score;
- Case roll-up;
- CVSS/KEV/EPSS/Applicability/Asset Context/Reachability/Business Impact combination formula.

The next isolated layer is a Finding-scoped **Decision Input Snapshot** that references an explicit methodology revision and records selected evidence plus `PRESENT|MISSING|AMBIGUOUS|STALE` state for every evidence dimension. A formula remains later than that snapshot layer.
