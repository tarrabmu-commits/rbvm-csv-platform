# Active Risk Method Execution Binding V1

`RBVM_ACTIVE_RISK_METHOD_EXECUTION_BINDING_V1` is the immutable provenance contract that connects one exact risk-method activation decision to one exact risk result produced from one exact Decision Input V3 snapshot.

## Purpose

Risk Method Selection Policy V1 identifies an exact PRIMARY method. Activation V1 records whether an exact policy revision + SHA is explicitly ACTIVE or CLEARED. Neither contract, by itself, proves which exact Decision Input was evaluated or which immutable result was produced. Execution Binding V1 closes that provenance gap.

The binding records all of these immutable identities together:

- activation revision and activation event SHA;
- policy revision and policy SHA;
- selection role (`PRIMARY`);
- method family, method ID, method version, and method SHA;
- Decision Input snapshot SHA;
- native result family and native canonical result SHA;
- canonical binding SHA.

A binding never stores or means `current`, `latest`, `default`, or `preferred`. Operational discovery may resolve a current activation elsewhere, but reproducible execution must carry the exact activation revision + event SHA into this contract.

## Exact execution semantics

The materialization command requires three explicit inputs: activation revision, activation event SHA, and Decision Input snapshot SHA. It resolves the activation by exact revision and verifies the supplied event SHA. `CLEARED` fails closed and cannot execute a risk method. An ACTIVE event must resolve the exact policy revision + SHA captured by the event.

The selected method must still match an executable catalog identity at execution time. RBVM Formula execution dispatches only the exact Formula V1 identity. `STANDARD_DERIVED` execution dispatches only the exact methodology ID/version/SHA selected by the policy. Catalog order has no precedence or fallback meaning.

If a binding already exists for the same activation event SHA + Decision Input SHA, the immutable binding is replayed and the risk method is not executed again. A different binding for that same execution identity is `EXECUTION_CONFLICT`.

## V27 persistence integrity

V27 creates `rbvm.active_risk_method_execution_binding` as an append-only tenant-scoped registry. PostgreSQL foreign keys require all of the following to exist and agree exactly:

- the ACTIVE activation revision + event SHA + referenced policy revision + policy SHA;
- the immutable policy revision + SHA;
- the immutable Decision Input snapshot SHA;
- for Formula, the exact Formula result explanation SHA produced from that same snapshot and Formula ID/version/SHA;
- for derived methodologies, the exact derived result SHA produced from that same snapshot and methodology ID/version/SHA.

Formula and derived result references are mutually exclusive. A Formula policy cannot bind a derived result, and a `STANDARD_DERIVED` policy cannot bind a Formula result. A valid result SHA belonging to a different methodology is rejected by PostgreSQL rather than being accepted as provenance.

The runtime role receives only `SELECT, INSERT` on the binding table. `UPDATE`, `DELETE`, and `TRUNCATE` are revoked.

## Canonical identity

Canonical format: `RBVM_ACTIVE_RISK_METHOD_EXECUTION_BINDING_CANONICAL_BINARY_V1`.

The frozen Formula fixture has canonical payload length **541 bytes** and binding SHA:

`72cb38f987d28316565dca9794fcd3f9b22b4f1e4b4c57272ebad22cb35a5760`

Rehydration recomputes canonical identity and rejects normalized-field or result-identity tampering.

## Deliberate exclusions

This contract does not calculate risk and does not modify native Formula or derived methodology results. It does not average, normalize, rank, or choose between methodologies. It has no Priority, Treatment, SLA, remediation deadline, or remediation workflow semantics.

No HTTP endpoint or browser control is introduced in this increment. A later API increment can expose exact execution by activation identity while retaining the same rule: operational `current` discovery is not a reproducibility key.
