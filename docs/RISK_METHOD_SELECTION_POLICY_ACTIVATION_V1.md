# Risk Method Selection Policy Activation V1

Contract: `RBVM_RISK_METHOD_SELECTION_POLICY_ACTIVATION_EVENT_V1`

Semantics: `TENANT_SCOPED_EXPLICIT_ACTIVE_POLICY_POINTER_APPEND_ONLY`

Canonical payload: `RBVM_RISK_METHOD_SELECTION_POLICY_ACTIVATION_EVENT_CANONICAL_BINARY_V1`

## Purpose

Risk Method Selection Policy revisions are immutable definitions. Persisting revision 7 does not make revision 7 active and the greatest policy revision is never an activation rule.

V1 introduces a separate tenant-scoped append-only activation event stream. Only this stream may establish operational active-policy state.

## Activation revision is not policy revision

Every event has an explicit positive `activationRevision`. This revision orders activation events only. It is independent from the referenced policy revision.

For example, activation revision 12 may explicitly activate policy revision 3. A later installed policy revision 9 does not alter that active pointer. The current activation state is the greatest accepted explicit activation revision, never the greatest policy revision, policy installation time, or catalog order.

The PostgreSQL store rejects a newly introduced activation revision lower than the current activation revision as `STALE_ACTIVATION_REVISION`. Exact replay of an already persisted activation revision remains idempotent.

## States

`ACTIVE` requires one exact already-persisted Risk Method Selection Policy identity:

- policy revision
- policy SHA-256

The V26 foreign key binds both values together. A policy object that is valid in code but has never been installed cannot be activated.

`CLEARED` carries no policy identity. It explicitly records that no Risk Method Selection Policy is active. This preserves the distinction between:

- no activation event has ever existed;
- an active policy exists;
- an operator explicitly cleared the active policy.

Clearing is an append-only event. It never deletes or rewrites prior activation history.

## Current and active views

`rbvm.current_risk_method_selection_policy_activation` returns the greatest explicit activation revision per tenant, including `CLEARED`.

`rbvm.active_risk_method_selection_policy` returns a row only when the current explicit event is `ACTIVE`, and joins the referenced immutable policy by exact policy revision + SHA.

The word current is therefore scoped to the explicit activation event stream. It is not a shortcut for latest policy, max policy revision, first/last catalog entry, or recently installed methodology.

## Concurrency and immutability

Installation is serialized with a PostgreSQL advisory transaction lock. Outcomes are:

- `INSERTED`
- `REPLAYED`
- `REVISION_CONFLICT`
- `STALE_ACTIVATION_REVISION`

The runtime role receives `SELECT, INSERT` only for activation events. `UPDATE`, `DELETE`, and `TRUNCATE` are revoked.

The canonical event identity includes:

- contract and semantics
- activation revision
- activation state
- exact policy identity when active
- actor
- change note
- recorded timestamp

## Decision boundary

Activation selects which already-defined Risk Method Selection Policy is operationally active. It does not calculate or alter any risk score. Formula V1 and every standard-derived methodology keep their own native result semantics and scales.

Activation V1 does not create or infer Priority, Treatment, SLA, remediation deadline, expected loss, exploitation probability, or cross-methodology averaging.

## Transport boundary

V26 establishes the domain and persistence contract only. HTTP/API mutation and browser activation controls are intentionally deferred to a later increment. That transport must preserve explicit activation revision, exact policy revision + SHA, append-only replay/conflict semantics, and explicit `CLEARED` state.
