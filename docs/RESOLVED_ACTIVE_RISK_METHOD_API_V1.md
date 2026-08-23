# RBVM Resolved Active Risk Method API V1

Contract: `RBVM_RESOLVED_ACTIVE_RISK_METHOD_API_V1`

Resolution semantics: `EXPLICIT_ACTIVATION_TO_EXACT_POLICY_TO_EXACT_METHOD_NO_DEFAULT`

## Purpose

This read-only control-plane projection resolves one explicit Risk Method Selection Policy activation event through its exact persisted V25 policy revision + SHA to the exact selected method identity.

It does not evaluate risk, choose a method from catalog order, rank results, or create Priority, Treatment, SLA, remediation deadline, exploitation probability, or expected-loss semantics.

## Current resolved selection

`GET /api/v1/risk-method-selection-policy-activation/current/resolved`

Authorization: `VIEWER`.

`current` is operational discovery only. It means the greatest explicit **activation revision**, exactly as defined by the V26 activation stream. It never means the greatest policy revision, latest policy, first catalog method, preferred Formula, or highest score.

The response always includes the exact activation event identity. A downstream decision that must be auditable or replayable must capture:

- `activation.activationRevision`
- `activation.eventSha256`

It must not persist only the word `current`.

If no activation event has ever been persisted, the route returns `404`. Never-activated is not synthesized as CLEARED.

## Exact historical resolved selection

`GET /api/v1/risk-method-selection-policy-activations/{activationRevision}/{eventSha256}/resolved`

This is the replay/audit form. Both immutable activation identifiers are mandatory. A wrong SHA for an existing revision remains `404`; there is no fallback event.

Successful current resolution returns this exact historical URL in `Location` so consumers can retain the immutable replay anchor.

## ACTIVE

For an `ACTIVE` event the API resolves the exact `policyRevision + policySha256` referenced by the activation event. The response includes:

- the complete immutable activation event;
- the complete immutable Risk Method Selection Policy revision;
- `selectedMethod.selectionRole = PRIMARY`;
- exact method family;
- exact method ID;
- exact method version;
- exact method SHA-256.

The method identity is copied from the resolved persisted policy. It is not re-selected from Formula or derived-methodology catalogs.

If an ACTIVE event references a policy identity that cannot be resolved, the API fails closed with `500 RISK_METHOD_SELECTION_POLICY_ACTIVATION_INTEGRITY_FAILURE`. It does not choose another policy or method.

## CLEARED

An explicit `CLEARED` event returns `200` with:

- `selectionState = CLEARED`;
- the exact CLEARED activation event;
- `policy = null`;
- `selectedMethod = null`.

This is an intentional no-selection state and remains different from never-activated (`404`).

## Identity headers

Successful responses use a strong ETag derived from the activation event SHA and return the exact historical resolved-selection route in `Location`.

The event SHA is sufficient to anchor the projection because ACTIVE canonically contains the exact policy revision + policy SHA, while CLEARED contains no policy identity.

## Capability and authorization ordering

The routes use the existing Risk Method Selection Policy router and V26 activation capability. No new database migration or independent runtime capability is introduced.

Route RBAC is resolved before capability lookup. Therefore an unauthenticated caller receives `401` without learning whether V26 persistence is available; an authorized Viewer may receive `503` if activation persistence is unavailable.

## Deliberate exclusions

V1 exposes no:

- activation collection/list;
- policy collection/list;
- `latest`, preferred, or default selector;
- catalog-order precedence;
- fallback policy or method;
- score lookup or result materialization;
- score averaging or normalization;
- Priority, Treatment, SLA, remediation deadline, or remediation ranking.

This projection is only the auditable bridge from explicit activation to exact policy to exact method identity.
