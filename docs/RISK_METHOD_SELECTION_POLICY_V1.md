# RBVM Risk Method Selection Policy V1

## Purpose

`RBVM_RISK_METHOD_SELECTION_POLICY_V1` is the control-plane contract for selecting exactly one
**primary risk methodology identity** for a tenant-scoped downstream decision.

It exists because RBVM now supports independent result families that must never be silently merged:

- the accepted RBVM Formula V1 result,
- OWASP-derived RBVM risk,
- Microsoft Probability × Damage-derived RBVM risk.

The policy does **not** evaluate risk. It only records which exact risk-method definition a later
decision is allowed to treat as its primary risk result.

## Separation from Decision Methodology V1

`RBVM_DECISION_METHODOLOGY_V1` remains the pre-evaluation evidence-selection/freshness contract. It
does not select a risk formula or derived risk methodology.

`RBVM_RISK_METHOD_SELECTION_POLICY_V1` is a separate post-evidence control-plane contract. Reusing
the Decision Methodology contract for this purpose would incorrectly mix evidence eligibility with
risk-method selection.

## Exact identity

Every policy revision binds all of the following:

- `selectionRole = PRIMARY`
- one `methodFamily`
- exact `methodId`
- exact `methodVersion`
- exact `methodSha256`
- positive policy `revision`
- canonical `policySha256`

V1 method families are:

- `RBVM_FORMULA`
- `STANDARD_DERIVED`

A newly installed policy must match an exact method identity in the executable catalog. Historical
persisted policies remain readable by canonical identity even if a future executable catalog changes.

## No implicit selection

V1 deliberately defines no:

- default methodology,
- catalog-order precedence,
- fallback methodology,
- `latest` or `current` policy lookup,
- weighted blend,
- score averaging,
- automatic comparison winner.

A downstream operation that needs this policy must carry an exact policy revision and SHA. Adding an
activation/head concept later requires a separately versioned contract; it must not be inferred from
the greatest revision number.

## No Priority / Treatment / SLA semantics

The selected method output remains a risk result in that method's native scale. This policy does not
create or imply:

- remediation Priority,
- Treatment,
- SLA,
- due date,
- workflow state,
- official vendor score status for RBVM-derived models.

Those layers require separate explicit policy contracts.

## Canonical payload

Canonical payload format:

`RBVM_RISK_METHOD_SELECTION_POLICY_CANONICAL_BINARY_V1`

The payload is deterministic binary data using big-endian integers and length-prefixed UTF-8 strings
in this order:

1. contract ID,
2. policy revision,
3. fixed semantics identifier,
4. selection role,
5. method family,
6. method ID,
7. method version,
8. method SHA-256.

`policySha256` itself is excluded from the payload to avoid a self-referential hash.

Frozen Formula V1 revision-1 vector:

- canonical payload length: `223` bytes
- policy SHA-256: `92303a4df7e0381f379a929359349158aba2f5dbe8dd7e51fc211abc8f2238cf`

The selected Formula identity inside that vector is:

- ID: `RBVM_FORMULA_V1`
- version: `1`
- SHA-256: `88bf31f510089b4209b1ffcf1c15b39fef60548209875334f084888316e9028e`

## V25 PostgreSQL persistence

Migration `V25__risk_method_selection_policy.sql` adds
`rbvm.risk_method_selection_policy` as an immutable tenant-scoped registry.

Key constraints:

- one row per `(tenant, contract, revision)`,
- unique canonical policy SHA per tenant,
- exact method family / ID / version / SHA stored with the policy,
- no mutable active/current pointer,
- no current/latest/default view,
- runtime role receives `SELECT, INSERT` only,
- runtime `UPDATE`, `DELETE`, and `TRUNCATE` are revoked.

`PostgresRiskMethodSelectionPolicyStore` provides exact lookup by revision or policy SHA and
idempotent installation outcomes:

- `INSERTED`
- `REPLAYED`
- `REVISION_CONFLICT`

A revision conflict never overwrites the existing immutable policy.

## Current scope boundary

This increment establishes the domain contract and persistence boundary only. HTTP/API activation or
browser controls are intentionally not part of V1 persistence. They must consume the exact policy
identity rather than inventing a default or selecting the first catalog entry.
