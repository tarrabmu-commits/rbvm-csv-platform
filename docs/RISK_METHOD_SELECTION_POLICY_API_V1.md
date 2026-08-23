# RBVM Risk Method Selection Policy API V1

## Purpose

The V1 API exposes the immutable `RBVM_RISK_METHOD_SELECTION_POLICY_V1` registry without adding an
active/current/default methodology concept to the V25 policy registry itself.

It is a control-plane API. It does not evaluate Formula V1, OWASP-derived risk, or Microsoft-derived
risk and it does not convert those risk results into Priority, Treatment, SLA, or remediation state.

## Exact read

`GET /api/v1/risk-method-selection-policies/{revision}/{policySha256}`

The route requires both exact identities:

- positive immutable policy revision,
- lowercase canonical policy SHA-256.

A revision that exists under another SHA is still a `404` for this exact lookup. There is no
`latest`, `current`, max-revision, or default lookup.

Authorization: `VIEWER`.

Successful response:

- `200 OK`
- strong `ETag` derived from the policy SHA
- `Location` containing the same exact revision/SHA route
- canonical payload Base64 for audit/replay identity
- exact selected method family, ID, version, and SHA

## Explicit installation

`POST /api/v1/risk-method-selection-policy-installations/{revision}/{methodFamily}/{methodId}/{methodVersion}/{methodSha256}`

Authorization: `OPERATOR`.

The route accepts no request body and no query parameters. All selection inputs are explicit in the
path. V1 families are:

- `RBVM_FORMULA`
- `STANDARD_DERIVED`

The exact method identity must match the executable Formula/derived methodology catalog. Canonical
method IDs are required; aliases or case-normalized spellings are rejected.

Outcomes:

- `201 INSERTED` — the immutable revision was appended,
- `200 REPLAYED` — the same exact revision/policy identity already exists,
- `409 RISK_METHOD_SELECTION_POLICY_REVISION_CONFLICT` — the revision is already bound to a
  different immutable policy identity.

The server computes the canonical policy SHA from the V1 policy contract. A successful response
returns the exact read URL in `Location` and a strong policy `ETag`.

## Authentication ordering and capability privacy

The server resolves route shape and required role first, authenticates/authorizes the caller, and
only then checks whether PostgreSQL V25 persistence is available.

Therefore:

- an unauthenticated caller receives `401`,
- a `VIEWER` attempting installation receives `403`,
- only an authorized caller can observe
  `503 RISK_METHOD_SELECTION_POLICY_PERSISTENCE_UNAVAILABLE` when V25 capability is disabled.

This mirrors the Formula and Derived Risk transport rule that backend/schema availability is not
leaked before authorization.

## Deliberately absent V25 policy endpoints

The immutable policy-registry routes have no collection list endpoint and no routes or parameters
for:

- `latest`
- `current`
- `default`
- `preferred`
- activation/deactivation inside the V25 policy registry
- catalog-order precedence
- fallback
- score averaging

RBVM now provides activation through the separate versioned, auditable activation contract
`RBVM_RISK_METHOD_SELECTION_POLICY_ACTIVATION_EVENT_V1` on PostgreSQL V26. That contract references
an exact policy revision and SHA and orders only explicit activation revisions; it does not infer an
active policy from the highest V25 policy revision. See
[`RISK_METHOD_SELECTION_POLICY_ACTIVATION_API_V1.md`](RISK_METHOD_SELECTION_POLICY_ACTIVATION_API_V1.md).

## Method independence

A policy selects exactly one method identity. It does not mutate or reinterpret existing result
stores:

- Formula V1 remains `rbvm.formula_result`,
- standard-derived methodologies remain `rbvm.derived_risk_result`,
- multiple methodologies may still coexist for the same Decision Input V3,
- their scores are never averaged.

## Runtime capability

`RiskMethodSelectionPolicyRuntimeFactory` exposes the V25 policy registry when PostgreSQL schema
version is at least `25`. On schema `26+`, the same runtime additionally attaches the explicit V26
activation capability; schema 25 policy reads/installations remain independently available.
