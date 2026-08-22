# RBVM Formula Result API V1

Contract ID: `RBVM_FORMULA_RESULT_API_V1`

This contract exposes one already-persisted `RBVM_FORMULA_V1` result and its exact canonical explanation through a read-only exact-identity boundary. It is an **exact immutable identity** boundary; it is not a current-state query, ranking service, Priority policy, Treatment policy, or SLA engine.

## 1. Lookup identity

The contract supports two exact lookups:

1. canonical explanation SHA-256;
2. Decision Input snapshot SHA-256 + Formula SHA-256.

There is deliberately **no latest** result lookup in V1. The API does not choose a newest Formula evaluation, a current Finding state, or a preferred methodology/Formula revision on behalf of the caller.

Malformed identities fail as invalid requests. Well-formed identities that do not resolve to an immutable persisted result return not found.

## 2. Replay-verified reads

Every successful response is replay-verified before it is exposed.

The read path:

```text
Persisted Formula Result
        ↓
Exact persisted Decision Input V3 snapshot
        ↓
Exact native evidence + exact binding provenance
        ↓
RBVM_FORMULA_V1 deterministic replay
        ↓
Canonical explanation regeneration
        ↓
byte-for-byte / SHA verification
        ↓
API response
```

The API never rebuilds a Decision Input snapshot and never re-runs current evidence selection. A stored row whose result semantics or canonical explanation cannot be reproduced from its exact immutable provenance fails closed instead of being returned as trusted output.

## 3. Response semantics

A successful response contains:

- API contract identity;
- immutable Formula-result ID;
- exact Decision Input snapshot SHA;
- Finding ID;
- evaluation time;
- exact methodology revision/SHA;
- exact Formula ID/version/SHA;
- `COMPUTED`, `NOT_APPLICABLE`, or `NON_COMPUTABLE` result state;
- terminal reason codes;
- nullable `RBVM Relative Risk Index`;
- persistence time;
- canonical explanation payload format/SHA;
- exact canonical explanation bytes encoded as Base64;
- replay verification state;
- fixed-order structured dimension explanations;
- exact native evidence references and exact association/binding provenance.

Decimal Formula values are serialized as plain decimal strings to preserve exact decimal representation rather than passing through floating-point JSON conversion.

`NOT_APPLICABLE` and `NON_COMPUTABLE` keep the numeric risk field null. The API never substitutes zero or a partial score for a terminal result.

## 4. Strong identity and caching

Successful immutable responses carry a strong ETag derived from the canonical explanation SHA-256. The ETag identifies exact Formula explanation content; it is not a Finding version or a current-state cursor.

## 5. HTTP and runtime transport

The dependency-free HTTP server exposes the exact read contract at:

```text
GET /api/v1/formula-results/{explanationSha256}
GET /api/v1/formula-results?inputSnapshotSha256={sha256}&formulaSha256={sha256}
```

Only `GET` is supported. Item lookup accepts no query parameters. Collection lookup requires exactly `inputSnapshotSha256` and `formulaSha256`; unknown or duplicate parameters are rejected. There is no `latest`, current-state, or inferred-winner route.

Formula Result HTTP reads require Viewer permission. Authorization is resolved before runtime-capability lookup, so an unauthenticated caller cannot distinguish an unavailable Formula capability from an available one.

The Formula Result runtime capability is enabled only when the PostgreSQL projection is active and schema V23 or newer is installed. Otherwise an authenticated request receives `503 FORMULA_RESULT_PERSISTENCE_UNAVAILABLE`.

Health and metrics expose only capability availability:

- `/api/v1/health` → `formulaResults.readEnabled` and `formulaResults.replayVerified`;
- `/api/v1/metrics` → `rbvm_formula_result_api_enabled`.

The transport contract is published in `api/formula-result-v1.openapi.yaml`.

## 6. Browser boundary

The HTTP/API transport is available, but Frontend System V2 does not yet present Formula results in the browser. A later UI increment must consume this exact replay-verified API and must not reconstruct Formula inputs, select current evidence, or silently derive Priority/Treatment/SLA.

## 7. Explicit non-goals

Formula Result API V1 does not derive or expose:

- Priority;
- Treatment;
- SLA;
- remediation deadline;
- ticket/workflow decision;
- a hidden ranking;
- an inferred latest/current Formula winner.

Those remain separate downstream contracts. Formula V1 remains an evidence-derived relative-risk result bound to one exact immutable Decision Input V3 evaluation.
