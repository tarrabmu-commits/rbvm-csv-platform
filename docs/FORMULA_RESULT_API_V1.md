# RBVM Formula Result API V1

Contract ID: `RBVM_FORMULA_RESULT_API_V1`

This increment defines the read-only application/API contract for exposing one already-persisted `RBVM_FORMULA_V1` result and its exact canonical explanation. It is an exact immutable identity boundary; it is not a current-state query, ranking service, Priority policy, Treatment policy, or SLA engine.

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

## 5. Security and transport boundary

This increment defines and verifies the pure Formula Result API V1 contract only. HTTP socket routing is not part of this increment. Runtime capability discovery, Viewer authorization routing, OpenAPI publication, and browser presentation remain the next transport/runtime increment.

Because transport wiring is not present yet, this document does not claim an HTTP URL exists for Formula results.

## 6. Explicit non-goals

Formula Result API V1 does not derive or expose:

- Priority;
- Treatment;
- SLA;
- remediation deadline;
- ticket/workflow decision;
- a hidden ranking;
- an inferred latest/current Formula winner.

Those remain separate downstream contracts. Formula V1 remains an evidence-derived relative-risk result bound to one exact immutable Decision Input V3 evaluation.
