# Derived Risk Result Canonicalization V1

Contract: `RBVM_DERIVED_RISK_RESULT_CANONICAL_BINARY_V1`

Status: `IMPLEMENTED_DOMAIN_ONLY`

Classification: `RBVM_POLICY`

Input: one deterministic `RbvmDerivedRiskMethodology.Evaluation` produced from one exact `RBVM_DECISION_INPUT_SNAPSHOT_V3`.

## Purpose

`RBVM_FORMULA_V1` already has a historical Formula-specific canonical explanation format and append-only V23 persistence. The externally-derived OWASP and Microsoft methodology profiles have different result semantics: each has its own methodology identity, source-model provenance, numeric scale, optional native rating, and visible intermediate measures.

They therefore must not be serialized into `RBVM_FORMULA_EXPLANATION_CANONICAL_BINARY_V1` or persisted through a store that requires the Formula V1 ID/SHA.

This contract creates the immutable result identity required before generic multi-methodology persistence and replay.

## Canonical identity

The canonical payload binds:

1. payload format and format version;
2. exact derived methodology definition:
   - methodology ID/version;
   - classification;
   - provider;
   - source model;
   - source equation;
   - source URL;
   - methodology SHA-256;
   - output name;
3. exact Decision Input contract ID and snapshot SHA-256;
4. exact Finding UUID;
5. result state;
6. terminal reason when present;
7. computed numeric score and scale when present;
8. optional methodology-native rating;
9. the complete visible reproducibility measures.

All strings are UTF-8 length-prefixed values. UUIDs use their two signed 64-bit Java components. Nullable result fields have explicit presence bits. Decimal values use their exact plain decimal representation, preserving methodology output scale.

Measures are canonicalized by deterministic sorting on:

```text
measureId
role
scale
plain decimal value
```

Duplicate `measureId` values are rejected. This makes a methodology result insensitive to incidental Java collection ordering while preserving every declared measure value.

The exact canonical payload bytes are hashed with SHA-256. The SHA is the future durable result/explanation identity.

## Required semantics

- Only `RBVM_DECISION_INPUT_SNAPSHOT_V3` evaluations are accepted.
- `COMPUTED` retains numeric score/scale, optional rating, and all measures.
- `NOT_APPLICABLE` and `NON_COMPUTABLE` remain non-numeric and carry their terminal reason.
- No missing/stale/ambiguous evidence is reinterpreted during canonicalization.
- No methodology is selected by catalog order.
- No Priority, Treatment, SLA, remediation deadline, or ranking is introduced.
- The canonicalizer never queries current evidence or rebuilds Decision Input.

## Frozen acceptance identity

For the documented OWASP baseline profile represented with snapshot SHA `cccc...cccc` and Finding UUID `22222222-2222-4222-8222-222222222222`, the canonical payload is `981` bytes and has SHA-256:

```text
1260c23be5c03990440af13650797d382d640f77f0cc358fd1fd92dc4cdea13d
```

The self-test also proves that reversing the input measure list yields byte-identical canonical output, while changing rating or methodology identity changes the canonical SHA.

## Persistence boundary

This increment intentionally stops before PostgreSQL persistence and HTTP transport.

The next safe persistence contract can now bind at least:

```text
inputSnapshotSha256
methodologyId
methodologySha256
canonicalResultSha256
canonicalResultPayload
```

Replay must load the exact persisted Decision Input V3 snapshot, resolve only its captured evidence/bindings, select the methodology by immutable `methodologyId + methodologySha256`, re-evaluate it, regenerate `RBVM_DERIVED_RISK_RESULT_CANONICAL_BINARY_V1`, and require byte-identical canonical payload content.

Existing `RBVM_FORMULA_V1` rows and Formula-specific canonical explanations remain unchanged and replayable.
