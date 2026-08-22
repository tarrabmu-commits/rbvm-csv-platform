# RBVM Formula Canonicalization V1

Contract ID: `RBVM_FORMULA_CANONICALIZATION_V1`

Canonical payload format: `RBVM_FORMULA_CANONICAL_BINARY_V1`

Deterministic explanation payload format: `RBVM_FORMULA_EXPLANATION_CANONICAL_BINARY_V1`

This contract defines the byte-level identity envelope for the future `RBVM_FORMULA_V1`. It does **not** define Formula weights, thresholds, mappings, transforms, or a scoring equation.

## 1. Formula SHA identity

`formulaSha256` is the lowercase hexadecimal SHA-256 of the exact canonical Formula payload bytes.

The SHA field itself is excluded from the canonical payload so identity is not circular.

Two Formula artifacts are the same Formula identity only when their canonical payload bytes are byte-equivalent and therefore have the same SHA-256.

Display formatting, Markdown/JSON/YAML whitespace, source-file property order, comments, UI labels, and localized text are never part of Formula identity unless a value is explicitly encoded as a semantic Formula field below.

## 2. Primitive encoding

Canonical bytes use these primitives:

- unsigned byte: one byte;
- signed integer fields: fixed-width big-endian two's-complement as specified by the field;
- Boolean: one byte, `0x00` false and `0x01` true;
- string: 32-bit unsigned big-endian byte length followed by strict UTF-8 bytes;
- enum: its stable contract identifier encoded as a canonical string;
- nullable field: one presence byte (`0x00` absent, `0x01` present) followed by the value when present;
- list: 32-bit unsigned big-endian element count followed by canonical elements in the contract-defined order;
- map/set: represented as a list sorted by the contract-defined stable key before encoding.

Strings must be semantic contract values, not display prose. Unicode strings are encoded exactly as their contract-normalized value; a Formula field must declare any normalization rule before it is allowed into the canonical payload.

## 3. Canonical decimal encoding

Formula decimal constants are encoded as canonical base-10 strings using these rules:

1. finite decimal values only;
2. no exponent notation;
3. no leading `+`;
4. no unnecessary leading integer zeroes;
5. no trailing fractional zeroes;
6. no decimal point when the fractional part is empty;
7. every representation of numeric zero canonicalizes to `0`;
8. negative zero is forbidden.

Examples:

- `0.5000` -> `0.5`
- `100.00` -> `100`
- `0002.50` -> `2.5`
- `-0.0` -> invalid; canonical zero is `0`

Output display scale is a separate semantic field. Therefore an output may be displayed as `42.50` while the canonical decimal constant `42.5` remains representation-stable.

## 4. Formula payload field order

`RBVM_FORMULA_CANONICAL_BINARY_V1` encodes these top-level fields in exactly this order:

1. canonical payload format identifier;
2. `formulaId`;
3. `formulaVersion` as positive signed 32-bit integer;
4. `formulaSemantics`;
5. `inputContractId`;
6. `outputName`;
7. output minimum canonical decimal;
8. output maximum canonical decimal;
9. output display scale as non-negative signed 32-bit integer;
10. arithmetic/intermediate precision policy;
11. rounding mode identifier;
12. applicability gate policy;
13. evidence-state policy;
14. multi-subgrain policy;
15. ordered factor definitions;
16. ordered interaction/gate definitions;
17. explanation schema identifier;
18. reserved-extension list.

Formula V1 must set:

- `inputContractId = RBVM_DECISION_INPUT_SNAPSHOT_V3`
- `outputName = RBVM Relative Risk Index`
- output minimum = canonical decimal `0`
- output maximum = canonical decimal `100`
- output display scale = `2`
- explanation schema identifier = `RBVM_FORMULA_EXPLANATION_CANONICAL_BINARY_V1`

## 5. Ordered executable definitions

Factor and interaction order can affect execution and explanation. Therefore order is explicit Formula semantics, not a source-file accident.

Each factor definition has a positive `ordinal` unique within the Formula and a stable `factorId`. Factor definitions are encoded by ascending ordinal; duplicate or skipped ordinals are invalid.

Each interaction/gate definition likewise has a positive unique `ordinal` and stable rule identifier and is encoded by ascending ordinal.

Any categorical mapping inside a factor or rule is semantically a map and is encoded by lexicographically ascending canonical key, not source-file insertion order.

Any set-valued allowlist is sorted lexicographically before encoding unless the Formula contract explicitly declares the order semantically meaningful.

Every numeric constant, category mapping, transform identifier, threshold, gate, coefficient, bound, and execution-order ordinal that can affect a Risk Result must appear in these canonical definitions and therefore be covered by `formulaSha256`.

## 6. Reserved extensions

Formula V1 contains a final reserved-extension list so later compatible metadata can be distinguished from semantic Formula changes.

For V1 the list must be empty.

Adding a semantic field requires a new canonical payload format identifier and cannot be smuggled through display metadata or an unversioned extension.

## 7. Explanation canonicalization

`RBVM_FORMULA_EXPLANATION_CANONICAL_BINARY_V1` defines deterministic result explanation identity.

The explanation payload encodes, in order:

1. explanation payload format identifier;
2. result state identifier;
3. Formula ID/version/SHA;
4. Decision Input contract ID and snapshot SHA;
5. Finding ID;
6. evaluated-at timestamp in canonical UTC instant text;
7. methodology revision/SHA;
8. ordered dimension explanation entries in the fixed `EvidenceDimension` enum order;
9. ordered terminal/gating reason codes;
10. nullable final Risk Result canonical decimal.

Each dimension entry encodes:

1. evidence dimension identifier;
2. Decision Input dimension state;
3. retained native evidence references in canonical snapshot order;
4. each reference's evidence kind/UUID/SHA/source/observed-at;
5. nullable binding event kind/UUID/SHA/source/observed-at;
6. normalized Formula-consumed value when applicable;
7. applied factor/transform identifier when applicable;
8. nullable canonical intermediate/contribution value.

`NOT_APPLICABLE` and `NON_COMPUTABLE` explanations must encode the final Risk Result field as absent. `COMPUTED` explanations require it present.

UI prose and localization are derived views and are excluded from canonical explanation identity.

## 8. Replay invariants

Stage 8 and Formula implementation tests must prove:

- parsing and serializing the same Formula semantics reproduces byte-identical canonical payload bytes;
- source JSON/YAML/Markdown field order cannot change Formula SHA;
- semantically equivalent decimal spellings canonicalize identically;
- changing any result-affecting constant/rule/order changes Formula SHA;
- changing only display/localized prose does not change Formula SHA;
- exact Decision Input + exact Formula produces deterministic canonical explanation semantics;
- a Formula version/SHA change creates a distinct result identity even if a sample numeric output happens to be equal.

## 9. Boundary

This contract closes Formula identity/canonicalization readiness only.

It does not authorize `RBVM_FORMULA_V1` runtime implementation before the versioned Stage 8 golden-case and invariant suite is approved.