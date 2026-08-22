# Derived Risk Result API V1

Status: `IMPLEMENTED_CONTRACT_RUNTIME`

Result contract: `RBVM_DERIVED_RISK_RESULT_API_V1`

Catalog contract: `RBVM_DERIVED_RISK_METHODOLOGY_CATALOG_API_V1`

Materialization contract: `RBVM_DERIVED_RISK_RESULT_MATERIALIZATION_API_V1`

This increment defines the replay-verified API boundary and PostgreSQL V24 runtime capability. It does not yet expose HTTP socket routes.

## Exact result reads

Two immutable lookup forms are supported:

```text
resultSha256
```

or:

```text
inputSnapshotSha256
+ canonical methodologyId
+ methodologySha256
```

Successful reads are returned only after `DerivedRiskResultReplayVerifier` reproduces the exact canonical result from the persisted Decision Input V3, exact captured evidence/bindings, and exact methodology implementation.

There is no `latest`, `current`, or preferred-result selector.

## Methodology catalog

The catalog exposes the exact implemented definitions, including provider/source provenance and methodology SHA-256. It declares:

```text
selectionSemantics = EXPLICIT_ID_AND_SHA_ONLY_NO_DEFAULT
```

Catalog list order is deterministic representation only. It is not precedence, preference, recommendation, or a default.

The API requires the canonical methodology ID exactly as published by the catalog. Case-normalized aliases are not accepted as public identities even though internal catalog lookup can locate them.

## Materialization command

The API materialization boundary requires all three explicit values:

```text
inputSnapshotSha256
methodologyId
methodologySha256
```

It delegates to `DefaultDerivedRiskResultMaterializer`, therefore it cannot rebuild Decision Input or select evidence/current state on its own.

First exact materialization returns semantic status `INSERTED`; a byte-identical retry returns `REPLAYED`. A deterministic conflict fails closed.

## Result representation

The read contract returns:

- persistent result UUID;
- exact Decision Input snapshot SHA;
- Finding UUID;
- complete exact methodology definition;
- `COMPUTED / NOT_APPLICABLE / NON_COMPUTABLE`;
- terminal reason code or methodology-native numeric score/scale/rating;
- persistence time;
- exact `RBVM_DERIVED_RISK_RESULT_CANONICAL_BINARY_V1` bytes in Base64;
- canonical result SHA-256;
- visible methodology measures;
- `replayVerified=true`.

Strong ETag identity is derived only from the canonical result SHA.

## Runtime discovery

`DerivedRiskResultRuntimeFactory` is available only when PostgreSQL projection is enabled and schema version is V24 or newer. It constructs the exact result store, Decision Input snapshot store, native evidence resolver, replay verifier, and production materializer as one capability.

A future HTTP router must perform authentication and route-specific RBAC before checking whether this V24 capability is available, so backend capability state is not disclosed to an unauthorized caller.

## Boundary

This contract does not define HTTP transport, browser presentation, a primary/preferred methodology, cross-methodology averaging or normalization, Priority, Treatment, SLA, remediation deadlines, ranking, or ticket workflow.
