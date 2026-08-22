# RBVM Formula Result Materialization V1

Runtime contract: `FORMULA_RESULT_MATERIALIZATION_V1`  
HTTP contract: `RBVM_FORMULA_RESULT_MATERIALIZATION_API_V1`

This capability evaluates and append-only persists `RBVM_FORMULA_V1` from one **exact already-persisted `RBVM_DECISION_INPUT_SNAPSHOT_V3` identity** and exposes that exact operation as an explicit Operator command.

It does not build a Decision Input, select current evidence, choose a Finding, choose a methodology, or expose remediation Priority/Treatment/SLA policy.

## 1. Input boundary

The only materialization input is:

```text
inputSnapshotSha256
```

The value must identify one immutable Decision Input snapshot already present in the Decision Input store. The materializer does not accept a Finding ID, CVE, asset, methodology revision, evaluation time, evidence source, association target, or Formula parameters as alternative selectors.

A missing snapshot fails closed. A persisted V1/V2 snapshot is rejected: Formula V1 production materialization requires Decision Input V3.

## 2. Exact materialization flow

```text
Exact persisted Decision Input V3 SHA
        ↓
DecisionInputSnapshotStore.findBySha256
        ↓
verify exact SHA + V3 contract
        ↓
DecisionInputEvidenceResolver.resolve(exact snapshot)
        ↓
RBVM_FORMULA_V1.evaluate
        ↓
RBVM_FORMULA_EXPLANATION_CANONICAL_BINARY_V1
        ↓
FormulaResultStore.install
        ↓
INSERTED or exact REPLAYED
        ↓
reload exact canonical explanation identity
        ↓
FormulaResultReplayVerifier.replay
        ↓
replay-verified materialization result
```

There is no call to `DecisionInputSnapshotBuilder` in this path. Native evidence and customer-confirmed association bindings are resolved only from references already captured by the persisted Decision Input V3 snapshot.

## 3. Persistence and replay semantics

The existing V23 Formula-result store remains append-only.

- First deterministic materialization of an exact snapshot/Formula identity returns `INSERTED`.
- Repeating the same exact materialization returns `REPLAYED` and does not append a duplicate row.
- If storage already contains different canonical Formula content for the same snapshot/Formula identity, materialization fails closed as `RESULT_CONFLICT`.
- A successful install is reloaded by exact canonical explanation SHA and must pass deterministic historical replay before the materializer returns it.

`NOT_APPLICABLE` and `NON_COMPUTABLE` remain terminal, non-numeric Formula results. Materialization never substitutes zero or a partial score.

## 4. Runtime capability

`FormulaResultRuntimeFactory` exposes the materializer only when the PostgreSQL projection is active with schema V23 or newer. It composes the same exact stores and resolver used by replay-verified Formula Result reads:

- `PostgresDecisionInputSnapshotStore`;
- `PostgresDecisionInputEvidenceResolver`;
- `PostgresFormulaResultStore`;
- `FormulaResultReplayVerifier`;
- `DefaultFormulaResultMaterializer`.

The live V23 integration test exercises this production materializer directly against PostgreSQL and proves INSERTED → REPLAYED behavior, exact snapshot identity, replay verification, and one-row append-only persistence.

## 5. Operator HTTP transport

The materialization command is deliberately separate from the read-only Formula Result API:

```text
POST /api/v1/formula-result-materializations/{inputSnapshotSha256}
```

Transport rules:

- `OPERATOR` permission is required; exact Formula Result reads remain `VIEWER` operations.
- authentication and authorization are resolved before V23 capability lookup, so an unavailable Formula runtime is not disclosed to an unauthenticated or under-privileged caller;
- the path SHA is the only selector;
- query parameters are rejected;
- request bodies are rejected;
- first append returns HTTP `201` with materialization status `INSERTED`;
- an exact deterministic retry returns HTTP `200` with status `REPLAYED`;
- `Location` points to `/api/v1/formula-results/{explanationSha256}`;
- `ETag` is the same strong immutable explanation identity used by the read API;
- the response states `replayVerified: true` only after the exact persisted result passes historical replay.

The transport maps exact missing snapshot identity to `404`, non-V3 input to `422`, deterministic storage conflict to `409`, and unavailable V23 runtime to `503`. Unexpected evidence-resolution or replay failures remain server failures rather than being converted into invented Formula output.

See `api/formula-result-materialization-v1.openapi.yaml` for the transport schema. `RBVM_FORMULA_RESULT_API_V1` itself remains the read-only exact-identity contract; the write command has its own contract ID.

## 6. Explicit non-goals

Formula Result Materialization V1 does not:

- rebuild or mutate a Decision Input snapshot;
- select current/latest evidence;
- infer customer context or Finding associations;
- accept Formula weights/mappings from the request;
- derive Priority, Treatment, SLA, remediation deadline, or ticket workflow;
- rank Findings;
- mutate previously persisted Formula results;
- expose a browser control in this increment.
