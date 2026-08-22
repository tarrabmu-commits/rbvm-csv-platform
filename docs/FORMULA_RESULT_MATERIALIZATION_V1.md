# RBVM Formula Result Materialization V1

Runtime contract: `FORMULA_RESULT_MATERIALIZATION_V1`

This increment defines the production runtime path that evaluates and append-only persists `RBVM_FORMULA_V1` from one **exact already-persisted `RBVM_DECISION_INPUT_SNAPSHOT_V3` identity**.

It does not build a Decision Input, select current evidence, choose a Finding, choose a methodology, or expose a remediation Priority/Treatment/SLA policy.

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

## 5. Transport boundary

This increment does **not** publish a Formula materialization HTTP write route. `RBVM_FORMULA_RESULT_API_V1` remains a read-only exact-identity API.

A later transport increment may expose the materializer as an explicit Operator action, but it must preserve this contract: the request may identify only an already-persisted Decision Input V3 SHA and must not reintroduce current evidence selection, hidden `latest` behavior, or downstream Priority/Treatment/SLA logic.

## 6. Explicit non-goals

Formula Result Materialization V1 does not:

- rebuild or mutate a Decision Input snapshot;
- select current/latest evidence;
- infer customer context or Finding associations;
- accept Formula weights/mappings from the request;
- derive Priority, Treatment, SLA, remediation deadline, or ticket workflow;
- rank Findings;
- mutate previously persisted Formula results.
