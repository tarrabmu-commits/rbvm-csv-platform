# RBVM Decision Input Runtime

The Decision Input runtime composes the already-versioned methodology registry, PostgreSQL evidence-history builder, and immutable V17 snapshot store. It is an orchestration boundary only; it does not define an RBVM score, priority, SLA, treatment, source ranking, or active methodology.

## Availability

`CanonicalProjectionFactory.RuntimeComponents.decisionRuntime()` is absent when PostgreSQL is disabled and remains absent below schema V17.

Schema V17 is the first complete runtime boundary because it provides all three required pieces:

1. the immutable V16 `DecisionMethodologyPolicyStore`;
2. the policy-aware Decision Input builder backed by the V17-capable evidence foundation; and
3. the immutable V17 `DecisionInputSnapshotStore`.

The runtime factory does not infer `max(revision)`, `current`, or `active` policy. Callers must still provide an explicit methodology revision and SHA-256 for every materialization.

## Build then install

`DecisionInputSnapshotMaterializer.materialize(...)` performs exactly two ordered operations:

1. `DecisionInputSnapshotBuilder.build(...)` constructs one canonical snapshot from transaction-consistent native evidence history at the caller-supplied `evaluatedAt`;
2. `DecisionInputSnapshotStore.install(...)` applies V17 immutable insert/replay/evaluation-conflict semantics to that exact snapshot.

The materialization result carries both the built snapshot and its install result, and verifies that the store's requested snapshot SHA-256 is the SHA of the built snapshot.

A build failure prevents any install attempt. An install failure is propagated without rebuilding or silently retrying. `EVALUATION_CONFLICT` is returned as a first-class immutable outcome rather than overwritten.

## Runtime bundle

At V17+, `CanonicalProjectionFactory.DecisionRuntime` exposes:

- `methodologyPolicies` — immutable methodology registry access;
- `snapshots` — immutable Decision Input Snapshot persistence/read access;
- `materializer` — explicit build-then-install orchestration.

The raw builder is intentionally not a separate runtime-factory capability: normal runtime callers should either materialize an immutable snapshot or use the lower-level PostgreSQL builder explicitly in controlled internal code.

## Boundary

This increment introduces no HTTP endpoint and no release/OpenAPI change. It also introduces no evidence-value comparison, risk equation, priority mapping, SLA, treatment, monetary-loss model, attack-path score, or Case roll-up. Any later decision-output contract must consume an immutable Decision Input Snapshot and define its own separately versioned methodology.
