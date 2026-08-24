# RBVM Performance & Scale V1

This increment improves execution performance without changing any RBVM evidence, CVSS, EPSS, KEV, SSVC, customer-context, treatment-priority, or Organizational Risk semantics.

## Public-intelligence collection

NVD remains sequential and retains its established pacing (`0.7s` between 100-CVE batches with an API key, `6.1s` without one). FIRST EPSS and CISA KEV retain their existing source contracts.

CVE Program/CVE Services is the safe parallelization boundary because the provider API is queried independently per unique CVE. Collection now uses a bounded thread pool:

- default: 6 workers;
- configurable with `RBVM_CVE_SERVICES_WORKERS`;
- hard maximum: 12 workers;
- offline replay: 1 worker.

One CVE request failing remains local to that CVE and is represented through the existing error/missing-evidence path. No failed request is converted to a negative exploitation or severity signal.

Provider-cache publication uses unique temporary files followed by atomic replacement. This removes the prior fixed `.tmp` writer collision while preserving the raw-response cache and SHA provenance model.

## Frozen Pareto priority performance

`RBVM_MVP_PRIORITY_POLICY_V1` remains byte-for-byte the same canonical method with SHA-256:

`88d5cdb8702c6c0ed2c033c3df6b8abbe1aa392f44f4507685b54082a16dc388`

The implementation now groups identical five-dimensional admitted vectors and compares each pair of unique vectors once. Identical vectors do not dominate one another because the frozen policy requires at least one strict improvement. Row-level `Dominates`, `Dominated_By`, front numbers, blockers, explanations, and method SHA are preserved exactly.

A randomized equivalence verifier compares the optimized implementation against the previous reference algorithm.

## 6000-row scale gate

`RBVM_6000_ROW_SCALE_BENCHMARK_V1` generates and processes a deterministic 6000-row run through:

1. CSV-first enrichment using a provenance-bound replay snapshot;
2. customer Asset Criticality, Internet Facing and direct CVSS CR/IR/AR context;
3. contextual CVSS v4 analysis;
4. RBVM V2 method admission;
5. frozen MVP Pareto treatment priority.

The benchmark checks row preservation, exact method identity, full rankability of the generated evidence set, `Organizational Risk = NON_COMPUTABLE`, wall-clock time, and peak child-process RSS. Default CI guardrails are intentionally generous regression boundaries rather than performance promises:

- total application pipeline: <= 90 seconds;
- peak child RSS: <= 768 MiB.

The benchmark is deterministic and does not use the network. The existing live CSV V2 benchmark continues to validate current NVD, FIRST EPSS, CISA KEV and CVE Program behavior on real public intelligence.
