# Full Scalability Benchmark V1

Contract: `RBVM_FULL_SCALABILITY_BENCHMARK_V1`

## Purpose

This benchmark measures the real CSV-first RBVM path after the local public-intelligence cutover. It is a capacity and bottleneck measurement contract, not a product-size declaration.

The standard progression is:

`1K -> 5K -> 10K -> 25K -> 50K -> 100K Findings`

**10K is a regression checkpoint, not a platform limit.** The benchmark implementation does not impose a 10K Finding or CVE ceiling. With stress mode enabled, the harness doubles beyond the largest requested tier until it observes a timeout/failure or reaches an explicit run-safety ceiling. If the run reaches that safety ceiling without a measured bottleneck, the result is `CAPACITY_NOT_REACHED_AT_RUN_SAFETY_CEILING`; the ceiling must not be reported as platform capacity.

## Measured pipeline

A benchmark tier covers:

1. deterministic Wazuh CSV generation;
2. V30 PostgreSQL current public-intelligence lookup/export for the exact CVEs in the CSV;
3. local `PUBLIC_CVE_INTEL_SNAPSHOT_V1` construction;
4. CSV enrichment from the local snapshot only;
5. customer asset context application and contextual analysis;
6. RBVM V2 method admission;
7. canonical PostgreSQL Finding projection and exact import-to-Finding manifest export;
8. frozen `RBVM_MVP_PRIORITY_POLICY_V1` Pareto priority computation;
9. V29 canonical Finding priority persistence;
10. bounded representative PostgreSQL read paths for case/Finding and priority results.

The benchmark does not call NVD, FIRST, CISA, or the CVE Program over the network during the CSV hot path.

## Setup versus hot path

Synthetic public-intelligence seeding is benchmark setup and is measured separately as `setupSeedSeconds`. It is deliberately excluded from upload hot-path throughput.

The hot-path acquisition metric begins at local PostgreSQL lookup/export (`localLookupExportSeconds`). This prevents a benchmark fixture-generation cost from being mislabeled as product upload latency.

The benchmark seeds deterministic provider records for:

- NVD;
- FIRST EPSS;
- CISA KEV;
- CVE Program.

CISA non-membership semantics are exercised through the same V31-linked V30 validation boundary used by the product cutover. Only a deterministic subset is stored as KEV-listed; absence for the rest is eligible for `listed=false` only after the benchmark CISA run satisfies the linked COMPLETE validation contract.

## Safety boundary

`PostgresFullScalabilityBenchmarkBridge` exists only in the test source tree. It writes synthetic public-intelligence records and therefore refuses to run unless both conditions are true:

- `RBVM_SCALABILITY_BENCHMARK_MODE=true`;
- the configured PostgreSQL JDBC target starts with `jdbc:postgresql://127.0.0.1:` or `jdbc:postgresql://localhost:`.

The standard harness resets the local `rbvm` schema between tiers so each tier has an isolated database population. `--keep-database-between-tiers` exists only for experiments that intentionally measure cumulative database growth.

Never run this harness against an operational RBVM database.

## Dataset profiles

Finding count and unique-CVE count are separate dimensions. The standard profile uses `--unique-cve-ratio 0.05`, preserving repeated Findings across assets while still exercising local lookup and provider provenance. The harness records the exact ratio in every tier result.

For a lookup-heavy worst-case profile, run with `--unique-cve-ratio 1.0`. A 100K-Finding / 100K-unique-CVE result is materially different from a 100K-Finding / 5K-unique-CVE result and must be labeled accordingly.

The benchmark also scales the number of assets and emits deterministic customer declarations for:

- Asset Criticality;
- Internet Facing;
- CVSS v4 CR/IR/AR.

These are synthetic customer inputs for benchmarking only. They do not change RBVM decision semantics.

## Measurements

Each tier produces stage and aggregate metrics including:

- wall-clock seconds;
- user CPU seconds;
- system CPU seconds;
- peak process RSS;
- page faults;
- context switches;
- filesystem I/O counters when `/usr/bin/time -v` is available;
- rows per second;
- unique CVEs per second for local lookup/export;
- PostgreSQL `pg_stat_database` deltas for transactions, blocks, tuples, and temp usage;
- canonical Finding counts;
- mapped priority source-row counts;
- representative read latency;
- artifact byte sizes;
- exact stage that timed out or failed.

The summary records host identity: Git commit, Python version, Java version, platform, machine architecture, CPU count, visible memory, and sanitized local JDBC database endpoint.

## Correctness gates

A tier is not considered a valid performance result unless it preserves correctness:

- input, enriched, analysis, and priority CSV row counts equal the requested Finding count;
- `RBVM_MVP_PRIORITY_POLICY_V1` identity and frozen SHA remain exact;
- every row is rankable in the standard synthetic profile;
- no Organizational Risk is fabricated; `riskStatus` remains `NON_COMPUTABLE`;
- canonical priority materialization maps every source row;
- representative materialized priority reads resolve successfully;
- CISA negative semantics pass the V31/V30 validation boundary.

A subprocess exit failure is treated as a correctness regression and fails the benchmark run. A stage timeout is recorded as a measured bottleneck for that environment.

## Standard versus stress runs

A standard full run executes all configured checkpoints through 100K and reports `STANDARD_PROGRESSION_COMPLETE` if they pass.

Stress mode continues geometrically beyond the standard progression. The `--stress-max-rows` option is a run-safety ceiling to prevent unbounded CI/resource consumption. Reaching it without a bottleneck proves only that capacity was not reached within that run.

No benchmark result should be generalized beyond its recorded machine, PostgreSQL configuration, unique-CVE ratio, commit, and dataset profile.

## CI strategy

Normal pull-request verification checks the benchmark contract structurally and compiles the bridge. PostgreSQL integration runs a bounded smoke tier to prove the live harness on an ephemeral local database.

The full 1K-to-100K progression and stress mode are intentionally exposed as a manual workflow. Running 100K+ on every pull request would measure shared GitHub runner contention as much as application performance and would unnecessarily slow correctness feedback.

Full-run artifacts retain `summary.json`, `summary.csv`, per-tier results, process timing logs, PostgreSQL bridge metrics, and generated benchmark artifacts for later engineering comparison.

## Semantic non-goals

This benchmark does not modify:

- `RBVM_MVP_PRIORITY_POLICY_V1` or its frozen SHA;
- CVSS, EPSS, CISA KEV, or CVE Program semantics;
- customer-context evidence contracts;
- Organizational Risk computability;
- SLA semantics;
- historical decision artifacts.

It measures the implementation; it does not define a new risk method.
