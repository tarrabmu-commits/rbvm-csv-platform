# RBVM CSV Platform — Increment 23

RBVM CSV Platform is a local, evidence-driven vulnerability-management platform that ingests Wazuh vulnerability CSV data, enriches findings with independent external and organizational evidence, preserves immutable provenance, prepares reproducible Decision Inputs, and evaluates the versioned RBVM Formula V1 without conflating relative risk with priority, SLA, or remediation policy.

Current release contract: **0.23.2**  
Java runtime/toolchain: **17**  
Database migrations: **V1–V23**

## Product interface

The operator interface is **RBVM Frontend System V2** (`RBVM_FRONTEND_SYSTEM_V2`): one dependency-free, English-only, LTR single-page application shared by the legacy UI entry points.

Primary workspaces:

- **Overview** — current exposure and direct investigation entry points.
- **Findings** — searchable/filterable current findings with detail drawer and evidence drill-down.
- **Assets** — managed assets, immutable revisions, and explicit scanner-to-managed-asset links.
- **Analytics** — current-state Exposure, Threat, Aging, Assets, and Decision Readiness views.
- **Reports** — template-first current-state browser reports with preview, Print/Save PDF, and CSV data export.
- **Evidence** — independent CVSS, CISA KEV, EPSS, Asset Context, Reachability, and Business Impact evidence.
- **Imports** — Wazuh and evidence import workflows.
- **Settings** — local display preferences only.

Legacy URLs remain valid: `/cvss`, `/kev`, `/epss`, `/asset-context`, `/reachability`, `/business-impact`, `/assets`, and `/asset-links`. New workspace state is represented through shareable query routes on `/`.

Frontend V2 deliberately does **not** fabricate historical trends when the current API cannot support defensible historical aggregation. It also does not yet expose the RBVM Formula result, a remediation priority, SLA, or remediation ranking in the browser product surface.

See [`docs/FRONTEND_SYSTEM_V2.md`](docs/FRONTEND_SYSTEM_V2.md) for the operator UX and security contract.

## Evidence model

The platform keeps evidence families independent and source-bound:

| Evidence family | Contract / semantics |
|---|---|
| Wazuh observations | `WAZUH_CSV_V1` and optional richer `WAZUH_CSV_V2` |
| Applicability | `APPLICABILITY_CSV_V1` with `APPLICABLE / NOT_APPLICABLE / UNKNOWN` |
| Technical severity | `CVSS_V31_CSV_V1`; CVSS remains technical severity, not organizational risk |
| Known exploitation | `CISA_KEV_CSV_V1`; `LISTED / NOT_LISTED`, with absence of usable evidence remaining unknown |
| Exploitation probability | `EPSS_CSV_V1`; probability/percentile/model/date provenance, with missing evidence never converted to zero |
| Asset Context | `ASSET_CONTEXT_CSV_V1`; qualitative organizational context without numeric weights |
| Network Reachability | `NETWORK_REACHABILITY_CSV_V1`; scoped origin/endpoint evidence, not an asset-wide risk verdict |
| Business / Mission Impact | `BUSINESS_IMPACT_CSV_V1`; qualitative source-reported impact without hidden weighting |

The core rule is: **missing evidence is information**. Missing, ambiguous, and stale evidence must not silently become false, low, safe, or zero.

## Managed assets and scanner links

Customer-managed asset identity is separate from scanner identity.

- `managed_asset` provides a stable customer-owned asset identity.
- `managed_asset_revision` stores append-only customer context revisions.
- Managed Asset writes use strong `ETag` / `If-Match` optimistic concurrency.
- Retirement/reactivation is represented as a new revision; there is no destructive delete workflow.
- Guided classification records explicit `ASSET_CLASSIFICATION_GUIDE_V1` provenance.
- Scanner-to-managed-asset links are explicit customer-confirmed `LINK / UNLINK / RELINK` decisions with append-only history.
- `never assessed` is different from explicit `UNLINKED`.
- The platform does not infer links from hostname, OS, product, CVSS, KEV, EPSS, or other hidden heuristics.

## Decision-input and Formula architecture

The evidence-to-Formula pipeline is intentionally reproducible:

```text
Native Evidence History
        ↓
Versioned Decision Methodology
        ↓
Evidence Selection
        ↓
Immutable Decision Input Snapshot V3
        ↓
Exact Native Evidence + Association-Event Resolution
        ↓
RBVM_FORMULA_V1 Pure Evaluator
        ↓
Canonical Formula Explanation Identity
        ↓
Immutable Formula Result Persistence
        ↓
Exact Historical Replay Verification
```

PostgreSQL V22 stores Decision Input V3 snapshots with typed native references. Managed-asset context is bound to the exact scanner↔managed-asset link event and managed-asset revision used as of evaluation time. Reachability and Business Impact evidence are admitted only through exact customer-confirmed Finding-context association events, rather than being inherited asset-wide.

Current Decision Input semantics preserve `PRESENT / MISSING / AMBIGUOUS / STALE`; the resolver dereferences exact immutable evidence and exact binding provenance rather than re-selecting from `current_*` views.

`RBVM_FORMULA_V1` consumes only one exact resolved `RBVM_DECISION_INPUT_SNAPSHOT_V3`. It produces `COMPUTED`, `NOT_APPLICABLE`, or `NON_COMPUTABLE`; only `COMPUTED` carries the dimensionless `RBVM Relative Risk Index` on `0.00 .. 100.00`. `RBVM_FORMULA_EXPLANATION_CANONICAL_BINARY_V1` deterministically binds that result to the exact Formula identity, snapshot, Finding, methodology, native evidence references, association events, dimension states, normalized Formula values, contributions, and terminal reason code.

PostgreSQL V23 persists that exact Formula result and canonical explanation append-only. The row is foreign-key bound to the exact persisted Decision Input V3 identity; exact retries replay, conflicting result content for the same snapshot/Formula identity is rejected, and historical verification reloads the persisted snapshot, resolves only its captured native evidence/bindings, re-evaluates Formula V1, regenerates the explanation, and requires byte-identical canonical explanation content.

The read-only `RBVM_FORMULA_RESULT_API_V1` transport exposes only exact persisted identities and replay-verifies every successful response:

```text
GET /api/v1/formula-results/{explanationSha256}
GET /api/v1/formula-results?inputSnapshotSha256={sha256}&formulaSha256={sha256}
```

The Formula Result runtime requires PostgreSQL schema V23+, is Viewer-protected before capability lookup, and deliberately has no `latest` selector. The production `FORMULA_RESULT_MATERIALIZATION_V1` runtime path now takes only one exact already-persisted Decision Input V3 SHA, resolves only that snapshot's captured evidence/bindings, evaluates Formula V1, append/replay installs the canonical explanation, reloads it, and requires historical replay before returning. A Formula materialization HTTP write route and browser presentation are not implemented yet.

See [`docs/DECISION_INPUT_V3.md`](docs/DECISION_INPUT_V3.md) for the immutable Decision Input boundary, [`docs/RBVM_FORMULA_V1.md`](docs/RBVM_FORMULA_V1.md) for the accepted Formula contract, [`docs/RBVM_FORMULA_CANONICALIZATION_V1.md`](docs/RBVM_FORMULA_CANONICALIZATION_V1.md) for canonical Formula/explanation identity, [`docs/FORMULA_RESULT_API_V1.md`](docs/FORMULA_RESULT_API_V1.md) for exact replay-verified Formula Result reads, and [`docs/FORMULA_RESULT_MATERIALIZATION_V1.md`](docs/FORMULA_RESULT_MATERIALIZATION_V1.md) for exact production materialization semantics.

## External intelligence refresh

CVSS, CISA KEV, and FIRST EPSS use the same normalized, deduplicated canonical CVE inventory derived from current canonical Cases. The umbrella refresh and the deployed source-only refresh services both export that canonical inventory before invoking their official-source pipelines:

```text
Canonical Cases
    ↓
Normalized / deduplicated CVE inventory
    ├── NVD CVSS v3.1
    ├── FIRST EPSS
    └── CISA KEV
         ↓
Validated source snapshots
         ↓
Canonical evidence contracts
         ↓
Authenticated API handoff
         ↓
Transactional PostgreSQL imports
```

Finding/Case reads and intelligence summaries use the dedicated CVSS, EPSS, and KEV evidence stores. Missing evidence remains `MISSING`/unknown, multiple admissible current sources remain `AMBIGUOUS`, and no hidden source winner is selected. In particular, absence of usable KEV evidence never becomes `NOT_LISTED`.

The umbrella and source-only systemd schedules are mutually exclusive so enabling both cannot duplicate scheduled refresh work. Supplied hardened user services whitelist only their documented per-user work/output/cache paths.

There is no official-source-to-database shortcut. Remote canonical-CVE export requires HTTPS; HTTP is accepted only on loopback, and credentialed export requests do not follow redirects.

## Local access model

The default trusted-local deployment uses:

```text
RBVM_AUTH_MODE=DISABLED
```

Frontend System V2 contains **no in-app login and no browser Access Token field**. It does not persist API credentials in browser storage.

The repository local launcher enforces that trusted-local boundary explicitly:

```bash
./scripts/run-server.sh
```

`run-server.sh` forces `RBVM_AUTH_MODE=DISABLED`, even when the current shell inherited an old `RBVM_AUTH_MODE=API_KEY` value. This prevents a stale hardened-shell setting from making the same-origin browser UI unusable.

To deliberately test backend API-key mode, opt in explicitly:

```bash
RBVM_AUTH_MODE=API_KEY \
RBVM_API_KEYS_FILE=/secure/path/api-keys.txt \
./scripts/run-server.sh --auth-from-env
```

Direct JAR and deployment launches continue to honor authentication environment variables normally. Hardened remote deployments may retain backend API-key capability for API clients or place authentication at the deployment boundary.

## Run locally

Requirements:

- JDK 17 or newer.
- Python 3 and PyYAML for repository verification.
- PostgreSQL + pgJDBC only when PostgreSQL projection/integration is enabled.

Verify and run:

```bash
./scripts/verify.sh
./scripts/run-server.sh
```

Open:

```text
http://127.0.0.1:8080
```

Build the reproducible distribution:

```bash
./scripts/build-distribution.sh
java -jar dist/rbvm-csv-platform-0.23.2.jar
```

Verify the reproducible artifact and checksum:

```bash
./scripts/verify-reproducible-build.sh
sha256sum --check dist/rbvm-csv-platform-0.23.2.jar.sha256
```

## Core API and runtime properties

The platform includes:

- RFC 4180 and strict UTF-8 CSV validation with bounded streaming upload.
- Canonical Assets, Vulnerabilities, Components, Observations, Exposures, and Cases.
- Immutable observations and evidence history.
- Explicit workflow events for accepted risk, false positive, manual close, reopen, and comments.
- Tenant-scoped PostgreSQL projection and reads.
- Serializable/transactional evidence importers with replay/conflict/quarantine semantics.
- Migration integrity with SHA-256 checks and advisory locking through V23.
- Append-only runtime privileges/guards for immutable evidence, association decisions, Formula results, and audit history.
- Exact Decision Input V3 native-evidence and association-event resolution.
- Canonical `RBVM_FORMULA_V1` identity plus a deterministic pure evaluator over resolved Decision Input V3.
- Deterministic `RBVM_FORMULA_EXPLANATION_CANONICAL_BINARY_V1` bytes and SHA-256 identity for exact Formula result provenance/replay semantics.
- Append-only Formula V1 result/explanation persistence with exact Decision Input V3 binding and deterministic historical replay verification.
- Exact persisted-Decision-Input Formula V1 materialization with INSERTED/REPLAYED semantics, conflict fail-closed behavior, and replay verification before return.
- Viewer-protected, exact-identity Formula Result HTTP/API reads with replay verification and no implicit current/latest selection.
- TLS `verify-full` support, backup/restore tooling, readiness/liveness, metrics, and reconciliation health.
- Backend API-key/RBAC capability for hardened deployments.
- Reproducible JAR, SHA-256 checksum, SPDX 2.3 SBOM, CodeQL, and GitHub build/release verification.

## Important semantic boundaries

The current platform intentionally does **not** equate:

```text
CVSS                         = Risk
CISA KEV listed              = Priority
EPSS probability             = Priority
Missing EPSS                 = 0
No KEV evidence              = NOT_LISTED
RBVM policy weight/mapping   = Standards-mandated truth
Reachable endpoint           = Every finding is internet-reachable
Business impact              = Every finding inherits that service impact
Formula result               = Priority / SLA / Treatment
Finding disappearance        = Remediated
```

Formula V1 is an explicit, versioned RBVM policy for a relative risk result. Priority, Treatment, SLA, remediation deadlines, and workflow decisions remain separate later contracts and must consume the Formula/Decision Input boundary rather than being hidden inside Formula arithmetic.

## Verification

The repository verification pipeline includes Java/domain/API/SQL/web/script checks, Formula V1 contract/runtime/canonical-explanation/persistence/replay checks, Formula Result materialization/API/HTTP/runtime/OpenAPI checks, Frontend System V2 structural checks, reproducible distribution verification, PostgreSQL integration coverage, and CodeQL.

Frontend V2 itself is additionally guarded for:

- English-only SPA hosts.
- one shared application shell across legacy UI entry points.
- no browser credential state.
- accessibility/focus/reduced-motion/forced-colors contracts.
- managed-asset ETag concurrency.
- explicit scanner-link and Finding-context association semantics.
- no fabricated historical analytics or hidden risk score.

## Formula implementation and roadmap boundary

Formula-readiness semantics, canonicalization, the Stage 8 golden-case corpus, the canonical `RBVM_FORMULA_V1` artifact, the pure Java evaluator, deterministic canonical explanation identity, append-only Formula-result persistence/replay, exact replay-verified read transport, and exact persisted-snapshot production materialization are implemented and verified. Formula evaluation consumes exactly one resolved `RBVM_DECISION_INPUT_SNAPSHOT_V3`, preserves terminal `NOT_APPLICABLE / NON_COMPUTABLE` behavior, rejects missing/stale/ambiguous required evidence, applies only the accepted SHA-bound mappings/weights, reproduces the frozen numeric examples, and produces replay-stable explanation bytes bound to exact evidence and association provenance.

The next Formula-layer increment is an explicit Operator transport for the exact materializer; browser presentation can then consume the existing replay-verified read API and invoke materialization without rebuilding Decision Inputs. Priority, Treatment, SLA, remediation deadlines, and workflow policy remain separate later contracts and must not be hidden inside Formula V1.
