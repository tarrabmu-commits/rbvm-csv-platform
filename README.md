# RBVM CSV Platform — Increment 23

RBVM CSV Platform is a local, evidence-driven vulnerability-management platform that ingests Wazuh vulnerability CSV data, enriches findings with independent external and organizational evidence, preserves immutable provenance, and prepares reproducible Decision Inputs without inventing risk, priority, SLA, or remediation semantics before their contracts exist.

Current release contract: **0.23.2**  
Java runtime/toolchain: **17**  
Database migrations: **V1–V22**

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

Frontend V2 deliberately does **not** fabricate historical trends when the current API cannot support defensible historical aggregation. It also does not introduce an RBVM Formula result, priority, SLA, or remediation ranking.

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

Current Finding/Case reads use the dedicated current CVSS v3.1, FIRST EPSS, and CISA KEV evidence stores. Legacy intelligence embedded in older Wazuh V2 imports remains historical import data, not the current evidence authority. Multiple current sources remain `AMBIGUOUS`; no hidden source precedence is introduced.

## Managed assets and scanner links

Customer-managed asset identity is separate from scanner identity.

- `managed_asset` provides a stable customer-owned asset identity.
- `managed_asset_revision` stores append-only customer context revisions.
- Managed Asset writes use strong `ETag` / `If-Match` optimistic concurrency.
- Retirement/reactivation is represented as a new revision; there is no destructive delete workflow.
- Guided classification records explicit `ASSET_CLASSIFICATION_GUIDE_V1` provenance.
- Scanner-to-managed-asset links are explicit customer-confirmed link/unlink/relink decisions with append-only history.
- `never assessed` is different from explicit `UNLINKED`.
- The platform does not infer links from hostname, OS, product, CVSS, KEV, EPSS, or other hidden heuristics.

## Finding context associations

Network Reachability and Business / Mission Impact remain native evidence families. A Finding may use them only through explicit customer-confirmed Finding-scoped associations.

- Reachability association identity uses origin scope, normalized origin label, transport protocol, and target port.
- Business association identity uses the normalized Business Service.
- `LINKED`, `UNLINKED`, and never-assessed states are distinct.
- Association history is append-only and replayable as of the evaluation time.
- Association is provenance/binding; it never fabricates native evidence or converts missing evidence into a negative conclusion.

## Decision-input architecture

The pre-Formula pipeline is intentionally reproducible:

```text
Native Evidence History
        ↓
Versioned Decision Methodology
        ↓
Finding-scoped Association Filtering
        ↓
Evidence Selection
        ↓
Immutable Decision Input Snapshot
        ↓
Exact Native Evidence + Binding Resolution
        ↓
[Formula evaluation — separate versioned layer]
```

PostgreSQL V22 supports `RBVM_DECISION_INPUT_SNAPSHOT_V3`. Decision Input V3 carries exact typed native evidence references and, where required, the exact association/binding event used as of the evaluation boundary. Managed-asset evidence is bound through the exact scanner↔managed-asset link event and managed-asset revision; Finding reachability and business-impact evidence are bound through their exact Finding association events.

Current Decision Input semantics preserve `PRESENT / MISSING / AMBIGUOUS / STALE`; the resolver dereferences exact immutable evidence and binding references rather than re-selecting from `current_*` views. Later association changes do not rewrite historical snapshots.

## Formula readiness boundary

Formula readiness and golden-case contracts exist, but a production Formula result is still a separate implementation layer.

The readiness rules include:

- `NOT_APPLICABLE` is terminal and non-numeric; it is not risk `0`.
- Required `MISSING / STALE / AMBIGUOUS` dimensions make the Formula non-computable rather than producing a partial score.
- EPSS probability is the arithmetic exploitation-probability signal; percentile is not a second factor.
- CISA KEV membership is exploitation evidence, not an independent organizational-risk score.
- Multi-subgrain Reachability and Business Impact cannot be silently collapsed with an undocumented max/average/first rule.
- Formula output must remain separate from Priority, Treatment, SLA, and remediation workflow.

Golden cases cover state gates, controlled one-factor sensitivity, exclusions, partial ordering, replay, and qualitative customer context.

## External intelligence refresh

CVSS, CISA KEV, and FIRST EPSS support safe scheduled refresh pipelines that follow the canonical boundary:

```text
Current Canonical Cases
        ↓
Normalized unique CVE set
        ↓
Official source
        ↓
Validated source snapshot
        ↓
Canonical evidence CSV contract
        ↓
Same-origin / authenticated API handoff as configured
        ↓
Transactional PostgreSQL import
```

There is no official-source-to-database shortcut. Missing source evidence stays missing; a failed or incomplete source acquisition cannot be converted into `0`, `false`, or `NOT_LISTED`.

The supplied deployment offers either one umbrella `rbvm-intelligence-refresh.timer` or the source-only CVSS / EPSS / KEV timers. These schedules are mutually exclusive to avoid duplicate refresh work. Both deployment paths derive their CVE input from the current canonical Cases API. The source-specific scripts still accept explicit input files for controlled/manual/replay workflows.

To refresh immediately after a new Wazuh import instead of waiting for the daily timer, run the canonical refresh service/script explicitly. External-intelligence availability is not coupled to Wazuh import success.

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
- Canonical Assets, Vulnerabilities, Components, Observations, Exposures, Findings, and Cases.
- Immutable observations and independent evidence history.
- Explicit workflow events for accepted risk, false positive, manual close, reopen, and comments.
- Tenant-scoped PostgreSQL projection and reads.
- Serializable/transactional evidence importers with replay/conflict/quarantine semantics.
- Migration integrity with SHA-256 checks and advisory locking through V22.
- Append-only runtime privileges/guards for immutable evidence, association decisions, Decision Inputs, and audit history.
- Dedicated current CVSS/EPSS/KEV read projections with explicit `MISSING / PRESENT / AMBIGUOUS` semantics.
- TLS `verify-full` support, backup/restore tooling, readiness/liveness, metrics, and reconciliation health.
- Backend API-key/RBAC capability for hardened deployments.
- Reproducible JAR, SHA-256 checksum, SPDX 2.3 SBOM, CodeQL, and GitHub build/release verification.

## Important semantic boundaries

The current platform intentionally does **not** equate:

```text
CVSS                    = Risk
CISA KEV listed         = Priority
EPSS probability        = Priority
Missing EPSS            = 0
No KEV evidence         = NOT_LISTED
Asset criticality       = Numeric weight
Reachable endpoint      = Every finding is internet-reachable
Business impact         = Every finding inherits that service impact
Finding disappearance   = Remediated
Formula result          = Priority / SLA / Treatment
```

Formula evaluation, priority, treatment, SLA, and remediation-policy contracts remain separate layers. They must consume the existing immutable Decision Input boundary rather than bypass it.

## Verification

The repository verification pipeline includes Java/domain/API/SQL/web/script checks, Frontend System V2 structural checks, canonical intelligence deployment checks, reproducible distribution verification, PostgreSQL integration coverage, and CodeQL.

Frontend V2 itself is additionally guarded for:

- English-only SPA hosts.
- one shared application shell across legacy UI entry points.
- no browser credential state.
- accessibility/focus/reduced-motion/forced-colors contracts.
- managed-asset ETag concurrency.
- explicit scanner-link and Finding-context association semantics.
- no fabricated historical analytics or hidden risk score.

## Roadmap boundary

The next core methodology implementation is the versioned Formula layer over the already-defined Formula Readiness and golden-case boundaries. It must consume immutable resolved Decision Inputs, remain non-computable when required evidence gates fail, produce deterministic explanation/provenance, and stay explicitly separate from Priority, Treatment, SLA, and remediation workflow.
