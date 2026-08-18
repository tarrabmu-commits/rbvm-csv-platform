# Python Prototype Feature Migration

This document preserves the complete feature intent from the legacy `va.py` and `dashboard.py` prototype while moving the implementation into the Java/PostgreSQL platform.

The rule is **preserve product capability, not legacy defects**. Features that depended on unsafe lifecycle inference, unstructured intelligence files, or hard-coded risk/SLA policy are redesigned before adoption.

## Disposition legend

- `EXISTING` — capability already exists in the Java/PostgreSQL platform.
- `WAVE1` — implemented by the operational analytics foundation in this change set.
- `PLANNED` — preserve and implement in a later migration wave.
- `REDESIGN` — preserve the user-facing capability, but replace the legacy semantics/data model.
- `DEFER_RBVM` — keep the feature requirement but do not implement its decision logic until the RBVM methodology is selected.
- `REJECT_LOGIC` — the legacy behavior is intentionally prohibited; only a corrected equivalent may exist.

## Feature preservation matrix

| # | Legacy capability | Disposition | Target / note |
|---:|---|---|---|
| 1 | Multi-client / tenant management | EXISTING | Native `rbvm.tenant` isolation replaces per-client folders. |
| 2 | Historical database storage | EXISTING | PostgreSQL canonical domain + immutable observations. |
| 3 | Dimension / lookup caching | EXISTING | Canonical normalized entities and DB keys replace SQLite dimension caches. |
| 4 | Critical agents | REDESIGN | Future asset-context model; do not keep a text-file boolean as the final model. |
| 5 | Global exploitable CVE list | REDESIGN | Replace text file with provenance-bound threat intelligence. |
| 6 | Zstd CSV export | PLANNED | Preserve compressed export capability. |
| 7 | Quarter/date-range reporting | PLANNED | Add API/report date filters including quarter convenience. |
| 8 | Windows/Linux semantic grouping | PLANNED | Preserve as report facets, not source-data normalization. |
| 9 | Weekly Wazuh CSV ingestion | EXISTING | Current CSV import API + contracts. |
| 10 | Agent exclusion rules | REDESIGN | Move hard-coded prefixes to tenant-scoped source policy/configuration. |
| 11 | Snapshot model | REDESIGN | Use immutable observations + derived point-in-time analytics instead of snapshot-as-truth. |
| 12 | Vulnerability lifecycle tracking | EXISTING | Explicit source lifecycle supported by V2. |
| 13 | New finding detection | EXISTING | Canonical first observation. |
| 14 | Reappearance / reopen | EXISTING | Explicit newer ACTIVE evidence reopens source-resolved findings. |
| 15 | Last-seen tracking | EXISTING | Canonical finding/exposure state. |
| 16 | Vulnerability event history | WAVE1 | Derived evidence-based lifecycle event view. |
| 17 | Absence-based remediation detection | REJECT_LOGIC | Missing from a later export must never imply remediation. |
| 18 | Exploitable findings table | REDESIGN | Later use structured KEV/EPSS/exploitation evidence. |
| 19 | Agent severity distribution | WAVE1 | Tenant-scoped asset/severity analytics view. |
| 20 | Exploitable findings by agent | REDESIGN | Restore after threat-evidence model is corrected. |
| 21 | Critical + exploitable assets | DEFER_RBVM | Depends on asset context + threat evidence. |
| 22 | Product severity distribution | WAVE1 | Component/product severity analytics view. |
| 23 | Exploitable products | REDESIGN | Restore after structured threat evidence. |
| 24 | Severity-based SLA policy | DEFER_RBVM | Do not hard-code until treatment policy follows selected methodology. |
| 25 | Active-finding SLA | DEFER_RBVM | Preserve dashboard/report requirement; decision policy deferred. |
| 26 | Remediation SLA | DEFER_RBVM | Preserve dashboard/report requirement; decision policy deferred. |
| 27 | SLA summary by severity | DEFER_RBVM | Preserve analytics requirement. |
| 28 | SLA summary by asset | DEFER_RBVM | Preserve analytics requirement. |
| 29 | Most vulnerable assets | REDESIGN | Preserve ranking view, but do not call severity counts organizational risk. |
| 30 | Active finding age | WAVE1 | Evidence-derived age. |
| 31 | Remediated finding age / time-to-resolution | WAVE1 | Only when explicit resolution exists. |
| 32 | Vulnerability trend | WAVE1 | Evidence-based DETECTED/REOPENED/RESOLVED event trend. |
| 33 | Asset CVE-age statistics | WAVE1 | Count/max/avg/median age for current observed/active findings. |
| 34 | New/remediated totals | REDESIGN | New is safe; remediated becomes explicit `RESOLVED` only. |
| 35 | Global severity metrics | WAVE1 | Findings and observations by severity. |
| 36 | Exposure by severity | WAVE1 | Exposure/finding count by technical severity. |
| 37 | Central metrics engine | PLANNED | API/service aggregation over analytics views. |
| 38 | Excel intelligence report | PLANNED | Export generated from canonical analytics. |
| 39 | Full historical VA report | PLANNED | Canonical historical export. |
| 40 | Active CVE report | PLANNED | Current observed/active findings report. |
| 41 | Exact-date active snapshot | PLANNED | Derived point-in-time report; no absence-close semantics. |
| 42 | Remediation report | PLANNED | Explicitly resolved evidence only. |
| 43 | Exploitable CVE report | REDESIGN | Structured threat intelligence required. |
| 44 | CVE-age report | PLANNED | Source from operational finding view. |
| 45 | Weekly trend report | PLANNED | Source from lifecycle event analytics. |
| 46 | Interactive text menu | REDESIGN | Browser/API workflow supersedes local menu; optional admin CLI may remain. |
| 47 | Intelligence reload menu | REDESIGN | Scheduled/provenance-bound refresh replaces manual text-file reload. |
| 48 | Operational reports menu | PLANNED | Browser/API report actions. |
| 49 | CLI | PLANNED | Keep automation-friendly command surface where useful. |
| 50 | CLI report types | PLANNED | Active/resolved/trend/age/metrics/export equivalents. |
| 51 | Weekly automated pipeline | PLANNED | Import + materialize + analytics/report generation. |
| 52 | Full operational pipeline | PLANNED | Auditable orchestration, no unsafe lifecycle inference. |
| 53 | Interactive HTML dashboard | PLANNED | Extend current embedded web UI. |
| 54 | Severity color scheme | PLANNED | UI presentation feature. |
| 55 | Dashboard summary cards | PLANNED | Unique CVEs/findings/assets/new/resolved/observed counts. |
| 56 | Generic bar-chart engine | PLANNED | Front-end visualization utility. |
| 57 | Vulnerability trend combo chart | PLANNED | Uses corrected lifecycle-event series. |
| 58 | Product treemap | PLANNED | Uses product analytics view. |
| 59 | Exploitable vs non-exploitable donut | REDESIGN | Reintroduce only when numerator/denominator use identical units and threat evidence is structured. |
| 60 | Top critical exploitable assets | DEFER_RBVM | Depends on corrected threat + asset context semantics. |
| 61 | SLA compliance by severity chart | DEFER_RBVM | Treatment policy must be selected first. |
| 62 | Overall SLA compliance chart | DEFER_RBVM | Treatment policy must be selected first. |
| 63 | Top SLA violating assets | DEFER_RBVM | Treatment policy must be selected first. |
| 64 | Remediation SLA performance | DEFER_RBVM | Treatment policy must be selected first. |
| 65 | Dashboard visualization set | PLANNED | Restore every safe chart and redesigned equivalent. |
| 66 | Responsive chart rendering | PLANNED | Keep responsive browser behavior. |
| 67 | Responsive HTML layout | PLANNED | Extend current embedded UI. |
| 68 | Auto-open local dashboard | PLANNED | Optional local-development convenience only. |
| 69 | PDF report generator | PLANNED | Re-enable only after canonical report data is stable. |

## Wave 1 implemented here

The first migration wave creates PostgreSQL analytics views that preserve the safe historical/operational ideas from the prototype without introducing RBVM scoring:

- canonical operational-finding view;
- evidence state (`OBSERVED_ONLY`, `ACTIVE`, `RESOLVED`) with explicit lifecycle flag;
- finding age and explicit time-to-resolution;
- age buckets;
- severity distribution;
- asset-by-severity distribution;
- product/component-by-severity distribution;
- asset age statistics;
- evidence-derived lifecycle events (`DETECTED`, `REOPENED`, `RESOLVED`, `RESOLVED_INITIAL_EVIDENCE`);
- daily and weekly lifecycle-event aggregates;
- tenant overview counts.

## Non-negotiable semantic corrections

### No remediation by absence

The legacy state-diff behavior that treated `previous_active - current_snapshot` as remediated is not migrated. V1 remains observation-only. Only explicit V2 resolution evidence may create a `RESOLVED` lifecycle state/event.

### No unstructured `exploitable_cves.txt` truth

The old file-based exploitability capability is preserved as a product requirement but will be rebuilt using source-specific evidence and provenance. `NOT_LISTED` must not be interpreted as proof of non-exploitation.

### No severity-as-risk naming

Severity counts, asset counts, age and technical-severity visualizations are operational vulnerability-management analytics. They are not organizational risk scores and must not be labelled as RBVM decisions.

### No hard-coded RBVM/SLA policy yet

The legacy `Critical=3`, `High=30`, etc. treatment policy is intentionally deferred. SLA analytics will return after the RBVM/treatment methodology is explicitly selected.

## Migration sequence

```text
Wave 1  Operational analytics foundation
Wave 2  Analytics API + browser dashboard + report filters
Wave 3  CSV/Zstd/Excel/PDF exports + scheduled operational reports
Wave 4  Tenant-scoped asset context and configurable source policies
Wave 5  Structured threat-evidence features that replace exploitable_cves.txt
Wave 6  RBVM decision methodology and treatment/SLA layer
```

This sequence keeps every prototype feature in scope while preventing prototype defects from becoming production semantics.
