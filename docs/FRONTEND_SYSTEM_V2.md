# RBVM Frontend System V2

Contract ID: `RBVM_FRONTEND_SYSTEM_V2`

Frontend System V2 is the operator-facing product architecture for the pre-V24 RBVM platform. It replaces the V1 page-by-page presentation layer with one dependency-free single-page application shared by every legacy entry point. It does not change Evidence, Decision Input, Formula, Risk, Priority, SLA, or remediation semantics.

## Product principles

1. **Evidence before inference.** Source evidence is displayed before derived conclusions. V2 does not introduce an RBVM risk score, priority, SLA, or hidden weighting.
2. **Recognition over recall.** Findings, assets, evidence, analytics, imports, and reports are organized by operator task instead of backend table or feed names.
3. **Progressive disclosure.** The default view stays concise while exact IDs, revisions, source hashes, timestamps, and audit data remain available in details.
4. **One primary question per screen.** Overview monitors, Findings investigates, Assets provides context, Analytics explains patterns, Reports communicates, and Data surfaces evidence/import boundaries.
5. **Tables for investigation; charts for patterns.** Charts are restrained and lead to the underlying records when the current API can express the filter.
6. **Preserve context.** Finding details open without discarding the current filtered list, and filter state is encoded in a shareable URL.
7. **Missing is information.** `PRESENT`, `MISSING`, `AMBIGUOUS`, and `STALE` are distinct operator-facing states. Absence is never displayed as zero or safe.
8. **Technical detail remains available.** Immutable evidence identity, source timestamps, managed-asset revisions, and link history remain accessible.
9. **No hidden prioritization.** Existing vendor/source signals such as CVSS, CISA KEV, and EPSS are shown independently. V24 remains the Formula Contract boundary.
10. **Simple, not simplistic.** The default interface is calm and task-oriented while retaining audit and operator depth.

## Information architecture

The English-only operator interface exposes:

- Overview
- Work: Findings, Assets
- Insights: Analytics, Reports
- Data: Evidence, Imports
- Settings

Legacy URLs (`/cvss`, `/kev`, `/epss`, `/asset-context`, `/reachability`, `/business-impact`, `/asset-links`) remain valid entry points and resolve into the corresponding V2 workspace. New workspaces use shareable query routes on `/`, for example `/?view=findings&severity=CRITICAL`, so no new HTTP routing or API contract is required.

## Local access model

Frontend System V2 has **no in-app login** and no browser Access Token field. It does not read or write API credentials in `sessionStorage` or `localStorage`. The default trusted-local deployment uses `RBVM_AUTH_MODE=DISABLED`. Hardened remote deployments keep backend API-key capability for non-browser clients or may place access control at the deployment boundary.

## Interaction and accessibility contract

- English-only copy and `lang="en" dir="ltr"`.
- System fonts only; no remote font dependency.
- Product control floor: **44 CSS pixels** for interactive controls.
- Visible `:focus-visible` treatment.
- Keyboard escape closes overlays; `/` focuses global search when focus is not in a form control.
- Semantic HTML tables for investigation data.
- Drawer/dialog content is labelled and does not rely on color alone.
- `prefers-reduced-motion` and forced-colors modes are supported.
- Mobile prioritizes reading/review while desktop preserves data density.

## Analytics contract

V2 provides current-state Exposure, Threat, Aging, Asset, and Decision Readiness analytics from existing APIs. It deliberately does **not** fabricate a historical trend when no historical aggregation API is exposed. The Trend workspace explains this boundary and points to defensible current-state analytics instead.

Decision Readiness makes evidence availability visible. Source-specific rows remain authoritative; the UI never fabricates a missing evidence row merely to fill a table.

## Reports contract

V2 provides template-first browser report generation for Executive, Vulnerability Analysis, Threat Exposure, Asset Exposure, and Decision Readiness views. The current frontend can preview, print/save as PDF through the browser, and export current report rows as CSV.

These browser reports are explicitly current-state artifacts. V2 does not claim immutable server-side report identity, historical snapshot replay, scheduled delivery, Formula binding, or report hashes. Those require a dedicated report backend increment.

## Managed assets and scanner links

Managed-asset create/revise operations keep strong ETag / `If-Match` concurrency behavior and complete immutable revisions. Guided classification records `ASSET_CLASSIFICATION_GUIDE_V1` references and does not infer criticality from CVSS, KEV, EPSS, or a hidden score.

Scanner-to-managed-asset links remain explicit append-only decisions. `Not assessed` is different from `UNLINKED`; the UI never selects a managed-asset target automatically.

## Security boundary

The frontend remains dependency-free and same-origin. CSP continues to prohibit external objects, framing, base replacement, and cross-origin form submission. Browser rendering does not weaken the canonical API validation, authorization, tenant resolution, immutable evidence, or append-only history boundaries.
