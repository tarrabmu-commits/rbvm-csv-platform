# RBVM Stabilization V1

This increment removes runtime dashboard layering and restores a single first-class product flow.

## Goals

- One dashboard renderer in the core SPA.
- No V3/V4/V5 MutationObserver dashboard overlays in the runtime bundle.
- Dashboard data requests are bounded and explicit.
- CSV-first enrichment must not be confused with canonical catalog state.
- Current-run and canonical-catalog scopes remain explicit.

## Runtime rules

1. `rbvm-ui.js` owns the Overview/Dashboard route.
2. `rbvm-dashboard.js`, `rbvm-dashboard-v4.js`, and `rbvm-dashboard-v5.js` remain repository history/reference sources but are not concatenated into the runtime bundle.
3. The dashboard renders immediately from canonical summary plus one bounded current-finding page. It must label finding-level visualizations as the current page when they are not complete-catalog aggregates.
4. Full-catalog aggregates must come from server-side summary APIs, never by silently truncating client-side pagination.
5. CSV-first runs remain run-scoped until explicit canonical handoff.

## Next transport increment

CSV-first public-intelligence enrichment currently blocks one HTTP request while a Python process runs. The next transport increment must expose an asynchronous run-status contract and provider progress. Increasing the blocking timeout is not an acceptable product fix.
