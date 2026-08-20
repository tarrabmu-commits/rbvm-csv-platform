# Managed Assets UI V1

`MANAGED_ASSETS_UI_V1` is a browser management surface over `MANAGED_ASSET_API_V1`. It does not introduce new asset semantics, scanner correlation, Decision Input behavior, or RBVM scoring.

## Contract boundary

The UI is a client of the existing HTTP API only:

- `GET /api/v1/health`
- `GET /api/v1/managed-assets`
- `POST /api/v1/managed-assets`
- `GET /api/v1/managed-assets/{managedAssetId}`
- `GET /api/v1/managed-assets/{managedAssetId}/revisions`
- `POST /api/v1/managed-assets/{managedAssetId}/revisions`

There is no browser-only persistence model and no direct PostgreSQL access.

## Standards traceability

### STANDARD

- WCAG 2.2 is the accessibility baseline used to review keyboard operation, programmatic name/role/value, status messages, visible focus, and target sizing.
- Native HTML form controls, tables, and modal `dialog` elements are used rather than replacing equivalent host-language semantics with custom ARIA widgets.

Authoritative accessibility references:

- W3C WCAG 2.2: https://www.w3.org/TR/WCAG22/
- W3C WAI-ARIA APG Dialog (Modal) Pattern: https://www.w3.org/WAI/ARIA/apg/patterns/dialog-modal/
- W3C WAI Tables Tutorial: https://www.w3.org/WAI/tutorials/tables/

This document records an implementation basis; it does not claim external WCAG certification.

### STANDARD_DERIVED

- Modal create/revise/detail flows use native `<dialog>` so focus behavior can rely on host-language semantics, with explicit labels and ordinary buttons/forms.
- Dynamic operation results use live status regions so updates can be announced without forcing focus moves.
- Current-state asset data uses a native HTML table because the list is tabular data, not a composite grid widget.

### RBVM_POLICY

- The browser token remains scoped to `sessionStorage`, matching the existing platform UI. No token is written to `localStorage`. This is a platform policy informed by OWASP HTML5 storage guidance; it does not make browser storage immune to XSS.
- The UI never fabricates or parses a managed-asset ETag. It stores the opaque `ETag` header received from the latest successful current-state response and sends it unchanged in `If-Match`.
- A `412 Precondition Failed` is shown as a conflict that requires an explicit reload/review. The UI never auto-merges customer state.
- Pagination uses the API's `afterId` and `beforeRevision` cursors exactly as exposed by V19.
- Cards on the current-state page are explicitly page-local counts; the UI does not present them as tenant totals.

## Customer-state editing

Create accepts only the client-writable fields defined by V19. The server still owns UUID, lifecycle revision 1, `changedBy`, `recordedAt`, context source, revision identity, and evidence hash.

Revision editing always submits the complete customer state required by V19:

- lifecycle status;
- display name;
- environment;
- business service;
- business owner;
- business criticality;
- classification method;
- guide provenance when guided;
- optional change note.

`customerAssetKey` is displayed but not revision-editable.

## Classification guardrails

The UI exposes the exact current domain values. `UNKNOWN` remains available and is preferred over invented context. Selecting `GUIDED` makes guide provenance explicit and visible; it does not imply a classification until the customer submits the revision.

Business Criticality remains qualitative customer context. The UI does not calculate a numeric weight, Risk, Priority, SLA, or Treatment.

## Security guardrails

Security guidance reference: OWASP HTML5 Security Cheat Sheet, Storage APIs: https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#storage-apis

- API-derived text is rendered with DOM `textContent`, not `innerHTML`.
- Protected calls go through the same bearer-token `apiFetch` path as the existing web pages.
- No token or server-owned audit value is accepted as editable domain state.
- There is no DELETE path and no hidden lifecycle mutation.

## Deliberate boundary

This increment does not:

- correlate a managed asset to scanner `rbvm.asset`;
- infer context from hostname, IP, OS, product, CVSS, KEV, EPSS, or Wazuh severity;
- modify V13 Asset Context evidence;
- modify V17 Decision Input snapshots or resolution;
- add Formula, Risk, Priority, SLA, Treatment, or scoring.
