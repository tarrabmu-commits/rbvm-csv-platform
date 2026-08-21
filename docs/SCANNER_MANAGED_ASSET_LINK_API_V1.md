# SCANNER_MANAGED_ASSET_LINK_API_V1

Increment 23 exposes the existing append-only `SCANNER_MANAGED_ASSET_LINK_V1` registry through an authenticated HTTP API and operator UI. It does not introduce matching or inference.

## Boundary

The scanner asset is the existing tenant-scoped `rbvm.asset` identity. The managed asset is the existing tenant-scoped `rbvm.managed_asset` identity. The API never creates either identity and never derives a link from hostname, observed OS, product, vulnerability, CVSS, KEV, EPSS, severity, or any other scanner/intelligence field.

`missing link history` means **never assessed**. An `UNLINKED` event is an explicit customer decision and must not be collapsed into missing state.

## Routes

- `GET /api/v1/scanner-assets?limit=&afterId=` — VIEWER; lists scanner identities and their current explicit link state.
- `GET /api/v1/scanner-assets/{scannerAssetId}/managed-asset-link` — VIEWER; returns current state and a strong ETag. A never-assessed asset returns `currentLink: null` and a deterministic revision-0 ETag.
- `GET /api/v1/scanner-assets/{scannerAssetId}/managed-asset-link/revisions?limit=&beforeRevision=` — VIEWER; newest-first immutable history.
- `POST /api/v1/scanner-assets/{scannerAssetId}/managed-asset-link/revisions` — OPERATOR; appends the complete next link decision.

There is no `PATCH` or `DELETE` route.

## Revision request

```json
{
  "linkStatus": "LINKED",
  "managedAssetId": "00000000-0000-0000-0000-000000000000",
  "changeNote": "customer-confirmed mapping"
}
```

or:

```json
{
  "linkStatus": "UNLINKED",
  "managedAssetId": null,
  "changeNote": "customer removed the mapping"
}
```

`changedBy`, `linkMethod`, `revision`, `eventId`, `evidenceSha256`, and `recordedAt` are server-owned and rejected if supplied. `changedBy` comes only from the authenticated principal. `linkMethod` remains `CUSTOMER_CONFIRMED`.

## Optimistic concurrency

Every revision write requires exactly one strong ETag in `If-Match`.

- Missing `If-Match` → `428 Precondition Required`.
- Weak, wildcard, malformed, or comma-list validators → `400` under the strict RBVM API contract.
- A stale validator with a different requested customer state → `412 Precondition Failed`.
- An exact retry may replay successfully without appending a duplicate revision.

Never-assessed scanner assets use a deterministic strong revision-0 ETag bound to the scanner asset UUID and the API contract. This protects the first explicit decision from concurrent lost updates while preserving the semantic distinction between no history and an explicit `UNLINKED` revision.

## Pagination

Scanner assets use stable UUID ascending pagination with `limit` (default 100, maximum 500) and `afterId`. Link history is newest first and uses `limit` plus `beforeRevision`.

No snapshot-consistency claim is made across separate scanner-asset list pages.

## Standards and policy attribution

- **STANDARD:** HTTP strong validators and `If-Match` semantics follow RFC 9110; `428 Precondition Required` is defined by RFC 6585; error responses use RFC 9457 `application/problem+json`; method-level/object-level authorization is consistent with OWASP API Security guidance.
- **RBVM_POLICY:** the route design, deterministic revision-0 ETag, exact retry behavior, append-only link state, customer-confirmed-only link method, scanner-list pagination, and prohibition on inferred matching are RBVM contract choices.

The external standards above do **not** define the scanner-to-managed-asset association algorithm and do not define evidence precedence.

## UI

`/asset-links` consumes this API only. It stores an optional API token in `sessionStorage`, not `localStorage`; uses native HTML controls/dialog/table semantics; requires an explicit `LINKED` or `UNLINKED` choice for never-assessed assets; and never auto-selects a managed asset target. A `412` is surfaced for human review with no automatic merge or retry.
