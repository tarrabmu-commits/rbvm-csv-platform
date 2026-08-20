# Managed Asset API V1

`MANAGED_ASSET_API_V1` exposes the V18 customer-managed asset registry over the authenticated HTTP boundary. It is an inventory and audit capability only. It does not link customer assets to scanner identities and does not calculate Risk, Priority, SLA, Treatment, or Decision Input.

## Resources

```text
POST /api/v1/managed-assets
GET  /api/v1/managed-assets

GET  /api/v1/managed-assets/{managedAssetId}

GET  /api/v1/managed-assets/{managedAssetId}/revisions
POST /api/v1/managed-assets/{managedAssetId}/revisions
```

There is deliberately no `DELETE` endpoint. Retirement and reactivation are new immutable revisions whose `lifecycleStatus` is `RETIRED` or `ACTIVE`.

## Authorization

- current-state and revision-history reads require `VIEWER`;
- creation and revision append require `OPERATOR`;
- every object lookup remains tenant-scoped inside the PostgreSQL registry;
- a managed-asset identifier that is not visible in the authenticated tenant is treated as not found.

## Server-owned audit fields

The client may not supply the following values:

- `changedBy`;
- `recordedAt`;
- `contextSource`;
- `evidenceSha256`;
- revision number or revision UUID;
- the RBVM managed-asset UUID on create.

`changedBy` is taken from the authenticated `AuthPrincipal.actorId()`. `recordedAt`, `contextSource`, immutable revision number/identity, and evidence SHA-256 remain server-controlled.

Unknown JSON members are rejected rather than silently bound to domain state.

## Create

`POST /api/v1/managed-assets` accepts `application/json` and creates an `ACTIVE` revision `1`. The server generates the RBVM managed-asset UUID. `customerAssetKey` remains the optional immutable customer/CMDB identity.

Request fields:

- optional `customerAssetKey`;
- `displayName`;
- `environment`;
- `businessService`;
- `businessOwner`;
- `businessCriticality`;
- `classificationMethod`;
- optional `guideContractId` and `guideRevision` when `classificationMethod=GUIDED`;
- optional `changeNote`.

A successful create returns `201 Created`, a `Location` header for the new asset, a strong `ETag`, and the current managed-asset representation.

## Current representation

`GET /api/v1/managed-assets/{managedAssetId}` returns the stable asset identity plus its latest immutable revision. The response carries a strong `ETag` derived from the revision number and revision evidence SHA-256.

The ETag is an HTTP concurrency validator. Clients must treat it as opaque.

## Append a revision

`POST /api/v1/managed-assets/{managedAssetId}/revisions` requires the strong `ETag` returned by a prior current-state response in `If-Match`.

The request supplies a complete next customer state, not a partial patch:

- `lifecycleStatus` (`ACTIVE | RETIRED`);
- `displayName`;
- `environment`;
- `businessService`;
- `businessOwner`;
- `businessCriticality`;
- `classificationMethod`;
- optional guide provenance when guided;
- optional `changeNote`.

A complete state is required so the HTTP layer never performs a hidden field merge and every stored revision is self-contained.

`customerAssetKey` is not revision-editable because V18 defines it as immutable identity.

### Optimistic concurrency

The HTTP layer maps V18 `expectedRevision` semantics to standard conditional requests:

- missing `If-Match` -> `428 Precondition Required`;
- malformed, weak, wildcard, or multi-value managed-asset validator -> `400`;
- stale validator whose requested state is not an exact retry -> `412 Precondition Failed`;
- matching current validator and changed state -> append one revision and return `200` with the new ETag;
- unchanged state -> replay with no append and return `200`;
- an exact retry using the immediately prior valid ETag is accepted only when V18 replay semantics prove the already-current customer state matches the request.

This preserves the registry's existing retry behavior without accepting forged revision numbers: the supplied ETag must authenticate either the current immutable revision or the immediately prior immutable replay basis.

## List current managed assets

`GET /api/v1/managed-assets` supports:

- `limit` from `1` to `500`, default `100`;
- optional `afterId` UUID cursor;
- `lifecycle=ACTIVE|RETIRED|ALL`, default `ALL`.

The store orders current assets deterministically by managed-asset UUID and fetches one additional row to determine whether another page exists. The response returns `nextAfterId` only when another page exists.

No lifecycle filter is applied implicitly.

## Revision history

`GET /api/v1/managed-assets/{managedAssetId}/revisions` supports:

- `limit` from `1` to `500`, default `100`;
- optional positive `beforeRevision`.

History is returned newest-first by immutable revision number. Pagination uses `revision < beforeRevision`, so it does not depend on wall-clock ordering.

## Media type and size

Mutation requests require `application/json`. The request body is bounded to 16 KiB. The dependency-free server uses a strict flat-object parser for this contract and rejects duplicate members, invalid UTF-8, malformed JSON, nested values, and unknown fields.

## Error representation

HTTP problems continue to use the platform's existing `application/problem+json` representation with:

- `type`;
- `title`;
- `status`;
- `detail`;
- `correlationId`.

## Deliberate boundary

This increment does not:

- automatically correlate a managed asset to `rbvm.asset`;
- infer identity from hostname, IP, OS, product, CVSS, KEV, EPSS, or scanner severity;
- modify V13 Asset Context evidence;
- alter V17 Decision Input selection or resolution;
- calculate Formula, Risk, Priority, SLA, or Treatment;
- add a browser management UI.

Explicit scanner-identity linking remains a later increment.
