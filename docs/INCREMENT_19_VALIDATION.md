# Increment 19 Validation — Managed Asset API

Increment 19 exposes the V18 customer-managed asset registry through an authenticated HTTP API without changing scanner identity, Decision Input, or Formula semantics.

## Required invariants

- Managed-asset root identity remains stable and independent from `rbvm.asset`.
- Every customer edit is an appended immutable revision; no HTTP or store path updates or deletes prior revisions.
- Create forces `ACTIVE` revision 1 and server-generates the managed-asset UUID.
- `customerAssetKey` remains optional and immutable after creation.
- Client request bodies cannot set `changedBy`, `recordedAt`, `contextSource`, `evidenceSha256`, revision number, or revision UUID.
- `changedBy` comes from the authenticated API principal.
- Revision append requires a strong `If-Match` validator derived from an immutable prior revision.
- Missing precondition returns 428; a stale non-replay validator returns 412.
- Exact retry semantics remain those of V18 and do not create duplicate revisions.
- Current-state and history reads are tenant-scoped.
- List pagination is deterministic by managed-asset UUID and has no hidden lifecycle filter.
- History pagination is deterministic by descending immutable revision number.
- Missing/unknown business context remains explicit; the API does not infer context from vulnerability intelligence or scanner metadata.
- The increment does not link managed assets to scanner assets and does not alter Decision Input or calculate Risk/Priority/SLA/Treatment.

## Verification layers

`PlatformSelfTest` covers the HTTP behavior against the dependency-free server, including create/read/list/history, ETag concurrency, replay, retirement, duplicate customer key, server-owned audit fields, unavailable persistence, and DELETE rejection.

`verify-managed-asset-api.py` enforces structural boundaries across the HTTP contract, registry read surface, tenant-scoped PostgreSQL queries, runtime wiring, and OpenAPI description.

The existing `verify-managed-asset-registry.py` continues to enforce V18 append-only persistence and restricted runtime-role invariants.

The complete repository verification command remains:

```bash
./scripts/verify.sh
```
