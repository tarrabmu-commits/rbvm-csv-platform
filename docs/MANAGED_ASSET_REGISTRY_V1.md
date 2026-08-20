# Managed Asset Registry V1

`MANAGED_ASSET_REGISTRY_V1` introduces durable customer-owned asset identity and append-only customer context history. It is a pre-formula inventory capability. It does not calculate risk, priority, treatment, or SLA.

## Why this exists

The canonical `rbvm.asset` table represents scanner/source-profile identity. A customer asset inventory has different semantics:

- the customer may create an asset before Wazuh or another scanner observes it;
- a scanner hostname or source identity may change while the business asset remains the same;
- the customer must be able to return later and change organizational context without re-entering the asset from scratch;
- prior classifications must remain auditable instead of being overwritten.

V18 therefore keeps scanner identity and customer-managed inventory identity separate.

## Persistent model

### `rbvm.managed_asset`

Stable tenant-owned identity:

- `id`: permanent RBVM UUID;
- `tenant_id`: tenant isolation;
- `customer_asset_key`: optional immutable customer/CMDB identifier;
- `created_at`: creation time.

`customer_asset_key` is optional because a manually created asset may not have a CMDB identifier. When supplied, it is unique within the tenant and is treated as an identity value, not an editable display label.

### `rbvm.managed_asset_revision`

Every customer edit appends a numbered revision. A revision contains:

- lifecycle: `ACTIVE | RETIRED`;
- display name;
- Environment;
- Business Service;
- Business Owner;
- Business Criticality;
- classification method: `CUSTOMER_DIRECT | GUIDED`;
- optional guide contract/revision when `GUIDED` was used;
- fixed semantic source `CUSTOMER_ASSET_REGISTRY`;
- evidence SHA-256;
- actor, change note, and recorded time.

There is no update-in-place path for these revisions. The runtime database role has `SELECT, INSERT` only and explicitly revokes `UPDATE`, `DELETE`, and `TRUNCATE` on both managed-asset tables.

## Customer editing semantics

Creating an asset creates revision `1`.

Editing an asset requires `expectedRevision`. The PostgreSQL store runs the mutation in a SERIALIZABLE transaction under an advisory transaction lock:

- current revision equals `expectedRevision` and content changed → append `expectedRevision + 1`;
- current revision equals `expectedRevision` and content is unchanged → `REPLAYED` with no new row;
- current revision equals `expectedRevision + 1` and content matches the requested state → retry replay;
- otherwise → `REVISION_CONFLICT` and no write.

Increment 19 exposes these same semantics over HTTP using a strong `ETag` on the current representation and a required `If-Match` precondition for revision append. The HTTP layer does not weaken or replace the registry's optimistic-concurrency invariant.

## Retirement, not deletion

Customer assets are not hard-deleted. Retirement is represented by a new revision whose lifecycle is `RETIRED`. Reactivation can later append another `ACTIVE` revision. Historical findings and classifications therefore retain a stable audit subject.

The Managed Asset API deliberately has no `DELETE` endpoint; lifecycle transitions remain append-only revisions.

## `UNKNOWN` remains explicit

A customer may create an asset without knowing all organizational context. Existing Asset Context vocabulary is reused:

- `Environment.UNKNOWN`;
- `BusinessCriticality.UNKNOWN`;
- the literal `UNKNOWN` may be used for Business Service or Business Owner when assessed but not known.

The registry does not infer values from hostname, OS, product, CVSS, KEV, EPSS, or scanner severity.

## Classification guide provenance

When the customer used the interactive guide, the revision records:

- `classification_method = GUIDED`;
- `guide_contract_id`;
- `guide_revision`.

When the customer selected values directly, the revision records `CUSTOMER_DIRECT` and must not claim a guide version.

This distinguishes customer judgment from standards-guided customer judgment without turning the guide into an automatic classifier.

## Views

`rbvm.current_managed_asset` exposes the latest revision for each customer-managed asset.

`rbvm.active_managed_asset` filters that projection to assets whose latest lifecycle state is `ACTIVE`.

These are operational convenience views only. The immutable source of history remains `rbvm.managed_asset_revision`.

## Increment 19 HTTP surface

`MANAGED_ASSET_API_V1` exposes authenticated create, current-state read, deterministic list, immutable revision-history read, and revision append over `/api/v1/managed-assets`.

The HTTP boundary preserves server-owned audit metadata: the authenticated principal supplies `changedBy`; the server controls timestamps, revision identity/number, fixed context source, and evidence SHA-256. Client request objects reject unknown fields rather than accepting audit metadata through generic object binding.

See `docs/MANAGED_ASSET_API_V1.md` for the request contract, pagination, ETag/If-Match behavior, status mapping, and authorization requirements.

## Deliberate boundary after Increment 19

The managed-asset registry and its HTTP API still do **not**:

- add a browser asset-management UI;
- link `managed_asset` to scanner `rbvm.asset` identities;
- infer that link from hostname, IP, OS, product, or vulnerability intelligence;
- alter V13 imported Asset Context evidence;
- change Decision Input selection or resolution;
- derive Risk, Priority, SLA, treatment, or Formula output.

The next semantic step is an explicit customer-controlled managed-asset ↔ scanner-asset identity link. Only after that association exists should customer-managed context be wired into Decision Input.
