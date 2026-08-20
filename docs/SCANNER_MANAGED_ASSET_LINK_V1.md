# SCANNER_MANAGED_ASSET_LINK_V1

## Purpose

Increment 21 introduces one narrowly scoped relationship: an explicit customer-confirmed mapping from the existing scanner/source-profile `rbvm.asset` identity to the existing durable customer `rbvm.managed_asset` identity.

This is **not** a generic association-evidence layer and it does not merge either identity model.

## Source classification

| Rule | Classification | Basis |
|---|---|---|
| Maintain accountable inventory identities | STANDARD_DERIVED | NIST SP 800-53 Rev. 5.1 CM-8 requires an inventory that reflects the system, avoids duplicate accounting, and tracks identifiable components. It does not prescribe this link schema. |
| Link only by explicit customer decision in Increment 21 | RBVM_POLICY | The scanner contract exposes only weak source-profile/name identity; no authoritative standard requires hostname/OS/product auto-linking. |
| Preserve never-linked separately from explicitly-unlinked | RBVM_POLICY | Evidence-first project invariant: missing must not be rewritten as an explicit negative state. |
| One ordered link-decision stream per scanner asset | RBVM_POLICY | Concurrency and audit design choice. |
| Allow many scanner identities to one managed asset | RBVM_POLICY | Supports multiple source profiles/scanners without duplicating the tenant-owned managed identity. |
| Tenant-scoped foreign keys and object authorization | RBVM_POLICY informed by OWASP API Security guidance | UUID unpredictability is not an authorization mechanism; API exposure must authorize both resource sides. |

No certification or NIST-compliance claim is made by this contract.

## Semantics

- `rbvm.asset` remains scanner/source-profile identity.
- `rbvm.managed_asset` remains durable customer inventory identity.
- `LINKED` requires one managed asset UUID.
- `UNLINKED` carries no managed asset UUID and may be the first explicit customer decision.
- No link-event history means **never assessed / no explicit link decision**.
- A latest `UNLINKED` event means **explicitly no current link**, whether it removed a prior link or was the first decision.
- Relinking is a new `LINKED` revision pointing at a different managed asset; prior link history remains immutable.
- A managed asset may have multiple current scanner identities. A scanner asset has only one current decision stream and therefore at most one current target.
- Managed-asset lifecycle does not silently create, delete, or change links. Retirement may surface as a consistency signal later, but it does not auto-unlink.

## Prohibited inference

Increment 21 must not create a link from:

- hostname/display-name equality,
- normalized scanner asset name,
- OS name,
- product/component name,
- CVSS, KEV, EPSS, scanner severity, or vulnerability presence,
- temporal proximity or "best match" heuristics.

Candidate suggestions, if ever introduced, must remain separate from confirmed link state and must never be written as a confirmed link without an explicit customer action.

## Persistence

This product increment adds **database migration V19**, because PostgreSQL schema migrations are sequenced independently and V19/V20 product increments did not add database migrations. The resulting required PostgreSQL schema version is 19.

`rbvm.scanner_managed_asset_link_event` is append-only. Runtime writers receive `SELECT, INSERT`; `UPDATE`, `DELETE`, and `TRUNCATE` remain revoked.

The current view intentionally includes a latest `UNLINKED` event. The active view includes only latest `LINKED` decisions.

## Concurrency contract

The domain registry uses an integer revision stream. Revision `0` means no link decision has ever been recorded. A future HTTP adapter should expose an opaque strong validator and require `If-Match` for state-changing revisions, following the same lost-update pattern already used by the Managed Asset API.

## Deliberate boundary

Increment 21 foundation does not yet:

- expose HTTP/UI linking operations,
- feed managed-asset customer context into Decision Input,
- choose precedence between V13 Asset Context and managed-asset context,
- introduce Formula, Risk, Priority, SLA, or Treatment.
