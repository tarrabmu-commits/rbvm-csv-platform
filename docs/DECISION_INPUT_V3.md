# RBVM Decision Input Snapshot V3

`RBVM_DECISION_INPUT_SNAPSHOT_V3` extends the immutable Decision Input contract with exact Finding-context association provenance for the two evidence families that cannot safely be inherited from an entire scanner asset.

## Purpose

V3 prevents asset-wide context from being applied to every Finding on that asset.

A V3 Reachability reference is eligible only when an effective customer-confirmed Finding↔Reachability Scope link exists as-of the snapshot `evaluatedAt` and the native evidence matches both the Finding asset and the exact linked scope.

A V3 Business/Mission Impact reference is eligible only when an effective customer-confirmed Finding↔Business Service link exists as-of `evaluatedAt` and the native evidence matches both the Finding asset and the exact normalized linked business service.

## Binding kinds

- `MANAGED_ASSET_REVISION` → `SCANNER_MANAGED_ASSET_LINK_EVENT`
- `NETWORK_REACHABILITY_EVIDENCE` → `FINDING_REACHABILITY_SCOPE_LINK_EVENT`
- `BUSINESS_IMPACT_EVIDENCE` → `FINDING_BUSINESS_SERVICE_LINK_EVENT`

All other native evidence kinds remain unbound.

Historical V1 and V2 snapshots remain valid. V3 has a distinct contract ID, semantics string, canonical payload format, and canonical SHA-256 identity.

## Builder ordering

For Reachability and Business/Mission Impact the builder performs these steps in order:

1. Resolve the exact canonical Finding and its scanner asset.
2. Read append-only association history with `recorded_at <= evaluatedAt`.
3. Resolve the latest revision independently per logical association stream.
4. Admit only streams whose effective state is `LINKED`.
5. Match native evidence on the same Finding asset and exact association target/service, with native observation time `<= evaluatedAt`.
6. Only then apply methodology source allowlists, latest-per-source history reduction, freshness, and ambiguity semantics.
7. Emit exact native evidence references carrying the exact association event UUID/SHA/source/time that authorized the join.

Association filtering is therefore candidate construction, not a post-selection annotation.

## Exact target rules

Reachability target identity:

- `origin_scope`
- normalized `origin_label`
- `transport_protocol`
- `target_port` semantics

Business Impact target identity:

- normalized `business_service`

A target match without the same scanner asset is never sufficient.

## Resolver invariants

The PostgreSQL resolver re-verifies:

- native evidence UUID, SHA-256, semantic source, and observation time;
- exact binding event UUID, SHA-256, source/method, and recorded time;
- binding event belongs to the snapshot Finding;
- binding event state is `LINKED`;
- binding target exactly matches the native evidence target/service;
- native evidence asset equals the snapshot Finding asset.

The resolver never re-runs source selection and never substitutes current evidence or current association state.

## Missing semantics

No association history and an explicit effective `UNLINKED` decision both prevent the corresponding native evidence from entering the V3 candidate set. They do not fabricate `NOT_REACHABLE`, `LOW`, `UNKNOWN`, or any numeric value.

Association history remains independently auditable in its append-only native tables.

## Non-goals

V3 contains no Formula, Risk Score, Priority, SLA, treatment policy, source winner, numeric impact weight, or automatic association inference.
