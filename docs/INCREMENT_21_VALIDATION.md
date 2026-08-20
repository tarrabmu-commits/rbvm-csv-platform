# Increment 21 Validation

`SCANNER_MANAGED_ASSET_LINK_V1` is the explicit customer-confirmed identity bridge between scanner `rbvm.asset` and durable `rbvm.managed_asset`.

## Required invariants

- PostgreSQL migration sequence advances from schema V18 to **V19**.
- Scanner and managed asset identities remain separate tables and separate semantics.
- Link events are append-only and tenant scoped.
- `LINKED` always names one managed asset; `UNLINKED` names none.
- No event history means no explicit decision has been recorded; first revision may be `UNLINKED`.
- `CUSTOMER_CONFIRMED` is the only link method in this contract.
- Hostname, normalized name, OS, product, CVSS, KEV, EPSS, severity, timing, and best-match heuristics are not link inputs.
- The runtime store validates both scanner and managed asset existence inside the tenant before a linked revision is appended.
- Optimistic revision semantics distinguish replay from conflict and preserve immutable history.
- Runtime role has `SELECT, INSERT` only for link events and `SELECT` for projections; mutation of prior link events remains revoked.
- Runtime factory exposes the link registry only with PostgreSQL schema V19 or newer.
- No HTTP/UI link mutation surface and no Decision Input integration are added by this increment.
- No Formula, Risk, Priority, SLA, Treatment, or score is introduced.

## Standards traceability

NIST SP 800-53 Rev. 5.1 CM-8 is used only as a `STANDARD_DERIVED` inventory/accountability basis. It does not prescribe the RBVM link schema or matching algorithm.

OWASP API Security Top 10 2023 API1 (BOLA) informs the authorization requirement for any future API that accepts scanner or managed asset identifiers. It does not define link identity semantics.

The link/relink/unlink state machine is therefore explicitly `RBVM_POLICY`.
