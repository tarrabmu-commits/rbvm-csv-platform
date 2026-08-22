# Finding Context Association UI V1

`FINDING_CONTEXT_ASSOCIATION_UI_V1` is the English-only operator workflow for explicit, customer-confirmed context associations on one canonical Finding.

## Scope

The UI operates on the canonical `findingId` surfaced on a component-specific exposure. A Case can contain multiple component-specific Findings, so the UI never sends a Case ID, CVE, asset name, or product label as a substitute for `findingId`.

The workflow covers two independent association families:

- Finding ↔ Network Reachability Scope
- Finding ↔ Business Service

It does not create Decision Input V3, Formula, Risk, Priority, SLA, or remediation decisions.

## Candidate evidence is not association truth

Current Network Reachability and Business/Mission Impact evidence may be shown as candidate context for the Finding's exact scanner asset and source profile. Evidence presence does not create a link.

The UI keeps these concepts visually and semantically separate:

- current native evidence exists or does not exist;
- association state is `NEVER_ASSESSED`, `LINKED`, or `UNLINKED`.

`NEVER_ASSESSED` is displayed as **Not assessed**. It is never converted to `UNLINKED`.

The interface never infers an association from a hostname, asset name, CVE, product, port, service name, CVSS, KEV, EPSS, or any other evidence signal.

## Exact target identity

Reachability decisions use the exact API target identity:

- `originScope`
- normalized `originLabel`
- `transportProtocol`
- `targetPort` when applicable

Business Service decisions use the server-normalized service identity.

The UI may display an explicit association even when current native evidence for that target is unavailable. It does not rewrite association history based on evidence disappearance.

## Optimistic concurrency

Before a mutation, the UI reads the exact current association state and uses the strong target-bound `ETag` returned by the API. The mutation sends that validator through `If-Match`.

HTTP `412 Precondition Failed` is shown as a concurrency conflict. The UI does not silently retry, merge, or substitute a different target.

An identical state request may be replay-safe at the API boundary. Therefore success copy states only that the requested association state is now current; it does not claim that a new audit event was written.

## Immutable history

For the exact selected reachability target or business service, the UI reads the immutable revision endpoint and displays revision, state, change note, actor, and recorded time. No history is represented as **No prior decision**, not as an explicit unlink.

## Language and presentation

All operator-visible copy in this contract is English and LTR. The workflow reuses `RBVM_FRONTEND_SYSTEM_V2` and preserves the shared SPA host used by all existing UI entry routes.

## Explicit non-goals

This contract contains no:

- automatic or heuristic linking;
- Case-level or asset-wide association shortcut;
- source-winner logic;
- numeric impact weight;
- Risk Score or Priority;
- Formula;
- SLA or treatment policy.
