# Increment 20 Validation — Managed Assets UI

Increment 20 adds a browser management surface over the already-versioned V19 Managed Asset API. It must not change the domain or persistence contracts.

## Required invariants

- `/assets` is a static browser entry point; all protected data access still goes through authenticated `/api/v1/managed-assets` routes.
- The page supports current-state list, create, current-state detail, immutable revision append, and history read.
- `customerAssetKey` is create-only and is never sent by revision requests.
- Revision submission is complete-state, not PATCH or client-side merge.
- Revision submission uses the opaque ETag from the latest successful current-state response as `If-Match`.
- A 412 conflict requires explicit reload/review; no auto-merge or silent retry occurs.
- Retirement and reactivation remain lifecycle revisions; no DELETE request exists.
- API data is inserted into the DOM using text nodes/textContent.
- Browser token storage remains session-scoped and the page does not use localStorage.
- `UNKNOWN` remains available for unknown environment/criticality rather than forcing invented context.
- Business Criticality remains qualitative context only.
- The page does not expose scanner-link, Decision Input, Formula, Risk, Priority, SLA, or Treatment controls.

## Accessibility review basis

The page is structured for WCAG 2.2 review using native HTML forms, buttons, tables, and modal dialogs; status updates use live regions and focus-visible styling is explicit. This is traceability, not a certification claim.

## Verification

The structural verifier must check at minimum:

- unique element IDs and valid JS element references;
- session-scoped token usage;
- no `innerHTML`, localStorage API, DELETE, or PATCH;
- V19 managed-asset endpoints and ETag/If-Match flow;
- modal create/detail/revise surfaces;
- current domain enum values and `UNKNOWN`;
- explicit 412/no-auto-merge behavior.
