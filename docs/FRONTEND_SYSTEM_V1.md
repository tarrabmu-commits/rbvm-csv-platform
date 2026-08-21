# RBVM Frontend System V1

`RBVM_FRONTEND_SYSTEM_V1` is the presentation contract for the operator-facing RBVM web UI. It is intentionally independent of Risk, Priority, Treatment, and SLA semantics.

## Scope

The contract covers the existing dependency-free pages served by `CsvPlatformServer`:

- `/`
- `/cvss`
- `/kev`
- `/epss`
- `/asset-context`
- `/reachability`
- `/business-impact`
- `/assets`
- `/asset-links`

The existing page-specific API behavior remains unchanged. The frontend system adds a shared visual and interaction layer without introducing a SPA framework, remote CDN, or new source-of-truth state.

## Standards classification

### STANDARD

The implementation targets WCAG 2.2 Level AA for the frontend surface. In particular:

- controls are designed at or above the WCAG 2.2 2.5.8 minimum pointer target size;
- keyboard focus remains visibly discernible;
- native semantic HTML controls are preferred;
- page structure uses landmarks, headings, labels, tables, captions, and status regions;
- layout is responsive and does not depend on pointer-only interaction;
- reduced-motion and forced-colors user preferences are respected.

Native modal dialogs are used where dialogs are required. Dialog labeling, contained focus behavior, visible close/cancel controls, and focus restoration follow the WAI-ARIA Authoring Practices modal-dialog guidance where applicable.

### RBVM_POLICY

The following are product design decisions, not requirements imposed by WCAG or WAI-ARIA:

- RTL-first Arabic operator presentation with English security/domain terminology where it is the canonical contract value;
- a shared top-level RBVM navigation shell;
- system-font typography with no remote font dependency;
- a common spacing, radius, elevation, status-color, form, table, panel, and badge token set;
- automatic system light/dark preference with an optional local non-sensitive theme override;
- a 44 CSS pixel minimum interactive control height, intentionally exceeding the WCAG 2.2 24×24 minimum target;
- no client-side framework or package manager requirement for the operator UI.

## Security boundary

The frontend loads CSS and JavaScript only from the same RBVM origin. The server keeps `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, frame protection, and a same-origin Content Security Policy. Existing page scripts/styles are still inline, therefore the current CSP must retain `unsafe-inline` for those two directives; this contract does not claim a strict nonce/hash-only CSP.

The existing bearer-token pages predate this contract and use browser Web Storage for per-tab convenience. OWASP currently recommends keeping authentication tokens out of `localStorage` and `sessionStorage` when possible and preferring server-managed HttpOnly cookie or BFF patterns. Replacing the authentication transport is a backend/security-contract change and is not silently redefined by this frontend increment. Theme preference is non-sensitive and may be stored locally.

## Shared resources

- `/ui/rbvm-ui.css` — design tokens, responsive layout, focus states, controls, tables, dialogs, reduced-motion and forced-colors behavior.
- `/ui/rbvm-ui.js` — global navigation shell, current-page state, skip link, theme preference, table/status semantic normalization, and frontend contract marker.

Every operator HTML page must load both resources from the local origin.

## Non-goals

This contract does not:

- calculate or display an RBVM Risk score;
- assign evidence weights or source precedence;
- change any import, evidence, asset, link, decision-input, or workflow API semantics;
- add a remote analytics service, font, JavaScript package, CDN, or tracking pixel;
- claim certification or conformance beyond the behavior actually verified by the repository checks.
