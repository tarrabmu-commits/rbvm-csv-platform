# RBVM Frontend System V1

## Arabic operator workspace

تعتمد الواجهة العربية مساحة تشغيل موحدة ذات اتجاه RTL، وتنقلاً عربياً، وهوية بصرية
هادئة مناسبة لعمليات إدارة المخاطر. الوضع الفاتح هو الافتراضي، مع وضع داكن اختياري،
وتبقى المصطلحات المعيارية مثل CVSS وEPSS ومعرّفات العقود بصيغتها الأصلية حتى لا تضيع
دلالتها الفنية.

تجربة الدخول مركزية في شريط التطبيق. يتحقق العميل من الرمز عبر `/api/v1/session`،
ويعرض هوية المشغّل ودوره، ويحفظ الرمز الخام في `sessionStorage` للتبويب الحالي فقط.
إنهاء الجلسة يحذف الرمز فوراً، ولا تقبل الواجهة الرمز ضمن URL أو `localStorage`.

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

The existing page-specific API behavior remains unchanged. The frontend system adds a shared visual, composition, and interaction layer without introducing a SPA framework, remote CDN, or new source-of-truth state.

## Product design model

### Modular composition

The shared layer is a design system rather than a page skin. Existing page markup is progressively enhanced into reusable presentation modules so page-specific API code does not need to duplicate visual behavior.

The stable presentation vocabulary includes:

- `rbvm-page-hero` and `rbvm-page-eyebrow` for page identity and information hierarchy;
- `rbvm-module` for primary operator work areas;
- `rbvm-metrics` and `rbvm-metric-card` for quantitative summaries;
- `rbvm-table-frame` and `rbvm-data-table` for dense evidence and inventory views;
- `rbvm-callout` for explanatory and cautionary context;
- `rbvm-status` for live operator feedback;
- `rbvm-chip` for compact labels and contract identifiers;
- `rbvm-detail-card` and `rbvm-history-item` for immutable-detail and history presentation;
- `rbvm-dialog` for modal workflows.

The JavaScript applicator maps the existing legacy-compatible classes to these modules at runtime. New pages can adopt the same component vocabulary directly. This keeps layout and visual behavior reusable while preserving each page's existing API and domain semantics.

### Page identity

All nine pages share the same component grammar but do not intentionally look identical. The current path sets a stable `data-rbvm-page` identity and page group, which selects a page-specific accent pair and an informational eyebrow:

- Overview — platform operations and Evidence → Decision orientation;
- CVSS — technical severity;
- KEV — known exploitation;
- EPSS — exploitation probability;
- Asset Context — customer context evidence;
- Reachability — scoped network reachability;
- Business Impact — business / mission impact;
- Assets — customer-owned managed asset registry;
- Links — explicit scanner-to-managed-asset association.

Page accents are decorative identity, not domain meaning. They never select evidence, calculate a score, imply severity, or establish source precedence. The shared shell, typography, spacing, controls, tables, modules, focus behavior, and interaction patterns remain consistent across pages.

### Visual state language

The presentation layer recognizes exact state labels where they already exist in rendered content and applies a consistent visual treatment for `PRESENT|MISSING|UNKNOWN|STALE|AMBIGUOUS` plus existing lifecycle/link labels such as `ACTIVE|RESOLVED|LINKED|UNLINKED`.

This is presentation-only normalization. It does not synthesize a state, reinterpret missing evidence, or convert one domain state into another. In particular, missing evidence remains distinct from negative evidence, and visual state decoration does not change Decision Input or evidence-selection semantics.

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
- a shared top-level RBVM navigation shell with functional page groups;
- system-font typography with no remote font dependency;
- a common spacing, radius, elevation, status-color, form, table, panel, and badge token set;
- page-specific decorative accent pairs within one shared product identity;
- progressively enhanced reusable modules instead of duplicated page-specific component CSS;
- restrained motion for hierarchy and responsiveness, disabled under reduced-motion preference;
- automatic system light/dark preference with an optional local non-sensitive theme override;
- a 44 CSS pixel minimum interactive control height, intentionally exceeding the WCAG 2.2 24×24 minimum target;
- no client-side framework or package manager requirement for the operator UI.

## Security boundary

The frontend loads CSS and JavaScript only from the same RBVM origin. The server keeps `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, frame protection, and a same-origin Content Security Policy. Existing page scripts/styles are still inline, therefore the current CSP must retain `unsafe-inline` for those two directives; this contract does not claim a strict nonce/hash-only CSP.

The existing bearer-token pages predate this contract and use browser Web Storage for per-tab convenience. OWASP currently recommends keeping authentication tokens out of `localStorage` and `sessionStorage` when possible and preferring server-managed HttpOnly cookie or BFF patterns. Replacing the authentication transport is a backend/security-contract change and is not silently redefined by this frontend increment. Theme preference is non-sensitive and may be stored locally.

The modular frontend applicator does not persist evidence or operator workflow state. Page identity, component classes, and visual-state attributes are derived presentation metadata only.

## Shared resources

- `/ui/rbvm-ui.css` — design tokens, page identity, modular component styling, responsive layout, focus states, controls, tables, dialogs, semantic visual states, reduced-motion and forced-colors behavior.
- `/ui/rbvm-ui.js` — global navigation shell, current-page identity, modular composition applicator, skip link, theme preference, table/status/state semantic normalization, dialog focus restoration, and frontend contract marker.

Every operator HTML page must load both resources from the local origin.

## Verification boundary

Repository verification guards both availability and design-system structure. It checks the nine-page applicator map, page identities, reusable module markers, semantic visual-state vocabulary, system-font and 44px control policies, accessibility behavior, local-only resources, server routes, CSP directives, and packaged-JAR frontend smoke behavior.

These checks establish repository invariants; they do not claim external certification or replace browser/device accessibility testing.

## Non-goals

This contract does not:

- calculate or display an RBVM Risk score;
- assign evidence weights or source precedence;
- change any import, evidence, asset, link, decision-input, or workflow API semantics;
- infer business context, reachability, applicability, exploitation, or remediation state from presentation;
- add a remote analytics service, font, JavaScript package, CDN, or tracking pixel;
- claim certification or conformance beyond the behavior actually verified by the repository checks.
