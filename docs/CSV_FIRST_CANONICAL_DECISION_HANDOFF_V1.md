# CSV-first canonical decision handoff V1

## Purpose

This handoff closes the boundary between a stateless CSV-first analysis run and the canonical evidence/decision pipeline without inventing identity, applicability, reachability, business impact, or a risk formula.

## Scanner evidence identity

The exact original uploaded scanner CSV is the only scanner artifact submitted to the canonical CSV importer. The enriched CSV is never re-imported as scanner evidence.

The operator supplies the Source Profile ID and the explicit scanner contract (`WAZUH_CSV_V1` or `WAZUH_CSV_V2`), reviews the import preview, and confirms the canonical import explicitly.

After confirmation, exact Finding identity is exported through `CANONICAL_IMPORT_FINDING_MANIFEST_HTTP_V1` using persisted lineage only:

`import_observation -> observation -> exposure_observation -> exposure`

`Finding_ID` is `exposure.id`. No hostname, CVE, product, filename, severity, or timestamp matching creates Finding identity.

## Canonical public evidence

`CSV_FIRST_CANONICAL_PUBLIC_EVIDENCE_HTTP_V1` uses the original CSV only to define the requested CVE scope. Public evidence is then re-acquired through the canonical source adapters already required by the dedicated evidence contracts.

### FIRST EPSS

Canonical EPSS is **not** copied from the CSV-first FIRST API response. `EPSS_CSV_V1` requires the official FIRST daily bulk feed, model version, score date, observation time, and exact source-byte SHA-256. The handoff therefore runs:

1. `fetch-first-epss-snapshot.py`
2. `build-first-epss-csv.py`
3. the existing `EpssImporter`

This preserves the semantics of `EPSS_CSV_V1` instead of relabeling a different source representation.

### CISA KEV

Canonical KEV is re-acquired from the official CISA KEV JSON feed through:

1. `fetch-cisa-kev-snapshot.py`
2. `build-cisa-kev-csv.py`
3. the existing `CisaKevImporter`

The resulting canonical evidence remains CVE-scoped and provenance-preserving.

### CVSS v4

CSV-first contextual CVSS v4 remains a contextual technical-severity analysis artifact. This handoff does not convert CVSS v4 to CVSS v3.1 and does not claim a canonical v4 persistence contract that does not exist.

## Customer evidence remains explicit

Canonical scanner identity and public intelligence do not resolve organization-specific decision inputs automatically.

The following remain explicit customer/operator evidence requirements:

- Applicability: a finding-scoped explicit assessment. Absence remains unassessed/unknown.
- Exact Network Reachability: evidence and a customer-confirmed Finding-to-scope association. `Internet Facing` is not equivalent to exact reachability and is not mapped to CVSS `MAV`.
- Business Service / Business Impact: customer evidence plus an explicit Finding-to-service association where required.
- Asset Criticality: remains organizational context and is not converted into CVSS `CR/IR/AR`.
- CVSS `CR/IR/AR`: only direct native CVSS declarations may populate them.

No auto-linking or inferred applicability is permitted.

## Decision Input boundary

The intended path is:

`Original CSV -> Canonical Import -> Exact Finding_ID -> Canonical EPSS/KEV -> Explicit Applicability/Context Associations -> Decision Input Snapshot -> Selected Method`

The Decision Input builder remains fail-closed when required evidence or exact associations are absent.

## Risk-method boundary

This handoff creates no Organizational Risk score and does not alter immutable Formula V1.

`RBVM V2` remains `NON_COMPUTABLE` / `NO_V2_PRIMARY_METHOD_ADMITTED` until an explicit, versioned methodology is approved and bound through the existing risk-method selection policy.

Prohibited shortcuts include:

- multiplying CVSS by EPSS;
- treating KEV, EPSS, CVSS, Internet Facing, or Asset Criticality as interchangeable scales;
- assigning hidden weights;
- silently choosing an existing methodology as the V2 primary method.
