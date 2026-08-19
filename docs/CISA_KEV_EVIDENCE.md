# CISA KEV Threat Evidence Foundation

This stage introduces **CISA Known Exploited Vulnerabilities (KEV)** as independent CVE-scoped threat evidence. It remains separate from CVSS Technical Severity, EPSS exploitation probability, asset context, remediation policy, and the legacy combined intelligence/priority model.

CISA describes the KEV catalog as the authoritative source of vulnerabilities known to have been exploited in the wild and recommends using it as an input to vulnerability-management prioritization. The platform therefore preserves KEV as evidence and does not reinterpret catalog membership as an RBVM score by itself.

## Question answered by this stage

```text
For this CVE, what did the successfully observed CISA KEV catalog snapshot say
about catalog membership, from which snapshot, and when was that snapshot observed?
```

It does **not** answer CVSS severity, exploitation probability, asset criticality, remediation priority, or SLA. Those are separate evidence or decision stages.

## Canonical status semantics

```text
LISTED
NOT_LISTED
UNKNOWN
```

### `LISTED`

The CVE was present in a successfully observed and validated complete CISA KEV catalog snapshot.

A listed observation carries snapshot provenance plus listing metadata:

```text
CVE_ID
KEV_Status = LISTED
KEV_Catalog_Version
KEV_Catalog_SHA256
KEV_Catalog_Count
KEV_Source
KEV_Observed_At
KEV_Date_Added
KEV_Due_Date
Known_Ransomware_Campaign_Use
```

The CISA due date is preserved as source evidence. It is **not** converted into the organization's remediation SLA by this stage.

### `NOT_LISTED`

The CVE was absent from a successfully observed and validated **complete** CISA KEV catalog snapshot.

This is snapshot-bound negative membership evidence:

```text
CVE_ID
KEV_Status = NOT_LISTED
KEV_Catalog_Version
KEV_Catalog_SHA256
KEV_Catalog_Count
KEV_Source
KEV_Observed_At
```

`NOT_LISTED` means only:

```text
not present in this observed KEV snapshot
```

It must never be interpreted as:

```text
not exploited
safe
not important
no exploit exists
```

Listing-only fields are absent for `NOT_LISTED` evidence.

### `UNKNOWN`

No usable KEV catalog evidence is currently attached to the CVE. A collection failure, incomplete catalog, or absent observation therefore remains missing evidence and is **not** converted into `NOT_LISTED`.

`UNKNOWN` carries no fabricated snapshot provenance, listing metadata, or negative-membership claim.

## Complete snapshot proof

Negative membership is only safe when the platform can prove it inspected a complete catalog snapshot. `CisaKevCatalogSnapshot` is the provenance token for that proof.

The current domain boundary requires:

```text
KEV_Catalog_Version
KEV_Source
KEV_Observed_At
KEV_Catalog_SHA256
Declared_Count
Parsed_Count
```

and requires:

```text
Declared_Count > 0
Parsed_Count   > 0
Declared_Count == Parsed_Count
```

The SHA-256 binds the evidence to exact catalog bytes, while the count equality prevents a partial parse from being used as the basis for `NOT_LISTED`.

Both `CisaKevEvidence.listed(...)` and `CisaKevEvidence.notListed(...)` require this validated snapshot object. The evidence API therefore has no overload that can create `NOT_LISTED` from only `CVE_ID + timestamp`.

The intended source is the CISA KEV catalog JSON published from the CISA domain. A future collector must validate the complete snapshot before creating `CisaKevCatalogSnapshot`.

## Provenance and freshness

`KEV_Observed_At` records when the platform successfully observed the catalog bytes. It is independent from CISA `dateAdded` and from CVSS/EPSS observation timestamps.

This foundation does not hard-code a freshness window. Freshness policy must remain explicit and must not silently rewrite historical `LISTED` or `NOT_LISTED` observations.

## Ransomware campaign field

The canonical evidence model preserves CISA's ransomware-campaign-use vocabulary semantically as:

```text
KNOWN
UNKNOWN
```

This `UNKNOWN` is listing metadata and is distinct from `KEV_Status = UNKNOWN`, which means the platform lacks usable KEV membership evidence.

## Domain model

The foundation consists of:

```text
CisaKevCatalogSnapshot
CisaKevEvidence
```

and explicit evidence constructors:

```text
CisaKevEvidence.unknown(...)
CisaKevEvidence.listed(..., validatedSnapshot, ...)
CisaKevEvidence.notListed(..., validatedSnapshot)
```

The model enforces valid CVE identity, HTTPS source provenance, complete-snapshot count validation, SHA-256 binding, no provenance on `UNKNOWN`, required listing metadata for `LISTED`, and no listing-only metadata for `NOT_LISTED`.

It deliberately does not expose `knownExploited=false` for negative membership and does not derive priority, risk score, SLA, EPSS, or asset/business context.

## Relationship to CVSS

```text
CVSS v3.1 Base
→ How technically severe is this vulnerability?

CISA KEV
→ Is this CVE present in an observed catalog of vulnerabilities exploited in the wild?
```

They remain independent. This stage does not calculate CVSS + KEV, CVSS × KEV, KEV bonus points, priority tiers, or risk scores.

## Relationship to legacy intelligence

The existing compatibility intelligence model contains a `knownExploited` boolean and can map it directly to a local `IMMEDIATE` priority. That behavior is legacy/local policy and is **not** the canonical KEV model.

The canonical replacement is snapshot-bound, provenance-aware KEV evidence with `LISTED / NOT_LISTED / UNKNOWN` semantics. Migration away from the legacy model must remain additive and auditable.

## Pipeline position

```text
Wazuh observation / canonical finding
        |
        +---- Applicability evidence
        |
        +---- CVSS v3.1 Technical Severity
        |
        +---- CVE_ID
                |
                v
        Validated complete CISA KEV snapshot
                |
                v
        CISA KEV Threat Evidence
        LISTED / NOT_LISTED / UNKNOWN
                |
                v
        later EPSS probability
                |
                v
        later asset/business context
                |
                v
        RBVM decision
```

## Current stage boundary

Implemented in this increment:

- independent `CisaKevCatalogSnapshot` provenance model;
- independent `CisaKevEvidence` threat-evidence model;
- `LISTED / NOT_LISTED / UNKNOWN` semantics;
- explicit distinction between missing evidence and negative catalog membership;
- SHA-256 and declared/parsed-count proof for a complete snapshot;
- CISA listing metadata boundary;
- source ransomware-campaign-use semantics;
- tests proving that incomplete snapshots cannot back `NOT_LISTED` and that no priority/risk/SLA/EPSS is derived.

Not implemented yet:

- `CISA_KEV_CSV_V1` exchange contract;
- official complete-snapshot collector/parser;
- PostgreSQL KEV history/current views;
- transactional importer;
- API/UI;
- scheduling;
- freshness policy;
- EPSS;
- RBVM decision logic.

The next increment should define the separate KEV CSV contract in a way that preserves the validated snapshot identity on every `LISTED` or `NOT_LISTED` row. It must not infer `NOT_LISTED` from an absent row in a partial or failed collection.
