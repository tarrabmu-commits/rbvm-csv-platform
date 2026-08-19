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

It must never be interpreted as `not exploited`, `safe`, `not important`, or `no exploit exists`.

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

## Official source acquisition

The official-source adapter is implemented before the persistence boundary:

```text
https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
        |
        v
scripts/fetch-cisa-kev-snapshot.py
        |
        v
CISA_KEV_VALIDATED_SNAPSHOT
```

The adapter uses a fixed CISA HTTPS origin, bounds response size, validates UTF-8 JSON, validates catalog metadata and dates, requires the declared count to equal the parsed array length, rejects duplicate/invalid CVE identifiers, validates ransomware-campaign values, and binds the exact source bytes with SHA-256.

A failed or incomplete acquisition produces no usable snapshot and therefore cannot create `NOT_LISTED` evidence. See [`CISA_KEV_SOURCE_ADAPTER.md`](CISA_KEV_SOURCE_ADAPTER.md).

## Provenance and freshness

`KEV_Observed_At` records when the platform successfully observed the catalog bytes. It is independent from CISA `dateAdded` and from CVSS/EPSS observation timestamps.

The scheduled collector refreshes evidence operationally, but the evidence model still does not hard-code an RBVM freshness window. Freshness policy must remain explicit and must not silently rewrite historical `LISTED` or `NOT_LISTED` observations.

## Ransomware campaign field

The canonical evidence model preserves CISA's ransomware-campaign-use vocabulary semantically as:

```text
KNOWN
UNKNOWN
```

This `UNKNOWN` is listing metadata and is distinct from `KEV_Status = UNKNOWN`, which means the platform lacks usable KEV membership evidence.

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

## Current stage boundary

Implemented:

- independent `CisaKevCatalogSnapshot` provenance model;
- independent `CisaKevEvidence` threat-evidence model;
- `LISTED / NOT_LISTED / UNKNOWN` semantics;
- explicit distinction between missing evidence and negative catalog membership;
- SHA-256 and declared/parsed-count proof for a complete snapshot;
- official fixed-origin CISA JSON acquisition adapter and fail-closed validation;
- `CISA_KEV_CSV_V1` exchange contract and LISTED/NOT_LISTED mapping;
- PostgreSQL V11 snapshot/evidence history plus current and finding views;
- transactional tenant-scoped importer with replay and conflict quarantine;
- import/read HTTP API and independent operator UI;
- OpenAPI/release-contract alignment for the KEV endpoints;
- authenticated CSV-to-API safe handoff with no direct database path;
- scheduled daily acquisition/build/handoff workflow with atomic publication and bounded retention;
- tests proving incomplete snapshots cannot back `NOT_LISTED` and that no priority/risk/SLA/EPSS is derived.

Not implemented yet:

- an explicit RBVM freshness decision policy for KEV;
- EPSS independent evidence;
- asset/business context stages;
- RBVM decision logic.

See [`CISA_KEV_AUTOMATION.md`](CISA_KEV_AUTOMATION.md) for the scheduled trust boundary and operational workflow.
