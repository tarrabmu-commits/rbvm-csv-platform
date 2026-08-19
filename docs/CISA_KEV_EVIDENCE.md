# CISA KEV Threat Evidence Foundation

This stage introduces **CISA Known Exploited Vulnerabilities (KEV)** as independent CVE-scoped threat evidence. It remains separate from CVSS Technical Severity, EPSS exploitation probability, asset context, remediation policy, and the legacy combined intelligence/priority model.

CISA describes the KEV catalog as the authoritative source of vulnerabilities known to have been exploited in the wild and recommends using it as an input to vulnerability-management prioritization. The platform therefore preserves KEV as evidence and does not reinterpret catalog membership as an RBVM score by itself.

## Question answered by this stage

```text
For this CVE, what did the successfully observed CISA KEV catalog snapshot say
about catalog membership, from which snapshot, and when was that snapshot observed?
```

It does **not** answer:

```text
What is the CVSS severity?
What is the exploitation probability?
How critical is the affected asset?
What should be remediated first?
What SLA applies?
```

Those are separate evidence or decision stages.

## Canonical status semantics

The canonical model uses three states:

```text
LISTED
NOT_LISTED
UNKNOWN
```

### `LISTED`

The CVE was present in a successfully observed complete CISA KEV catalog snapshot.

A listed observation carries snapshot provenance plus CISA listing metadata used by this stage:

```text
CVE_ID
KEV_Status = LISTED
KEV_Catalog_Version
KEV_Source
KEV_Observed_At
KEV_Date_Added
KEV_Due_Date
Known_Ransomware_Campaign_Use
```

The CISA due date is preserved as source evidence. It is **not** converted into the organization's remediation SLA by this stage.

### `NOT_LISTED`

The CVE was absent from a successfully observed **complete** CISA KEV catalog snapshot.

This is snapshot-bound negative membership evidence:

```text
CVE_ID
KEV_Status = NOT_LISTED
KEV_Catalog_Version
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

Listing-only fields such as `KEV_Date_Added`, `KEV_Due_Date`, and ransomware-campaign use are absent for `NOT_LISTED` evidence.

### `UNKNOWN`

No usable KEV catalog evidence is currently attached to the CVE.

Examples include:

- no KEV collection has been completed yet;
- the catalog could not be fetched or validated;
- no safe snapshot-bound membership determination is available.

`UNKNOWN` deliberately carries no fabricated catalog version, source time, listing metadata, or negative-membership claim.

A collector failure therefore remains an operational failure / missing evidence. It is **not** converted into `NOT_LISTED`.

## Provenance and freshness

For non-UNKNOWN evidence, the minimum provenance boundary is:

```text
KEV_Catalog_Version
KEV_Source
KEV_Observed_At
```

The intended official feed is the CISA KEV catalog JSON published from the CISA domain. The future collector must validate a complete catalog snapshot before it is permitted to produce `NOT_LISTED` evidence.

`KEV_Observed_At` records when the platform successfully observed the catalog evidence. It is separate from CISA `dateAdded` and from CVSS/EPSS observation timestamps.

This foundation does not hard-code a freshness window. Freshness policy must remain explicit and must not silently rewrite historical `LISTED` or `NOT_LISTED` observations.

## Ransomware campaign field

CISA exposes whether a KEV entry is known to be used in ransomware campaigns. The canonical evidence model preserves the source vocabulary semantically as:

```text
KNOWN
UNKNOWN
```

This field is listing metadata. `UNKNOWN` here means CISA has not asserted known ransomware-campaign use for that catalog entry; it is distinct from `KEV_Status = UNKNOWN`, which means the platform lacks usable KEV membership evidence.

## Domain model

`CisaKevEvidence` enforces the boundary with explicit constructors:

```text
CisaKevEvidence.unknown(...)
CisaKevEvidence.listed(...)
CisaKevEvidence.notListed(...)
```

The model enforces:

- valid CVE identity;
- HTTPS source provenance for observed catalog evidence;
- no provenance or listing metadata on `UNKNOWN`;
- full listing metadata for `LISTED`;
- no listing-only metadata on `NOT_LISTED`;
- no boolean `knownExploited=false` representation for negative membership;
- no priority, risk score, SLA, EPSS, or asset/business context derivation.

## Relationship to CVSS

The two stages answer different questions:

```text
CVSS v3.1 Base
→ How technically severe is this vulnerability?

CISA KEV
→ Is this CVE present in an observed catalog of vulnerabilities exploited in the wild?
```

They are stored and evaluated independently. This stage does not calculate:

```text
CVSS + KEV
CVSS × KEV
KEV bonus points
priority tier
risk score
```

Any later RBVM decision must consume these evidence dimensions explicitly rather than embedding an undocumented arithmetic rule here.

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

- independent `CisaKevEvidence` domain model;
- `LISTED / NOT_LISTED / UNKNOWN` semantics;
- explicit distinction between missing evidence and negative catalog membership;
- snapshot provenance fields for observed evidence;
- CISA listing metadata boundary;
- source ransomware-campaign-use semantics;
- tests proving no priority/risk/SLA/EPSS derivation.

Not implemented yet:

- `CISA_KEV_CSV_V1` exchange contract;
- complete-snapshot collector and validation;
- PostgreSQL KEV history/current views;
- transactional importer;
- API/UI;
- scheduling;
- freshness policy;
- EPSS;
- RBVM decision logic.

The next increment should define the separate KEV CSV contract in a way that allows `NOT_LISTED` only when it is bound to a validated complete catalog snapshot. It must not infer `NOT_LISTED` from an absent row in a partial or failed collection.
