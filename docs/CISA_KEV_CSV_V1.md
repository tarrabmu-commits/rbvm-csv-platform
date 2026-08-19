# CISA_KEV_CSV_V1

`CISA_KEV_CSV_V1` is the dedicated CVE-scoped exchange contract for CISA Known Exploited Vulnerabilities catalog membership evidence.

It is generated from a previously validated `CISA_KEV_VALIDATED_SNAPSHOT`. The contract does not replace Wazuh input and does not derive priority, risk score, EPSS, SLA, asset criticality, or business impact.

## Required headers

```text
CVE_ID
KEV_Status
KEV_Catalog_Version
KEV_Catalog_SHA256
KEV_Catalog_Count
KEV_Source
KEV_Observed_At
KEV_Date_Added
KEV_Due_Date
Known_Ransomware_Campaign_Use
```

## Status semantics

Rows may contain only:

```text
LISTED
NOT_LISTED
```

`UNKNOWN` is deliberately not a row value in this contract.

```text
no usable validated snapshot evidence
→ UNKNOWN
→ no CISA_KEV_CSV_V1 row is fabricated
```

A successful complete snapshot can produce an explicit membership result for every input CVE:

```text
present in validated snapshot
→ LISTED

absent from validated complete snapshot
→ NOT_LISTED
```

`NOT_LISTED` means only that the CVE was absent from the identified snapshot. It does not mean safe, not exploitable, or not exploited.

## Snapshot provenance

Every row carries the snapshot identity that makes positive or negative membership auditable:

```text
KEV_Catalog_Version
KEV_Catalog_SHA256
KEV_Catalog_Count
KEV_Source
KEV_Observed_At
```

`KEV_Catalog_SHA256` is the SHA-256 of the exact official CISA feed bytes observed by the source adapter. `KEV_Catalog_Count` is the count already validated against the parsed vulnerability array before the CSV is generated.

The current official source is pinned to:

```text
https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
```

## LISTED rows

A LISTED row requires all listing metadata:

```text
KEV_Date_Added
KEV_Due_Date
Known_Ransomware_Campaign_Use = KNOWN | UNKNOWN
```

The CISA due date is source evidence. It is not the organization's remediation SLA.

## NOT_LISTED rows

A NOT_LISTED row requires the same complete-snapshot provenance but listing-only fields must be blank:

```text
KEV_Date_Added = blank
KEV_Due_Date = blank
Known_Ransomware_Campaign_Use = blank
```

This prevents metadata that exists only for catalog entries from being attached to negative membership evidence.

## Generation from the official source adapter

The normal acquisition path is:

```text
CISA official JSON feed
        ↓
fetch-cisa-kev-snapshot.py
        ↓
CISA_KEV_VALIDATED_SNAPSHOT
        ↓
build-cisa-kev-csv.py + input CSV containing CVE_ID
        ↓
CISA_KEV_CSV_V1
```

Example:

```bash
python3 scripts/fetch-cisa-kev-snapshot.py data/cisa-kev-snapshot.json
python3 scripts/build-cisa-kev-csv.py \
  wazuh-vulnerabilities.csv \
  data/cisa-kev-snapshot.json \
  data/cisa-kev.csv \
  --report data/cisa-kev-build.json
```

The generator deduplicates input CVE identifiers and emits one deterministic row per unique CVE. It refuses incomplete, unvalidated, non-official-source, malformed, or internally inconsistent snapshot artifacts.

## Replay and conflict semantics

Within one CSV, evidence identity is:

```text
CVE_ID + KEV_Source + KEV_Observed_At
```

An exact repeated row is deduplicated. Different evidence with the same identity is quarantined as a same-time conflict.

Historical observations from another observation time remain separate evidence and can later be persisted independently.

## Current boundary

Implemented:

- official CISA source acquisition and complete-snapshot validation;
- `LISTED / NOT_LISTED / UNKNOWN` domain semantics;
- `CISA_KEV_CSV_V1` contract;
- strict UTF-8/RFC4180 parsing;
- snapshot provenance validation;
- LISTED/NOT_LISTED field rules;
- deterministic source-snapshot-to-CSV generator;
- exact replay deduplication and same-time conflict quarantine;
- tests proving no priority/risk/EPSS/SLA derivation.

Not implemented yet:

- PostgreSQL KEV snapshot/evidence history;
- transactional KEV importer;
- platform KEV API/UI;
- scheduled automatic KEV refresh;
- freshness policy;
- EPSS;
- RBVM decision logic.
