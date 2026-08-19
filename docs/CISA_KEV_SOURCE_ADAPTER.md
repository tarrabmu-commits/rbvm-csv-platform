# CISA KEV Official Source Adapter

This increment deliberately establishes the **external acquisition boundary before the KEV CSV/persistence work**.

CISA publishes the Known Exploited Vulnerabilities catalog as a public JSON feed. The platform consumes only the fixed official HTTPS endpoint:

```text
https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
```

No API key is required for this CISA feed.

## Why this comes before the KEV CSV contract

The downstream contract must be based on evidence that the acquisition layer can actually prove. In particular, `NOT_LISTED` is safe only after the platform has validated a complete catalog snapshot. Defining source acquisition first makes that proof concrete rather than theoretical.

```text
Official CISA JSON
        |
        v
Source adapter
        |
        +-- HTTPS-only fixed origin
        +-- bounded response size
        +-- UTF-8 JSON parse
        +-- root metadata validation
        +-- declared count validation
        +-- unique valid CVE identifiers
        +-- listing metadata validation
        +-- SHA-256 over exact source bytes
        |
        v
CISA_KEV_VALIDATED_SNAPSHOT
        |
        v
future CISA_KEV_CSV_V1
```

## Validated snapshot artifact

`scripts/fetch-cisa-kev-snapshot.py` writes an internal acquisition artifact containing:

```text
artifactType = CISA_KEV_VALIDATED_SNAPSHOT
source
observedAt
sha256
title
catalogVersion
dateReleased
declaredCount
parsedCount
complete
vulnerabilities[]
```

Each canonical vulnerability entry currently preserves only the KEV fields required by the threat-evidence model:

```text
cveId
dateAdded
dueDate
knownRansomwareCampaignUse = KNOWN | UNKNOWN
```

The exact source bytes are bound by SHA-256. The snapshot is accepted only when the declared catalog count is positive and equals the parsed vulnerability-array length, and every CVE identifier is unique and valid.

## Failure semantics

A network error, non-200 response, oversized response, invalid JSON, invalid catalog metadata, count mismatch, duplicate CVE, invalid date, or unsupported ransomware-campaign value causes the acquisition to fail closed.

The adapter does **not** produce a partial snapshot and does not convert any acquisition failure into `NOT_LISTED` evidence.

```text
failed / incomplete acquisition
        != NOT_LISTED
        -> no usable KEV snapshot
        -> downstream state remains UNKNOWN
```

## Offline input

`--offline-input` exists for deterministic testing and controlled replay. It parses local bytes through the same validation logic while preserving the official CISA feed URL as the semantic source. The emitted artifact records `acquisitionMode` so an operator can distinguish online acquisition from offline replay.

Example:

```bash
python3 scripts/fetch-cisa-kev-snapshot.py \
  data/cisa-kev-snapshot.json
```

Deterministic replay/testing:

```bash
python3 scripts/fetch-cisa-kev-snapshot.py \
  data/cisa-kev-snapshot.json \
  --offline-input testdata/known_exploited_vulnerabilities.json \
  --observed-at 2026-08-19T10:00:00Z
```

## Boundary

This adapter performs acquisition and source validation only. It does not yet:

- emit `CISA_KEV_CSV_V1`;
- persist KEV evidence;
- expose KEV through the platform HTTP API/UI;
- schedule refreshes;
- calculate priority, risk, or SLA;
- combine KEV with CVSS or EPSS.

The next KEV increment should derive the dedicated exchange contract from this validated snapshot artifact, so every explicit `LISTED` or `NOT_LISTED` row carries the same snapshot identity and provenance.
