# FIRST EPSS Official Source Adapter

This increment starts the independent EPSS exploitation-probability evidence path at the external acquisition boundary. It deliberately does **not** persist EPSS, expose an EPSS platform API, schedule refreshes, or convert EPSS into RBVM priority.

## Why the daily bulk feed is the primary acquisition source

FIRST publishes EPSS scores daily and provides both a lookup API and a complete daily CSV feed. FIRST's data guidance says the API is intended for one-CVE or small-batch lookups, while the daily CSV is the appropriate source for bulk workflows that keep local data in sync.

The platform therefore pins the current bulk source to:

```text
https://epss.empiricalsecurity.com/epss_scores-current.csv.gz
```

The public FIRST API remains useful for future focused lookup/reconstruction workflows, but this adapter does not generate thousands of per-CVE API requests for a Wazuh inventory.

## What EPSS means here

EPSS is preserved as independent CVE-scoped evidence:

```text
EPSS score       = estimated probability in [0,1] that the CVE will be exploited in the wild
                   in the next 30 days following score publication
EPSS percentile  = proportion of scored vulnerabilities with the same or a lower score
```

This stage does not reinterpret either value as organizational risk.

## Acquisition flow

```text
Current CSV containing CVE_ID
        |
        v
Official FIRST/Empirical Security daily EPSS .csv.gz
        |
        +-- fixed semantic source URL
        +-- HTTPS-only redirect target
        +-- bounded compressed response
        +-- bounded gzip decompression
        +-- strict UTF-8
        +-- model_version + score_date metadata
        +-- exact cve,epss,percentile header
        +-- canonical CVE validation
        +-- EPSS and percentile in [0,1]
        +-- duplicate-CVE rejection
        +-- SHA-256 over exact compressed source bytes
        |
        v
FIRST_EPSS_VALIDATED_SNAPSHOT
```

The entire downloaded feed is parsed and validated before requested CVEs are selected. This prevents a malformed row elsewhere in the source file from being silently ignored while the adapter claims a valid snapshot.

## Validated snapshot artifact

`scripts/fetch-first-epss-snapshot.py` writes:

```text
schemaVersion = 1
artifactType = FIRST_EPSS_VALIDATED_SNAPSHOT
source
resolvedSource
observedAt
sourceBytesSha256
compressedBytes
decompressedBytes
modelVersion
scoreDate
feedRowCount
inputRows
requestedCveCount
scoredCveCount
missingCveCount
completeParse
acquisitionMode
scores[]
missingCves[]
```

Each selected score contains only:

```text
cveId
epss
percentile
```

The adapter extracts `modelVersion` and `scoreDate` from the feed metadata rather than hard-coding an EPSS model generation. Model changes therefore remain explicit evidence instead of silently changing the meaning of historical values.

## Missing CVEs

Absence from the daily EPSS feed is **not** converted into an EPSS score of zero.

```text
CVE absent from validated EPSS feed
        != EPSS 0.0
        != no exploitation probability
        -> no EPSS score evidence for that CVE
        -> downstream state remains UNKNOWN
```

`missingCves[]` is an acquisition diagnostic only. The future `EPSS_CSV_V1` contract should emit rows only for CVEs with explicit score evidence.

## Provenance and time

Two time concepts remain separate:

```text
scoreDate   = date represented by the EPSS publication
observedAt  = when this platform successfully acquired and validated the bytes
```

The exact compressed source is bound with SHA-256. A future persistence layer should retain both score date and observation time so historical decisions can be reconstructed without pretending they are the same event.

## Offline replay

`--offline-input` is provided for deterministic tests and controlled replay. Local bytes go through the same gzip, metadata, CSV, CVE, score, percentile, and duplicate validation path. The semantic source remains the pinned official daily EPSS feed and the artifact records:

```text
acquisitionMode = OFFLINE_REPLAY
```

## Boundary

Implemented in this increment:

- official daily bulk EPSS acquisition;
- source-byte SHA-256 provenance;
- bounded gzip handling;
- feed metadata validation;
- CVE/score/percentile validation;
- duplicate rejection;
- source-limited extraction for current CVEs;
- explicit missing-evidence semantics;
- deterministic offline replay tests.

Not implemented yet:

- `EPSS_CSV_V1`;
- PostgreSQL EPSS history/current views;
- transactional EPSS importer;
- EPSS platform import/read API;
- EPSS operator UI;
- automatic scheduled handoff;
- freshness decision policy;
- thresholds;
- priority, risk score, SLA, or combination with CVSS/KEV.

The next increment should define `EPSS_CSV_V1` from this validated snapshot artifact, preserving `modelVersion`, `scoreDate`, `source`, `observedAt`, and source-byte SHA-256 as independent provenance.
