# Public Intelligence Source Acquisition V1

Contract: `PUBLIC_INTELLIGENCE_SOURCE_ACQUISITION_V1`

## Purpose

This layer acquires exact public-source bytes before `PUBLIC_INTELLIGENCE_SYNC_BUNDLE_V1` and PostgreSQL V30 admission.

```text
Official HTTPS source
        ↓
fixed provider endpoint / metadata
        ↓
size + transport + source-integrity checks
        ↓
PUBLIC_INTELLIGENCE_SOURCE_ACQUISITION_V1
        ↓
exact source SHA-256
        ↓
PUBLIC_INTELLIGENCE_SYNC_BUNDLE_V1
        ↓
V30 STAGING → COMPLETE
```

The acquisition artifact does not calculate CVSS, EPSS, KEV priority, MVP Pareto priority, Formula risk, Organizational Risk, Treatment, or SLA. It only establishes which official bytes were observed.

## Provider strategy

### NVD

NVD local mirroring follows the NVD traditional-feed guidance:

1. bootstrap from the compressed JSON 2.0 year feeds (`2002` through the current UTC year);
2. use the JSON 2.0 `modified` feed for subsequent incremental updates.

The fetcher always retrieves/validates the matching NVD `.meta` identity. It requires exact `gzSize`, exact uncompressed `size`, and exact uncompressed `sha256` before publishing an acquisition descriptor. `sourceSha256` separately binds the exact compressed bytes downloaded by RBVM.

A yearly feed is marked `BOOTSTRAP`; the `modified` feed is marked `INCREMENTAL`. Absence from the modified feed is never a tombstone.

### FIRST EPSS

FIRST EPSS uses the official daily bulk GZip CSV, not per-CVE HTTP calls. Acquisition validates a complete gzip stream and extracts the exact `model_version` and `score_date` needed for source versioning. The downstream bundle contract performs row-level score validation.

### CISA KEV

CISA KEV uses the official complete JSON catalog. Acquisition validates the root metadata, catalog version, release timestamp, positive declared count, and exact array-count equality before publication. Downstream source/bundle validation remains responsible for CVE-level contract checks.

### CVE Program

The CVE Program source is the official `CVEProject/cvelistV5` repository. V1 resolves the exact current `main` commit through the GitHub API and downloads an archive pinned to that 40-character commit SHA. The archive must contain CVE JSON records under `/cves/`.

This is the safe bootstrap source. Efficient CVE Program delta synchronization remains a later synchronization layer; V1 does not pretend that downloading a full archive is an efficient incremental strategy.

## Acquisition artifact

Each output directory contains:

```text
acquisition.json
source.<provider format>
```

`acquisition.json` includes:

- provider identity;
- source scope (`BOOTSTRAP` or `INCREMENTAL`);
- exact source URI;
- exact source version;
- source publication timestamp when available;
- RBVM observation timestamp;
- SHA-256 of exact downloaded source bytes;
- byte size;
- provider-specific integrity metadata where applicable.

`build-public-intelligence-bundle-from-acquisition.py` verifies that the source bytes still match `sourceSha256` and transfers the descriptor fields into `PUBLIC_INTELLIGENCE_SYNC_BUNDLE_V1`. Operators do not manually retype provenance fields.

## Transport hardening

- all remote endpoints are HTTPS;
- each provider has a final-host allowlist;
- source size is bounded even when `Content-Length` is absent;
- empty responses are rejected;
- gzip sources must fully decompress within a separate decompressed-size bound;
- NVD content is independently authenticated against its `.meta` SHA-256;
- CVE Program archives are pinned to an exact commit identity;
- `GITHUB_TOKEN`, when present, is used only for `api.github.com` commit resolution and is never sent to NVD, FIRST, CISA, `github.com` archive downloads, or `codeload.github.com`;
- offline fixtures must be regular non-symlink files;
- failed acquisition removes partial source/descriptor files rather than publishing an incomplete artifact.

## Current scope and next layer

This increment closes official HTTPS acquisition and exact acquisition-to-bundle provenance continuity. It intentionally does not yet turn the server into a background synchronization service.

Next layers remain:

1. provider synchronization orchestration and persisted provider/job status;
2. status/read and Operator sync HTTP APIs;
3. Intelligence Sources UI with **Update Intelligence Now**;
4. daily scheduling, stale-source policy, recovery, and observability;
5. CSV enrichment cutover to PostgreSQL local lookup;
6. full capacity/performance validation at 1K, 5K, 10K, 25K, 50K, 100K+ Findings plus progressive stress testing until the measured bottleneck. 10K is not a platform ceiling.
