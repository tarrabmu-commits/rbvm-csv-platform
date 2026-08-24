# Public Intelligence Sync Bundle V1

Contract: `PUBLIC_INTELLIGENCE_SYNC_BUNDLE_V1`

## Purpose

This contract is the source-adapter boundary between downloaded official public vulnerability intelligence and `LOCAL_PUBLIC_INTELLIGENCE_STORE_V1` (PostgreSQL V30).

It exists so network acquisition, source parsing, and database admission remain separate operations:

```text
Official source bytes
        ↓
Provider-specific validation / parsing
        ↓
PUBLIC_INTELLIGENCE_SYNC_BUNDLE_V1
        ↓
Full bundle validation
        ↓
V30 STAGING run
        ↓
bounded append / replay
        ↓
exact record-count verification
        ↓
COMPLETE
```

A bundle does not create tenant evidence, does not change customer context, and does not calculate RBVM priority, Formula results, Organizational Risk, Treatment, or SLA.

## Supported providers

The exact V30 provider identities are retained:

- `NVD`
- `FIRST_EPSS`
- `CISA_KEV`
- `CVE_PROGRAM`

The builder accepts only an explicit HTTPS source URI and records the SHA-256 of the exact source bytes. For an offline CVE Program directory fixture, the source SHA is a deterministic digest over relative JSON paths and their exact bytes.

## Bundle files

A bundle directory contains exactly the two contract files consumed by the importer:

```text
manifest.properties
records.tsv
```

`manifest.properties` contains:

```text
artifactType=PUBLIC_INTELLIGENCE_SYNC_BUNDLE
schemaVersion=1
provider=<provider>
syncMode=BOOTSTRAP|INCREMENTAL
sourceUri=<exact HTTPS source URI>
sourceVersion=<provider/source version>
sourceSha256=<exact source SHA-256>
sourcePublishedAt=<UTC instant or empty>
observedAt=<UTC instant>
startedAt=<UTC instant>
recordCount=<non-negative integer>
recordsSha256=<SHA-256 of records.tsv>
```

The importer rejects missing and unknown manifest properties. `records.tsv` is also SHA-bound before PostgreSQL is touched.

## Record format

`records.tsv` has the exact header:

```text
CVE_ID
Record_State
Source_Modified_At
Source_Published_At
Observed_At
Payload_Base64
```

The physical file uses tab delimiters and one record per CVE. Payload JSON is canonical compact JSON encoded as Base64 so provider JSON cannot alter the tabular framing.

Record states are the V30 states:

- `ACTIVE` — must carry provider JSON.
- `TOMBSTONE` — must carry no provider JSON.

The importer validates the entire bundle before opening a V30 run, then streams records in bounded batches. Duplicate CVEs, malformed timestamps, malformed Base64/UTF-8, invalid record state, hash mismatch, wrong record count, or malformed framing fail before source admission.

## Provider adapters

### NVD

The adapter consumes NVD JSON 2.0 payloads (`vulnerabilities[].cve`) and preserves the canonical NVD CVE object as source JSON. `id`, `published`, and `lastModified` are retained as source identity/timestamps.

NVD incremental data is a delta. A modified-feed bundle therefore must not generate tombstones merely because a CVE is absent from that delta.

### FIRST EPSS

The adapter consumes the official daily bulk CSV/GZip source. It preserves `cve`, `epss`, `percentile`, and the feed metadata (`model_version`, `score_date`) in provider JSON.

A complete daily EPSS snapshot may use an explicit prior-current CVE list to emit tombstones when a CVE is no longer represented. Missing EPSS is never converted to probability zero.

### CISA KEV

The adapter consumes the complete official KEV JSON catalog and requires the declared catalog count, when present as an integer, to equal the parsed vulnerability count. Each catalog entry is preserved as provider JSON.

A complete KEV snapshot may use an explicit prior-current CVE list to generate tombstones. A tombstone in this global mirror is only local source-state suppression; it is not automatically tenant `NOT_LISTED` evidence. Tenant KEV semantics still require the validated complete-catalog evidence contract.

### CVE Program

The adapter consumes CVE Record 5.x JSON from an extracted official source tree, release ZIP, or equivalent validated JSON input. The exact `cveMetadata.cveId`, `datePublished`, and `dateUpdated` fields are retained with the full record JSON.

A complete source snapshot may generate explicit tombstones against a prior-current list. Incremental/delta inputs must only tombstone when the source itself establishes deletion/withdrawal semantics.

## PostgreSQL admission semantics

`PublicIntelligenceSyncBundleImporter` performs two distinct phases:

1. validate the manifest, hashes, exact header, every record, duplicate-CVE invariant, and exact record count without modifying PostgreSQL;
2. call `PostgresPublicIntelligenceStore` to begin/replay the exact provider source, append in bounded batches, then complete only with exact record accounting.

If a newly-created run fails after STAGING is opened, the importer attempts the explicit V30 `FAILED` transition. The previous COMPLETE provider state remains current. Exact COMPLETE source replay does not duplicate provider data.

## Security and data-integrity boundaries

- source URI must use HTTPS;
- database credentials remain in `RBVM_DB_USER` / `RBVM_DB_PASSWORD`, never in a bundle;
- manifest and records must be regular non-symlink files;
- bundle text and decoded payloads must be valid UTF-8;
- one record line is bounded to prevent unbounded single-record payloads;
- no provider is combined with another provider during bundle generation or admission;
- local mirror refresh never mutates historical Decision Input, Formula, contextual-analysis, or MVP-priority artifacts.

## Follow-up layers

This contract closes the deterministic source-format-to-V30 admission boundary. The remaining Local Public Intelligence roadmap is:

1. hardened official network acquisition/bootstrap orchestration for all four providers;
2. incremental provider synchronization and persisted provider status;
3. background synchronization runtime plus `GET /api/v1/intelligence/status` and Operator `POST /api/v1/intelligence/sync`;
4. Intelligence Sources UI with **Update Intelligence Now**;
5. daily scheduling, stale-source policy, recovery, and observability;
6. CSV enrichment cutover to PostgreSQL `lookupCurrent(...)` rather than per-upload provider requests;
7. full scalability/capacity benchmark: 1K, 5K, 10K, 25K, 50K, 100K+ Findings plus progressive stress testing to the measured bottleneck. 10K is a regression checkpoint, not a platform limit.
