# PUBLIC_INTELLIGENCE_SYNC_ORCHESTRATOR_V1

## Purpose

This increment turns the already-merged local public-intelligence source admission contracts into an executable server-side synchronization path.

The product flow is:

`POST trigger -> V31 ACQUIRING -> official source acquisition -> V31 BUILDING -> PUBLIC_INTELLIGENCE_SYNC_BUNDLE_V1 -> V31 ADMITTING -> V30 source admission -> V31 COMPLETE/FAILED`

V30 remains the source-record authority. V31 remains the end-to-end operational lifecycle authority. The orchestrator coordinates the two; it does not redefine either contract.

## Manual API

`POST /api/v1/intelligence/sync/{provider}` requires the OPERATOR role.

Supported providers are `NVD`, `FIRST_EPSS`, `CISA_KEV`, and `CVE_PROGRAM`.

The request has no body. NVD accepts an optional `feed` query parameter:

- omitted or `modified`: exact NVD modified JSON 2.0 feed, admitted as `INCREMENTAL`
- a supported four-digit year: one exact annual NVD JSON 2.0 feed, admitted as `BOOTSTRAP`

`feed` is rejected for every non-NVD provider.

An accepted request returns HTTP 202 with the persisted V31 job identity and points `Location` to `GET /api/v1/intelligence/status`. The POST is asynchronous; 202 means the job was durably accepted, not that source acquisition or admission has completed.

Only one RUNNING V31 job may exist for a provider. A second request for that provider returns HTTP 409 rather than creating an overlapping acquisition.

## Source granularity

One V31 job represents one exact acquired source payload and one exact V30 source run. Multiple feeds must not be hidden behind one job identity.

This is especially important for NVD bootstrap. Annual feeds are separate source payloads, so a future full bootstrap scheduler must submit a sequence of exact annual-feed jobs rather than pretending that several year files are one source.

## Tombstone semantics

Absence has provider-specific meaning and is not generalized.

Complete-snapshot providers are:

- FIRST EPSS daily bulk snapshot
- CISA KEV complete catalog
- CVE Program repository snapshot

For these providers the coordinator reads the current local provider CVE set and supplies it to the bundle builder so explicit tombstones may be produced for records that disappeared from the new complete snapshot.

NVD annual and modified feeds are partial/source-scoped feeds. The coordinator always supplies an empty previous-CVE set for NVD. Missing CVEs in one NVD feed therefore never become tombstones merely because they were absent from that feed.

## Execution boundary

The Java coordinator owns lifecycle and persistence. The packaged Python source tools remain parsers/acquisition helpers only and receive no PostgreSQL credentials from the coordinator.

The subprocess pipeline:

- extracts fixed packaged helper resources into a per-job directory
- invokes the configured Python executable directly with `ProcessBuilder`; no shell is involved
- uses allowlisted provider/feed identities rather than arbitrary command fragments
- bounds combined process output
- enforces a hard helper timeout
- validates the acquisition directory and the generated bundle before V30 admission
- verifies that provider, source URI, source version, source SHA-256, and sync mode exactly match the acquired source
- removes the per-job workspace after a terminal outcome

Runtime settings:

- `RBVM_INTELLIGENCE_PYTHON` defaults to `python3`
- `RBVM_INTELLIGENCE_TOOL_TIMEOUT_SECONDS` defaults to 1800 and is bounded to 30..7200 seconds
- `RBVM_INTELLIGENCE_SYNC_WORKERS` defaults to 2 and is bounded to 1..4
- working state is created under `<RBVM_DATA_DIR>/public-intelligence-sync-work`

The runtime is available only when the PostgreSQL projection is enabled and schema V31 is installed.

## Failure behavior

A V31 job exists before acquisition starts. Therefore network/acquisition failure is durable even when no V30 source run was ever created.

The coordinator uses stable stage-oriented failure codes:

- `SOURCE_ACQUISITION_FAILED`
- `SOURCE_BUNDLE_BUILD_FAILED`
- `SOURCE_ADMISSION_FAILED`
- `SYNC_INTERRUPTED`
- `SYNC_EXECUTOR_REJECTED`

A failed refresh does not erase the previous successful V30 source state. `GET /api/v1/intelligence/status` reports the latest end-to-end job independently from the last successful V30 source run.

## Explicit non-goals

This layer does not:

- calculate or alter MVP Priority
- calculate Formula/Risk or Organizational Risk
- infer applicability
- create customer evidence
- derive Treatment or SLA
- merge provider payloads into a synthetic score
- treat NVD absence as negative evidence

The next layers remain scheduler/startup orchestration, Intelligence Sources UI, CSV enrichment cutover to the local V30 store, and full capacity testing at 1K/5K/10K/25K/50K/100K+ with progressive stress beyond the measured bottleneck. 10K remains a regression checkpoint, not a platform ceiling.
