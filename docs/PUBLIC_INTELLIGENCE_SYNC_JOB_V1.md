# Public Intelligence Sync Job V1

Contract: `PUBLIC_INTELLIGENCE_SYNC_JOB_V1`

## Purpose

V31 makes the end-to-end public-intelligence refresh lifecycle durable before V30 source admission begins.

V30 intentionally records one exact validated source payload. That means an HTTPS failure, provider metadata failure, archive validation failure, or bundle-construction failure can occur before a V30 `public_intelligence_sync_run` exists. V31 records those operational attempts without weakening V30 source identity semantics.

This lifecycle is global and non-tenant. It does not create customer evidence and does not calculate RBVM priority, Formula results, Organizational Risk, Treatment, SLA, reachability, business impact, or customer asset context.

## Lifecycle

Every provider job begins as:

```text
RUNNING / ACQUIRING
```

The only successful stage progression is:

```text
ACQUIRING
    ↓ exact source acquired and validated
BUILDING
    ↓ PUBLIC_INTELLIGENCE_SYNC_BUNDLE_V1 built and validated
ADMITTING
    ↓ exact V30 sync_run linked and reaches COMPLETE
COMPLETE
```

A running job may transition to `FAILED` from any non-terminal stage.

The PostgreSQL trigger rejects skipped/backward stages and makes terminal jobs immutable. A partial unique index permits at most one RUNNING job for a provider, preventing a scheduled/manual/startup collision from performing concurrent refreshes against the same provider.

## Source identity

When acquisition succeeds, the job records exactly:

- `source_uri`
- `source_version`
- `source_sha256`

Those fields are all-null before acquisition and all-present after acquisition. Once present they are immutable.

The job may link `sync_run_id` only after the V30 source run exists. The link is immutable once set. A V31 job can become `COMPLETE` only when its linked V30 run is itself `COMPLETE` for the same provider.

This creates an explicit chain:

```text
PUBLIC_INTELLIGENCE_SOURCE_ACQUISITION_V1
        ↓ exact URI/version/SHA
PUBLIC_INTELLIGENCE_SYNC_BUNDLE_V1
        ↓ exact provider source admission
LOCAL_PUBLIC_INTELLIGENCE_STORE_V1 / V30 sync_run
        ↓ exact sync_run_id
PUBLIC_INTELLIGENCE_SYNC_JOB_V1 / V31 terminal job
```

## Failure semantics

A failure during `ACQUIRING` may have no source identity and no V30 run. That is valid and is the main reason V31 exists.

A failure during `BUILDING` retains the acquired source identity but may have no V30 run.

A failure during `ADMITTING` may retain both source identity and a linked V30 run. A failed/staging V30 run is still excluded from current provider lookup by V30.

A new terminal failure never erases the last successful V30 provider state.

## Unified status

`rbvm.public_intelligence_provider_status_v1` always returns all four supported providers:

- `NVD`
- `FIRST_EPSS`
- `CISA_KEV`
- `CVE_PROGRAM`

For each provider it exposes two independent concepts:

1. the latest V31 end-to-end operational job, including acquisition failures;
2. the last successful V30 source run, including source version/SHA and record count.

This distinction is required. If today's refresh fails, operators must see that failure while the product can still identify yesterday's last successful local intelligence state.

## HTTP status API

`GET /api/v1/intelligence/status` is the read-only `PUBLIC_INTELLIGENCE_STATUS_HTTP_V1` transport.

It requires at least the `VIEWER` role when API-key authentication is enabled and returns a non-cacheable response with one status object per provider. Each provider object contains:

- `neverAttempted`
- `neverSucceeded`
- `latestJob`
- `lastSuccess`

The API is status-only. It does not trigger network synchronization.

## Remaining orchestration work

V31 provides durable lifecycle and read status, but it does not yet execute the complete provider refresh pipeline by itself. The next layers are:

1. background/manual orchestration that starts a V31 job, executes acquisition, bundle build and V30 admission, and advances/fails the job automatically;
2. Operator `POST /api/v1/intelligence/sync`;
3. Intelligence Sources UI with **Update Intelligence Now**;
4. daily scheduling, stale-source policy, recovery and observability;
5. CSV enrichment cutover to local PostgreSQL public-intelligence lookup;
6. capacity validation at 1K, 5K, 10K, 25K, 50K, 100K+ Findings and progressive stress testing until the measured bottleneck. 10K remains a regression checkpoint, not a platform limit.
