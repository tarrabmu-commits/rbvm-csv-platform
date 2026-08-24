# PUBLIC_INTELLIGENCE_AUTOMATION_V1

## Purpose

This layer automates the already-merged manual public-intelligence synchronization path without changing its V30/V31 semantics.

Automation is **disabled by default**. There is no hidden refresh cadence and no automatic NVD bootstrap unless an operator explicitly configures it.

Every automated source still follows the same path:

`V31 job -> acquisition -> bundle -> V30 admission -> V31 terminal state`

One V31 job continues to represent one exact acquired source payload. Automation never creates a synthetic compound source identity.

## Startup refresh

`RBVM_INTELLIGENCE_STARTUP_REFRESH_PROVIDERS` is an optional comma-separated provider list using exact provider names:

- `NVD`
- `FIRST_EPSS`
- `CISA_KEV`
- `CVE_PROGRAM`

When configured, each selected provider receives one startup refresh after the HTTP server has started. NVD startup refresh uses the exact `modified` feed. Complete-snapshot providers do not receive a synthetic feed identity.

## Resumable NVD bootstrap

`RBVM_INTELLIGENCE_NVD_BOOTSTRAP_ON_STARTUP=true` enables full NVD annual bootstrap sequencing.

The plan is exact and sequential:

`2002 -> 2003 -> ... -> current UTC year -> modified`

The bootstrap does not assume that all years are missing. Before it starts, PostgreSQL reads successful V30 NVD runs and recognizes only exact official annual source URIs:

`https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-YYYY.json.gz`

Only `COMPLETE` annual runs count as covered. Failed/staging annual runs do not count, and the `modified` source never counts as annual coverage.

Therefore a restart resumes from the first missing annual source instead of replaying already-complete years. If one annual job reaches V31 `FAILED`, the sequence stops immediately. It does not skip the failed year and it does not run the modified tail. A later startup derives coverage again from V30 and resumes from what is still missing.

If `NVD` also appears in `RBVM_INTELLIGENCE_STARTUP_REFRESH_PROVIDERS` while bootstrap-on-startup is enabled, the separate NVD startup refresh is suppressed because the bootstrap already ends with the exact modified feed.

## Scheduled refresh

Scheduled refresh is configured independently per provider. Omitting the variable or setting it to `0` disables scheduling for that provider:

- `RBVM_INTELLIGENCE_SCHEDULE_NVD_SECONDS`
- `RBVM_INTELLIGENCE_SCHEDULE_FIRST_EPSS_SECONDS`
- `RBVM_INTELLIGENCE_SCHEDULE_CISA_KEV_SECONDS`
- `RBVM_INTELLIGENCE_SCHEDULE_CVE_PROGRAM_SECONDS`

Configured intervals must be between 3600 seconds and 2678400 seconds (31 days). The platform intentionally does not choose a default cadence.

Schedules use **fixed delay**, not fixed rate. The delay starts again only after the previous automated refresh action returns, so slow source processing does not create an accumulating timer backlog.

NVD scheduled refresh always uses `modified`; annual feeds belong to the explicit bootstrap sequence only.

The persisted V31 one-running-job-per-provider constraint remains authoritative. If a manual or other automated job already owns a provider, an overlapping automated attempt is skipped rather than creating a second provider job.

## Runtime and shutdown

Automation requires the PostgreSQL V31 orchestration runtime. Supplying automation settings while PostgreSQL/orchestration is unavailable is a startup configuration error rather than a silent fallback.

The automation controller is constructed without source I/O. It starts only after the product HTTP server has started.

On graceful shutdown, the automation scheduler is stopped before the underlying source orchestrator. This prevents new timer work from being submitted while active source workers are being interrupted and terminalized.

## Hard-crash boundary

This version does not guess that an existing V31 `RUNNING` row is stale after a hard process crash. There is no lease/owner/heartbeat identity yet, so automatically failing such a row could incorrectly terminate work owned by another application node.

Hard-crash recovery therefore requires a future explicit ownership/lease contract. It must not be implemented as an age-based heuristic.

## Semantic boundaries

Automation does not:

- alter customer or tenant evidence
- infer applicability
- change frozen MVP Priority semantics
- calculate Formula/Risk or Organizational Risk
- derive Treatment or SLA
- convert NVD absence into tombstones
- combine multiple NVD annual files under one source/job identity

The next product layers remain the Intelligence Sources UI, CSV enrichment cutover to the local V30 public-intelligence store, and full 1K/5K/10K/25K/50K/100K+ capacity/stress testing. 10K remains a regression checkpoint rather than a platform ceiling.
