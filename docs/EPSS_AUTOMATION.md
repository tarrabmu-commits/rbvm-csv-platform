# FIRST EPSS Scheduled Safe Refresh

This automation delivers independent FIRST EPSS probability evidence without creating a second persistence or scoring route.

## Deployed end-to-end path

The supplied systemd service derives its CVE scope from current canonical Cases:

```text
Canonical Cases API
        ↓
Unique current CVE set
        ↓
scheduled-canonical-source-refresh.sh epss
        ↓
Official FIRST daily bulk feed
        ↓
fetch-first-epss-snapshot.py
        ↓
FIRST_EPSS_VALIDATED_SNAPSHOT
        ↓
build-first-epss-csv.py
        ↓
EPSS_CSV_V1
        ↓
import-epss.py
        ↓
POST /api/v1/epss-imports
        ↓
PostgresEpssImporter / PostgreSQL evidence history
        ↓
atomic local refresh publication
```

The scheduler does not write PostgreSQL directly. The canonical API remains the runtime persistence boundary.

`scripts/scheduled-epss-refresh.sh` remains the source-specific primitive and can accept an explicit CVE-bearing CSV for controlled manual use and tests. The supplied systemd service instead runs `scripts/scheduled-canonical-source-refresh.sh epss`, which exports the current CVE set from canonical Cases and supplies that generated scope as `RBVM_EPSS_INPUT`.

## Canonical source wrapper

For deployed source-only scheduling, `scheduled-canonical-source-refresh.sh epss`:

1. reads the current canonical Cases API;
2. writes the unique current CVE set into a private staging file;
3. skips safely when there are no canonical CVEs;
4. invokes the existing EPSS source-specific workflow with that generated input;
5. preserves `PASS`, `PARTIAL`, or `SKIPPED` status from the source workflow.

This prevents a stale external inventory file from silently defining a different vulnerability scope than the platform itself.

## Atomic publication

`scripts/scheduled-epss-refresh.sh` performs source collection and handoff in a hidden staging directory. It publishes an immutable `epss-YYYYMMDDTHHMMSSZ` directory and advances `latest` only after:

1. FIRST acquisition or controlled offline replay succeeds;
2. the complete bulk feed validates;
3. `EPSS_CSV_V1` construction succeeds for the supplied canonical CVE scope;
4. checksums are written for the validated snapshot and canonical CSV;
5. the canonical API handoff returns a validated successful response.

A failed acquisition, build, or API import removes staging and leaves the previous `latest` target unchanged.

Each published directory contains:

```text
first-snapshot.json
first-snapshot.json.sha256
evidence.csv
evidence.csv.sha256
build.json
import.json
```

Retention runs only after successful publication. The default is 14 immutable refresh directories and the minimum configurable value is 2.

## Configuration

Copy:

```text
deploy/epss-refresh.example
```

to:

```text
~/.config/rbvm-platform/epss-refresh.env
```

with mode `0600`.

For the supplied source-only systemd service, the active scope configuration is API-based rather than a static `RBVM_EPSS_INPUT` path. Relevant values include:

```text
RBVM_API_BASE_URL
RBVM_INTELLIGENCE_WORK_DIR
RBVM_EPSS_OUTPUT_DIR
RBVM_EPSS_KEEP
RBVM_EPSS_MAX_BYTES
RBVM_EPSS_OFFLINE_INPUT
```

Authentication is optional in trusted-local mode and may use `RBVM_INTELLIGENCE_API_KEY` for the canonical-CVE read plus `RBVM_EPSS_API_KEY` as a source-specific handoff override in hardened deployments.

`RBVM_EPSS_OFFLINE_INPUT` exists for deterministic testing and controlled replay. Normal production operation should leave it unset so `fetch-first-epss-snapshot.py` acquires the pinned official FIRST daily feed.

## systemd user timer

The repository includes:

```text
deploy/systemd/rbvm-epss-refresh.service
deploy/systemd/rbvm-epss-refresh.timer
```

The supplied schedule runs daily with a randomized delay of up to 30 minutes and is persistent across missed timer windows. The EPSS source-only timer conflicts with `rbvm-intelligence-refresh.timer`; enable either the umbrella schedule or the source-only schedules, not both.

The service uses `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome=read-only`, restricted address families, a `0077` umask, and explicit per-user writable refresh paths.

A newly imported Wazuh dataset may be followed by an explicit canonical intelligence refresh rather than waiting for the next scheduled window. Failure of FIRST acquisition or EPSS import remains independent from Wazuh import success.

## Concurrency and failure semantics

A non-blocking `flock` prevents overlapping source refreshes. A second invocation exits successfully with:

```text
epss_refresh=SKIPPED reason=already_running
```

The canonical source wrapper preserves that `SKIPPED` state. If the API accepts rows while quarantining some persistence evidence, the immutable run is published and reported as `PARTIAL`, not `PASS`.

Missing EPSS for a CVE remains missing evidence. It is never converted to probability `0`.

## Methodology boundary

Automation does not add:

- an EPSS threshold;
- priority or risk score;
- CVSS/KEV/EPSS combination logic;
- freshness-to-decision policy;
- asset criticality or reachability weighting;
- business impact;
- organizational SLA;
- Formula evaluation.

It only automates current-scope FIRST EPSS acquisition, canonical contract construction, safe API handoff, and immutable evidence publication.