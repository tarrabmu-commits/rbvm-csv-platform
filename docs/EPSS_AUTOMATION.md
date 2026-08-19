# FIRST EPSS Scheduled Safe Refresh

This increment automates the independent EPSS evidence path without creating a second persistence route.

## End-to-end path

```text
Current inventory CSV with CVE_ID
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
PostgresEpssImporter / PostgreSQL V12
        ↓
atomic local refresh publication
```

The scheduler does not write PostgreSQL directly. The authenticated API remains the only runtime persistence boundary.

## Atomic publication

`scripts/scheduled-epss-refresh.sh` performs all work in a hidden staging directory under the configured output directory. It publishes an immutable `epss-YYYYMMDDTHHMMSSZ` directory and advances the `latest` symlink only after:

1. FIRST acquisition or controlled offline replay succeeds;
2. the complete bulk feed validates;
3. `EPSS_CSV_V1` construction succeeds;
4. checksums are written for the validated snapshot and canonical CSV;
5. the authenticated canonical API handoff returns a validated successful response.

A failed acquisition, build, or API import removes staging and leaves the previously published `latest` target unchanged.

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

with mode `0600`. Required values are:

```text
RBVM_EPSS_INPUT
RBVM_EPSS_API_KEY
```

Optional values include:

```text
RBVM_EPSS_OUTPUT_DIR
RBVM_EPSS_KEEP
RBVM_API_BASE_URL
RBVM_EPSS_MAX_BYTES
RBVM_EPSS_OFFLINE_INPUT
```

`RBVM_EPSS_OFFLINE_INPUT` exists for deterministic testing and controlled replay. Production operation should normally leave it unset so `fetch-first-epss-snapshot.py` acquires the pinned official FIRST daily feed.

## systemd user timer

Install or link:

```text
deploy/systemd/rbvm-epss-refresh.service
deploy/systemd/rbvm-epss-refresh.timer
```

into the user systemd directory, then enable the timer. The supplied schedule runs daily with a randomized delay of up to 30 minutes and is persistent across missed timer windows.

The service uses `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome=read-only`, a restricted address-family set, and a `0077` umask. The default writable path is limited to the EPSS refresh directory.

## Concurrency and failure semantics

A non-blocking `flock` prevents overlapping refreshes. A second invocation exits successfully with:

```text
epss_refresh=SKIPPED reason=already_running
```

A successful run emits a concise ledger line. If the API accepted rows but quarantined some persistence evidence, the local run is published because the canonical importer completed transactionally, but the scheduler reports `PARTIAL` rather than `PASS` so operators can investigate the immutable `import.json` ledger.

## Methodology boundary

Automation does not add:

- an EPSS threshold;
- priority or risk score;
- CVSS/KEV/EPSS combination logic;
- freshness-to-decision policy;
- asset criticality or reachability weighting;
- business impact;
- organizational SLA.

After this stage, EPSS evidence acquisition, contract construction, persistence, API/UI, safe handoff, and scheduling are complete. The next methodology foundation should move to asset context rather than introduce a scoring shortcut.
