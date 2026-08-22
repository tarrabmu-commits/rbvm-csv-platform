# CISA KEV Scheduled Collection and Safe Handoff

This automation delivers independent CISA KEV threat evidence without creating a second persistence, risk, or priority path.

## Deployed trust boundary

The supplied systemd path derives the vulnerability scope from current canonical Cases rather than from a separately maintained vulnerability CSV:

```text
Canonical Cases API
        ↓
Unique current CVE set
        ↓
scheduled-canonical-source-refresh.sh kev
        ↓
Official CISA KEV JSON acquisition
        ↓
Complete validated CISA snapshot
        ↓
CISA_KEV_CSV_V1
        ↓
Authenticated / same-origin HTTP handoff
        ↓
Existing KEV contract validation
        ↓
Existing tenant/CVE resolution
        ↓
Transactional PostgreSQL KEV importer
        ↓
Immutable snapshot-bound KEV history
```

There is no `CISA -> PostgreSQL` shortcut. The scheduler does not use JDBC, `psql`, the legacy combined-intelligence path, or RBVM scoring logic.

`scripts/scheduled-cisa-kev-refresh.sh` remains the source-specific collection/handoff primitive and can accept an explicit CVE-bearing CSV for controlled manual use and tests. The supplied systemd service instead runs `scripts/scheduled-canonical-source-refresh.sh kev`, which first exports current CVEs from canonical Cases and supplies that generated scope as `RBVM_KEV_INPUT`.

## Canonical source wrapper

For deployed source-only scheduling, `scheduled-canonical-source-refresh.sh kev`:

1. reads current canonical Cases through the configured API;
2. exports a deterministic unique CVE set into private staging;
3. skips safely when there are no canonical CVEs;
4. invokes the source-specific KEV refresh with that generated scope;
5. preserves `PASS`, `PARTIAL`, or `SKIPPED` from the source workflow.

This prevents a stale external inventory file from defining KEV evidence for a different CVE set than the platform currently holds.

## Source-specific workflow

`scripts/scheduled-cisa-kev-refresh.sh`:

1. validates configuration and the supplied CVE scope;
2. acquires a non-blocking `flock` so overlapping source refreshes do not run concurrently;
3. creates a private staging directory;
4. runs `fetch-cisa-kev-snapshot.py` against the pinned official CISA feed;
5. accepts only a complete validated snapshot and records its checksum;
6. derives `CISA_KEV_CSV_V1` for the supplied CVEs;
7. records a checksum for the exact generated evidence CSV;
8. sends that exact CSV through `import-cisa-kev.py` to `POST /api/v1/cisa-kev-imports`;
9. publishes the refresh directory only after the canonical importer completes successfully;
10. atomically advances `latest` and retains a bounded number of immutable refresh directories.

A published refresh contains:

```text
cisa-kev-YYYYMMDDTHHMMSSZ/
    catalog-snapshot.json
    catalog-snapshot.json.sha256
    evidence.csv
    evidence.csv.sha256
    build.json
    import.json
```

`catalog-snapshot.json` is the validated source artifact. Its source digest binds the evidence semantics to the exact CISA snapshot. `build.json` records how in-scope CVEs were mapped to `LISTED` or `NOT_LISTED`; `import.json` records what the canonical platform inserted, replayed, or quarantined.

## KEV status semantics

`LISTED` is positive membership evidence in the validated complete CISA KEV snapshot.

`NOT_LISTED` is negative membership evidence only when the CVE was evaluated against that validated complete snapshot and was absent. It does not mean the vulnerability is safe or has never been exploited.

Failure to obtain or validate a complete catalog cannot produce `NOT_LISTED` evidence. In that condition no new usable KEV evidence is published:

```text
failed / incomplete CISA acquisition
        != NOT_LISTED
        → no published refresh
        → no new usable KEV evidence
```

At read time, absence of usable KEV evidence remains unknown rather than being fabricated as `NOT_LISTED`. Ambiguous current evidence also remains explicit rather than being silently collapsed.

## Failure semantics

The workflow fails closed before publication if acquisition fails, the CISA catalog is incomplete, evidence construction fails, authentication or transport validation fails, the API response is invalid, or the canonical importer fails.

If the canonical importer completes but quarantines some rows, the refresh is published with its immutable import ledger and reports:

```text
cisa_kev_refresh=PARTIAL
```

A concurrent source invocation may report `SKIPPED`; the canonical source wrapper preserves that state rather than relabeling it `PASS`.

## Scheduling

The repository includes:

```text
deploy/systemd/rbvm-cisa-kev-refresh.service
deploy/systemd/rbvm-cisa-kev-refresh.timer
deploy/cisa-kev-refresh.example
```

The supplied timer runs daily with a randomized delay of up to 30 minutes and `Persistent=true`. This is an operational refresh default, not a remediation SLA, priority rule, or Formula freshness threshold.

The KEV source-only timer conflicts with the umbrella `rbvm-intelligence-refresh.timer`; operators should enable either the umbrella schedule or the source-only schedules, not both. The service uses `NoNewPrivileges`, `ProtectSystem=strict`, kernel/control-group protections, restricted address families, a restrictive umask, and explicit per-user writable refresh paths.

A newly imported Wazuh dataset may be followed by an explicit canonical intelligence refresh rather than waiting for the next timer window. CISA availability remains independent from Wazuh import success.

## Secrets and transport

CISA's public KEV feed does not require an API key. In hardened deployments, `RBVM_INTELLIGENCE_API_KEY` may authenticate the canonical-CVE read and `RBVM_KEV_API_KEY` may override it for the KEV import endpoint. Trusted-local deployments may require no bearer token when `RBVM_AUTH_MODE=DISABLED`.

The handoff preserves the transport rules:

- loopback may use HTTP;
- non-local endpoints must use HTTPS;
- credentials embedded in URLs are rejected;
- bearer-key material is not echoed in error output.

## Controlled offline replay

`RBVM_KEV_OFFLINE_INPUT` may be configured for deterministic tests or controlled replay. The local bytes still pass through the same CISA source validation logic, and downstream evidence remains bound to the validated source snapshot. Normal production scheduling should leave this unset.

## Methodology boundary

This automation does not derive or change:

- CVSS;
- EPSS;
- asset criticality;
- reachability;
- business impact;
- remediation priority;
- risk score;
- organizational SLA;
- CISA due-date interpretation;
- Formula evaluation.

It only automates current-scope collection and safe delivery of snapshot-bound CISA KEV threat evidence through the canonical evidence boundary.