# CISA KEV Scheduled Collection and Safe Handoff

This increment automates the already-established CISA KEV threat-evidence path without creating a second persistence path.

## Trust boundary

The scheduled workflow is deliberately:

```text
current vulnerability CSV containing CVE_ID
        |
        v
Official CISA KEV JSON acquisition
        |
        v
Complete validated CISA snapshot
        |
        v
CISA_KEV_CSV_V1
        |
        v
Authenticated HTTP handoff
        |
        v
Existing KEV contract validation
        |
        v
Existing tenant/CVE resolution
        |
        v
Existing transactional PostgreSQL V11 importer
        |
        v
Immutable snapshot-bound KEV history
```

There is no `CISA -> PostgreSQL` shortcut. The scheduler does not use JDBC, `psql`, the legacy combined-intelligence path, or any RBVM scoring logic.

## Components

### `scripts/scheduled-cisa-kev-refresh.sh`

The workflow:

1. validates configuration and the current CVE-bearing input CSV;
2. acquires a non-blocking `flock` so overlapping refreshes do not run concurrently;
3. creates a private staging directory;
4. runs `fetch-cisa-kev-snapshot.py` against the pinned official CISA feed;
5. accepts only a complete validated snapshot and records a checksum of the canonical snapshot artifact;
6. derives `CISA_KEV_CSV_V1` for the CVEs in the configured input;
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

`catalog-snapshot.json` is the validated source artifact. Its embedded `sha256` binds the evidence semantics to the exact CISA source bytes. The adjacent checksum binds the locally published canonical artifact itself.

`build.json` records how the input CVEs were mapped to `LISTED` or `NOT_LISTED`. `import.json` records what the canonical platform inserted, replayed, or quarantined. These layers remain separate so acquisition provenance, evidence construction, and persistence outcome are auditable independently.

## Failure semantics

The workflow fails closed before publication if acquisition fails, the CISA catalog is incomplete, the evidence contract cannot be built, authentication fails, the API transport is unsafe, the API response is invalid, or the canonical importer fails.

A failed acquisition therefore cannot create `NOT_LISTED` evidence:

```text
failed / incomplete CISA acquisition
        != NOT_LISTED
        -> no published refresh
        -> no new usable KEV evidence
```

If the canonical importer completes but quarantines some rows, the refresh is published with the import ledger and the command reports:

```text
cisa_kev_refresh=PARTIAL
```

This preserves the evidence and makes quarantine visible without pretending that already-committed rows were rolled back.

## Scheduling

The repository includes:

```text
deploy/systemd/rbvm-cisa-kev-refresh.service
deploy/systemd/rbvm-cisa-kev-refresh.timer
deploy/cisa-kev-refresh.example
```

The supplied timer runs daily with a randomized delay of up to 30 minutes and `Persistent=true`. This is an operational refresh default, not a vulnerability-remediation SLA or an RBVM freshness decision threshold.

The service uses the existing hardened pattern with `NoNewPrivileges`, `ProtectSystem=strict`, kernel/control-group protections, restricted address families, a restrictive umask, and an explicit writable path for the default published refresh directory.

## Secrets and transport

`RBVM_KEV_API_KEY` is a dedicated platform OPERATOR credential used only for the canonical KEV import endpoint. CISA's public KEV feed itself does not require an API key.

The handoff client preserves the transport rule already established for canonical evidence import:

- loopback may use HTTP;
- non-local endpoints must use HTTPS;
- credentials in the URL are rejected;
- bearer-key material is not echoed in error output.

## Controlled offline replay

`RBVM_KEV_OFFLINE_INPUT` may be configured for deterministic testing or controlled replay. The local bytes still pass through the same CISA source validation logic, and downstream evidence continues to use the pinned official CISA feed as its semantic source. Normal production scheduling should leave this unset.

## What this automation does not do

It does not derive or change:

- CVSS;
- EPSS;
- asset criticality;
- internet exposure or reachability;
- business impact;
- remediation priority;
- risk score;
- organizational SLA;
- CISA due-date interpretation;
- `LISTED`/`NOT_LISTED` semantics.

It only automates collection and safe delivery of snapshot-bound CISA KEV threat evidence through the canonical evidence boundary.
