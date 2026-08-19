# CVSS v3.1 Scheduled Collection and Safe Handoff

This increment automates the already-established CVSS v3.1 Technical Severity evidence path without creating a second persistence path.

## Trust boundary

The scheduled workflow is deliberately:

```text
current Wazuh CSV (V1 or another CSV containing CVE_ID)
        |
        v
Official NVD CVSS v3.1 collector
        |
        v
CVSS_V31_CSV_V1
        |
        v
Authenticated HTTP handoff
        |
        v
Existing CVSS contract validation
        |
        v
Existing tenant/CVE resolution
        |
        v
Existing transactional PostgreSQL importer
        |
        v
Immutable CVSS history
```

There is no `NVD -> PostgreSQL` shortcut. The scheduler does not use JDBC, `psql`, or the legacy combined intelligence enrichment path.

## Components

### `scripts/import-cvss-v31.py`

This is a narrow API client for:

```text
POST /api/v1/cvss-v31-imports
```

It requires `RBVM_CVSS_API_KEY`, sends the generated CSV as `text/csv`, and verifies that a successful response identifies:

```text
contractId = CVSS_V31_CSV_V1
semantics  = CVE_SCOPED_CVSS_V31_BASE_EVIDENCE
```

Transport policy is fail-closed:

- loopback (`127.0.0.1`, `localhost`, `::1`) may use HTTP;
- any non-local API endpoint must use HTTPS;
- credentials embedded in the URL are rejected;
- the bearer key is never included in diagnostic output.

The handoff input must be a bounded, regular, non-symlink file. The default bound is 16 MiB and may be reduced or increased with `RBVM_CVSS_MAX_BYTES`.

### `scripts/scheduled-cvss-v31-refresh.sh`

The scheduled workflow:

1. validates configuration and acquires a non-blocking `flock`;
2. creates a private staging directory;
3. runs `collect-nvd-cvss-v31.py` against the configured CSV;
4. records SHA-256 for the generated contract;
5. passes that exact generated file to `import-cvss-v31.py`;
6. publishes the snapshot directory only after the HTTP importer completes successfully;
7. atomically moves the `latest` symlink to the newly published snapshot;
8. retains a bounded number of immutable snapshots.

A published snapshot contains:

```text
cvss-v31-YYYYMMDDTHHMMSSZ/
    evidence.csv
    evidence.csv.sha256
    collection.json
    import.json
```

`collection.json` records what the NVD collector observed. `import.json` records what the canonical platform accepted, replayed, or quarantined. These are intentionally separate provenance layers.

If the canonical importer reports quarantined rows, the scheduled command reports:

```text
cvss_v31_refresh=PARTIAL
```

but retains the completed snapshot and import ledger. Quarantine is therefore visible without pretending that already-inserted evidence was rolled back.

A collector failure, transport failure, authentication failure, invalid API response, or canonical importer failure prevents publication of the staging snapshot and prevents the `latest` pointer from moving.

## Scheduling

The repository includes:

```text
deploy/systemd/rbvm-cvss-v31-refresh.service
deploy/systemd/rbvm-cvss-v31-refresh.timer
deploy/cvss-v31-refresh.example
```

The supplied timer runs daily with a randomized delay of up to 30 minutes and `Persistent=true`. This is an operational default, not an RBVM scoring or SLA policy.

The service is hardened with a restrictive umask, `NoNewPrivileges`, `ProtectSystem=strict`, kernel/control-group protections, and restricted address families.

## Secrets

Two credentials are intentionally separate:

```text
NVD_API_KEY
```

is optional and is used only by the collector when calling NVD, while:

```text
RBVM_CVSS_API_KEY
```

is a platform OPERATOR credential used only for the canonical CVSS import endpoint.

They must not be reused as one another. The example environment file contains placeholders only; production values should come from protected configuration or secret management.

## Replay behavior

The scheduled workflow is safe to retry because the existing persistence identity remains:

```text
Tenant + CVE + CVSS Source + CVSS Observed At
```

A repeated identical observation is replayed instead of inserted twice. Conflicting same-source/same-time evidence is quarantined by the existing importer. Scheduling does not weaken either behavior.

## What this automation does not do

It does not derive or change:

- remediation priority;
- risk score;
- EPSS;
- CISA KEV status;
- asset criticality;
- business impact;
- SLA;
- cross-source CVSS precedence;
- RBVM decisions.

It only automates collection and safe delivery of CVSS v3.1 Base Technical Severity evidence through the canonical evidence boundary.
