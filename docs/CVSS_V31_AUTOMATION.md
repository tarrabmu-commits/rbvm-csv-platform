# CVSS v3.1 Scheduled Collection and Safe Handoff

This automation delivers independent CVSS v3.1 Technical Severity evidence without creating a second persistence or scoring path.

## Deployed trust boundary

The deployed systemd path derives the vulnerability scope from the platform's current canonical Cases rather than from a separately maintained Wazuh CSV:

```text
Canonical Cases API
        ↓
Unique current CVE set
        ↓
scheduled-canonical-source-refresh.sh cvss
        ↓
Official NVD CVSS v3.1 collector
        ↓
CVSS_V31_CSV_V1
        ↓
Authenticated / same-origin HTTP handoff
        ↓
Existing CVSS contract validation
        ↓
Existing tenant/CVE resolution
        ↓
Transactional PostgreSQL CVSS importer
        ↓
Immutable CVSS evidence history
```

There is no `NVD -> PostgreSQL` shortcut. The scheduler does not use JDBC, `psql`, the legacy combined-intelligence enrichment path, or RBVM scoring logic.

`scripts/scheduled-cvss-v31-refresh.sh` remains the source-specific collector/handoff primitive and can still be given an explicit CVE-bearing CSV for controlled manual use or tests. The supplied systemd service does not pin such a file: it calls `scripts/scheduled-canonical-source-refresh.sh cvss`, which first exports current CVEs from canonical Cases and passes the generated scope to the source-specific script.

## Components

### `scripts/scheduled-canonical-source-refresh.sh cvss`

For deployed source-only scheduling, this wrapper:

1. reads current canonical Cases through the configured API;
2. exports a deterministic CSV containing the unique current CVE set;
3. skips safely when there are no canonical CVEs;
4. passes that generated scope as `RBVM_CVSS_INPUT` to the source-specific CVSS refresh;
5. preserves the source result as `PASS`, `PARTIAL`, or `SKIPPED` rather than converting a skipped source run into success.

### `scripts/scheduled-cvss-v31-refresh.sh`

The source-specific workflow:

1. validates configuration and acquires a non-blocking `flock`;
2. creates a private staging directory;
3. runs `collect-nvd-cvss-v31.py` against the supplied CVE scope;
4. records SHA-256 for the generated `CVSS_V31_CSV_V1` contract;
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

`collection.json` records what the NVD collector observed. `import.json` records what the canonical platform accepted, replayed, or quarantined. These are separate provenance layers.

If the canonical importer reports quarantined rows, the source-specific command reports `cvss_v31_refresh=PARTIAL`. Collector, transport, authentication, response-validation, or canonical-import failures prevent publication and leave the previous `latest` target unchanged.

## Scheduling

The repository includes:

```text
deploy/systemd/rbvm-cvss-v31-refresh.service
deploy/systemd/rbvm-cvss-v31-refresh.timer
deploy/cvss-v31-refresh.example
```

The supplied timer runs daily with a randomized delay of up to 30 minutes and `Persistent=true`. This is an operational refresh default, not an RBVM scoring, freshness, remediation, or SLA policy.

The source-only CVSS timer conflicts with the umbrella `rbvm-intelligence-refresh.timer`. Operators should enable either the umbrella schedule or the source-only schedules, not both. The service is hardened with a restrictive umask, `NoNewPrivileges`, `ProtectSystem=strict`, kernel/control-group protections, restricted address families, and explicit per-user writable refresh paths.

A newly imported Wazuh dataset does not have to wait for the next timer window: an operator may explicitly invoke the canonical intelligence refresh after the import. External-source failure remains independent from Wazuh import success.

## Secrets

`NVD_API_KEY` is optional and is sent only to NVD. `RBVM_CVSS_API_KEY` is a platform OPERATOR credential for the canonical CVSS import endpoint. In hardened deployments the canonical-CVE read may use `RBVM_INTELLIGENCE_API_KEY`; the source-specific key may override it for the CVSS handoff. Local trusted operation may require no bearer token when `RBVM_AUTH_MODE=DISABLED`.

Credentials must not be embedded in URLs or committed to repository configuration.

## Replay behavior

The source-specific workflow remains safe to retry because the existing persistence identity is unchanged:

```text
Tenant + CVE + CVSS Source + CVSS Observed At
```

A repeated identical observation is replayed rather than inserted twice. Conflicting same-source/same-time evidence is quarantined by the existing importer. Canonical Cases-driven scheduling does not weaken either rule.

## Methodology boundary

This automation does not derive or change:

- remediation priority;
- risk score;
- EPSS;
- CISA KEV status;
- asset criticality;
- reachability;
- business impact;
- SLA;
- cross-source CVSS precedence;
- Formula evaluation.

It only automates current-scope collection and safe delivery of CVSS v3.1 Base Technical Severity evidence through the canonical evidence boundary.