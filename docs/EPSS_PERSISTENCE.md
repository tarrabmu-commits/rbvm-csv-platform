# EPSS PostgreSQL Persistence

This increment persists canonical `EPSS_CSV_V1` evidence without turning EPSS into an
RBVM score or organizational priority.

## Data model

EPSS provenance and CVE scores have different grains and are stored separately:

```text
rbvm.epss_score_snapshot
  tenant_id
  model_version
  score_date
  epss_source
  source_sha256
  observed_at
  ingested_at
        |
        | 1:N
        v
rbvm.epss_evidence
  tenant_id
  vulnerability_id
  snapshot_id
  epss_probability
  epss_percentile
  ingested_at
  evidence_sha256
```

A score row cannot exist without its persisted source snapshot. The snapshot preserves the
FIRST publication/model identity separately from the platform acquisition time.

## Missing evidence

A CVE missing from a validated FIRST feed is not persisted as a score row:

```text
missing CVE
  != EPSS 0
  != LOW
  != SAFE
  -> no rbvm.epss_evidence row
```

`rbvm.finding_epss_evidence` exposes this as `epss_evidence_observed=false` with NULL
probability and percentile. It does not fabricate an UNKNOWN evidence record.

## Current evidence semantics

`rbvm.current_epss_evidence` is current independently per tenant, CVE, and source. Ordering is:

```text
score_date DESC
observed_at DESC
potential ingestion tie-breakers
```

`score_date` intentionally precedes `observed_at`. A controlled offline replay may acquire an
older FIRST daily feed at a later wall-clock time; that replay must not silently replace a newer
published EPSS score.

## Transactional importer

`PostgresEpssImporter`:

1. validates the complete `EPSS_CSV_V1` file with the canonical analyzer;
2. opens a `SERIALIZABLE` transaction and takes an EPSS-specific advisory lock;
3. requires the initialized local tenant;
4. resolves CVEs only when attached to canonical findings in that tenant;
5. groups source rows by `EPSS_Source + EPSS_Observed_At`;
6. quarantines an entire group if one observation time carries contradictory model/date/source-byte identities;
7. inserts or exactly replays immutable score snapshots;
8. inserts or exactly replays immutable CVE score evidence;
9. quarantines persisted snapshot/evidence conflicts rather than overwriting history;
10. increments catalog revision only when new CVE score evidence is inserted;
11. commits atomically or rolls back the full transaction.

Snapshot and evidence IDs are deterministic tenant-scoped UUIDs derived from semantic SHA-256
identities. Exact replays therefore remain stable and do not create duplicate history.

## Runtime-role hardening

The persistence work also closes a pre-existing deployment-role gap: the runtime role now has
explicit `SELECT, INSERT` access to CISA KEV V11 tables/views as well as EPSS V12, while
`UPDATE`, `DELETE`, and `TRUNCATE` are explicitly revoked on immutable intelligence history.

## Boundary

This increment does **not** add:

- EPSS HTTP import/read endpoints;
- an EPSS operator page;
- automatic safe handoff or scheduling;
- freshness decision thresholds;
- EPSS-to-priority thresholds;
- CVSS/KEV/EPSS formulas;
- asset criticality or reachability weighting;
- business impact, risk score, or organizational SLA.

The next increment can expose the V12 importer and current-evidence view through authenticated
runtime API/UI without creating a direct FIRST-to-database path.
