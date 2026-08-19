# CISA KEV PostgreSQL Persistence

`CISA_KEV_CSV_V1` is persisted without turning KEV into priority or risk logic.

## Storage grain

Two immutable histories are separated:

```text
rbvm.cisa_kev_catalog_snapshot
→ one validated catalog observation for one tenant/source/observed_at

rbvm.cisa_kev_evidence
→ one CVE membership conclusion within one persisted snapshot
```

The separation is intentional. A `NOT_LISTED` record is valid only because it has a foreign-key reference to the validated complete snapshot that established negative membership.

## Snapshot identity and replay boundary

A persisted snapshot carries:

```text
Catalog Version
Catalog SHA-256
Catalog Count
KEV Source
Observed At
Ingested At
```

At one tenant/source/observation timestamp only one snapshot may exist:

```text
UNIQUE (tenant_id, kev_source, observed_at)
```

The transactional importer compares the complete snapshot identity before persistence:

```text
same source + same observed_at + same version/hash/count
→ snapshot replay

same source + same observed_at + different version/hash/count
→ quarantine affected rows
→ no overwrite
```

The same exact catalog bytes may be observed again at a later time and remain a distinct historical observation. This preserves freshness evidence rather than collapsing all equal SHA-256 values into one row.

The importer also detects a contradictory file that assigns multiple snapshot identities to the same `KEV_Source + KEV_Observed_At`. Every affected row is quarantined so row order cannot become an implicit winner-selection policy.

## Membership history

A CVE may have one explicit result per snapshot:

```text
UNIQUE (tenant_id, vulnerability_id, snapshot_id)
```

Allowed stored statuses are only:

```text
LISTED
NOT_LISTED
```

`UNKNOWN` is never inserted into `rbvm.cisa_kev_evidence`. It means no usable persisted KEV membership evidence exists.

### LISTED

Requires all listing-only metadata:

```text
KEV_Date_Added
KEV_Due_Date
Known_Ransomware_Campaign_Use = KNOWN | UNKNOWN
```

### NOT_LISTED

Requires all listing-only metadata to be null. It remains bound to the same snapshot provenance through `snapshot_id`.

## Transactional importer

`PostgresCisaKevImporter` is the canonical persistence boundary for `CISA_KEV_CSV_V1`.

It requires PostgreSQL schema V11 or newer and runs at `SERIALIZABLE` isolation under a transaction-scoped advisory lock.

The import sequence is:

```text
CISA_KEV_CSV_V1
        ↓
contract validation
        ↓
in-file snapshot consistency check
        ↓
resolve tenant
        ↓
resolve CVE only if attached to a canonical finding in that tenant
        ↓
persist / replay / quarantine snapshot
        ↓
persist / replay / quarantine membership evidence
        ↓
catalog revision only when new membership evidence is inserted
        ↓
commit
```

A CVE not attached to a canonical finding in the selected tenant is quarantined as:

```text
CVE_NOT_FOUND_IN_TENANT
```

Snapshot conflicts are quarantined as either:

```text
CONFLICTING_KEV_SNAPSHOT_TIMESTAMP
CONFLICTING_PERSISTED_KEV_SNAPSHOT_TIMESTAMP
```

A persisted membership conflict for the same tenant/CVE/snapshot is quarantined as:

```text
CONFLICTING_PERSISTED_KEV_EVIDENCE
```

Exact snapshot and evidence replay is idempotent. Fatal database errors roll back the entire persistence transaction. Row-level evidence problems are quarantined without converting them into fabricated `UNKNOWN` or `NOT_LISTED` claims.

Snapshot and evidence UUIDs are deterministic tenant-scoped RFC 9562 version-8 UUIDs derived from canonical SHA-256 material. The semantic evidence digest remains independent of tenant identity; tenant scope is applied only when deriving the persistent UUID.

## Current view

`rbvm.current_cisa_kev_evidence` selects the newest observation independently per:

```text
tenant + CVE + KEV source
```

This avoids silently arbitrating between sources if the acquisition boundary ever expands. The current official adapter emits the pinned CISA JSON feed.

## Finding view

`rbvm.finding_cisa_kev_evidence` joins current KEV evidence to canonical findings through `tenant_id + vulnerability_id`.

No matching evidence is represented as:

```text
KEV_Status = UNKNOWN
KEV_Evidence_Observed = false
```

This is a read-model interpretation of missing evidence, not a fabricated database row.

## Deliberate exclusions

Persistence and import do not introduce or derive:

```text
Priority
Risk Score
EPSS
Asset Criticality
Business Impact
Organizational SLA
```

CISA `dueDate` remains source evidence only.

## Current boundary

Implemented:

- official CISA source acquisition and complete-snapshot validation;
- `CISA_KEV_CSV_V1` generation and contract validation;
- immutable PostgreSQL snapshot history;
- immutable CVE membership history;
- current and finding read views;
- transactional importer;
- tenant/CVE resolution;
- exact snapshot/evidence replay idempotency;
- in-file and persisted snapshot conflict quarantine;
- persisted membership conflict quarantine;
- catalog revision only on new membership evidence;
- rollback on fatal persistence failure.

Not implemented yet:

- platform KEV upload API;
- KEV evidence read API;
- KEV operator UI;
- scheduled automatic KEV refresh and safe handoff;
- freshness policy;
- EPSS;
- RBVM decision logic.

## Next increment

Expose this importer through the authenticated platform API and operator UI while preserving the same contract and persistence boundary. The API must not create a second path from the CISA feed directly into PostgreSQL.
