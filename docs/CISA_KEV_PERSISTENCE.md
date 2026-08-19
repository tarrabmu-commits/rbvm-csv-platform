# CISA KEV PostgreSQL Persistence

This increment persists `CISA_KEV_CSV_V1` semantics without turning KEV into priority or risk logic.

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

The later transactional importer will use this constraint to implement exact replay versus same-time conflict handling. The schema does not overwrite an existing snapshot.

The same exact catalog bytes may be observed again at a later time and remain a distinct historical observation. This preserves freshness evidence rather than collapsing all equal SHA-256 values into one row.

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

This migration does not introduce or derive:

```text
Priority
Risk Score
EPSS
Asset Criticality
Business Impact
Organizational SLA
```

CISA `dueDate` remains source evidence only.

## Next increment

The next step is the transactional `CISA_KEV_CSV_V1` importer. It must:

1. require PostgreSQL schema V11 or newer;
2. resolve the selected tenant and CVEs already present in that tenant's canonical findings;
3. persist or replay the snapshot atomically;
4. quarantine same source/time snapshot conflicts;
5. insert immutable LISTED/NOT_LISTED evidence bound to that snapshot;
6. treat exact evidence replay as idempotent;
7. never create UNKNOWN rows;
8. increment catalog revision only when new persisted evidence is inserted;
9. roll back the entire persistence transaction on fatal database failure.
