# Asset Context PostgreSQL Persistence

V13 persists `ASSET_CONTEXT_CSV_V1` as immutable organizational-context evidence without turning that context into a risk decision.

## Tables

`rbvm.asset_context_snapshot` stores one tenant-scoped source-artifact observation:

- semantic `context_source`;
- exact source-artifact SHA-256;
- source observation time;
- platform ingestion time.

`rbvm.asset_context_evidence` stores one context row for an already-canonical asset and one persisted snapshot:

- canonical `asset_id`;
- identity basis and source identity evidence;
- observed asset name;
- environment;
- business service;
- business owner;
- qualitative business criticality;
- evidence SHA-256 and ingestion time.

Both tables are append-only for the runtime role. Exact replay is recognized by the importer rather than implemented as mutation.

## Asset resolution

The importer never creates assets. Every accepted contract row must resolve to an existing tenant asset through:

1. `Source_Profile_Key`;
2. identity basis matching the source profile contract;
3. the existing canonical normalized asset identity.

`SOURCE_NAME_ONLY` is valid only for WAZUH_CSV_V1 profiles. `SOURCE_STABLE_ID` is valid only for WAZUH_CSV_V2 profiles. An unresolved row is quarantined as `ASSET_NOT_FOUND_IN_TENANT`.

This prevents CMDB/business-context data from inventing scanner inventory or silently merging assets across source profiles.

## Snapshot and conflict semantics

`Context_Source + Context_Observed_At` identifies one source-artifact observation within a tenant. The same observation time cannot name different source bytes.

- exact persisted snapshot replay is reused;
- a different SHA-256 for the same source/time is a snapshot conflict;
- if the input file itself contains multiple SHA-256 values for the same source/time, the whole conflicting group is quarantined rather than allowing row order to choose a winner;
- an asset may have at most one evidence row per persisted snapshot;
- exact evidence replay is idempotent;
- conflicting persisted asset evidence is quarantined and never overwritten.

The import transaction is `SERIALIZABLE` and takes a dedicated transaction advisory lock. Catalog revision changes only when new asset-context evidence is inserted.

## Current views

`rbvm.current_asset_context_evidence` selects the latest observation independently for each tenant + asset + context source.

There is intentionally **no cross-source arbitration**. If two context systems publish different values, both remain visible as independent current evidence streams until a later explicit source-policy methodology is selected.

`rbvm.finding_asset_context_evidence` joins current context to canonical findings through `asset_id`. A finding may therefore have multiple rows when multiple context sources exist. Missing context remains absence of evidence with `asset_context_observed=false`.

## Decision boundary

V13 does not calculate or persist:

- numeric asset criticality weights;
- risk score or priority tier;
- SLA/treatment policy;
- network reachability, internet exposure, segmentation, or attack paths;
- CVSS, KEV, or EPSS combinations;
- monetary/business-loss impact.

Those remain later, separately versioned evidence or decision layers.
