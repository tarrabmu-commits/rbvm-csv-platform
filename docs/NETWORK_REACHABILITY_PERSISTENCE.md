# Network Reachability PostgreSQL Persistence

V14 persists `NETWORK_REACHABILITY_CSV_V1` as immutable, origin- and endpoint-scoped technical connectivity evidence. It does not convert reachability into an RBVM score or an asset-wide exposure verdict.

## Tables

`rbvm.network_reachability_snapshot` stores one tenant-scoped source-artifact observation:

- semantic `evidence_source`;
- exact source-artifact SHA-256;
- evidence observation time;
- platform ingestion time.

`rbvm.network_reachability_evidence` stores one scoped endpoint observation for an already-canonical asset and one persisted source snapshot:

- canonical `asset_id` and source identity evidence;
- origin scope and source-defined origin label;
- transport protocol, optional/required target port according to the contract, and target service label;
- `REACHABLE`, `NOT_REACHABLE`, or `UNKNOWN` status;
- observation method;
- evidence SHA-256 and ingestion time.

The runtime role receives append-only access to both history tables.

## Asset resolution

The importer never creates assets. Every accepted row must resolve through:

1. tenant;
2. `Source_Profile_Key`;
3. identity basis matching the Wazuh source-profile contract;
4. the existing canonical normalized asset identity.

`SOURCE_NAME_ONLY` resolves only through WAZUH_CSV_V1 profiles. `SOURCE_STABLE_ID` resolves only through WAZUH_CSV_V2 profiles. An unresolved row is quarantined as `ASSET_NOT_FOUND_IN_TENANT`.

## Snapshot, endpoint, and replay semantics

`Evidence_Source + Evidence_Observed_At` identifies one source-artifact observation in a tenant. The same source/time cannot name different source bytes.

The importer stores `Origin_Label` in the same NFKC + lowercase identity form used by the CSV observation key, so casing or Unicode presentation changes do not fork endpoint streams.

Within a persisted snapshot, endpoint identity is:

`asset + Origin_Scope + Origin_Label + Transport_Protocol + Target_Port`

PostgreSQL 14 does not support `NULLS NOT DISTINCT` on unique constraints. V14 therefore uses `COALESCE(Target_Port, 0)` only inside the unique index; port 0 is forbidden by the table check and has no evidence semantic.

- exact persisted snapshot replay is reused;
- different source SHA for the same source/time is a snapshot conflict;
- conflicting SHA values inside one file for the same source/time quarantine the whole group;
- exact endpoint evidence replay is idempotent;
- different content for an already-persisted endpoint observation is quarantined rather than overwritten;
- import is `SERIALIZABLE` under a dedicated transaction advisory lock;
- catalog revision changes only when new reachability evidence is inserted.

## Current views

`rbvm.current_network_reachability_evidence` selects latest evidence independently per tenant + asset + evidence source + origin scope/label + protocol + endpoint.

There is deliberately no source arbitration and no derived asset-wide `internet_exposed` field. `INTERNET + REACHABLE` remains a scoped positive observation. `NOT_REACHABLE` remains a scoped negative observation. Neither is broadened beyond its source/origin/endpoint/time.

`rbvm.finding_network_reachability_evidence` joins current evidence to canonical findings through `asset_id`. A finding can therefore have zero or many reachability rows. Missing evidence remains NULL with `network_reachability_observed=false`; it is never converted to `NOT_REACHABLE`.

## Decision boundary

V14 does not derive or persist:

- risk score, priority tier, remediation SLA, or treatment decision;
- Business Criticality or business/mission impact;
- CVSS, KEV, EPSS, or applicability combinations;
- attack-path probability or lateral-movement score;
- source precedence;
- an asset-wide Internet-exposure boolean detached from endpoint evidence.

Those remain later evidence or methodology layers.
