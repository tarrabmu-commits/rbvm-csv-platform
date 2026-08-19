# Business / Mission Impact PostgreSQL Persistence

V15 persists `BUSINESS_IMPACT_CSV_V1` as immutable, source-reported qualitative consequence evidence. It does not assign numeric weights to impact levels and does not calculate organizational risk.

## Tables

`rbvm.business_impact_snapshot` stores one tenant-scoped source-artifact observation:

- semantic `impact_source`;
- exact source-artifact SHA-256;
- impact observation time;
- platform ingestion time.

`rbvm.business_impact_evidence` stores one impact dimension for an already-canonical asset and stated business service within one persisted source snapshot:

- canonical asset ID plus source identity evidence;
- observed and normalized business-service values;
- impact dimension;
- source-reported qualitative impact level;
- assessment/evidence method;
- source statement/rationale;
- evidence SHA-256 and ingestion time.

## Asset and service resolution

The importer never creates assets. Rows resolve through tenant + `Source_Profile_Key` + identity basis + canonical normalized Wazuh asset identity. `SOURCE_NAME_ONLY` resolves only through WAZUH_CSV_V1 profiles; `SOURCE_STABLE_ID` only through WAZUH_CSV_V2 profiles.

Business Service is normalized NFKC + trim + lowercase exactly as the CSV evidence identity. The observed display value is retained. V15 does not create or reconcile a global business-service master-data entity.

## Snapshot and replay semantics

`Impact_Source + Impact_Observed_At` identifies one impact source-artifact observation. The same source/time cannot name different source bytes.

Within a snapshot, evidence identity is:

`asset + normalized Business_Service + Impact_Dimension`

- conflicting source SHA values for the same source/time inside one file quarantine the whole group;
- exact persisted snapshot replay is reused;
- persisted source/time with different SHA is quarantined;
- exact dimension evidence replay is idempotent;
- different content for an already-persisted asset/service/dimension observation is quarantined, never overwritten;
- import is SERIALIZABLE under a dedicated advisory lock;
- catalog revision changes only when new Business Impact evidence is inserted.

## Current views

`rbvm.current_business_impact_evidence` selects latest evidence independently per tenant + asset + impact source + normalized business service + impact dimension.

There is deliberately no source arbitration, no aggregate impact score, and no conversion between Asset Context `Business_Criticality` and Business Impact `Impact_Level`.

`rbvm.finding_business_impact_evidence` joins current evidence to findings through asset ID. A finding can have zero or many impact rows. Missing impact evidence remains absent and is never fabricated as `LOW`, `NEGLIGIBLE`, or `UNKNOWN`.

## Decision boundary

V15 does not derive or persist:

- impact multiplier/weight or aggregate impact score;
- monetary loss amount or quantitative loss distribution;
- risk score, priority tier, remediation SLA, or treatment decision;
- CVSS, KEV, EPSS, Applicability, Reachability, or Asset Context combination logic;
- source precedence/winner selection;
- vulnerability-specific consequence inference.

The later RBVM methodology must remain an explicit, auditable layer above this evidence.
