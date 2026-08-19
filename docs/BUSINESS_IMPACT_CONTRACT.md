# Business / Mission Impact Evidence Contract

`BUSINESS_IMPACT_CSV_V1` introduces provenance-bound qualitative consequence evidence for an asset's stated business service without turning impact classifications into an RBVM score.

## Semantics

- Contract ID: `BUSINESS_IMPACT_CSV_V1`
- Semantics: `ASSET_SERVICE_SCOPED_BUSINESS_MISSION_IMPACT_EVIDENCE`
- Grain: one impact dimension for one canonical asset + stated business service, from one impact source at one observation time.
- Row absence means no usable impact evidence was supplied. It never means `LOW`, `NEGLIGIBLE`, or `UNKNOWN`.
- `Impact_Level` is a source-reported qualitative classification. The platform does not assign it a numeric weight in this contract.
- Different impact sources remain independent evidence; this contract does not choose a winning BIA, policy register, or service-owner statement.

## Columns

| Column | Meaning |
|---|---|
| `Source_Profile_Key` | Wazuh source profile used to resolve the already-canonical asset. |
| `Asset_Identity_Basis` | `SOURCE_NAME_ONLY` for WAZUH_CSV_V1 identity or `SOURCE_STABLE_ID` for WAZUH_CSV_V2 identity. |
| `Asset_Name` | Observed asset name retained for audit and used as the V1 identity input. |
| `Asset_Source_ID` | Stable source asset ID. Blank for `SOURCE_NAME_ONLY`, required for `SOURCE_STABLE_ID`. |
| `Business_Service` | Source-stated service/business capability associated with the impact observation. |
| `Impact_Dimension` | `AVAILABILITY`, `INTEGRITY`, `CONFIDENTIALITY`, `SAFETY`, `FINANCIAL`, `REGULATORY`, `OPERATIONAL`, `REPUTATIONAL`, `MISSION`, `OTHER`, or `UNKNOWN`. |
| `Impact_Level` | Source-reported `SEVERE`, `HIGH`, `MODERATE`, `LOW`, `NEGLIGIBLE`, or `UNKNOWN`. |
| `Impact_Method` | `BUSINESS_IMPACT_ANALYSIS`, `SERVICE_OWNER_ATTESTATION`, `POLICY_CLASSIFICATION`, `INCIDENT_ANALYSIS`, `OTHER`, or `UNKNOWN`. |
| `Impact_Statement` | Human-readable source rationale/evidence statement for the qualitative classification. |
| `Impact_Source` | Semantic source identifier for the BIA/register/attestation/artifact. |
| `Impact_Observed_At` | ISO-8601 timestamp for the source observation. |
| `Impact_Source_SHA256` | Lowercase SHA-256 of the exact source artifact represented by the observation. |

All headers are part of the contract. `Asset_Source_ID` is the only conditionally blank field.

## Asset and service identity

Asset identity reuses the platform Wazuh semantics:

- `SOURCE_NAME_ONLY`: identity input is `Asset_Name`;
- `SOURCE_STABLE_ID`: identity input is `Asset_Source_ID`;
- NFKC + trim + lowercase normalization is used for canonical identity matching.

`Business_Service` is also normalized NFKC + trim + lowercase for evidence identity, while the observed display text is preserved. This does not create a global business-service master-data entity or silently reconcile different service taxonomies.

A later PostgreSQL importer must resolve to an existing canonical asset. It must not create scanner assets from BIA/business-impact data.

## Observation identity and replay

The in-file observation identity is:

`Source_Profile_Key + Asset_Identity_Basis + normalized asset identity + normalized Business_Service + Impact_Dimension + Impact_Source + Impact_Observed_At`

`Impact_Level`, `Impact_Method`, normalized statement content, and source-artifact SHA are immutable content for that observation identity.

- exact observation/content replay is deduplicated;
- conflicting content for the same observation identity is quarantined;
- later observation times are new evidence, not history mutation;
- a later persistence layer should quarantine a whole same-source/same-time group when source-artifact SHA conflicts, so row order cannot choose a winner.

## Relationship to Asset Context

Asset Context already carries source-reported `Business_Service`, owner, environment, and qualitative `Business_Criticality`. Business Impact is deliberately separate:

- Asset Context answers *what organizational context is associated with this asset?*
- Business Impact answers *what source-reported consequence is associated with this asset/service for a specific impact dimension?*

The platform does not automatically convert `MISSION_CRITICAL` Asset Context into `SEVERE` Mission Impact or vice versa. Any later reconciliation or methodology must be explicit and auditable.

## Deliberate boundary

This contract does not contain or derive:

- impact weight/multiplier or aggregate impact score;
- currency loss amount, annualized loss, or quantitative FAIR-style loss model;
- risk score, priority tier, remediation SLA, or treatment decision;
- CVSS, KEV, EPSS, Applicability, or Reachability combination logic;
- source precedence or winner selection;
- vulnerability-specific consequence inference.

Business/Mission Impact therefore becomes one more independent evidence dimension. The RBVM methodology remains a later explicit layer that can state exactly how technical, threat, reachability, asset, and impact evidence influence a decision.
