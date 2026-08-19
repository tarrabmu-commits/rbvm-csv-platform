# Asset Context Evidence Contract

`ASSET_CONTEXT_CSV_V1` introduces explicit, asset-scoped organizational context evidence without turning that context into an RBVM decision.

## Semantics

- Contract ID: `ASSET_CONTEXT_CSV_V1`
- Semantics: `ASSET_SCOPED_ORGANIZATIONAL_CONTEXT_EVIDENCE`
- Grain: one explicit organizational-context observation for one canonical asset identity, context source, and observation time.
- Row absence means no usable asset-context evidence was supplied. It does not create default environment, owner, service, or criticality values.
- `UNKNOWN` is an explicit assessed value for dimensions whose source cannot determine a value.

## Columns

| Column | Meaning |
|---|---|
| `Source_Profile_Key` | External key of the Wazuh source profile whose canonical asset is being described. |
| `Asset_Identity_Basis` | `SOURCE_NAME_ONLY` for WAZUH_CSV_V1 identity or `SOURCE_STABLE_ID` for WAZUH_CSV_V2 identity. |
| `Asset_Name` | Observed asset name retained for evidence/audit and used as the V1 identity input. |
| `Asset_Source_ID` | Stable source asset ID. Must be blank for `SOURCE_NAME_ONLY` and non-blank for `SOURCE_STABLE_ID`. |
| `Environment` | `PRODUCTION`, `PRE_PRODUCTION`, `DEVELOPMENT`, `TEST`, `SANDBOX`, `DISASTER_RECOVERY`, or `UNKNOWN`. |
| `Business_Service` | Explicit business/application service label, or the literal `UNKNOWN` when assessed but unavailable. |
| `Business_Owner` | Explicit accountable owner label, or the literal `UNKNOWN` when assessed but unavailable. |
| `Business_Criticality` | `MISSION_CRITICAL`, `HIGH`, `MODERATE`, `LOW`, or `UNKNOWN`. This is qualitative evidence, not a weight. |
| `Context_Source` | Human-readable semantic source identifier for the organizational context. |
| `Context_Observed_At` | ISO-8601 timestamp for when this context source was observed. |
| `Context_Source_SHA256` | Lowercase SHA-256 of the exact source artifact represented by the observation. |

All headers are part of the contract. `Asset_Source_ID` is the only conditionally blank value; every other contract field is required.

## Canonical asset identity

The contract deliberately follows the platform's existing Wazuh identity semantics instead of inventing a parallel asset key:

- `SOURCE_NAME_ONLY`: identity input is `Asset_Name`;
- `SOURCE_STABLE_ID`: identity input is `Asset_Source_ID`;
- either identity input is normalized using Unicode NFKC, trim, and lowercase, matching the canonical Wazuh analyzer.

The later PostgreSQL importer must resolve the row to an already-canonical tenant asset through `Source_Profile_Key`, identity basis, and the corresponding normalized identity. An asset-context import must never create a new vulnerability-scanner asset simply because a context row did not resolve.

## Replay and conflict semantics

Within one file, the observation key is:

`Source_Profile_Key + Asset_Identity_Basis + normalized asset identity + Context_Source + Context_Observed_At`

- the same observation key with identical content is exact replay and is deduplicated;
- the same observation key with different context or provenance is conflicting evidence and is quarantined;
- later observations at a later `Context_Observed_At` remain independent evidence and are not mutations of earlier observations.

These same immutable-history rules are intended for V13 persistence.

## Deliberate boundary

`Business_Criticality` is not a numeric multiplier and `Environment` is not a risk coefficient. This contract does not contain or derive:

- risk score or priority tier;
- remediation SLA or treatment decision;
- CVSS/KEV/EPSS combination logic;
- network reachability, internet exposure, segmentation, or attack-path evidence;
- vulnerability applicability;
- business-impact loss estimates.

Reachability/exposure evidence and the eventual RBVM methodology remain separate later increments. Keeping them separate preserves provenance and prevents a qualitative asset label from silently becoming an organizational-risk formula.
