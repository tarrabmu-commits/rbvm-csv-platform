# Network Reachability Evidence Contract

`NETWORK_REACHABILITY_CSV_V1` introduces explicit, provenance-bound network reachability evidence without converting connectivity into an RBVM decision.

## Semantics

- Contract ID: `NETWORK_REACHABILITY_CSV_V1`
- Semantics: `ASSET_ENDPOINT_ORIGIN_SCOPED_NETWORK_REACHABILITY_EVIDENCE`
- Grain: one observation from one origin scope/label to one transport endpoint on one canonical asset, from one evidence source at one observation time.
- Row absence means no usable reachability evidence was supplied. It never means `NOT_REACHABLE`.
- `NOT_REACHABLE` is bounded to the recorded origin, endpoint, source, method, and observation time. It is not proof that the asset is globally isolated.
- `REACHABLE` from `INTERNET` is explicit Internet-origin reachability evidence for that endpoint. It is not by itself a complete organizational-risk decision.

## Columns

| Column | Meaning |
|---|---|
| `Source_Profile_Key` | External key of the Wazuh source profile whose canonical asset is being referenced. |
| `Asset_Identity_Basis` | `SOURCE_NAME_ONLY` for WAZUH_CSV_V1 identity or `SOURCE_STABLE_ID` for WAZUH_CSV_V2 identity. |
| `Asset_Name` | Observed asset name retained for audit and used as the V1 identity input. |
| `Asset_Source_ID` | Stable source asset ID. Blank for `SOURCE_NAME_ONLY`, required for `SOURCE_STABLE_ID`. |
| `Origin_Scope` | `INTERNET`, `EXTERNAL_PARTNER`, `INTERNAL_ENTERPRISE`, `LOCAL_SEGMENT`, `OTHER`, or `UNKNOWN`. |
| `Origin_Label` | Source-defined label that narrows the origin scope, such as a probe population, partner zone, or network segment. |
| `Transport_Protocol` | `TCP`, `UDP`, `ICMP`, `OTHER`, or `UNKNOWN`. |
| `Target_Port` | Port 1–65535. Required for TCP/UDP, forbidden for ICMP, optional for `OTHER`/`UNKNOWN`. |
| `Target_Service` | Source-observed endpoint/service label, or the literal `UNKNOWN` when assessed but unavailable. |
| `Reachability_Status` | `REACHABLE`, `NOT_REACHABLE`, or `UNKNOWN`. |
| `Reachability_Method` | `ACTIVE_PROBE`, `CONTROL_PLANE`, `FIREWALL_POLICY`, `CLOUD_CONFIGURATION`, `PASSIVE_OBSERVATION`, `OTHER`, or `UNKNOWN`. |
| `Evidence_Source` | Semantic identifier of the system/artifact that produced the observation. |
| `Evidence_Observed_At` | ISO-8601 timestamp for the observation. |
| `Evidence_Source_SHA256` | Lowercase SHA-256 of the exact source artifact represented by the evidence. |

Every header is part of the contract. `Asset_Source_ID` and `Target_Port` are the only conditionally blank fields.

## Canonical asset identity

The contract reuses the platform's existing Wazuh identity semantics:

- `SOURCE_NAME_ONLY`: identity input is `Asset_Name`;
- `SOURCE_STABLE_ID`: identity input is `Asset_Source_ID`;
- identity normalization uses Unicode NFKC, trim, and lowercase.

A later PostgreSQL importer must resolve reachability rows to already-canonical tenant assets and must not create scanner inventory from network evidence.

## Observation identity and replay

The in-file observation key is:

`Source_Profile_Key + Asset_Identity_Basis + normalized asset identity + Origin_Scope + normalized Origin_Label + Transport_Protocol + Target_Port + Evidence_Source + Evidence_Observed_At`

The endpoint label, reachability status, method, and source-artifact SHA are immutable content for that observation identity.

- exact same observation + content is replay and is deduplicated;
- conflicting content for the same observation identity is quarantined;
- a later `Evidence_Observed_At` is a new observation, not a mutation of history.

The later persistence layer should also treat same-source/same-observed-at artifact identity conflicts as source-snapshot conflicts, so file order cannot choose a winner.

## Deliberate boundary

This contract does not contain or derive:

- risk score, priority tier, remediation SLA, or treatment decision;
- Business Criticality or business/mission impact;
- CVSS, KEV, EPSS, or vulnerability-applicability combination logic;
- an asset-wide `internetExposed=true/false` conclusion detached from endpoint/origin evidence;
- attack-path probability or lateral-movement scoring;
- source precedence/arbitration between conflicting reachability systems.

Reachability becomes one independent evidence dimension. Business/Mission Impact and the eventual RBVM methodology remain separate later layers so the final decision can state exactly which evidence and policy produced it.
