# CSV-First MVP Customer Context V1

Contract IDs:

- UI: `CSV_FIRST_CUSTOMER_ASSET_SETUP_UI_V2`
- Reusable customer file: `RBVM_CUSTOMER_ASSET_BUNDLE_V2`

## Current product scope

The current MVP does not require a per-customer database to define a run. One uploaded vulnerability CSV defines the run scope.

```text
Customer vulnerability CSV
        ↓
Public enrichment
(CVSS v4 / EPSS / KEV / CISA SSVC / CWE / CPE / provenance)
        ↓
Assets page
        ↓
Customer supplies only:
- Asset Criticality
- Internet Facing? Yes / No
        ↓
Save current run context
        ↓
Download RBVM_CUSTOMER_ASSET_BUNDLE_V2
```

On a later CSV, the customer may upload the previously downloaded bundle. Matching uses `customerAssetKey` first and a unique normalized display name only when no key is available.

## Bundle schema

```json
{
  "contractId": "RBVM_CUSTOMER_ASSET_BUNDLE_V2",
  "schemaVersion": 2,
  "semantics": "CUSTOMER_DECLARED_MVP_ASSET_CONTEXT",
  "assets": [
    {
      "customerAssetKey": "001",
      "displayName": "web-01",
      "assetCriticality": "HIGH",
      "internetFacing": "YES"
    }
  ]
}
```

`assetCriticality` values are `MISSION_CRITICAL`, `HIGH`, `MODERATE`, or `LOW` after save. `UNKNOWN` is allowed only before the customer completes the form.

`internetFacing` is `YES` or `NO` after save. `UNKNOWN` is allowed only before the customer completes the form.

## Important semantic boundary

`internetFacing` is a customer-declared asset-level current-state input for this MVP. It is **not** silently converted into `NETWORK_REACHABILITY_CSV_V1` evidence.

The existing network-reachability contract is endpoint/origin scoped. It can establish facts such as `REACHABLE` from `INTERNET` for a specific transport endpoint, but it explicitly does not define an asset-wide Internet-exposed boolean. The MVP customer declaration therefore remains a separate input until a later methodology explicitly defines how it is consumed.

## Deliberately not requested in the MVP UI

The current customer step does not require:

- Business Owner
- Business Service
- Environment
- Classification Method
- CR / IR / AR
- detailed endpoint reachability
- financial or mission-impact dimensions

Those existing platform capabilities are retained for future methodology/customer-database work; they are not required for the current CSV-first demo path.

## Legacy bundle compatibility

`RBVM_CUSTOMER_ASSET_BUNDLE_V1` may be uploaded. Its prior `businessCriticality` value is carried forward as `assetCriticality`. Because V1 did not contain the MVP Internet-facing declaration, `internetFacing` remains `UNKNOWN` and must be completed before saving V2.

## Persistence boundary

For the current MVP, `Save customer data` validates and binds the two customer inputs to the current in-memory CSV-first run. Long-term browser storage is not used. The portable persistence mechanism is the downloadable `RBVM_CUSTOMER_ASSET_BUNDLE_V2` file. A future tenant database can persist the same semantic contract without changing the public-intelligence acquisition path.
