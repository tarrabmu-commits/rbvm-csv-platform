# RBVM Customer Asset Bundle V1

Contract ID: `RBVM_CUSTOMER_ASSET_BUNDLE_V1`

## Purpose

The bundle is a reusable customer-owned organizational-context file. It exists so operators do not have to re-enter the same asset metadata for every CSV-first vulnerability run.

It deliberately contains only customer truth, not public vulnerability intelligence.

```text
CSV-first public enrichment
        ↓
Assets customer-context step
        ├── manual entry
        └── upload RBVM_CUSTOMER_ASSET_BUNDLE_V1
        ↓
Managed Asset create/revision writes
        ↓
Download RBVM_CUSTOMER_ASSET_BUNDLE_V1 for reuse
```

## Fields

Each exported asset may contain:

- `customerAssetKey`
- `displayName`
- `environment`
- `businessService`
- `businessOwner`
- `businessCriticality`
- `classificationMethod`
- `guideContractId` and `guideRevision` only for guided classification

The bundle does not contain CVSS, EPSS, KEV, SSVC, vulnerability risk results, SLAs, or remediation priority.

## Identity and matching

When a bundle is reused for a new CSV-first run, customer asset identity is matched by exact `customerAssetKey` first. Exact display-name matching is used only when the CSV candidate has no customer key. Ambiguous display-name matches fail closed; they are not silently resolved.

## User flow

1. Open **Imports**.
2. Choose the customer vulnerability CSV and select **Enrich CSV & continue to Assets**.
3. Public intelligence is collected only for the CVEs in that CSV.
4. RBVM opens **Assets** with asset identities extracted from the uploaded CSV.
5. Either upload a previously downloaded customer-data bundle or complete the customer fields manually.
6. Select **Save customer data**.
7. Select **Download customer data** to retain the current reusable bundle for the next run.
8. The enriched vulnerability CSV remains separately downloadable from the Assets step.

Customer-only fields are never inferred from CVSS, EPSS, KEV, or public CVE metadata.
