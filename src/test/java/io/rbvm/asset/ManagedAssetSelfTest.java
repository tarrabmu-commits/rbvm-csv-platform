package io.rbvm.asset;

import io.rbvm.asset.ManagedAsset.ClassificationMethod;
import io.rbvm.asset.ManagedAsset.LifecycleStatus;
import io.rbvm.asset.ManagedAsset.Revision;
import io.rbvm.asset.ManagedAsset.RevisionDraft;
import io.rbvm.csv.AssetClassificationGuideV1;
import io.rbvm.csv.AssetContextCsvEvidence.BusinessCriticality;
import io.rbvm.csv.AssetContextCsvEvidence.Environment;

import java.time.Instant;
import java.util.UUID;

public final class ManagedAssetSelfTest {
    private ManagedAssetSelfTest() {
    }

    public static void main(String[] args) {
        acceptsCustomerDirectUnknownContext();
        guidedClassificationRequiresVersionedGuide();
        comparesCustomerStateWithoutAuditMetadata();
        preservesStableAssetIdentityAcrossRevisions();
        System.out.println("ManagedAssetSelfTest: PASS");
    }

    private static void acceptsCustomerDirectUnknownContext() {
        RevisionDraft draft = new RevisionDraft(
                LifecycleStatus.ACTIVE,
                "new-customer-asset",
                Environment.UNKNOWN,
                "UNKNOWN",
                "UNKNOWN",
                BusinessCriticality.UNKNOWN,
                ClassificationMethod.CUSTOMER_DIRECT,
                null,
                null,
                "customer@example.test",
                "initial creation"
        );
        assert draft.environment() == Environment.UNKNOWN;
        assert draft.businessCriticality() == BusinessCriticality.UNKNOWN;
        assert draft.guideContractId() == null;
    }

    private static void guidedClassificationRequiresVersionedGuide() {
        RevisionDraft guided = new RevisionDraft(
                LifecycleStatus.ACTIVE,
                "payments-prod-01",
                Environment.PRODUCTION,
                "Payments",
                "Payments Operations",
                BusinessCriticality.HIGH,
                ClassificationMethod.GUIDED,
                AssetClassificationGuideV1.CONTRACT_ID,
                AssetClassificationGuideV1.REVISION,
                "customer@example.test",
                "classified with guide"
        );
        assert guided.guideRevision() == 1;

        boolean rejected = false;
        try {
            new RevisionDraft(
                    LifecycleStatus.ACTIVE,
                    "payments-prod-01",
                    Environment.PRODUCTION,
                    "Payments",
                    "Payments Operations",
                    BusinessCriticality.HIGH,
                    ClassificationMethod.GUIDED,
                    null,
                    null,
                    "customer@example.test",
                    ""
            );
        } catch (IllegalArgumentException expected) {
            rejected = true;
        }
        assert rejected;
    }

    private static void comparesCustomerStateWithoutAuditMetadata() {
        UUID assetId = UUID.fromString("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
        Revision current = new Revision(
                UUID.fromString("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"),
                assetId,
                3,
                LifecycleStatus.ACTIVE,
                "payments-prod-01",
                Environment.PRODUCTION,
                "Payments",
                "Payments Operations",
                BusinessCriticality.HIGH,
                ClassificationMethod.GUIDED,
                AssetClassificationGuideV1.CONTRACT_ID,
                AssetClassificationGuideV1.REVISION,
                ManagedAsset.CONTEXT_SOURCE,
                "0".repeat(64),
                "first-actor",
                "first note",
                Instant.parse("2026-08-20T07:00:00Z")
        );
        RevisionDraft retry = new RevisionDraft(
                LifecycleStatus.ACTIVE,
                "payments-prod-01",
                Environment.PRODUCTION,
                "Payments",
                "Payments Operations",
                BusinessCriticality.HIGH,
                ClassificationMethod.GUIDED,
                AssetClassificationGuideV1.CONTRACT_ID,
                AssetClassificationGuideV1.REVISION,
                "retry-actor",
                "retry note"
        );
        assert retry.sameCustomerState(current);
    }

    private static void preservesStableAssetIdentityAcrossRevisions() {
        UUID assetId = UUID.fromString("cccccccc-cccc-4ccc-8ccc-cccccccccccc");
        Revision revision = new Revision(
                UUID.fromString("dddddddd-dddd-4ddd-8ddd-dddddddddddd"),
                assetId,
                2,
                LifecycleStatus.RETIRED,
                "legacy-app",
                Environment.PRODUCTION,
                "Legacy Billing",
                "Finance IT",
                BusinessCriticality.MODERATE,
                ClassificationMethod.CUSTOMER_DIRECT,
                null,
                null,
                ManagedAsset.CONTEXT_SOURCE,
                "1".repeat(64),
                "customer@example.test",
                "retired",
                Instant.parse("2026-08-20T08:00:00Z")
        );
        ManagedAsset asset = new ManagedAsset(
                assetId,
                "CMDB-0042",
                Instant.parse("2026-08-20T07:00:00Z"),
                revision
        );
        assert asset.id().equals(asset.currentRevision().managedAssetId());
        assert asset.currentRevision().lifecycleStatus() == LifecycleStatus.RETIRED;
        assert asset.customerAssetKey().equals("CMDB-0042");
    }
}
