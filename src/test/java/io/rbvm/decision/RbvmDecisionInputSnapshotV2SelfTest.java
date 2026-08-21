package io.rbvm.decision;

import io.rbvm.decision.DecisionInputEvidenceSelection.Candidate;
import io.rbvm.decision.DecisionInputEvidenceSelection.Selection;
import io.rbvm.decision.RbvmDecisionInputSnapshot.BindingKind;
import io.rbvm.decision.RbvmDecisionInputSnapshot.BindingReference;
import io.rbvm.decision.RbvmDecisionInputSnapshot.DimensionInput;
import io.rbvm.decision.RbvmDecisionInputSnapshot.DimensionState;
import io.rbvm.decision.RbvmDecisionInputSnapshot.EvidenceReference;
import io.rbvm.decision.RbvmDecisionInputSnapshot.NativeEvidenceKind;
import io.rbvm.decision.RbvmDecisionMethodologyPolicy.EvidenceDimension;
import io.rbvm.decision.RbvmDecisionMethodologyPolicy.EvidenceSelectionPolicy;
import io.rbvm.decision.RbvmDecisionMethodologyPolicy.FreshnessMode;
import io.rbvm.decision.RbvmDecisionMethodologyPolicy.SourceSelectionMode;

import java.time.Instant;
import java.util.EnumMap;
import java.util.List;
import java.util.UUID;

/** Regression checks for the V22 typed Decision Input Snapshot contract. */
public final class RbvmDecisionInputSnapshotV2SelfTest {
    private static final Instant EVALUATED_AT = Instant.parse("2026-08-20T20:00:00Z");
    private static final String SOURCE = "CUSTOMER_ASSET_REGISTRY";

    private RbvmDecisionInputSnapshotV2SelfTest() {
    }

    public static void main(String[] args) {
        preservesIndependentNativeStoresWithSameSourceAndUuid();
        requiresExactManagedAssetBinding();
        keepsManagedAssetReferencesOutOfV1();
        System.out.println("RbvmDecisionInputSnapshotV2SelfTest: PASS");
    }

    private static void preservesIndependentNativeStoresWithSameSourceAndUuid() {
        UUID sameUuid = UUID.fromString("11111111-1111-4111-8111-111111111111");
        BindingReference binding = binding();
        EvidenceSelectionPolicy policy = new EvidenceSelectionPolicy(
                EvidenceDimension.ASSET_CONTEXT,
                SourceSelectionMode.ALL_SOURCES,
                List.of(),
                FreshnessMode.NO_AGE_LIMIT,
                null
        );

        Selection selection = DecisionInputEvidenceSelection.select(
                policy,
                EVALUATED_AT,
                List.of(
                        new Candidate(
                                EvidenceDimension.ASSET_CONTEXT,
                                "asset|36:22222222-2222-4222-8222-222222222222",
                                NativeEvidenceKind.ASSET_CONTEXT_EVIDENCE,
                                sameUuid,
                                "a".repeat(64),
                                SOURCE,
                                EVALUATED_AT.minusSeconds(120),
                                null
                        ),
                        new Candidate(
                                EvidenceDimension.ASSET_CONTEXT,
                                "asset|36:22222222-2222-4222-8222-222222222222",
                                NativeEvidenceKind.MANAGED_ASSET_REVISION,
                                sameUuid,
                                "b".repeat(64),
                                SOURCE,
                                EVALUATED_AT.minusSeconds(60),
                                binding
                        )
                )
        );

        assert selection.state() == DimensionState.AMBIGUOUS;
        assert selection.evidenceReferences().size() == 2;
        assert selection.evidenceReferences().stream()
                .map(EvidenceReference::nativeEvidenceKind)
                .distinct()
                .count() == 2;

        EnumMap<EvidenceDimension, DimensionInput> dimensions = missingDimensions();
        dimensions.put(
                EvidenceDimension.ASSET_CONTEXT,
                new DimensionInput(
                        EvidenceDimension.ASSET_CONTEXT,
                        selection.state(),
                        selection.evidenceReferences()
                )
        );
        RbvmDecisionInputSnapshot snapshot = RbvmDecisionInputSnapshot.createV2(
                UUID.fromString("33333333-3333-4333-8333-333333333333"),
                1,
                "c".repeat(64),
                EVALUATED_AT,
                dimensions
        );
        assert snapshot.isV2();
        assert snapshot.contractId().equals(RbvmDecisionInputSnapshot.V2_ID);
        assert snapshot.canonicalPayloadFormat().equals(
                RbvmDecisionInputSnapshot.V2_CANONICAL_PAYLOAD_FORMAT);
    }

    private static void requiresExactManagedAssetBinding() {
        boolean rejected = false;
        try {
            new EvidenceReference(
                    EvidenceDimension.ASSET_CONTEXT,
                    NativeEvidenceKind.MANAGED_ASSET_REVISION,
                    UUID.fromString("44444444-4444-4444-8444-444444444444"),
                    "d".repeat(64),
                    SOURCE,
                    EVALUATED_AT.minusSeconds(30),
                    null
            );
        } catch (NullPointerException expected) {
            rejected = expected.getMessage().contains("bindingReference");
        }
        assert rejected;
    }

    private static void keepsManagedAssetReferencesOutOfV1() {
        EvidenceReference managed = new EvidenceReference(
                EvidenceDimension.ASSET_CONTEXT,
                NativeEvidenceKind.MANAGED_ASSET_REVISION,
                UUID.fromString("55555555-5555-4555-8555-555555555555"),
                "e".repeat(64),
                SOURCE,
                EVALUATED_AT.minusSeconds(30),
                binding()
        );
        EnumMap<EvidenceDimension, DimensionInput> dimensions = missingDimensions();
        dimensions.put(
                EvidenceDimension.ASSET_CONTEXT,
                new DimensionInput(
                        EvidenceDimension.ASSET_CONTEXT,
                        DimensionState.PRESENT,
                        List.of(managed)
                )
        );

        boolean rejected = false;
        try {
            RbvmDecisionInputSnapshot.create(
                    UUID.fromString("66666666-6666-4666-8666-666666666666"),
                    1,
                    "f".repeat(64),
                    EVALUATED_AT,
                    dimensions
            );
        } catch (IllegalArgumentException expected) {
            rejected = expected.getMessage().contains("V1 Decision Input");
        }
        assert rejected;
    }

    private static BindingReference binding() {
        return new BindingReference(
                BindingKind.SCANNER_MANAGED_ASSET_LINK_EVENT,
                UUID.fromString("77777777-7777-4777-8777-777777777777"),
                "7".repeat(64),
                "CUSTOMER_CONFIRMED",
                EVALUATED_AT.minusSeconds(180)
        );
    }

    private static EnumMap<EvidenceDimension, DimensionInput> missingDimensions() {
        EnumMap<EvidenceDimension, DimensionInput> dimensions =
                new EnumMap<>(EvidenceDimension.class);
        for (EvidenceDimension dimension : EvidenceDimension.values()) {
            dimensions.put(
                    dimension,
                    new DimensionInput(dimension, DimensionState.MISSING, List.of())
            );
        }
        return dimensions;
    }
}
