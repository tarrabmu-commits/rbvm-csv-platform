package io.rbvm.decision;

import io.rbvm.decision.RbvmDecisionInputSnapshot.BindingKind;
import io.rbvm.decision.RbvmDecisionInputSnapshot.BindingReference;
import io.rbvm.decision.RbvmDecisionInputSnapshot.DimensionInput;
import io.rbvm.decision.RbvmDecisionInputSnapshot.DimensionState;
import io.rbvm.decision.RbvmDecisionInputSnapshot.EvidenceReference;
import io.rbvm.decision.RbvmDecisionInputSnapshot.NativeEvidenceKind;
import io.rbvm.decision.RbvmDecisionMethodologyPolicy.EvidenceDimension;

import java.time.Instant;
import java.util.EnumMap;
import java.util.List;
import java.util.UUID;

/** Regression checks for exact Finding-context association provenance in Snapshot V3. */
public final class RbvmDecisionInputSnapshotV3SelfTest {
    private static final Instant EVALUATED_AT = Instant.parse("2026-08-22T08:00:00Z");
    private static final UUID FINDING_ID =
            UUID.fromString("11111111-1111-4111-8111-111111111111");

    private RbvmDecisionInputSnapshotV3SelfTest() {
    }

    public static void main(String[] args) {
        requiresExactAssociationBindings();
        preservesV2UnboundSemantics();
        separatesV2AndV3CanonicalHashes();
        rejectsWrongBindingKinds();
        rejectsFutureBindingProvenance();
        System.out.println("RbvmDecisionInputSnapshotV3SelfTest: PASS");
    }

    private static void requiresExactAssociationBindings() {
        EnumMap<EvidenceDimension, DimensionInput> dimensions = missingDimensions();
        dimensions.put(
                EvidenceDimension.NETWORK_REACHABILITY,
                new DimensionInput(
                        EvidenceDimension.NETWORK_REACHABILITY,
                        DimensionState.PRESENT,
                        List.of(reachabilityReference(reachabilityBinding(EVALUATED_AT.minusSeconds(60))))
                )
        );
        dimensions.put(
                EvidenceDimension.BUSINESS_MISSION_IMPACT,
                new DimensionInput(
                        EvidenceDimension.BUSINESS_MISSION_IMPACT,
                        DimensionState.PRESENT,
                        List.of(businessReference(businessBinding(EVALUATED_AT.minusSeconds(90))))
                )
        );

        RbvmDecisionInputSnapshot snapshot = RbvmDecisionInputSnapshot.createV3(
                FINDING_ID,
                4,
                "a".repeat(64),
                EVALUATED_AT,
                dimensions
        );
        assert snapshot.isV3();
        assert !snapshot.isV2();
        assert snapshot.contractId().equals(RbvmDecisionInputSnapshot.V3_ID);
        assert snapshot.semantics().equals(RbvmDecisionInputSnapshot.V3_SEMANTICS);
        assert snapshot.canonicalPayloadFormat().equals(
                RbvmDecisionInputSnapshot.V3_CANONICAL_PAYLOAD_FORMAT);
        assert snapshot.dimensions().get(EvidenceDimension.NETWORK_REACHABILITY)
                .evidenceReferences().get(0).bindingReference().bindingKind()
                == BindingKind.FINDING_REACHABILITY_SCOPE_LINK_EVENT;
        assert snapshot.dimensions().get(EvidenceDimension.BUSINESS_MISSION_IMPACT)
                .evidenceReferences().get(0).bindingReference().bindingKind()
                == BindingKind.FINDING_BUSINESS_SERVICE_LINK_EVENT;
    }

    private static void preservesV2UnboundSemantics() {
        EnumMap<EvidenceDimension, DimensionInput> dimensions = missingDimensions();
        dimensions.put(
                EvidenceDimension.NETWORK_REACHABILITY,
                new DimensionInput(
                        EvidenceDimension.NETWORK_REACHABILITY,
                        DimensionState.PRESENT,
                        List.of(reachabilityReference(null))
                )
        );
        dimensions.put(
                EvidenceDimension.BUSINESS_MISSION_IMPACT,
                new DimensionInput(
                        EvidenceDimension.BUSINESS_MISSION_IMPACT,
                        DimensionState.PRESENT,
                        List.of(businessReference(null))
                )
        );
        RbvmDecisionInputSnapshot v2 = RbvmDecisionInputSnapshot.createV2(
                FINDING_ID,
                4,
                "a".repeat(64),
                EVALUATED_AT,
                dimensions
        );
        assert v2.isV2();

        boolean v2BoundRejected = false;
        dimensions.put(
                EvidenceDimension.NETWORK_REACHABILITY,
                new DimensionInput(
                        EvidenceDimension.NETWORK_REACHABILITY,
                        DimensionState.PRESENT,
                        List.of(reachabilityReference(reachabilityBinding(EVALUATED_AT.minusSeconds(60))))
                )
        );
        try {
            RbvmDecisionInputSnapshot.createV2(
                    FINDING_ID,
                    4,
                    "a".repeat(64),
                    EVALUATED_AT,
                    dimensions
            );
        } catch (IllegalArgumentException expected) {
            v2BoundRejected = expected.getMessage().contains("V2 Decision Input");
        }
        assert v2BoundRejected;

        EnumMap<EvidenceDimension, DimensionInput> v3Unbound = missingDimensions();
        v3Unbound.put(
                EvidenceDimension.NETWORK_REACHABILITY,
                new DimensionInput(
                        EvidenceDimension.NETWORK_REACHABILITY,
                        DimensionState.PRESENT,
                        List.of(reachabilityReference(null))
                )
        );
        boolean v3UnboundRejected = false;
        try {
            RbvmDecisionInputSnapshot.createV3(
                    FINDING_ID,
                    4,
                    "a".repeat(64),
                    EVALUATED_AT,
                    v3Unbound
            );
        } catch (IllegalArgumentException expected) {
            v3UnboundRejected = expected.getMessage().contains("V3 network reachability");
        }
        assert v3UnboundRejected;
    }

    private static void separatesV2AndV3CanonicalHashes() {
        EnumMap<EvidenceDimension, DimensionInput> v2Dimensions = missingDimensions();
        v2Dimensions.put(
                EvidenceDimension.NETWORK_REACHABILITY,
                new DimensionInput(
                        EvidenceDimension.NETWORK_REACHABILITY,
                        DimensionState.PRESENT,
                        List.of(reachabilityReference(null))
                )
        );
        RbvmDecisionInputSnapshot v2 = RbvmDecisionInputSnapshot.createV2(
                FINDING_ID, 4, "b".repeat(64), EVALUATED_AT, v2Dimensions);

        EnumMap<EvidenceDimension, DimensionInput> v3Dimensions = missingDimensions();
        v3Dimensions.put(
                EvidenceDimension.NETWORK_REACHABILITY,
                new DimensionInput(
                        EvidenceDimension.NETWORK_REACHABILITY,
                        DimensionState.PRESENT,
                        List.of(reachabilityReference(reachabilityBinding(EVALUATED_AT.minusSeconds(60))))
                )
        );
        RbvmDecisionInputSnapshot v3 = RbvmDecisionInputSnapshot.createV3(
                FINDING_ID, 4, "b".repeat(64), EVALUATED_AT, v3Dimensions);
        assert !v2.snapshotSha256().equals(v3.snapshotSha256());
        assert !java.util.Arrays.equals(v2.canonicalPayload(), v3.canonicalPayload());
    }

    private static void rejectsWrongBindingKinds() {
        boolean rejected = false;
        try {
            reachabilityReference(new BindingReference(
                    BindingKind.FINDING_BUSINESS_SERVICE_LINK_EVENT,
                    UUID.fromString("99999999-9999-4999-8999-999999999999"),
                    "9".repeat(64),
                    "CUSTOMER_CONFIRMED",
                    EVALUATED_AT.minusSeconds(30)
            ));
        } catch (IllegalArgumentException expected) {
            rejected = expected.getMessage().contains("reachability");
        }
        assert rejected;
    }

    private static void rejectsFutureBindingProvenance() {
        EnumMap<EvidenceDimension, DimensionInput> dimensions = missingDimensions();
        dimensions.put(
                EvidenceDimension.BUSINESS_MISSION_IMPACT,
                new DimensionInput(
                        EvidenceDimension.BUSINESS_MISSION_IMPACT,
                        DimensionState.PRESENT,
                        List.of(businessReference(businessBinding(EVALUATED_AT.plusSeconds(1))))
                )
        );
        boolean rejected = false;
        try {
            RbvmDecisionInputSnapshot.createV3(
                    FINDING_ID, 1, "c".repeat(64), EVALUATED_AT, dimensions);
        } catch (IllegalArgumentException expected) {
            rejected = expected.getMessage().contains("binding recorded after evaluatedAt");
        }
        assert rejected;
    }

    private static EvidenceReference reachabilityReference(BindingReference binding) {
        return new EvidenceReference(
                EvidenceDimension.NETWORK_REACHABILITY,
                NativeEvidenceKind.NETWORK_REACHABILITY_EVIDENCE,
                UUID.fromString("22222222-2222-4222-8222-222222222222"),
                "2".repeat(64),
                "NETWORK_OBSERVATION",
                EVALUATED_AT.minusSeconds(120),
                binding
        );
    }

    private static EvidenceReference businessReference(BindingReference binding) {
        return new EvidenceReference(
                EvidenceDimension.BUSINESS_MISSION_IMPACT,
                NativeEvidenceKind.BUSINESS_IMPACT_EVIDENCE,
                UUID.fromString("33333333-3333-4333-8333-333333333333"),
                "3".repeat(64),
                "BUSINESS_IMPACT_REGISTER",
                EVALUATED_AT.minusSeconds(180),
                binding
        );
    }

    private static BindingReference reachabilityBinding(Instant recordedAt) {
        return new BindingReference(
                BindingKind.FINDING_REACHABILITY_SCOPE_LINK_EVENT,
                UUID.fromString("44444444-4444-4444-8444-444444444444"),
                "4".repeat(64),
                "CUSTOMER_CONFIRMED",
                recordedAt
        );
    }

    private static BindingReference businessBinding(Instant recordedAt) {
        return new BindingReference(
                BindingKind.FINDING_BUSINESS_SERVICE_LINK_EVENT,
                UUID.fromString("55555555-5555-4555-8555-555555555555"),
                "5".repeat(64),
                "CUSTOMER_CONFIRMED",
                recordedAt
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
