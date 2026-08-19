package io.rbvm.decision;

import io.rbvm.decision.RbvmDecisionInputSnapshot.DimensionInput;
import io.rbvm.decision.RbvmDecisionInputSnapshot.DimensionState;
import io.rbvm.decision.RbvmDecisionInputSnapshot.EvidenceReference;
import io.rbvm.decision.RbvmDecisionMethodologyPolicy.EvidenceDimension;

import java.lang.reflect.RecordComponent;
import java.time.Instant;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

public final class RbvmDecisionInputSnapshotSelfTest {
    private static final UUID FINDING_ID =
            UUID.fromString("11111111-1111-4111-8111-111111111111");
    private static final Instant EVALUATED_AT = Instant.parse("2026-08-19T18:00:00Z");
    private static final String POLICY_SHA = "a".repeat(64);

    private RbvmDecisionInputSnapshotSelfTest() {
    }

    public static void main(String[] args) {
        createsCompleteFindingScopedPolicyBoundSnapshot();
        canonicalHashIgnoresInputReferenceOrder();
        enforcesDimensionStateReferenceCardinality();
        rejectsIncompleteFutureOrForgedSnapshots();
        exposesNoDecisionFormulaFieldsOrEvidenceValues();
        System.out.println("RbvmDecisionInputSnapshotSelfTest: PASS");
    }

    private static void createsCompleteFindingScopedPolicyBoundSnapshot() {
        RbvmDecisionInputSnapshot snapshot = RbvmDecisionInputSnapshot.create(
                FINDING_ID,
                4,
                POLICY_SHA,
                EVALUATED_AT,
                completeDimensions(false)
        );

        assert snapshot.contractId().equals("RBVM_DECISION_INPUT_SNAPSHOT_V1");
        assert snapshot.semantics().equals(
                "FINDING_SCOPED_POLICY_BOUND_EVIDENCE_REFERENCE_SNAPSHOT");
        assert snapshot.findingId().equals(FINDING_ID);
        assert snapshot.methodologyRevision() == 4;
        assert snapshot.methodologyPolicySha256().equals(POLICY_SHA);
        assert snapshot.snapshotSha256().matches("[a-f0-9]{64}");
        assert snapshot.canonicalPayload().length > 0;
        assert snapshot.dimensions().keySet().equals(Set.of(EvidenceDimension.values()));
        assert snapshot.dimensions().get(EvidenceDimension.APPLICABILITY).state()
                == DimensionState.PRESENT;
        assert snapshot.dimensions().get(EvidenceDimension.TECHNICAL_SEVERITY).state()
                == DimensionState.MISSING;
        assert snapshot.dimensions().get(EvidenceDimension.KNOWN_EXPLOITATION).state()
                == DimensionState.AMBIGUOUS;
        assert snapshot.dimensions().get(EvidenceDimension.EXPLOITATION_PROBABILITY).state()
                == DimensionState.STALE;
    }

    private static void canonicalHashIgnoresInputReferenceOrder() {
        RbvmDecisionInputSnapshot first = RbvmDecisionInputSnapshot.create(
                FINDING_ID,
                4,
                POLICY_SHA,
                EVALUATED_AT,
                completeDimensions(false)
        );
        RbvmDecisionInputSnapshot reordered = RbvmDecisionInputSnapshot.create(
                FINDING_ID,
                4,
                POLICY_SHA,
                EVALUATED_AT,
                completeDimensions(true)
        );

        assert first.snapshotSha256().equals(reordered.snapshotSha256());
        assert Arrays.equals(first.canonicalPayload(), reordered.canonicalPayload());
        List<EvidenceReference> references = reordered.dimensions()
                .get(EvidenceDimension.KNOWN_EXPLOITATION)
                .evidenceReferences();
        assert references.get(0).evidenceId().compareTo(references.get(1).evidenceId()) < 0;
    }

    private static void enforcesDimensionStateReferenceCardinality() {
        EvidenceReference applicability = reference(
                EvidenceDimension.APPLICABILITY,
                "00000000-0000-4000-8000-000000000001",
                "applicability-source",
                "b"
        );
        assertRejected(() -> new DimensionInput(
                EvidenceDimension.APPLICABILITY,
                DimensionState.MISSING,
                List.of(applicability)
        ));
        assertRejected(() -> new DimensionInput(
                EvidenceDimension.APPLICABILITY,
                DimensionState.PRESENT,
                List.of()
        ));
        assertRejected(() -> new DimensionInput(
                EvidenceDimension.APPLICABILITY,
                DimensionState.STALE,
                List.of()
        ));
        assertRejected(() -> new DimensionInput(
                EvidenceDimension.APPLICABILITY,
                DimensionState.AMBIGUOUS,
                List.of(applicability)
        ));
        assertRejected(() -> new DimensionInput(
                EvidenceDimension.APPLICABILITY,
                DimensionState.PRESENT,
                List.of(applicability, applicability)
        ));
        assertRejected(() -> new DimensionInput(
                EvidenceDimension.TECHNICAL_SEVERITY,
                DimensionState.PRESENT,
                List.of(applicability)
        ));
    }

    private static void rejectsIncompleteFutureOrForgedSnapshots() {
        EnumMap<EvidenceDimension, DimensionInput> incomplete = completeDimensions(false);
        incomplete.remove(EvidenceDimension.BUSINESS_MISSION_IMPACT);
        assertRejected(() -> RbvmDecisionInputSnapshot.create(
                FINDING_ID,
                4,
                POLICY_SHA,
                EVALUATED_AT,
                incomplete
        ));

        EnumMap<EvidenceDimension, DimensionInput> future = completeDimensions(false);
        future.put(
                EvidenceDimension.ASSET_CONTEXT,
                new DimensionInput(
                        EvidenceDimension.ASSET_CONTEXT,
                        DimensionState.PRESENT,
                        List.of(new EvidenceReference(
                                EvidenceDimension.ASSET_CONTEXT,
                                UUID.fromString("00000000-0000-4000-8000-000000000020"),
                                "d".repeat(64),
                                "cmdb",
                                EVALUATED_AT.plusSeconds(1)
                        ))
                )
        );
        assertRejected(() -> RbvmDecisionInputSnapshot.create(
                FINDING_ID,
                4,
                POLICY_SHA,
                EVALUATED_AT,
                future
        ));

        RbvmDecisionInputSnapshot valid = RbvmDecisionInputSnapshot.create(
                FINDING_ID,
                4,
                POLICY_SHA,
                EVALUATED_AT,
                completeDimensions(false)
        );
        assertRejected(() -> new RbvmDecisionInputSnapshot(
                valid.contractId(),
                "0".repeat(64),
                valid.findingId(),
                valid.methodologyRevision(),
                valid.methodologyPolicySha256(),
                valid.evaluatedAt(),
                valid.dimensions()
        ));
    }

    private static void exposesNoDecisionFormulaFieldsOrEvidenceValues() {
        Set<String> forbiddenSnapshotTokens = Set.of(
                "riskscore", "priority", "sla", "decision", "treatment", "weight",
                "threshold", "multiplier", "coefficient", "caseid", "aggregate"
        );
        Set<String> forbiddenReferenceTokens = Set.of(
                "cvss", "epss", "kevstatus", "impactlevel", "businesscriticality",
                "reachabilitystatus", "applicabilitystatus", "score", "value", "weight"
        );
        Set<String> snapshotComponents = componentNames(RbvmDecisionInputSnapshot.class);
        Set<String> referenceComponents = componentNames(EvidenceReference.class);
        for (String token : forbiddenSnapshotTokens) {
            assert snapshotComponents.stream().noneMatch(name -> name.contains(token)) : token;
        }
        for (String token : forbiddenReferenceTokens) {
            assert referenceComponents.stream().noneMatch(name -> name.contains(token)) : token;
        }
    }

    private static EnumMap<EvidenceDimension, DimensionInput> completeDimensions(boolean reverseAmbiguous) {
        EnumMap<EvidenceDimension, DimensionInput> output = new EnumMap<>(EvidenceDimension.class);
        EvidenceReference applicability = reference(
                EvidenceDimension.APPLICABILITY,
                "00000000-0000-4000-8000-000000000001",
                "applicability-source",
                "b"
        );
        output.put(
                EvidenceDimension.APPLICABILITY,
                new DimensionInput(
                        EvidenceDimension.APPLICABILITY,
                        DimensionState.PRESENT,
                        List.of(applicability)
                )
        );
        output.put(
                EvidenceDimension.TECHNICAL_SEVERITY,
                new DimensionInput(
                        EvidenceDimension.TECHNICAL_SEVERITY,
                        DimensionState.MISSING,
                        List.of()
                )
        );

        EvidenceReference kevA = reference(
                EvidenceDimension.KNOWN_EXPLOITATION,
                "00000000-0000-4000-8000-000000000002",
                "cisa-kev",
                "c"
        );
        EvidenceReference kevB = reference(
                EvidenceDimension.KNOWN_EXPLOITATION,
                "00000000-0000-4000-8000-000000000003",
                "partner-threat-feed",
                "d"
        );
        output.put(
                EvidenceDimension.KNOWN_EXPLOITATION,
                new DimensionInput(
                        EvidenceDimension.KNOWN_EXPLOITATION,
                        DimensionState.AMBIGUOUS,
                        reverseAmbiguous ? List.of(kevB, kevA) : List.of(kevA, kevB)
                )
        );
        output.put(
                EvidenceDimension.EXPLOITATION_PROBABILITY,
                new DimensionInput(
                        EvidenceDimension.EXPLOITATION_PROBABILITY,
                        DimensionState.STALE,
                        List.of(reference(
                                EvidenceDimension.EXPLOITATION_PROBABILITY,
                                "00000000-0000-4000-8000-000000000004",
                                "first-epss",
                                "e"
                        ))
                )
        );
        output.put(
                EvidenceDimension.ASSET_CONTEXT,
                new DimensionInput(
                        EvidenceDimension.ASSET_CONTEXT,
                        DimensionState.PRESENT,
                        List.of(reference(
                                EvidenceDimension.ASSET_CONTEXT,
                                "00000000-0000-4000-8000-000000000005",
                                "cmdb",
                                "f"
                        ))
                )
        );
        output.put(
                EvidenceDimension.NETWORK_REACHABILITY,
                new DimensionInput(
                        EvidenceDimension.NETWORK_REACHABILITY,
                        DimensionState.PRESENT,
                        List.of(reference(
                                EvidenceDimension.NETWORK_REACHABILITY,
                                "00000000-0000-4000-8000-000000000006",
                                "reachability-export",
                                "1"
                        ))
                )
        );
        output.put(
                EvidenceDimension.BUSINESS_MISSION_IMPACT,
                new DimensionInput(
                        EvidenceDimension.BUSINESS_MISSION_IMPACT,
                        DimensionState.PRESENT,
                        List.of(reference(
                                EvidenceDimension.BUSINESS_MISSION_IMPACT,
                                "00000000-0000-4000-8000-000000000007",
                                "bia-2026",
                                "2"
                        ))
                )
        );
        return output;
    }

    private static EvidenceReference reference(
            EvidenceDimension dimension,
            String uuid,
            String source,
            String shaCharacter
    ) {
        return new EvidenceReference(
                dimension,
                UUID.fromString(uuid),
                shaCharacter.repeat(64),
                source,
                EVALUATED_AT.minusSeconds(3_600)
        );
    }

    private static Set<String> componentNames(Class<?> type) {
        return Arrays.stream(type.getRecordComponents())
                .map(RecordComponent::getName)
                .map(name -> name.toLowerCase(Locale.ROOT))
                .collect(Collectors.toSet());
    }

    private static void assertRejected(Runnable operation) {
        boolean rejected = false;
        try {
            operation.run();
        } catch (IllegalArgumentException expected) {
            rejected = true;
        }
        assert rejected;
    }
}
