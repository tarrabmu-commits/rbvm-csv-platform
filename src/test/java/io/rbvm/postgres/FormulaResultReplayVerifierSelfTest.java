package io.rbvm.postgres;

import io.rbvm.decision.RbvmDecisionInputSnapshot;
import io.rbvm.decision.RbvmDecisionInputSnapshot.DimensionInput;
import io.rbvm.decision.RbvmDecisionInputSnapshot.DimensionState;
import io.rbvm.decision.RbvmDecisionInputSnapshot.EvidenceReference;
import io.rbvm.decision.RbvmDecisionMethodologyPolicy.EvidenceDimension;
import io.rbvm.decision.RbvmFormulaV1;
import io.rbvm.decision.RbvmFormulaV1Explanation;
import io.rbvm.decision.RbvmResolvedDecisionInput;
import io.rbvm.decision.RbvmResolvedDecisionInput.ApplicabilityEvidenceValue;
import io.rbvm.decision.RbvmResolvedDecisionInput.ApplicabilityStatus;

import java.io.IOException;
import java.time.Instant;
import java.util.EnumMap;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public final class FormulaResultReplayVerifierSelfTest {
    private static final UUID FINDING_ID =
            UUID.fromString("81111111-1111-4111-8111-111111111111");
    private static final String POLICY_SHA = "a".repeat(64);
    private static final Instant EVALUATED_AT = Instant.parse("2026-08-22T12:00:00Z");
    private static final Instant PERSISTED_AT = Instant.parse("2026-08-22T12:00:05Z");

    private FormulaResultReplayVerifierSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        verifiesExactHistoricalReplay();
        rejectsStoredSemanticDriftEvenWhenExplanationBytesAreIntact();
        rejectsMissingDecisionInputSnapshot();
        System.out.println("FormulaResultReplayVerifierSelfTest: PASS");
    }

    private static void verifiesExactHistoricalReplay() throws Exception {
        Fixture fixture = fixture();
        FormulaResultReplayVerifier verifier = new FormulaResultReplayVerifier(
                formulaStore(fixture.stored()),
                decisionStore(fixture.snapshot()),
                snapshot -> {
                    assert snapshot.equals(fixture.snapshot());
                    return fixture.resolved();
                }
        );

        StoredFormulaResult verified = verifier.verifyByExplanationSha256(
                fixture.explanation().canonicalSha256()
        );
        assert verified == fixture.stored();
        assert verifier.verifyBySnapshotAndFormula(
                fixture.snapshot().snapshotSha256(),
                RbvmFormulaV1.FORMULA_SHA256
        ) == fixture.stored();
    }

    private static void rejectsStoredSemanticDriftEvenWhenExplanationBytesAreIntact()
            throws Exception {
        Fixture fixture = fixture();
        StoredFormulaResult drifted = new StoredFormulaResult(
                fixture.stored().id(),
                fixture.stored().inputSnapshotSha256(),
                fixture.stored().findingId(),
                fixture.stored().evaluatedAt(),
                fixture.stored().methodologyRevision(),
                fixture.stored().methodologyPolicySha256(),
                fixture.stored().formulaId(),
                fixture.stored().formulaVersion(),
                fixture.stored().formulaSha256(),
                RbvmFormulaV1.ResultState.NON_COMPUTABLE,
                fixture.stored().reasonCodes(),
                null,
                fixture.stored().explanationPayloadFormat(),
                fixture.stored().explanationSha256(),
                fixture.stored().explanationPayload(),
                fixture.stored().persistedAt()
        );
        FormulaResultReplayVerifier verifier = new FormulaResultReplayVerifier(
                formulaStore(drifted),
                decisionStore(fixture.snapshot()),
                ignored -> fixture.resolved()
        );

        boolean rejected = false;
        try {
            verifier.verify(drifted);
        } catch (IOException expected) {
            rejected = expected.getMessage().contains("historical replay");
        }
        assert rejected : "replay must detect persisted semantic drift";
    }

    private static void rejectsMissingDecisionInputSnapshot() throws Exception {
        Fixture fixture = fixture();
        DecisionInputSnapshotStore missing = new DecisionInputSnapshotStore() {
            @Override
            public DecisionInputSnapshotInstallResult install(RbvmDecisionInputSnapshot snapshot) {
                throw new UnsupportedOperationException();
            }

            @Override
            public Optional<RbvmDecisionInputSnapshot> findBySha256(String snapshotSha256) {
                return Optional.empty();
            }
        };
        FormulaResultReplayVerifier verifier = new FormulaResultReplayVerifier(
                formulaStore(fixture.stored()),
                missing,
                ignored -> fixture.resolved()
        );

        boolean rejected = false;
        try {
            verifier.verify(fixture.stored());
        } catch (IOException expected) {
            rejected = expected.getMessage().contains("Decision Input snapshot");
        }
        assert rejected : "replay must fail closed when exact Decision Input provenance is absent";
    }

    private static Fixture fixture() {
        EvidenceReference applicabilityReference = new EvidenceReference(
                EvidenceDimension.APPLICABILITY,
                UUID.fromString("82222222-2222-4222-8222-222222222222"),
                "b".repeat(64),
                "CUSTOMER_APPLICABILITY",
                EVALUATED_AT.minusSeconds(60)
        );
        EnumMap<EvidenceDimension, DimensionInput> dimensions =
                new EnumMap<>(EvidenceDimension.class);
        for (EvidenceDimension dimension : EvidenceDimension.values()) {
            dimensions.put(
                    dimension,
                    new DimensionInput(dimension, DimensionState.MISSING, List.of())
            );
        }
        dimensions.put(
                EvidenceDimension.APPLICABILITY,
                new DimensionInput(
                        EvidenceDimension.APPLICABILITY,
                        DimensionState.PRESENT,
                        List.of(applicabilityReference)
                )
        );
        RbvmDecisionInputSnapshot snapshot = RbvmDecisionInputSnapshot.createV3(
                FINDING_ID,
                7,
                POLICY_SHA,
                EVALUATED_AT,
                dimensions
        );

        EnumMap<EvidenceDimension, List<RbvmResolvedDecisionInput.ResolvedEvidence>> evidence =
                new EnumMap<>(EvidenceDimension.class);
        for (EvidenceDimension dimension : EvidenceDimension.values()) {
            evidence.put(dimension, List.of());
        }
        evidence.put(
                EvidenceDimension.APPLICABILITY,
                List.of(new ApplicabilityEvidenceValue(
                        applicabilityReference,
                        ApplicabilityStatus.NOT_APPLICABLE,
                        "customer-confirmed not applicable"
                ))
        );
        RbvmResolvedDecisionInput resolved = new RbvmResolvedDecisionInput(snapshot, evidence);
        RbvmFormulaV1.FormulaResult result = RbvmFormulaV1.evaluate(resolved);
        assert result.state() == RbvmFormulaV1.ResultState.NOT_APPLICABLE;
        RbvmFormulaV1Explanation explanation = RbvmFormulaV1Explanation.from(resolved, result);
        StoredFormulaResult stored = new StoredFormulaResult(
                UUID.fromString("83333333-3333-4333-8333-333333333333"),
                snapshot.snapshotSha256(),
                snapshot.findingId(),
                snapshot.evaluatedAt(),
                snapshot.methodologyRevision(),
                snapshot.methodologyPolicySha256(),
                explanation.formulaId(),
                explanation.formulaVersion(),
                explanation.formulaSha256(),
                explanation.resultState(),
                explanation.reasonCodes(),
                explanation.finalRiskResult(),
                RbvmFormulaV1Explanation.PAYLOAD_FORMAT,
                explanation.canonicalSha256(),
                explanation.canonicalPayload(),
                PERSISTED_AT
        );
        return new Fixture(snapshot, resolved, explanation, stored);
    }

    private static FormulaResultStore formulaStore(StoredFormulaResult stored) {
        return new FormulaResultStore() {
            @Override
            public FormulaResultInstallResult install(RbvmFormulaV1Explanation explanation) {
                throw new UnsupportedOperationException();
            }

            @Override
            public Optional<StoredFormulaResult> findByExplanationSha256(
                    String explanationSha256
            ) {
                return stored.explanationSha256().equals(explanationSha256)
                        ? Optional.of(stored)
                        : Optional.empty();
            }

            @Override
            public Optional<StoredFormulaResult> findBySnapshotAndFormula(
                    String inputSnapshotSha256,
                    String formulaSha256
            ) {
                return stored.inputSnapshotSha256().equals(inputSnapshotSha256)
                        && stored.formulaSha256().equals(formulaSha256)
                        ? Optional.of(stored)
                        : Optional.empty();
            }
        };
    }

    private static DecisionInputSnapshotStore decisionStore(RbvmDecisionInputSnapshot snapshot) {
        return new DecisionInputSnapshotStore() {
            @Override
            public DecisionInputSnapshotInstallResult install(RbvmDecisionInputSnapshot ignored) {
                throw new UnsupportedOperationException();
            }

            @Override
            public Optional<RbvmDecisionInputSnapshot> findBySha256(String snapshotSha256) {
                return snapshot.snapshotSha256().equals(snapshotSha256)
                        ? Optional.of(snapshot)
                        : Optional.empty();
            }
        };
    }

    private record Fixture(
            RbvmDecisionInputSnapshot snapshot,
            RbvmResolvedDecisionInput resolved,
            RbvmFormulaV1Explanation explanation,
            StoredFormulaResult stored
    ) {
    }
}
