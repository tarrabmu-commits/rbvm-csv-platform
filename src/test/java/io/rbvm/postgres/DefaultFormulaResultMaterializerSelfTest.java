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

public final class DefaultFormulaResultMaterializerSelfTest {
    private static final UUID FINDING_ID =
            UUID.fromString("a1111111-1111-4111-8111-111111111111");
    private static final String POLICY_SHA = "a".repeat(64);
    private static final Instant EVALUATED_AT = Instant.parse("2026-08-22T16:00:00Z");
    private static final Instant PERSISTED_AT = Instant.parse("2026-08-22T16:00:05Z");

    private DefaultFormulaResultMaterializerSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        materializesOnlyTheExactPersistedV3SnapshotAndReplays();
        rejectsMalformedMissingAndNonV3Snapshots();
        failsClosedOnFormulaResultConflict();
        failsClosedWhenPersistedResultCannotReplay();
        System.out.println("DefaultFormulaResultMaterializerSelfTest: PASS");
    }

    private static void materializesOnlyTheExactPersistedV3SnapshotAndReplays() throws Exception {
        Fixture fixture = fixture(true);
        InMemoryFormulaStore results = new InMemoryFormulaStore();
        DecisionInputSnapshotStore snapshots = decisionStore(fixture.snapshot());
        FormulaResultReplayVerifier verifier = new FormulaResultReplayVerifier(
                results,
                snapshots,
                snapshot -> {
                    assert snapshot == fixture.snapshot();
                    return fixture.resolved();
                }
        );
        DefaultFormulaResultMaterializer materializer = new DefaultFormulaResultMaterializer(
                snapshots,
                snapshot -> {
                    assert snapshot == fixture.snapshot();
                    return fixture.resolved();
                },
                results,
                verifier
        );

        FormulaResultMaterializationResult first = materializer.materialize(
                fixture.snapshot().snapshotSha256()
        );
        assert first.installResult().status() == FormulaResultInstallResult.Status.INSERTED;
        assert first.explanation().resultState() == RbvmFormulaV1.ResultState.NOT_APPLICABLE;
        assert first.explanation().finalRiskResult() == null;
        assert first.explanation().reasonCodes().equals(List.of("NOT_APPLICABLE"));
        assert first.storedResult().inputSnapshotSha256()
                .equals(fixture.snapshot().snapshotSha256());
        assert first.storedResult().explanationSha256()
                .equals(first.explanation().canonicalSha256());
        assert !first.replayed();

        FormulaResultMaterializationResult second = materializer.materialize(
                fixture.snapshot().snapshotSha256()
        );
        assert second.installResult().status() == FormulaResultInstallResult.Status.REPLAYED;
        assert second.replayed();
        assert second.explanation().canonicalSha256()
                .equals(first.explanation().canonicalSha256());
        assert results.installCalls == 2;
    }

    private static void rejectsMalformedMissingAndNonV3Snapshots() throws Exception {
        Fixture fixture = fixture(true);
        InMemoryFormulaStore results = new InMemoryFormulaStore();
        FormulaResultReplayVerifier verifier = new FormulaResultReplayVerifier(
                results,
                decisionStore(fixture.snapshot()),
                ignored -> fixture.resolved()
        );
        DefaultFormulaResultMaterializer materializer = new DefaultFormulaResultMaterializer(
                decisionStore(fixture.snapshot()),
                ignored -> fixture.resolved(),
                results,
                verifier
        );

        boolean malformed = false;
        try {
            materializer.materialize("ABC");
        } catch (IllegalArgumentException expected) {
            malformed = expected.getMessage().contains("lowercase SHA-256");
        }
        assert malformed : "materializer must reject malformed snapshot identities";

        boolean missing = false;
        try {
            materializer.materialize("f".repeat(64));
        } catch (DefaultFormulaResultMaterializer.SnapshotNotFoundException expected) {
            missing = expected.inputSnapshotSha256().equals("f".repeat(64));
        }
        assert missing : "materializer must fail when exact persisted snapshot is absent";

        Fixture v2 = fixture(false);
        FormulaResultReplayVerifier v2Verifier = new FormulaResultReplayVerifier(
                results,
                decisionStore(v2.snapshot()),
                ignored -> v2.resolved()
        );
        DefaultFormulaResultMaterializer v2Materializer = new DefaultFormulaResultMaterializer(
                decisionStore(v2.snapshot()),
                ignored -> {
                    throw new AssertionError("non-V3 snapshot must be rejected before resolution");
                },
                results,
                v2Verifier
        );
        boolean nonV3 = false;
        try {
            v2Materializer.materialize(v2.snapshot().snapshotSha256());
        } catch (DefaultFormulaResultMaterializer.UnsupportedSnapshotContractException expected) {
            nonV3 = expected.contractId().equals(RbvmDecisionInputSnapshot.V2_ID);
        }
        assert nonV3 : "Formula materialization must accept only Decision Input V3";
    }

    private static void failsClosedOnFormulaResultConflict() throws Exception {
        Fixture fixture = fixture(true);
        DecisionInputSnapshotStore snapshots = decisionStore(fixture.snapshot());
        FormulaResultStore conflicting = new FormulaResultStore() {
            @Override
            public FormulaResultInstallResult install(RbvmFormulaV1Explanation explanation) {
                return new FormulaResultInstallResult(
                        FormulaResultInstallResult.Status.RESULT_CONFLICT,
                        explanation.canonicalSha256(),
                        "f".repeat(64)
                );
            }

            @Override
            public Optional<StoredFormulaResult> findByExplanationSha256(String ignored) {
                return Optional.empty();
            }

            @Override
            public Optional<StoredFormulaResult> findBySnapshotAndFormula(
                    String ignoredSnapshot,
                    String ignoredFormula
            ) {
                return Optional.empty();
            }
        };
        FormulaResultReplayVerifier verifier = new FormulaResultReplayVerifier(
                conflicting,
                snapshots,
                ignored -> fixture.resolved()
        );
        DefaultFormulaResultMaterializer materializer = new DefaultFormulaResultMaterializer(
                snapshots,
                ignored -> fixture.resolved(),
                conflicting,
                verifier
        );

        boolean conflict = false;
        try {
            materializer.materialize(fixture.snapshot().snapshotSha256());
        } catch (DefaultFormulaResultMaterializer.ResultConflictException expected) {
            conflict = expected.inputSnapshotSha256().equals(fixture.snapshot().snapshotSha256())
                    && expected.existingExplanationSha256().equals("f".repeat(64));
        }
        assert conflict : "conflicting persisted Formula semantics must fail closed";
    }

    private static void failsClosedWhenPersistedResultCannotReplay() throws Exception {
        Fixture fixture = fixture(true);
        DecisionInputSnapshotStore snapshots = decisionStore(fixture.snapshot());
        FormulaResultStore driftedStore = new FormulaResultStore() {
            private StoredFormulaResult stored;

            @Override
            public FormulaResultInstallResult install(RbvmFormulaV1Explanation explanation) {
                stored = new StoredFormulaResult(
                        UUID.fromString("a3333333-3333-4333-8333-333333333333"),
                        explanation.inputSnapshotSha256(),
                        explanation.findingId(),
                        explanation.evaluatedAt(),
                        explanation.methodologyRevision(),
                        explanation.methodologyPolicySha256(),
                        explanation.formulaId(),
                        explanation.formulaVersion(),
                        explanation.formulaSha256(),
                        RbvmFormulaV1.ResultState.NON_COMPUTABLE,
                        List.of("APPLICABILITY_MISSING"),
                        null,
                        RbvmFormulaV1Explanation.PAYLOAD_FORMAT,
                        explanation.canonicalSha256(),
                        explanation.canonicalPayload(),
                        PERSISTED_AT
                );
                return new FormulaResultInstallResult(
                        FormulaResultInstallResult.Status.INSERTED,
                        explanation.canonicalSha256(),
                        explanation.canonicalSha256()
                );
            }

            @Override
            public Optional<StoredFormulaResult> findByExplanationSha256(String explanationSha256) {
                return stored != null && stored.explanationSha256().equals(explanationSha256)
                        ? Optional.of(stored)
                        : Optional.empty();
            }

            @Override
            public Optional<StoredFormulaResult> findBySnapshotAndFormula(
                    String inputSnapshotSha256,
                    String formulaSha256
            ) {
                return Optional.ofNullable(stored);
            }
        };
        FormulaResultReplayVerifier verifier = new FormulaResultReplayVerifier(
                driftedStore,
                snapshots,
                ignored -> fixture.resolved()
        );
        DefaultFormulaResultMaterializer materializer = new DefaultFormulaResultMaterializer(
                snapshots,
                ignored -> fixture.resolved(),
                driftedStore,
                verifier
        );

        boolean failedClosed = false;
        try {
            materializer.materialize(fixture.snapshot().snapshotSha256());
        } catch (IOException expected) {
            failedClosed = expected.getMessage().contains("historical replay");
        }
        assert failedClosed : "materialization must not return replay-invalid persisted output";
    }

    private static Fixture fixture(boolean v3) {
        EvidenceReference applicability = new EvidenceReference(
                EvidenceDimension.APPLICABILITY,
                UUID.fromString("a2222222-2222-4222-8222-222222222222"),
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
                        List.of(applicability)
                )
        );
        RbvmDecisionInputSnapshot snapshot = v3
                ? RbvmDecisionInputSnapshot.createV3(
                        FINDING_ID, 11, POLICY_SHA, EVALUATED_AT, dimensions)
                : RbvmDecisionInputSnapshot.createV2(
                        FINDING_ID, 11, POLICY_SHA, EVALUATED_AT, dimensions);

        EnumMap<EvidenceDimension, List<RbvmResolvedDecisionInput.ResolvedEvidence>> evidence =
                new EnumMap<>(EvidenceDimension.class);
        for (EvidenceDimension dimension : EvidenceDimension.values()) {
            evidence.put(dimension, List.of());
        }
        evidence.put(
                EvidenceDimension.APPLICABILITY,
                List.of(new ApplicabilityEvidenceValue(
                        applicability,
                        ApplicabilityStatus.NOT_APPLICABLE,
                        "customer-confirmed not applicable"
                ))
        );
        return new Fixture(snapshot, new RbvmResolvedDecisionInput(snapshot, evidence));
    }

    private static DecisionInputSnapshotStore decisionStore(RbvmDecisionInputSnapshot snapshot) {
        return new DecisionInputSnapshotStore() {
            @Override
            public DecisionInputSnapshotInstallResult install(RbvmDecisionInputSnapshot ignored) {
                throw new UnsupportedOperationException("materializer must never install/rebuild input");
            }

            @Override
            public Optional<RbvmDecisionInputSnapshot> findBySha256(String snapshotSha256) {
                return snapshot.snapshotSha256().equals(snapshotSha256)
                        ? Optional.of(snapshot)
                        : Optional.empty();
            }
        };
    }

    private static final class InMemoryFormulaStore implements FormulaResultStore {
        private StoredFormulaResult stored;
        private int installCalls;

        @Override
        public FormulaResultInstallResult install(RbvmFormulaV1Explanation explanation) {
            installCalls++;
            if (stored != null) {
                if (stored.explanationSha256().equals(explanation.canonicalSha256())) {
                    return new FormulaResultInstallResult(
                            FormulaResultInstallResult.Status.REPLAYED,
                            explanation.canonicalSha256(),
                            stored.explanationSha256()
                    );
                }
                return new FormulaResultInstallResult(
                        FormulaResultInstallResult.Status.RESULT_CONFLICT,
                        explanation.canonicalSha256(),
                        stored.explanationSha256()
                );
            }
            stored = new StoredFormulaResult(
                    UUID.fromString("a4444444-4444-4444-8444-444444444444"),
                    explanation.inputSnapshotSha256(),
                    explanation.findingId(),
                    explanation.evaluatedAt(),
                    explanation.methodologyRevision(),
                    explanation.methodologyPolicySha256(),
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
            return new FormulaResultInstallResult(
                    FormulaResultInstallResult.Status.INSERTED,
                    explanation.canonicalSha256(),
                    explanation.canonicalSha256()
            );
        }

        @Override
        public Optional<StoredFormulaResult> findByExplanationSha256(String explanationSha256) {
            return stored != null && stored.explanationSha256().equals(explanationSha256)
                    ? Optional.of(stored)
                    : Optional.empty();
        }

        @Override
        public Optional<StoredFormulaResult> findBySnapshotAndFormula(
                String inputSnapshotSha256,
                String formulaSha256
        ) {
            return stored != null
                    && stored.inputSnapshotSha256().equals(inputSnapshotSha256)
                    && stored.formulaSha256().equals(formulaSha256)
                    ? Optional.of(stored)
                    : Optional.empty();
        }
    }

    private record Fixture(
            RbvmDecisionInputSnapshot snapshot,
            RbvmResolvedDecisionInput resolved
    ) {
    }
}
