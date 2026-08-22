package io.rbvm.csv;

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
import io.rbvm.postgres.DecisionInputSnapshotInstallResult;
import io.rbvm.postgres.DecisionInputSnapshotStore;
import io.rbvm.postgres.FormulaResultInstallResult;
import io.rbvm.postgres.FormulaResultReplayVerifier;
import io.rbvm.postgres.FormulaResultStore;
import io.rbvm.postgres.StoredFormulaResult;

import java.io.IOException;
import java.time.Instant;
import java.util.Base64;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

public final class FormulaResultApiSelfTest {
    private static final UUID FINDING_ID =
            UUID.fromString("91111111-1111-4111-8111-111111111111");
    private static final String POLICY_SHA = "a".repeat(64);
    private static final Instant EVALUATED_AT = Instant.parse("2026-08-22T15:00:00Z");
    private static final Instant PERSISTED_AT = Instant.parse("2026-08-22T15:00:05Z");

    private FormulaResultApiSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        returnsReplayVerifiedExactResultByExplanationIdentity();
        returnsReplayVerifiedExactResultBySnapshotAndFormulaIdentity();
        rejectsInvalidAndMissingIdentities();
        failsClosedWhenHistoricalReplayDoesNotMatchStorage();
        System.out.println("FormulaResultApiSelfTest: PASS");
    }

    private static void returnsReplayVerifiedExactResultByExplanationIdentity() throws Exception {
        Fixture fixture = fixture();
        FormulaResultApi api = api(fixture, fixture.stored(), fixture.resolved());

        FormulaResultApi.Response response = api.getByExplanationSha256(
                fixture.explanation().canonicalSha256()
        );
        assert response.status() == 200;
        assert response.headers().get("ETag").equals(
                FormulaResultApi.strongEtag(fixture.explanation().canonicalSha256())
        );
        assert response.body().get("contractId").equals(FormulaResultApi.CONTRACT_ID);

        @SuppressWarnings("unchecked")
        Map<String, Object> result = (Map<String, Object>) response.body().get("result");
        assert result.get("resultState").equals("NOT_APPLICABLE");
        assert result.get("relativeRiskIndex") == null;
        assert result.get("reasonCodes").equals(fixture.explanation().reasonCodes());
        assert result.get("formulaSha256").equals(RbvmFormulaV1.FORMULA_SHA256);
        assert result.get("inputSnapshotSha256").equals(fixture.snapshot().snapshotSha256());

        @SuppressWarnings("unchecked")
        Map<String, Object> explanation = (Map<String, Object>) response.body().get("explanation");
        assert Boolean.TRUE.equals(explanation.get("replayVerified"));
        assert explanation.get("payloadFormat").equals(RbvmFormulaV1Explanation.PAYLOAD_FORMAT);
        assert explanation.get("sha256").equals(fixture.explanation().canonicalSha256());
        byte[] decoded = Base64.getDecoder().decode(
                (String) explanation.get("canonicalPayloadBase64")
        );
        assert java.util.Arrays.equals(decoded, fixture.explanation().canonicalPayload());

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> dimensions =
                (List<Map<String, Object>>) explanation.get("dimensions");
        Map<String, Object> applicability = dimensions.stream()
                .filter(item -> item.get("dimension").equals("APPLICABILITY"))
                .findFirst()
                .orElseThrow();
        assert applicability.get("state").equals("PRESENT");
        assert applicability.get("normalizedValue").equals("NOT_APPLICABLE");
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> references =
                (List<Map<String, Object>>) applicability.get("evidenceReferences");
        assert references.size() == 1;
        assert references.get(0).get("evidenceId")
                .equals(fixture.applicabilityReference().evidenceId().toString());
        assert references.get(0).get("evidenceSha256")
                .equals(fixture.applicabilityReference().evidenceSha256());
        assert references.get(0).get("binding") == null;
    }

    private static void returnsReplayVerifiedExactResultBySnapshotAndFormulaIdentity()
            throws Exception {
        Fixture fixture = fixture();
        FormulaResultApi api = api(fixture, fixture.stored(), fixture.resolved());
        FormulaResultApi.Response response = api.getByInputSnapshotAndFormula(
                fixture.snapshot().snapshotSha256(),
                RbvmFormulaV1.FORMULA_SHA256
        );
        assert response.status() == 200;
        @SuppressWarnings("unchecked")
        Map<String, Object> result = (Map<String, Object>) response.body().get("result");
        assert result.get("resultId").equals(fixture.stored().id().toString());
        assert result.get("methodologyRevision").equals(fixture.snapshot().methodologyRevision());
        assert result.get("evaluatedAt").equals(EVALUATED_AT.toString());
    }

    private static void rejectsInvalidAndMissingIdentities() throws Exception {
        Fixture fixture = fixture();
        FormulaResultApi api = api(fixture, fixture.stored(), fixture.resolved());

        boolean invalid = false;
        try {
            api.getByExplanationSha256("ABC");
        } catch (FormulaResultApi.ApiProblem expected) {
            invalid = expected.status() == 400
                    && expected.code().equals("INVALID_FORMULA_RESULT_IDENTITY");
        }
        assert invalid : "invalid Formula result identity must be rejected as 400";

        boolean missingExplanation = false;
        try {
            api.getByExplanationSha256("f".repeat(64));
        } catch (FormulaResultApi.ApiProblem expected) {
            missingExplanation = expected.status() == 404
                    && expected.code().equals("FORMULA_RESULT_NOT_FOUND");
        }
        assert missingExplanation : "unknown explanation identity must be 404";

        boolean missingFormulaIdentity = false;
        try {
            api.getByInputSnapshotAndFormula(
                    fixture.snapshot().snapshotSha256(),
                    "e".repeat(64)
            );
        } catch (FormulaResultApi.ApiProblem expected) {
            missingFormulaIdentity = expected.status() == 404
                    && expected.code().equals("FORMULA_RESULT_NOT_FOUND");
        }
        assert missingFormulaIdentity : "unknown exact Formula identity must be 404";
    }

    private static void failsClosedWhenHistoricalReplayDoesNotMatchStorage() throws Exception {
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
                List.of("APPLICABILITY_MISSING"),
                null,
                fixture.stored().explanationPayloadFormat(),
                fixture.stored().explanationSha256(),
                fixture.stored().explanationPayload(),
                fixture.stored().persistedAt()
        );
        FormulaResultApi api = api(fixture, drifted, fixture.resolved());

        boolean failedClosed = false;
        try {
            api.getByExplanationSha256(drifted.explanationSha256());
        } catch (IOException expected) {
            failedClosed = expected.getMessage().contains("historical replay");
        }
        assert failedClosed : "Formula Result API must never expose replay-invalid storage";
    }

    private static FormulaResultApi api(
            Fixture fixture,
            StoredFormulaResult stored,
            RbvmResolvedDecisionInput resolved
    ) {
        FormulaResultStore formulaStore = formulaStore(stored);
        DecisionInputSnapshotStore snapshotStore = decisionStore(fixture.snapshot());
        FormulaResultReplayVerifier verifier = new FormulaResultReplayVerifier(
                formulaStore,
                snapshotStore,
                ignored -> resolved
        );
        return new FormulaResultApi(formulaStore, verifier);
    }

    private static Fixture fixture() {
        EvidenceReference applicabilityReference = new EvidenceReference(
                EvidenceDimension.APPLICABILITY,
                UUID.fromString("92222222-2222-4222-8222-222222222222"),
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
                8,
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
                UUID.fromString("93333333-3333-4333-8333-333333333333"),
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
        return new Fixture(snapshot, resolved, explanation, stored, applicabilityReference);
    }

    private static FormulaResultStore formulaStore(StoredFormulaResult stored) {
        return new FormulaResultStore() {
            @Override
            public FormulaResultInstallResult install(RbvmFormulaV1Explanation explanation) {
                throw new UnsupportedOperationException("read-only test store");
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
                throw new UnsupportedOperationException("read-only test store");
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
            StoredFormulaResult stored,
            EvidenceReference applicabilityReference
    ) {
    }
}
