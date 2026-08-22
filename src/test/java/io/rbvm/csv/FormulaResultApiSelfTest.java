package io.rbvm.csv;

import io.rbvm.decision.RbvmDecisionInputSnapshot;
import io.rbvm.decision.RbvmDecisionInputSnapshot.BindingKind;
import io.rbvm.decision.RbvmDecisionInputSnapshot.BindingReference;
import io.rbvm.decision.RbvmDecisionInputSnapshot.DimensionInput;
import io.rbvm.decision.RbvmDecisionInputSnapshot.DimensionState;
import io.rbvm.decision.RbvmDecisionInputSnapshot.EvidenceReference;
import io.rbvm.decision.RbvmDecisionInputSnapshot.NativeEvidenceKind;
import io.rbvm.decision.RbvmDecisionMethodologyPolicy.EvidenceDimension;
import io.rbvm.decision.RbvmFormulaV1;
import io.rbvm.decision.RbvmFormulaV1Explanation;
import io.rbvm.decision.RbvmResolvedDecisionInput;
import io.rbvm.decision.RbvmResolvedDecisionInput.ApplicabilityEvidenceValue;
import io.rbvm.decision.RbvmResolvedDecisionInput.ApplicabilityStatus;
import io.rbvm.decision.RbvmResolvedDecisionInput.AssetContextEvidenceValue;
import io.rbvm.decision.RbvmResolvedDecisionInput.BusinessCriticality;
import io.rbvm.decision.RbvmResolvedDecisionInput.BusinessMissionImpactEvidenceValue;
import io.rbvm.decision.RbvmResolvedDecisionInput.Environment;
import io.rbvm.decision.RbvmResolvedDecisionInput.ExploitationProbabilityEvidenceValue;
import io.rbvm.decision.RbvmResolvedDecisionInput.ImpactDimension;
import io.rbvm.decision.RbvmResolvedDecisionInput.ImpactLevel;
import io.rbvm.decision.RbvmResolvedDecisionInput.ImpactMethod;
import io.rbvm.decision.RbvmResolvedDecisionInput.KevStatus;
import io.rbvm.decision.RbvmResolvedDecisionInput.KnownExploitationEvidenceValue;
import io.rbvm.decision.RbvmResolvedDecisionInput.NetworkReachabilityEvidenceValue;
import io.rbvm.decision.RbvmResolvedDecisionInput.OriginScope;
import io.rbvm.decision.RbvmResolvedDecisionInput.ReachabilityMethod;
import io.rbvm.decision.RbvmResolvedDecisionInput.ReachabilityStatus;
import io.rbvm.decision.RbvmResolvedDecisionInput.ResolvedEvidence;
import io.rbvm.decision.RbvmResolvedDecisionInput.TechnicalSeverityEvidenceValue;
import io.rbvm.decision.RbvmResolvedDecisionInput.TransportProtocol;
import io.rbvm.postgres.DecisionInputSnapshotInstallResult;
import io.rbvm.postgres.DecisionInputSnapshotStore;
import io.rbvm.postgres.FormulaResultInstallResult;
import io.rbvm.postgres.FormulaResultReplayVerifier;
import io.rbvm.postgres.FormulaResultStore;
import io.rbvm.postgres.StoredFormulaResult;

import java.io.IOException;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.LocalDate;
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
        returnsComputedDecimalsAndExactBindingProvenance();
        rejectsInvalidAndMissingIdentities();
        failsClosedWhenHistoricalReplayDoesNotMatchStorage();
        System.out.println("FormulaResultApiSelfTest: PASS");
    }

    private static void returnsReplayVerifiedExactResultByExplanationIdentity() throws Exception {
        Fixture fixture = terminalFixture();
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
        Map<String, Object> applicability = dimension(dimensions, "APPLICABILITY");
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
        Fixture fixture = terminalFixture();
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

    private static void returnsComputedDecimalsAndExactBindingProvenance() throws Exception {
        Fixture fixture = computedFixture();
        FormulaResultApi api = api(fixture, fixture.stored(), fixture.resolved());
        FormulaResultApi.Response response = api.getByExplanationSha256(
                fixture.explanation().canonicalSha256()
        );

        @SuppressWarnings("unchecked")
        Map<String, Object> result = (Map<String, Object>) response.body().get("result");
        assert result.get("resultState").equals("COMPUTED");
        assert result.get("relativeRiskIndex").equals("45.00") : result;
        assert result.get("reasonCodes").equals(List.of());

        @SuppressWarnings("unchecked")
        Map<String, Object> explanation = (Map<String, Object>) response.body().get("explanation");
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> dimensions =
                (List<Map<String, Object>>) explanation.get("dimensions");

        Map<String, Object> severity = dimension(dimensions, "TECHNICAL_SEVERITY");
        assert severity.get("normalizedValue").equals("0.65") : severity;
        assert severity.get("appliedFactorOrTransformId").equals("CVSS_V31_BASE") : severity;
        assert severity.get("weightedContribution").equals("0.13") : severity;

        Map<String, Object> reachability = dimension(dimensions, "NETWORK_REACHABILITY");
        assert reachability.get("normalizedValue").equals("1") : reachability;
        assert reachability.get("weightedContribution").equals("0.15") : reachability;
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> references =
                (List<Map<String, Object>>) reachability.get("evidenceReferences");
        assert references.size() == 1;
        @SuppressWarnings("unchecked")
        Map<String, Object> binding = (Map<String, Object>) references.get(0).get("binding");
        BindingReference expectedBinding = fixture.reachabilityReference().bindingReference();
        assert binding.get("bindingKind").equals("FINDING_REACHABILITY_SCOPE_LINK_EVENT");
        assert binding.get("bindingId").equals(expectedBinding.bindingId().toString());
        assert binding.get("bindingSha256").equals(expectedBinding.bindingSha256());
        assert binding.get("bindingSource").equals(expectedBinding.bindingSource());
        assert binding.get("recordedAt").equals(expectedBinding.recordedAt().toString());
    }

    private static void rejectsInvalidAndMissingIdentities() throws Exception {
        Fixture fixture = terminalFixture();
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
        Fixture fixture = terminalFixture();
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

    private static Map<String, Object> dimension(
            List<Map<String, Object>> dimensions,
            String dimension
    ) {
        return dimensions.stream()
                .filter(item -> item.get("dimension").equals(dimension))
                .findFirst()
                .orElseThrow();
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

    private static Fixture terminalFixture() {
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

        EnumMap<EvidenceDimension, List<ResolvedEvidence>> evidence =
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
        return fixtureFromResolved(
                resolved,
                UUID.fromString("93333333-3333-4333-8333-333333333333"),
                applicabilityReference,
                null
        );
    }

    private static Fixture computedFixture() {
        EnumMap<EvidenceDimension, DimensionInput> dimensions =
                new EnumMap<>(EvidenceDimension.class);
        EnumMap<EvidenceDimension, List<ResolvedEvidence>> values =
                new EnumMap<>(EvidenceDimension.class);

        EvidenceReference applicability = reference(EvidenceDimension.APPLICABILITY, 1, null);
        put(dimensions, values, EvidenceDimension.APPLICABILITY, applicability,
                new ApplicabilityEvidenceValue(
                        applicability,
                        ApplicabilityStatus.APPLICABLE,
                        "customer-confirmed applicable"
                ));

        EvidenceReference cvss = reference(EvidenceDimension.TECHNICAL_SEVERITY, 2, null);
        put(dimensions, values, EvidenceDimension.TECHNICAL_SEVERITY, cvss,
                new TechnicalSeverityEvidenceValue(
                        cvss,
                        "3.1",
                        new BigDecimal("6.5"),
                        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"
                ));

        EvidenceReference kev = reference(EvidenceDimension.KNOWN_EXPLOITATION, 3, null);
        put(dimensions, values, EvidenceDimension.KNOWN_EXPLOITATION, kev,
                new KnownExploitationEvidenceValue(kev, KevStatus.NOT_LISTED, null, null, null));

        EvidenceReference epss = reference(EvidenceDimension.EXPLOITATION_PROBABILITY, 4, null);
        put(dimensions, values, EvidenceDimension.EXPLOITATION_PROBABILITY, epss,
                new ExploitationProbabilityEvidenceValue(
                        epss,
                        new BigDecimal("0.1"),
                        new BigDecimal("0.7"),
                        "2026.08.22",
                        LocalDate.parse("2026-08-22")
                ));

        EvidenceReference context = reference(EvidenceDimension.ASSET_CONTEXT, 5, null);
        put(dimensions, values, EvidenceDimension.ASSET_CONTEXT, context,
                new AssetContextEvidenceValue(
                        context,
                        Environment.PRODUCTION,
                        "payments",
                        "payments-owner",
                        BusinessCriticality.MODERATE
                ));

        BindingReference reachBinding = binding(
                BindingKind.FINDING_REACHABILITY_SCOPE_LINK_EVENT,
                6
        );
        EvidenceReference reachability = reference(
                EvidenceDimension.NETWORK_REACHABILITY,
                6,
                reachBinding
        );
        put(dimensions, values, EvidenceDimension.NETWORK_REACHABILITY, reachability,
                new NetworkReachabilityEvidenceValue(
                        reachability,
                        OriginScope.INTERNET,
                        "edge-a",
                        TransportProtocol.TCP,
                        443,
                        "https",
                        ReachabilityStatus.REACHABLE,
                        ReachabilityMethod.FIREWALL_POLICY
                ));

        BindingReference impactBinding = binding(
                BindingKind.FINDING_BUSINESS_SERVICE_LINK_EVENT,
                7
        );
        EvidenceReference impact = reference(
                EvidenceDimension.BUSINESS_MISSION_IMPACT,
                7,
                impactBinding
        );
        put(dimensions, values, EvidenceDimension.BUSINESS_MISSION_IMPACT, impact,
                new BusinessMissionImpactEvidenceValue(
                        impact,
                        "payments",
                        "payments",
                        ImpactDimension.AVAILABILITY,
                        ImpactLevel.MODERATE,
                        ImpactMethod.BUSINESS_IMPACT_ANALYSIS,
                        "payment processing interruption"
                ));

        RbvmDecisionInputSnapshot snapshot = RbvmDecisionInputSnapshot.createV3(
                FINDING_ID,
                8,
                POLICY_SHA,
                EVALUATED_AT,
                dimensions
        );
        RbvmResolvedDecisionInput resolved = new RbvmResolvedDecisionInput(snapshot, values);
        return fixtureFromResolved(
                resolved,
                UUID.fromString("94444444-4444-4444-8444-444444444444"),
                applicability,
                reachability
        );
    }

    private static void put(
            EnumMap<EvidenceDimension, DimensionInput> dimensions,
            EnumMap<EvidenceDimension, List<ResolvedEvidence>> values,
            EvidenceDimension dimension,
            EvidenceReference reference,
            ResolvedEvidence resolved
    ) {
        dimensions.put(
                dimension,
                new DimensionInput(dimension, DimensionState.PRESENT, List.of(reference))
        );
        values.put(dimension, List.of(resolved));
    }

    private static EvidenceReference reference(
            EvidenceDimension dimension,
            int ordinal,
            BindingReference binding
    ) {
        String identity = "formula-result-api:" + dimension + ':' + ordinal;
        return new EvidenceReference(
                dimension,
                NativeEvidenceKind.defaultFor(dimension),
                UUID.nameUUIDFromBytes(identity.getBytes(StandardCharsets.UTF_8)),
                Integer.toHexString(ordinal).repeat(64),
                "formula-result-api-self-test-" + dimension.name().toLowerCase(java.util.Locale.ROOT),
                EVALUATED_AT.minusSeconds(300L + ordinal),
                binding
        );
    }

    private static BindingReference binding(BindingKind kind, int ordinal) {
        String identity = "formula-result-api-binding:" + kind + ':' + ordinal;
        return new BindingReference(
                kind,
                UUID.nameUUIDFromBytes(identity.getBytes(StandardCharsets.UTF_8)),
                Integer.toHexString(ordinal + 7).repeat(64),
                "CUSTOMER_CONFIRMED",
                EVALUATED_AT.minusSeconds(120L + ordinal)
        );
    }

    private static Fixture fixtureFromResolved(
            RbvmResolvedDecisionInput resolved,
            UUID resultId,
            EvidenceReference applicabilityReference,
            EvidenceReference reachabilityReference
    ) {
        RbvmFormulaV1.FormulaResult result = RbvmFormulaV1.evaluate(resolved);
        RbvmFormulaV1Explanation explanation = RbvmFormulaV1Explanation.from(resolved, result);
        StoredFormulaResult stored = new StoredFormulaResult(
                resultId,
                resolved.snapshot().snapshotSha256(),
                resolved.snapshot().findingId(),
                resolved.snapshot().evaluatedAt(),
                resolved.snapshot().methodologyRevision(),
                resolved.snapshot().methodologyPolicySha256(),
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
        return new Fixture(
                resolved.snapshot(),
                resolved,
                explanation,
                stored,
                applicabilityReference,
                reachabilityReference
        );
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
            EvidenceReference applicabilityReference,
            EvidenceReference reachabilityReference
    ) {
    }
}
