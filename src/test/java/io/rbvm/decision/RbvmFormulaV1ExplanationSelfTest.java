package io.rbvm.decision;

import io.rbvm.decision.RbvmDecisionInputSnapshot.BindingKind;
import io.rbvm.decision.RbvmDecisionInputSnapshot.BindingReference;
import io.rbvm.decision.RbvmDecisionInputSnapshot.DimensionInput;
import io.rbvm.decision.RbvmDecisionInputSnapshot.DimensionState;
import io.rbvm.decision.RbvmDecisionInputSnapshot.EvidenceReference;
import io.rbvm.decision.RbvmDecisionInputSnapshot.NativeEvidenceKind;
import io.rbvm.decision.RbvmDecisionMethodologyPolicy.EvidenceDimension;
import io.rbvm.decision.RbvmFormulaV1.FormulaResult;
import io.rbvm.decision.RbvmFormulaV1.ResultState;
import io.rbvm.decision.RbvmFormulaV1Explanation.DimensionExplanation;
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

import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.LocalDate;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/** Canonical explanation/replay checks for RBVM_FORMULA_EXPLANATION_CANONICAL_BINARY_V1. */
public final class RbvmFormulaV1ExplanationSelfTest {
    private static final UUID FINDING_ID =
            UUID.fromString("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
    private static final Instant EVALUATED_AT = Instant.parse("2026-08-22T13:30:00Z");
    private static final String POLICY_SHA = "b".repeat(64);

    private RbvmFormulaV1ExplanationSelfTest() {
    }

    public static void main(String[] args) {
        canonicalizesComputedExplanationDeterministically();
        preservesTerminalExplanationWithoutNumericSubstitutes();
        bindsExplanationIdentityToExactEvidenceProvenance();
        rejectsAResultNotProducedByTheExactInput();
        System.out.println("RbvmFormulaV1ExplanationSelfTest: PASS");
    }

    private static void canonicalizesComputedExplanationDeterministically() {
        RbvmResolvedDecisionInput input = fixture(ApplicabilityStatus.APPLICABLE, false, 1);
        FormulaResult result = RbvmFormulaV1.evaluate(input);
        assert result.relativeRiskIndex().equals(new BigDecimal("45.00"));

        RbvmFormulaV1Explanation first = RbvmFormulaV1Explanation.from(input, result);
        RbvmFormulaV1Explanation second = RbvmFormulaV1Explanation.from(input, result);

        assert first.resultState() == ResultState.COMPUTED;
        assert first.formulaSha256().equals(RbvmFormulaV1.FORMULA_SHA256);
        assert first.inputSnapshotSha256().equals(input.snapshot().snapshotSha256());
        assert first.findingId().equals(FINDING_ID);
        assert first.evaluatedAt().equals(EVALUATED_AT);
        assert first.methodologyRevision() == 9;
        assert first.methodologyPolicySha256().equals(POLICY_SHA);
        assert first.finalRiskResult().equals(new BigDecimal("45.00"));
        assert first.reasonCodes().isEmpty();
        assert first.dimensions().size() == EvidenceDimension.values().length;
        assert first.canonicalSha256().matches("[0-9a-f]{64}");
        assert first.canonicalSha256().equals(second.canonicalSha256());
        assert Arrays.equals(first.canonicalPayload(), second.canonicalPayload());
        assert !first.canonicalPayload().equals(second.canonicalPayload());

        for (int index = 0; index < EvidenceDimension.values().length; index++) {
            assert first.dimensions().get(index).dimension() == EvidenceDimension.values()[index];
        }

        DimensionExplanation applicability = dimension(first, EvidenceDimension.APPLICABILITY);
        assert applicability.normalizedValue().equals("APPLICABLE");
        assert applicability.appliedFactorOrTransformId() == null;
        assert applicability.weightedContribution() == null;

        assertFactor(first, EvidenceDimension.TECHNICAL_SEVERITY,
                "0.65", "CVSS_V31_BASE", "0.13");
        assertFactor(first, EvidenceDimension.EXPLOITATION_PROBABILITY,
                "0.1", "EPSS_PROBABILITY", "0.02");
        assertFactor(first, EvidenceDimension.KNOWN_EXPLOITATION,
                "0", "CISA_KEV_MEMBERSHIP", "0");
        assertFactor(first, EvidenceDimension.NETWORK_REACHABILITY,
                "1", "REACHABILITY_STATUS", "0.15");
        assertFactor(first, EvidenceDimension.ASSET_CONTEXT,
                "0.5", "BUSINESS_CRITICALITY", "0.075");
        assertFactor(first, EvidenceDimension.BUSINESS_MISSION_IMPACT,
                "0.5", "BUSINESS_IMPACT_LEVEL", "0.075");

        EvidenceReference reachabilityRef = dimension(
                first,
                EvidenceDimension.NETWORK_REACHABILITY
        ).evidenceReferences().get(0);
        assert reachabilityRef.bindingReference() != null;
        assert reachabilityRef.bindingReference().bindingKind()
                == BindingKind.FINDING_REACHABILITY_SCOPE_LINK_EVENT;
    }

    private static void preservesTerminalExplanationWithoutNumericSubstitutes() {
        RbvmResolvedDecisionInput notApplicableInput = fixture(
                ApplicabilityStatus.NOT_APPLICABLE,
                false,
                2
        );
        FormulaResult notApplicableResult = RbvmFormulaV1.evaluate(notApplicableInput);
        RbvmFormulaV1Explanation notApplicable = RbvmFormulaV1Explanation.from(
                notApplicableInput,
                notApplicableResult
        );
        assert notApplicable.resultState() == ResultState.NOT_APPLICABLE;
        assert notApplicable.reasonCodes().equals(List.of("NOT_APPLICABLE"));
        assert notApplicable.finalRiskResult() == null;
        assert dimension(notApplicable, EvidenceDimension.APPLICABILITY)
                .normalizedValue().equals("NOT_APPLICABLE");
        for (DimensionExplanation entry : notApplicable.dimensions()) {
            assert entry.weightedContribution() == null;
            assert entry.appliedFactorOrTransformId() == null;
        }

        RbvmResolvedDecisionInput missingEpssInput = fixture(
                ApplicabilityStatus.APPLICABLE,
                true,
                3
        );
        FormulaResult missingEpssResult = RbvmFormulaV1.evaluate(missingEpssInput);
        RbvmFormulaV1Explanation missingEpss = RbvmFormulaV1Explanation.from(
                missingEpssInput,
                missingEpssResult
        );
        assert missingEpss.resultState() == ResultState.NON_COMPUTABLE;
        assert missingEpss.reasonCodes().equals(List.of("EXPLOITATION_PROBABILITY_MISSING"));
        assert missingEpss.finalRiskResult() == null;
        DimensionExplanation epss = dimension(
                missingEpss,
                EvidenceDimension.EXPLOITATION_PROBABILITY
        );
        assert epss.state() == DimensionState.MISSING;
        assert epss.evidenceReferences().isEmpty();
        assert epss.normalizedValue() == null;
    }

    private static void bindsExplanationIdentityToExactEvidenceProvenance() {
        RbvmResolvedDecisionInput leftInput = fixture(ApplicabilityStatus.APPLICABLE, false, 10);
        RbvmResolvedDecisionInput rightInput = fixture(ApplicabilityStatus.APPLICABLE, false, 11);
        FormulaResult leftResult = RbvmFormulaV1.evaluate(leftInput);
        FormulaResult rightResult = RbvmFormulaV1.evaluate(rightInput);
        assert leftResult.relativeRiskIndex().equals(rightResult.relativeRiskIndex());

        RbvmFormulaV1Explanation left = RbvmFormulaV1Explanation.from(leftInput, leftResult);
        RbvmFormulaV1Explanation right = RbvmFormulaV1Explanation.from(rightInput, rightResult);
        assert !left.inputSnapshotSha256().equals(right.inputSnapshotSha256());
        assert !left.canonicalSha256().equals(right.canonicalSha256());
        assert !Arrays.equals(left.canonicalPayload(), right.canonicalPayload());
    }

    private static void rejectsAResultNotProducedByTheExactInput() {
        RbvmResolvedDecisionInput input = fixture(ApplicabilityStatus.APPLICABLE, false, 20);
        FormulaResult actual = RbvmFormulaV1.evaluate(input);
        FormulaResult fabricated = new FormulaResult(
                actual.state(),
                actual.reasonCode(),
                actual.formulaId(),
                actual.formulaVersion(),
                actual.formulaSha256(),
                actual.inputContractId(),
                actual.inputSnapshotSha256(),
                actual.findingId(),
                new BigDecimal("46.00"),
                actual.factorContributions()
        );
        boolean rejected = false;
        try {
            RbvmFormulaV1Explanation.from(input, fabricated);
        } catch (IllegalArgumentException expected) {
            rejected = expected.getMessage().contains("exactly match deterministic Formula V1");
        }
        assert rejected;
    }

    private static void assertFactor(
            RbvmFormulaV1Explanation explanation,
            EvidenceDimension dimension,
            String normalized,
            String factorId,
            String contribution
    ) {
        DimensionExplanation entry = dimension(explanation, dimension);
        assert entry.normalizedValue().equals(normalized) : entry;
        assert entry.appliedFactorOrTransformId().equals(factorId) : entry;
        assert entry.weightedContribution().compareTo(new BigDecimal(contribution)) == 0 : entry;
    }

    private static DimensionExplanation dimension(
            RbvmFormulaV1Explanation explanation,
            EvidenceDimension dimension
    ) {
        return explanation.dimensions().stream()
                .filter(value -> value.dimension() == dimension)
                .findFirst()
                .orElseThrow();
    }

    private static RbvmResolvedDecisionInput fixture(
            ApplicabilityStatus applicabilityStatus,
            boolean missingEpss,
            int provenanceVariant
    ) {
        EnumMap<EvidenceDimension, DimensionInput> dimensions =
                new EnumMap<>(EvidenceDimension.class);
        EnumMap<EvidenceDimension, List<ResolvedEvidence>> values =
                new EnumMap<>(EvidenceDimension.class);

        EvidenceReference applicability = reference(
                EvidenceDimension.APPLICABILITY,
                provenanceVariant,
                1,
                null
        );
        put(
                dimensions,
                values,
                EvidenceDimension.APPLICABILITY,
                DimensionState.PRESENT,
                List.of(applicability),
                List.of(new ApplicabilityEvidenceValue(
                        applicability,
                        applicabilityStatus,
                        "explicit test applicability"
                ))
        );

        EvidenceReference cvss = reference(
                EvidenceDimension.TECHNICAL_SEVERITY,
                provenanceVariant,
                2,
                null
        );
        put(
                dimensions,
                values,
                EvidenceDimension.TECHNICAL_SEVERITY,
                DimensionState.PRESENT,
                List.of(cvss),
                List.of(new TechnicalSeverityEvidenceValue(
                        cvss,
                        "3.1",
                        new BigDecimal("6.5"),
                        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"
                ))
        );

        EvidenceReference kev = reference(
                EvidenceDimension.KNOWN_EXPLOITATION,
                provenanceVariant,
                3,
                null
        );
        put(
                dimensions,
                values,
                EvidenceDimension.KNOWN_EXPLOITATION,
                DimensionState.PRESENT,
                List.of(kev),
                List.of(new KnownExploitationEvidenceValue(
                        kev,
                        KevStatus.NOT_LISTED,
                        null,
                        null,
                        null
                ))
        );

        if (missingEpss) {
            put(
                    dimensions,
                    values,
                    EvidenceDimension.EXPLOITATION_PROBABILITY,
                    DimensionState.MISSING,
                    List.of(),
                    List.of()
            );
        } else {
            EvidenceReference epss = reference(
                    EvidenceDimension.EXPLOITATION_PROBABILITY,
                    provenanceVariant,
                    4,
                    null
            );
            put(
                    dimensions,
                    values,
                    EvidenceDimension.EXPLOITATION_PROBABILITY,
                    DimensionState.PRESENT,
                    List.of(epss),
                    List.of(new ExploitationProbabilityEvidenceValue(
                            epss,
                            new BigDecimal("0.1"),
                            new BigDecimal("0.7"),
                            "2026.08.22",
                            LocalDate.parse("2026-08-22")
                    ))
            );
        }

        EvidenceReference context = reference(
                EvidenceDimension.ASSET_CONTEXT,
                provenanceVariant,
                5,
                null
        );
        put(
                dimensions,
                values,
                EvidenceDimension.ASSET_CONTEXT,
                DimensionState.PRESENT,
                List.of(context),
                List.of(new AssetContextEvidenceValue(
                        context,
                        Environment.PRODUCTION,
                        "payments",
                        "payments-owner",
                        BusinessCriticality.MODERATE
                ))
        );

        BindingReference reachBinding = binding(
                BindingKind.FINDING_REACHABILITY_SCOPE_LINK_EVENT,
                provenanceVariant,
                6
        );
        EvidenceReference reachability = reference(
                EvidenceDimension.NETWORK_REACHABILITY,
                provenanceVariant,
                6,
                reachBinding
        );
        put(
                dimensions,
                values,
                EvidenceDimension.NETWORK_REACHABILITY,
                DimensionState.PRESENT,
                List.of(reachability),
                List.of(new NetworkReachabilityEvidenceValue(
                        reachability,
                        OriginScope.INTERNET,
                        "edge-a",
                        TransportProtocol.TCP,
                        443,
                        "https",
                        ReachabilityStatus.REACHABLE,
                        ReachabilityMethod.FIREWALL_POLICY
                ))
        );

        BindingReference impactBinding = binding(
                BindingKind.FINDING_BUSINESS_SERVICE_LINK_EVENT,
                provenanceVariant,
                7
        );
        EvidenceReference impact = reference(
                EvidenceDimension.BUSINESS_MISSION_IMPACT,
                provenanceVariant,
                7,
                impactBinding
        );
        put(
                dimensions,
                values,
                EvidenceDimension.BUSINESS_MISSION_IMPACT,
                DimensionState.PRESENT,
                List.of(impact),
                List.of(new BusinessMissionImpactEvidenceValue(
                        impact,
                        "payments",
                        "payments",
                        ImpactDimension.AVAILABILITY,
                        ImpactLevel.MODERATE,
                        ImpactMethod.BUSINESS_IMPACT_ANALYSIS,
                        "payment processing interruption"
                ))
        );

        RbvmDecisionInputSnapshot snapshot = RbvmDecisionInputSnapshot.createV3(
                FINDING_ID,
                9,
                POLICY_SHA,
                EVALUATED_AT,
                dimensions
        );
        return new RbvmResolvedDecisionInput(snapshot, Map.copyOf(values));
    }

    private static void put(
            EnumMap<EvidenceDimension, DimensionInput> dimensions,
            EnumMap<EvidenceDimension, List<ResolvedEvidence>> values,
            EvidenceDimension dimension,
            DimensionState state,
            List<EvidenceReference> references,
            List<? extends ResolvedEvidence> resolved
    ) {
        dimensions.put(dimension, new DimensionInput(dimension, state, references));
        values.put(dimension, List.copyOf(resolved));
    }

    private static EvidenceReference reference(
            EvidenceDimension dimension,
            int variant,
            int ordinal,
            BindingReference binding
    ) {
        String identity = "formula-explanation:" + variant + ":" + dimension + ":" + ordinal;
        return new EvidenceReference(
                dimension,
                NativeEvidenceKind.defaultFor(dimension),
                UUID.nameUUIDFromBytes(identity.getBytes(StandardCharsets.UTF_8)),
                hex(variant + ordinal).repeat(64),
                "formula-explanation-self-test-" + dimension.name().toLowerCase(java.util.Locale.ROOT),
                EVALUATED_AT.minusSeconds(300L + ordinal),
                binding
        );
    }

    private static BindingReference binding(
            BindingKind kind,
            int variant,
            int ordinal
    ) {
        String identity = "formula-explanation-binding:" + variant + ":" + kind + ":" + ordinal;
        return new BindingReference(
                kind,
                UUID.nameUUIDFromBytes(identity.getBytes(StandardCharsets.UTF_8)),
                hex(variant + ordinal + 7).repeat(64),
                "CUSTOMER_CONFIRMED",
                EVALUATED_AT.minusSeconds(120L + ordinal)
        );
    }

    private static String hex(int seed) {
        return Integer.toHexString(Math.floorMod(seed, 15) + 1);
    }
}
