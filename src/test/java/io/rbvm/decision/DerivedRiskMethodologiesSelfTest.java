package io.rbvm.decision;

import io.rbvm.decision.RbvmDecisionInputSnapshot.BindingKind;
import io.rbvm.decision.RbvmDecisionInputSnapshot.BindingReference;
import io.rbvm.decision.RbvmDecisionInputSnapshot.DimensionInput;
import io.rbvm.decision.RbvmDecisionInputSnapshot.DimensionState;
import io.rbvm.decision.RbvmDecisionInputSnapshot.EvidenceReference;
import io.rbvm.decision.RbvmDecisionInputSnapshot.NativeEvidenceKind;
import io.rbvm.decision.RbvmDecisionMethodologyPolicy.EvidenceDimension;
import io.rbvm.decision.RbvmDerivedRiskMethodology.Evaluation;
import io.rbvm.decision.RbvmDerivedRiskMethodology.ResultState;
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
import io.rbvm.decision.RbvmResolvedDecisionInput.KnownRansomwareCampaignUse;
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
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/** Runtime acceptance checks for the first two published-model-derived RBVM methodologies. */
public final class DerivedRiskMethodologiesSelfTest {
    private static final UUID FINDING_ID =
            UUID.fromString("22222222-2222-4222-8222-222222222222");
    private static final Instant EVALUATED_AT = Instant.parse("2026-08-22T18:30:00Z");
    private static final String POLICY_SHA = "b".repeat(64);

    private DerivedRiskMethodologiesSelfTest() {
    }

    public static void main(String[] args) {
        catalogIsExplicitAndNonPrecedential();
        computesFrozenProfiles();
        preservesEvidenceAndApplicabilityGates();
        keepsProviderEquationSeparateFromRbvmMapping();
        System.out.println("DerivedRiskMethodologiesSelfTest: PASS");
    }

    private static void catalogIsExplicitAndNonPrecedential() {
        List<RbvmDerivedRiskMethodology.Definition> definitions =
                RbvmDerivedRiskMethodologyCatalog.definitions();
        assert definitions.size() == 2;
        assert definitions.stream().allMatch(value ->
                value.classification() == RbvmDerivedRiskMethodology.Classification.STANDARD_DERIVED);
        assert definitions.stream().map(RbvmDerivedRiskMethodology.Definition::methodologyId).toList()
                .equals(List.of(
                        MicrosoftProbabilityDamageDerivedV1.METHODOLOGY_ID,
                        OwaspDerivedRiskV1.METHODOLOGY_ID
                ));
        assert RbvmDerivedRiskMethodologyCatalog.find(OwaspDerivedRiskV1.METHODOLOGY_ID).isPresent();
        assert RbvmDerivedRiskMethodologyCatalog.find("owasp_derived_rbvm_v1").isPresent();
        assert RbvmDerivedRiskMethodologyCatalog.find("missing").isEmpty();
    }

    private static void computesFrozenProfiles() {
        RbvmResolvedDecisionInput base = scenario().build();

        Evaluation owasp = OwaspDerivedRiskV1.INSTANCE.evaluate(base);
        assertComputed(owasp, "16.3350");
        assert owasp.rating().equals("MEDIUM");
        assertDecimal(measure(owasp, "LIKELIHOOD").value(), "3.3000");
        assertDecimal(measure(owasp, "IMPACT").value(), "4.9500");

        Evaluation microsoft = MicrosoftProbabilityDamageDerivedV1.INSTANCE.evaluate(base);
        assertComputed(microsoft, "25.5850");
        assert microsoft.rating() == null;
        assertDecimal(measure(microsoft, "PROBABILITY").value(), "4.3000");
        assertDecimal(measure(microsoft, "DAMAGE_POTENTIAL").value(), "5.9500");

        RbvmResolvedDecisionInput adverse = scenario()
                .withCvss("9.8")
                .withEpss("0.8")
                .withKev(KevStatus.LISTED)
                .withCriticality(BusinessCriticality.MISSION_CRITICAL)
                .withImpact(ImpactLevel.SEVERE)
                .build();

        Evaluation adverseOwasp = OwaspDerivedRiskV1.INSTANCE.evaluate(adverse);
        assertComputed(adverseOwasp, "75.0960");
        assert adverseOwasp.rating().equals("CRITICAL");

        Evaluation adverseMicrosoft = MicrosoftProbabilityDamageDerivedV1.INSTANCE.evaluate(adverse);
        assertComputed(adverseMicrosoft, "93.4360");

        assert OwaspDerivedRiskV1.INSTANCE.evaluate(base).equals(owasp);
        assert MicrosoftProbabilityDamageDerivedV1.INSTANCE.evaluate(base).equals(microsoft);
    }

    private static void preservesEvidenceAndApplicabilityGates() {
        for (RbvmDerivedRiskMethodology methodology : List.of(
                OwaspDerivedRiskV1.INSTANCE,
                MicrosoftProbabilityDamageDerivedV1.INSTANCE
        )) {
            Evaluation notApplicable = methodology.evaluate(
                    scenario().withApplicability(ApplicabilityStatus.NOT_APPLICABLE).build());
            assertTerminal(notApplicable, ResultState.NOT_APPLICABLE, "NOT_APPLICABLE");

            Evaluation missingEpss = methodology.evaluate(scenario()
                    .withState(EvidenceDimension.EXPLOITATION_PROBABILITY, DimensionState.MISSING)
                    .build());
            assertTerminal(
                    missingEpss,
                    ResultState.NON_COMPUTABLE,
                    "EXPLOITATION_PROBABILITY_MISSING"
            );

            Evaluation staleCvss = methodology.evaluate(scenario()
                    .withState(EvidenceDimension.TECHNICAL_SEVERITY, DimensionState.STALE)
                    .build());
            assertTerminal(staleCvss, ResultState.NON_COMPUTABLE, "TECHNICAL_SEVERITY_STALE");

            Evaluation unknownCriticality = methodology.evaluate(scenario()
                    .withCriticality(BusinessCriticality.UNKNOWN)
                    .build());
            assertTerminal(
                    unknownCriticality,
                    ResultState.NON_COMPUTABLE,
                    "BUSINESS_CRITICALITY_UNKNOWN"
            );

            Evaluation unknownReachability = methodology.evaluate(scenario()
                    .withReachability(ReachabilityStatus.UNKNOWN)
                    .build());
            assertTerminal(
                    unknownReachability,
                    ResultState.NON_COMPUTABLE,
                    "REACHABILITY_VALUE_UNKNOWN"
            );
        }
    }

    private static void keepsProviderEquationSeparateFromRbvmMapping() {
        assert OwaspDerivedRiskV1.INSTANCE.definition().sourceEquation()
                .equals("Risk = Likelihood * Impact");
        assert OwaspDerivedRiskV1.INSTANCE.definition().methodologySha256()
                .equals("03a72c8479e834174dc6985580d2543ad61b01628a79da5d59c5b5785e80c9c3");
        assert MicrosoftProbabilityDamageDerivedV1.INSTANCE.definition().sourceEquation()
                .equals("Risk = Probability * Damage Potential");
        assert MicrosoftProbabilityDamageDerivedV1.INSTANCE.definition().methodologySha256()
                .equals("b22520b7b5a7d5f06782270feaf6729089ebafef79f20aea43dddf18396dcce6");
    }

    private static RbvmDerivedRiskMethodology.Measure measure(Evaluation result, String id) {
        return result.measures().stream()
                .filter(value -> value.measureId().equals(id))
                .findFirst()
                .orElseThrow(() -> new AssertionError("missing measure " + id));
    }

    private static void assertComputed(Evaluation result, String expected) {
        assert result.state() == ResultState.COMPUTED : result;
        assert result.reasonCode() == null;
        assert result.numericScore() != null;
        assert result.numericScore().equals(new BigDecimal(expected))
                : "expected " + expected + " but got " + result.numericScore();
        assert result.inputContractId().equals(RbvmDecisionInputSnapshot.V3_ID);
        assert result.findingId().equals(FINDING_ID);
        assert !result.measures().isEmpty();
    }

    private static void assertTerminal(Evaluation result, ResultState state, String reason) {
        assert result.state() == state : result;
        assert result.reasonCode().equals(reason) : result;
        assert result.numericScore() == null;
        assert result.numericScale() == null;
        assert result.rating() == null;
        assert result.measures().isEmpty();
    }

    private static void assertDecimal(BigDecimal actual, String expected) {
        assert actual.compareTo(new BigDecimal(expected)) == 0
                : "expected " + expected + " but got " + actual;
    }

    private static Scenario scenario() {
        return new Scenario();
    }

    private static final class Scenario {
        private final EnumMap<EvidenceDimension, DimensionState> states =
                new EnumMap<>(EvidenceDimension.class);
        private ApplicabilityStatus applicability = ApplicabilityStatus.APPLICABLE;
        private BigDecimal cvss = new BigDecimal("6.5");
        private KevStatus kev = KevStatus.NOT_LISTED;
        private BigDecimal epss = new BigDecimal("0.1");
        private BusinessCriticality criticality = BusinessCriticality.MODERATE;
        private ReachabilityStatus reachability = ReachabilityStatus.REACHABLE;
        private ImpactLevel impact = ImpactLevel.MODERATE;

        private Scenario() {
            for (EvidenceDimension dimension : EvidenceDimension.values()) {
                states.put(dimension, DimensionState.PRESENT);
            }
        }

        Scenario withState(EvidenceDimension dimension, DimensionState state) {
            states.put(dimension, state);
            return this;
        }

        Scenario withApplicability(ApplicabilityStatus value) {
            applicability = value;
            return this;
        }

        Scenario withCvss(String value) {
            cvss = new BigDecimal(value);
            return this;
        }

        Scenario withKev(KevStatus value) {
            kev = value;
            return this;
        }

        Scenario withEpss(String value) {
            epss = new BigDecimal(value);
            return this;
        }

        Scenario withCriticality(BusinessCriticality value) {
            criticality = value;
            return this;
        }

        Scenario withReachability(ReachabilityStatus value) {
            reachability = value;
            return this;
        }

        Scenario withImpact(ImpactLevel value) {
            impact = value;
            return this;
        }

        RbvmResolvedDecisionInput build() {
            EnumMap<EvidenceDimension, DimensionInput> dimensions =
                    new EnumMap<>(EvidenceDimension.class);
            EnumMap<EvidenceDimension, List<ResolvedEvidence>> values =
                    new EnumMap<>(EvidenceDimension.class);

            addApplicability(dimensions, values);
            addCvss(dimensions, values);
            addKev(dimensions, values);
            addEpss(dimensions, values);
            addContext(dimensions, values);
            addReachability(dimensions, values);
            addImpact(dimensions, values);

            RbvmDecisionInputSnapshot snapshot = RbvmDecisionInputSnapshot.createV3(
                    FINDING_ID,
                    10,
                    POLICY_SHA,
                    EVALUATED_AT,
                    dimensions
            );
            return new RbvmResolvedDecisionInput(snapshot, Map.copyOf(values));
        }

        private void addApplicability(
                EnumMap<EvidenceDimension, DimensionInput> dimensions,
                EnumMap<EvidenceDimension, List<ResolvedEvidence>> values
        ) {
            EvidenceDimension dimension = EvidenceDimension.APPLICABILITY;
            List<EvidenceReference> refs = references(dimension, genericCount(dimension), false);
            List<ResolvedEvidence> resolved = new ArrayList<>();
            for (EvidenceReference ref : refs) {
                resolved.add(new ApplicabilityEvidenceValue(
                        ref,
                        applicability,
                        "derived risk methodology self-test"
                ));
            }
            put(dimensions, values, dimension, refs, resolved);
        }

        private void addCvss(
                EnumMap<EvidenceDimension, DimensionInput> dimensions,
                EnumMap<EvidenceDimension, List<ResolvedEvidence>> values
        ) {
            EvidenceDimension dimension = EvidenceDimension.TECHNICAL_SEVERITY;
            List<EvidenceReference> refs = references(dimension, genericCount(dimension), false);
            List<ResolvedEvidence> resolved = new ArrayList<>();
            for (EvidenceReference ref : refs) {
                resolved.add(new TechnicalSeverityEvidenceValue(
                        ref,
                        "3.1",
                        cvss,
                        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"
                ));
            }
            put(dimensions, values, dimension, refs, resolved);
        }

        private void addKev(
                EnumMap<EvidenceDimension, DimensionInput> dimensions,
                EnumMap<EvidenceDimension, List<ResolvedEvidence>> values
        ) {
            EvidenceDimension dimension = EvidenceDimension.KNOWN_EXPLOITATION;
            List<EvidenceReference> refs = references(dimension, genericCount(dimension), false);
            List<ResolvedEvidence> resolved = new ArrayList<>();
            for (EvidenceReference ref : refs) {
                boolean listed = kev == KevStatus.LISTED;
                resolved.add(new KnownExploitationEvidenceValue(
                        ref,
                        kev,
                        listed ? LocalDate.parse("2026-08-01") : null,
                        listed ? LocalDate.parse("2026-08-30") : null,
                        listed ? KnownRansomwareCampaignUse.UNKNOWN : null
                ));
            }
            put(dimensions, values, dimension, refs, resolved);
        }

        private void addEpss(
                EnumMap<EvidenceDimension, DimensionInput> dimensions,
                EnumMap<EvidenceDimension, List<ResolvedEvidence>> values
        ) {
            EvidenceDimension dimension = EvidenceDimension.EXPLOITATION_PROBABILITY;
            List<EvidenceReference> refs = references(dimension, genericCount(dimension), false);
            List<ResolvedEvidence> resolved = new ArrayList<>();
            for (EvidenceReference ref : refs) {
                resolved.add(new ExploitationProbabilityEvidenceValue(
                        ref,
                        epss,
                        new BigDecimal("0.7"),
                        "2026.08.22",
                        LocalDate.parse("2026-08-22")
                ));
            }
            put(dimensions, values, dimension, refs, resolved);
        }

        private void addContext(
                EnumMap<EvidenceDimension, DimensionInput> dimensions,
                EnumMap<EvidenceDimension, List<ResolvedEvidence>> values
        ) {
            EvidenceDimension dimension = EvidenceDimension.ASSET_CONTEXT;
            List<EvidenceReference> refs = references(dimension, genericCount(dimension), false);
            List<ResolvedEvidence> resolved = new ArrayList<>();
            for (EvidenceReference ref : refs) {
                resolved.add(new AssetContextEvidenceValue(
                        ref,
                        Environment.PRODUCTION,
                        "payments",
                        "payments-owner",
                        criticality
                ));
            }
            put(dimensions, values, dimension, refs, resolved);
        }

        private void addReachability(
                EnumMap<EvidenceDimension, DimensionInput> dimensions,
                EnumMap<EvidenceDimension, List<ResolvedEvidence>> values
        ) {
            EvidenceDimension dimension = EvidenceDimension.NETWORK_REACHABILITY;
            List<EvidenceReference> refs = references(dimension, genericCount(dimension), true);
            List<ResolvedEvidence> resolved = new ArrayList<>();
            for (int index = 0; index < refs.size(); index++) {
                resolved.add(new NetworkReachabilityEvidenceValue(
                        refs.get(index),
                        OriginScope.INTERNET,
                        "edge-" + index,
                        TransportProtocol.TCP,
                        443 + index,
                        "https",
                        reachability,
                        ReachabilityMethod.FIREWALL_POLICY
                ));
            }
            put(dimensions, values, dimension, refs, resolved);
        }

        private void addImpact(
                EnumMap<EvidenceDimension, DimensionInput> dimensions,
                EnumMap<EvidenceDimension, List<ResolvedEvidence>> values
        ) {
            EvidenceDimension dimension = EvidenceDimension.BUSINESS_MISSION_IMPACT;
            List<EvidenceReference> refs = references(dimension, genericCount(dimension), true);
            List<ResolvedEvidence> resolved = new ArrayList<>();
            for (int index = 0; index < refs.size(); index++) {
                resolved.add(new BusinessMissionImpactEvidenceValue(
                        refs.get(index),
                        "payments",
                        "payments",
                        index == 0 ? ImpactDimension.AVAILABILITY : ImpactDimension.INTEGRITY,
                        impact,
                        ImpactMethod.BUSINESS_IMPACT_ANALYSIS,
                        "derived risk methodology self-test"
                ));
            }
            put(dimensions, values, dimension, refs, resolved);
        }

        private int genericCount(EvidenceDimension dimension) {
            return switch (states.get(dimension)) {
                case MISSING -> 0;
                case AMBIGUOUS -> 2;
                case PRESENT, STALE -> 1;
            };
        }

        private List<EvidenceReference> references(
                EvidenceDimension dimension,
                int count,
                boolean associationBound
        ) {
            List<EvidenceReference> refs = new ArrayList<>();
            for (int index = 0; index < count; index++) {
                BindingReference binding = associationBound
                        ? binding(dimension, index)
                        : null;
                String identity = "derived-risk:" + dimension + ":" + index;
                int seed = dimension.ordinal() * 7 + index + 1;
                refs.add(new EvidenceReference(
                        dimension,
                        NativeEvidenceKind.defaultFor(dimension),
                        UUID.nameUUIDFromBytes(identity.getBytes(StandardCharsets.UTF_8)),
                        hex(seed).repeat(64),
                        "derived-risk-self-test",
                        EVALUATED_AT.minusSeconds(300L + seed),
                        binding
                ));
            }
            return List.copyOf(refs);
        }

        private BindingReference binding(EvidenceDimension dimension, int index) {
            BindingKind kind = dimension == EvidenceDimension.NETWORK_REACHABILITY
                    ? BindingKind.FINDING_REACHABILITY_SCOPE_LINK_EVENT
                    : BindingKind.FINDING_BUSINESS_SERVICE_LINK_EVENT;
            String identity = "derived-risk-binding:" + kind + ":" + index;
            int seed = 12 + dimension.ordinal() * 5 + index;
            return new BindingReference(
                    kind,
                    UUID.nameUUIDFromBytes(identity.getBytes(StandardCharsets.UTF_8)),
                    hex(seed).repeat(64),
                    "CUSTOMER_CONFIRMED",
                    EVALUATED_AT.minusSeconds(120L + seed)
            );
        }

        private void put(
                EnumMap<EvidenceDimension, DimensionInput> dimensions,
                EnumMap<EvidenceDimension, List<ResolvedEvidence>> values,
                EvidenceDimension dimension,
                List<EvidenceReference> refs,
                List<ResolvedEvidence> resolved
        ) {
            dimensions.put(
                    dimension,
                    new DimensionInput(dimension, states.get(dimension), refs)
            );
            values.put(dimension, List.copyOf(resolved));
        }

        private String hex(int seed) {
            return Integer.toHexString(Math.floorMod(seed, 15) + 1);
        }
    }
}
