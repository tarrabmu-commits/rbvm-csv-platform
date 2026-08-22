package io.rbvm.decision;

import io.rbvm.decision.RbvmDecisionInputSnapshot.BindingKind;
import io.rbvm.decision.RbvmDecisionInputSnapshot.BindingReference;
import io.rbvm.decision.RbvmDecisionInputSnapshot.DimensionInput;
import io.rbvm.decision.RbvmDecisionInputSnapshot.DimensionState;
import io.rbvm.decision.RbvmDecisionInputSnapshot.EvidenceReference;
import io.rbvm.decision.RbvmDecisionInputSnapshot.NativeEvidenceKind;
import io.rbvm.decision.RbvmDecisionMethodologyPolicy.EvidenceDimension;
import io.rbvm.decision.RbvmFormulaV1.FactorContribution;
import io.rbvm.decision.RbvmFormulaV1.FormulaResult;
import io.rbvm.decision.RbvmFormulaV1.ResultState;
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

/** Exact runtime checks for the accepted RBVM_FORMULA_V1 contract. */
public final class RbvmFormulaV1SelfTest {
    private static final UUID FINDING_ID =
            UUID.fromString("11111111-1111-4111-8111-111111111111");
    private static final Instant EVALUATED_AT = Instant.parse("2026-08-22T12:00:00Z");
    private static final String POLICY_SHA = "a".repeat(64);

    private RbvmFormulaV1SelfTest() {
    }

    public static void main(String[] args) {
        computesFrozenProfilesAndContributions();
        preservesAllEvidenceStateGates();
        preservesTerminalAndStructuralValueGates();
        preservesArithmeticExclusionsAndImpactReducer();
        rejectsNonV3AndReplaysDeterministically();
        System.out.println("RbvmFormulaV1SelfTest: PASS");
    }

    private static void computesFrozenProfilesAndContributions() {
        FormulaResult base = RbvmFormulaV1.evaluate(scenario().build());
        assertComputed(base, "45.00");
        assert base.formulaId().equals(RbvmFormulaV1.FORMULA_ID);
        assert base.formulaVersion() == RbvmFormulaV1.FORMULA_VERSION;
        assert base.formulaSha256().equals(
                "88bf31f510089b4209b1ffcf1c15b39fef60548209875334f084888316e9028e");
        assert base.inputContractId().equals(RbvmDecisionInputSnapshot.V3_ID);
        assert base.findingId().equals(FINDING_ID);

        List<String> factorIds = base.factorContributions().stream()
                .map(FactorContribution::factorId)
                .toList();
        assert factorIds.equals(List.of(
                "CVSS_V31_BASE",
                "EPSS_PROBABILITY",
                "CISA_KEV_MEMBERSHIP",
                "REACHABILITY_STATUS",
                "BUSINESS_CRITICALITY",
                "BUSINESS_IMPACT_LEVEL"
        ));
        assertDecimal(factor(base, "CVSS_V31_BASE").weightedContribution(), "0.13");
        assertDecimal(factor(base, "EPSS_PROBABILITY").weightedContribution(), "0.02");
        assertDecimal(factor(base, "CISA_KEV_MEMBERSHIP").weightedContribution(), "0");
        assertDecimal(factor(base, "REACHABILITY_STATUS").weightedContribution(), "0.15");
        assertDecimal(factor(base, "BUSINESS_CRITICALITY").weightedContribution(), "0.075");
        assertDecimal(factor(base, "BUSINESS_IMPACT_LEVEL").weightedContribution(), "0.075");

        assertComputed(RbvmFormulaV1.evaluate(scenario()
                .withCvss("9.8")
                .withKev(KevStatus.LISTED)
                .withEpss("0.8", "0.99")
                .withCriticality(BusinessCriticality.MISSION_CRITICAL)
                .withImpact(List.of(new ImpactSpec(
                        "payments", ImpactDimension.AVAILABILITY, ImpactLevel.SEVERE)))
                .build()), "95.60");

        assertComputed(RbvmFormulaV1.evaluate(scenario()
                .withCvss("9.8")
                .withKev(KevStatus.NOT_LISTED)
                .withEpss("0.01", "0.2")
                .build()), "49.80");

        assertComputed(RbvmFormulaV1.evaluate(scenario()
                .withCvss("6")
                .withKev(KevStatus.LISTED)
                .withEpss("0.65", "0.97")
                .build()), "70.00");

        assertComputed(RbvmFormulaV1.evaluate(scenario()
                .withCvss("9")
                .withEpss("0.1", "0.7")
                .withCriticality(BusinessCriticality.LOW)
                .withReachability(List.of(new ReachSpec(
                        OriginScope.INTERNET,
                        "edge-a",
                        TransportProtocol.TCP,
                        443,
                        ReachabilityStatus.NOT_REACHABLE)))
                .withImpact(List.of(new ImpactSpec(
                        "payments", ImpactDimension.AVAILABILITY, ImpactLevel.LOW)))
                .build()), "27.50");

        assertComputed(RbvmFormulaV1.evaluate(scenario()
                .withCvss("6.5")
                .withCriticality(BusinessCriticality.MISSION_CRITICAL)
                .withImpact(List.of(new ImpactSpec(
                        "payments", ImpactDimension.AVAILABILITY, ImpactLevel.SEVERE)))
                .build()), "60.00");
    }

    private static void preservesAllEvidenceStateGates() {
        for (EvidenceDimension dimension : EvidenceDimension.values()) {
            for (DimensionState state : List.of(
                    DimensionState.MISSING,
                    DimensionState.STALE,
                    DimensionState.AMBIGUOUS
            )) {
                FormulaResult result = RbvmFormulaV1.evaluate(
                        scenario().withState(dimension, state).build()
                );
                assertTerminal(
                        result,
                        ResultState.NON_COMPUTABLE,
                        dimension.name() + "_" + state.name()
                );
            }
        }
    }

    private static void preservesTerminalAndStructuralValueGates() {
        assertTerminal(
                RbvmFormulaV1.evaluate(
                        scenario().withApplicability(ApplicabilityStatus.NOT_APPLICABLE).build()),
                ResultState.NOT_APPLICABLE,
                "NOT_APPLICABLE"
        );
        assertTerminal(
                RbvmFormulaV1.evaluate(
                        scenario().withApplicability(ApplicabilityStatus.UNKNOWN).build()),
                ResultState.NON_COMPUTABLE,
                "APPLICABILITY_UNKNOWN"
        );
        assertTerminal(
                RbvmFormulaV1.evaluate(scenario()
                        .withCriticality(BusinessCriticality.UNKNOWN)
                        .build()),
                ResultState.NON_COMPUTABLE,
                "BUSINESS_CRITICALITY_UNKNOWN"
        );
        assertTerminal(
                RbvmFormulaV1.evaluate(scenario()
                        .withReachability(List.of(new ReachSpec(
                                OriginScope.INTERNET,
                                "edge-a",
                                TransportProtocol.TCP,
                                443,
                                ReachabilityStatus.UNKNOWN)))
                        .build()),
                ResultState.NON_COMPUTABLE,
                "REACHABILITY_VALUE_UNKNOWN"
        );
        assertTerminal(
                RbvmFormulaV1.evaluate(scenario()
                        .withImpact(List.of(new ImpactSpec(
                                "payments",
                                ImpactDimension.AVAILABILITY,
                                ImpactLevel.UNKNOWN)))
                        .build()),
                ResultState.NON_COMPUTABLE,
                "BUSINESS_IMPACT_VALUE_UNKNOWN"
        );
        assertTerminal(
                RbvmFormulaV1.evaluate(scenario()
                        .withReachability(List.of(
                                new ReachSpec(
                                        OriginScope.INTERNET,
                                        "edge-a",
                                        TransportProtocol.TCP,
                                        443,
                                        ReachabilityStatus.REACHABLE),
                                new ReachSpec(
                                        OriginScope.INTERNAL_ENTERPRISE,
                                        "corp-a",
                                        TransportProtocol.TCP,
                                        8443,
                                        ReachabilityStatus.REACHABLE)
                        ))
                        .build()),
                ResultState.NON_COMPUTABLE,
                "REACHABILITY_MULTI_SUBGRAIN"
        );
        assertTerminal(
                RbvmFormulaV1.evaluate(scenario()
                        .withImpact(List.of(
                                new ImpactSpec(
                                        "payments",
                                        ImpactDimension.AVAILABILITY,
                                        ImpactLevel.HIGH),
                                new ImpactSpec(
                                        "identity",
                                        ImpactDimension.AVAILABILITY,
                                        ImpactLevel.HIGH)
                        ))
                        .build()),
                ResultState.NON_COMPUTABLE,
                "BUSINESS_IMPACT_MULTI_SERVICE"
        );

        // CISA_KEV_CSV_V1 represents no usable KEV catalog evidence as absence of a row,
        // so the exact native runtime reaches the approved KNOWN_EXPLOITATION_MISSING gate.
        assertTerminal(
                RbvmFormulaV1.evaluate(scenario()
                        .withState(EvidenceDimension.KNOWN_EXPLOITATION, DimensionState.MISSING)
                        .build()),
                ResultState.NON_COMPUTABLE,
                "KNOWN_EXPLOITATION_MISSING"
        );
    }

    private static void preservesArithmeticExclusionsAndImpactReducer() {
        FormulaResult base = RbvmFormulaV1.evaluate(scenario().build());
        FormulaResult differentPercentile = RbvmFormulaV1.evaluate(
                scenario().withEpss("0.1", "0.99").build());
        FormulaResult differentEnvironment = RbvmFormulaV1.evaluate(
                scenario().withEnvironment(Environment.DEVELOPMENT).build());
        FormulaResult differentOwner = RbvmFormulaV1.evaluate(
                scenario().withOwner("new-payments-owner").build());
        FormulaResult differentServiceLabel = RbvmFormulaV1.evaluate(
                scenario().withContextService("settlement-ui-label").build());

        assert base.relativeRiskIndex().equals(differentPercentile.relativeRiskIndex());
        assert base.relativeRiskIndex().equals(differentEnvironment.relativeRiskIndex());
        assert base.relativeRiskIndex().equals(differentOwner.relativeRiskIndex());
        assert base.relativeRiskIndex().equals(differentServiceLabel.relativeRiskIndex());

        FormulaResult multiDimensionSameService = RbvmFormulaV1.evaluate(scenario()
                .withImpact(List.of(
                        new ImpactSpec(
                                "payments",
                                ImpactDimension.AVAILABILITY,
                                ImpactLevel.MODERATE),
                        new ImpactSpec(
                                "payments",
                                ImpactDimension.INTEGRITY,
                                ImpactLevel.HIGH)
                ))
                .build());
        assertComputed(multiDimensionSameService, "48.75");
        assertDecimal(
                factor(multiDimensionSameService, "BUSINESS_IMPACT_LEVEL").normalizedValue(),
                "0.75"
        );
    }

    private static void rejectsNonV3AndReplaysDeterministically() {
        RbvmResolvedDecisionInput input = scenario().build();
        FormulaResult first = RbvmFormulaV1.evaluate(input);
        FormulaResult second = RbvmFormulaV1.evaluate(input);
        assert first.equals(second);
        assert first.inputSnapshotSha256().equals(input.snapshot().snapshotSha256());

        boolean rejected = false;
        try {
            RbvmFormulaV1.evaluate(scenario()
                    .withContract(RbvmDecisionInputSnapshot.V2_ID)
                    .build());
        } catch (IllegalArgumentException expected) {
            rejected = expected.getMessage().contains("SNAPSHOT_V3");
        }
        assert rejected : "Formula V1 must reject non-V3 Decision Inputs";
    }

    private static FactorContribution factor(FormulaResult result, String factorId) {
        return result.factorContributions().stream()
                .filter(value -> value.factorId().equals(factorId))
                .findFirst()
                .orElseThrow(() -> new AssertionError("missing factor " + factorId));
    }

    private static void assertComputed(FormulaResult result, String expected) {
        assert result.state() == ResultState.COMPUTED : result;
        assert result.reasonCode() == null;
        assert result.relativeRiskIndex() != null;
        assert result.relativeRiskIndex().scale() == 2;
        assert result.relativeRiskIndex().equals(new BigDecimal(expected))
                : "expected " + expected + " but got " + result.relativeRiskIndex();
        assert result.factorContributions().size() == 6;
    }

    private static void assertTerminal(
            FormulaResult result,
            ResultState state,
            String reasonCode
    ) {
        assert result.state() == state : result;
        assert result.reasonCode().equals(reasonCode) : result;
        assert result.relativeRiskIndex() == null;
        assert result.factorContributions().isEmpty();
    }

    private static void assertDecimal(BigDecimal actual, String expected) {
        assert actual.compareTo(new BigDecimal(expected)) == 0
                : "expected decimal " + expected + " but got " + actual;
    }

    private static Scenario scenario() {
        return new Scenario();
    }

    private record ReachSpec(
            OriginScope originScope,
            String originLabel,
            TransportProtocol transportProtocol,
            Integer targetPort,
            ReachabilityStatus status
    ) {
    }

    private record ImpactSpec(
            String service,
            ImpactDimension dimension,
            ImpactLevel level
    ) {
    }

    private static final class Scenario {
        private String contractId = RbvmDecisionInputSnapshot.V3_ID;
        private final EnumMap<EvidenceDimension, DimensionState> states =
                new EnumMap<>(EvidenceDimension.class);
        private ApplicabilityStatus applicability = ApplicabilityStatus.APPLICABLE;
        private BigDecimal cvss = new BigDecimal("6.5");
        private KevStatus kev = KevStatus.NOT_LISTED;
        private BigDecimal epss = new BigDecimal("0.1");
        private BigDecimal percentile = new BigDecimal("0.7");
        private Environment environment = Environment.PRODUCTION;
        private String contextService = "payments";
        private String owner = "payments-owner";
        private BusinessCriticality criticality = BusinessCriticality.MODERATE;
        private List<ReachSpec> reachability = List.of(new ReachSpec(
                OriginScope.INTERNET,
                "edge-a",
                TransportProtocol.TCP,
                443,
                ReachabilityStatus.REACHABLE
        ));
        private List<ImpactSpec> impacts = List.of(new ImpactSpec(
                "payments",
                ImpactDimension.AVAILABILITY,
                ImpactLevel.MODERATE
        ));

        private Scenario() {
            for (EvidenceDimension dimension : EvidenceDimension.values()) {
                states.put(dimension, DimensionState.PRESENT);
            }
        }

        Scenario withContract(String value) {
            contractId = value;
            return this;
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

        Scenario withEpss(String probability, String percentileValue) {
            epss = new BigDecimal(probability);
            percentile = new BigDecimal(percentileValue);
            return this;
        }

        Scenario withEnvironment(Environment value) {
            environment = value;
            return this;
        }

        Scenario withContextService(String value) {
            contextService = value;
            return this;
        }

        Scenario withOwner(String value) {
            owner = value;
            return this;
        }

        Scenario withCriticality(BusinessCriticality value) {
            criticality = value;
            return this;
        }

        Scenario withReachability(List<ReachSpec> value) {
            reachability = List.copyOf(value);
            return this;
        }

        Scenario withImpact(List<ImpactSpec> value) {
            impacts = List.copyOf(value);
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

            RbvmDecisionInputSnapshot snapshot;
            if (RbvmDecisionInputSnapshot.V3_ID.equals(contractId)) {
                snapshot = RbvmDecisionInputSnapshot.createV3(
                        FINDING_ID, 9, POLICY_SHA, EVALUATED_AT, dimensions);
            } else if (RbvmDecisionInputSnapshot.V2_ID.equals(contractId)) {
                snapshot = RbvmDecisionInputSnapshot.createV2(
                        FINDING_ID, 9, POLICY_SHA, EVALUATED_AT, dimensions);
            } else {
                snapshot = RbvmDecisionInputSnapshot.create(
                        FINDING_ID, 9, POLICY_SHA, EVALUATED_AT, dimensions);
            }
            return new RbvmResolvedDecisionInput(snapshot, Map.copyOf(values));
        }

        private void addApplicability(
                EnumMap<EvidenceDimension, DimensionInput> dimensions,
                EnumMap<EvidenceDimension, List<ResolvedEvidence>> values
        ) {
            EvidenceDimension dimension = EvidenceDimension.APPLICABILITY;
            int count = genericCount(dimension);
            List<EvidenceReference> refs = new ArrayList<>();
            List<ResolvedEvidence> resolved = new ArrayList<>();
            for (int index = 0; index < count; index++) {
                EvidenceReference ref = reference(dimension, index, null);
                refs.add(ref);
                resolved.add(new ApplicabilityEvidenceValue(
                        ref,
                        applicability,
                        applicability == ApplicabilityStatus.APPLICABLE
                                ? "package is deployed"
                                : "explicit applicability assessment"
                ));
            }
            put(dimensions, values, dimension, refs, resolved);
        }

        private void addCvss(
                EnumMap<EvidenceDimension, DimensionInput> dimensions,
                EnumMap<EvidenceDimension, List<ResolvedEvidence>> values
        ) {
            EvidenceDimension dimension = EvidenceDimension.TECHNICAL_SEVERITY;
            int count = genericCount(dimension);
            List<EvidenceReference> refs = new ArrayList<>();
            List<ResolvedEvidence> resolved = new ArrayList<>();
            for (int index = 0; index < count; index++) {
                EvidenceReference ref = reference(dimension, index, null);
                refs.add(ref);
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
            int count = genericCount(dimension);
            List<EvidenceReference> refs = new ArrayList<>();
            List<ResolvedEvidence> resolved = new ArrayList<>();
            for (int index = 0; index < count; index++) {
                EvidenceReference ref = reference(dimension, index, null);
                refs.add(ref);
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
            int count = genericCount(dimension);
            List<EvidenceReference> refs = new ArrayList<>();
            List<ResolvedEvidence> resolved = new ArrayList<>();
            for (int index = 0; index < count; index++) {
                EvidenceReference ref = reference(dimension, index, null);
                refs.add(ref);
                resolved.add(new ExploitationProbabilityEvidenceValue(
                        ref,
                        epss,
                        percentile,
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
            int count = genericCount(dimension);
            List<EvidenceReference> refs = new ArrayList<>();
            List<ResolvedEvidence> resolved = new ArrayList<>();
            for (int index = 0; index < count; index++) {
                EvidenceReference ref = reference(dimension, index, null);
                refs.add(ref);
                resolved.add(new AssetContextEvidenceValue(
                        ref,
                        environment,
                        contextService,
                        owner,
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
            DimensionState state = states.get(dimension);
            List<ReachSpec> specs;
            if (state == DimensionState.MISSING) {
                specs = List.of();
            } else if (state == DimensionState.AMBIGUOUS && reachability.size() < 2) {
                specs = List.of(
                        reachability.get(0),
                        new ReachSpec(
                                OriginScope.INTERNAL_ENTERPRISE,
                                "ambiguous-corp",
                                TransportProtocol.TCP,
                                8443,
                                ReachabilityStatus.REACHABLE)
                );
            } else {
                specs = reachability;
            }
            List<EvidenceReference> refs = new ArrayList<>();
            List<ResolvedEvidence> resolved = new ArrayList<>();
            for (int index = 0; index < specs.size(); index++) {
                BindingReference binding = isV3()
                        ? binding(BindingKind.FINDING_REACHABILITY_SCOPE_LINK_EVENT, dimension, index)
                        : null;
                EvidenceReference ref = reference(dimension, index, binding);
                ReachSpec spec = specs.get(index);
                refs.add(ref);
                resolved.add(new NetworkReachabilityEvidenceValue(
                        ref,
                        spec.originScope(),
                        spec.originLabel(),
                        spec.transportProtocol(),
                        spec.targetPort(),
                        "service-" + index,
                        spec.status(),
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
            DimensionState state = states.get(dimension);
            List<ImpactSpec> specs;
            if (state == DimensionState.MISSING) {
                specs = List.of();
            } else if (state == DimensionState.AMBIGUOUS && impacts.size() < 2) {
                specs = List.of(
                        impacts.get(0),
                        new ImpactSpec(
                                impacts.get(0).service(),
                                ImpactDimension.INTEGRITY,
                                impacts.get(0).level())
                );
            } else {
                specs = impacts;
            }
            List<EvidenceReference> refs = new ArrayList<>();
            List<ResolvedEvidence> resolved = new ArrayList<>();
            for (int index = 0; index < specs.size(); index++) {
                BindingReference binding = isV3()
                        ? binding(BindingKind.FINDING_BUSINESS_SERVICE_LINK_EVENT, dimension, index)
                        : null;
                EvidenceReference ref = reference(dimension, index, binding);
                ImpactSpec spec = specs.get(index);
                refs.add(ref);
                resolved.add(new BusinessMissionImpactEvidenceValue(
                        ref,
                        spec.service(),
                        spec.service().trim().toLowerCase(java.util.Locale.ROOT),
                        spec.dimension(),
                        spec.level(),
                        ImpactMethod.BUSINESS_IMPACT_ANALYSIS,
                        "Synthetic Formula runtime acceptance evidence"
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

        private boolean isV3() {
            return RbvmDecisionInputSnapshot.V3_ID.equals(contractId);
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

        private EvidenceReference reference(
                EvidenceDimension dimension,
                int index,
                BindingReference binding
        ) {
            int seed = dimension.ordinal() * 7 + index + 1;
            String identity = "formula-v1:" + contractId + ":" + dimension + ":" + index;
            return new EvidenceReference(
                    dimension,
                    NativeEvidenceKind.defaultFor(dimension),
                    UUID.nameUUIDFromBytes(identity.getBytes(StandardCharsets.UTF_8)),
                    hex(seed).repeat(64),
                    "formula-self-test-" + dimension.name().toLowerCase(java.util.Locale.ROOT),
                    EVALUATED_AT.minusSeconds(300L + seed),
                    binding
            );
        }

        private BindingReference binding(
                BindingKind kind,
                EvidenceDimension dimension,
                int index
        ) {
            int seed = 12 + dimension.ordinal() * 5 + index;
            String identity = "formula-binding:" + kind + ":" + dimension + ":" + index;
            return new BindingReference(
                    kind,
                    UUID.nameUUIDFromBytes(identity.getBytes(StandardCharsets.UTF_8)),
                    hex(seed).repeat(64),
                    "CUSTOMER_CONFIRMED",
                    EVALUATED_AT.minusSeconds(120L + seed)
            );
        }

        private String hex(int seed) {
            return Integer.toHexString(Math.floorMod(seed, 15) + 1);
        }
    }
}
