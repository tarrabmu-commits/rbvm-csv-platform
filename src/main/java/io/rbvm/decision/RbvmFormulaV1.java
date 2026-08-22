package io.rbvm.decision;

import io.rbvm.decision.RbvmDecisionInputSnapshot.DimensionState;
import io.rbvm.decision.RbvmDecisionMethodologyPolicy.EvidenceDimension;
import io.rbvm.decision.RbvmResolvedDecisionInput.ApplicabilityEvidenceValue;
import io.rbvm.decision.RbvmResolvedDecisionInput.ApplicabilityStatus;
import io.rbvm.decision.RbvmResolvedDecisionInput.AssetContextEvidenceValue;
import io.rbvm.decision.RbvmResolvedDecisionInput.BusinessCriticality;
import io.rbvm.decision.RbvmResolvedDecisionInput.BusinessMissionImpactEvidenceValue;
import io.rbvm.decision.RbvmResolvedDecisionInput.ExploitationProbabilityEvidenceValue;
import io.rbvm.decision.RbvmResolvedDecisionInput.ImpactLevel;
import io.rbvm.decision.RbvmResolvedDecisionInput.KevStatus;
import io.rbvm.decision.RbvmResolvedDecisionInput.KnownExploitationEvidenceValue;
import io.rbvm.decision.RbvmResolvedDecisionInput.NetworkReachabilityEvidenceValue;
import io.rbvm.decision.RbvmResolvedDecisionInput.ReachabilityStatus;
import io.rbvm.decision.RbvmResolvedDecisionInput.ResolvedEvidence;
import io.rbvm.decision.RbvmResolvedDecisionInput.TechnicalSeverityEvidenceValue;

import java.math.BigDecimal;
import java.math.MathContext;
import java.math.RoundingMode;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/**
 * Pure deterministic evaluator for the accepted {@code RBVM_FORMULA_V1} contract.
 *
 * <p>The evaluator consumes exactly one already-resolved Decision Input V3. It never queries
 * current state, selects evidence, persists a result, infers missing values, or produces Priority,
 * Treatment, SLA, or remediation workflow decisions.</p>
 */
public final class RbvmFormulaV1 {
    public static final String FORMULA_ID = "RBVM_FORMULA_V1";
    public static final int FORMULA_VERSION = 1;
    public static final String FORMULA_SHA256 =
            "88bf31f510089b4209b1ffcf1c15b39fef60548209875334f084888316e9028e";
    public static final String OUTPUT_NAME = "RBVM Relative Risk Index";

    private static final MathContext MATH_CONTEXT = new MathContext(34, RoundingMode.HALF_EVEN);
    private static final BigDecimal OUTPUT_MULTIPLIER = new BigDecimal("100");

    private static final BigDecimal WEIGHT_CVSS = new BigDecimal("0.20");
    private static final BigDecimal WEIGHT_EPSS = new BigDecimal("0.20");
    private static final BigDecimal WEIGHT_KEV = new BigDecimal("0.15");
    private static final BigDecimal WEIGHT_REACHABILITY = new BigDecimal("0.15");
    private static final BigDecimal WEIGHT_CRITICALITY = new BigDecimal("0.15");
    private static final BigDecimal WEIGHT_IMPACT = new BigDecimal("0.15");

    private RbvmFormulaV1() {
    }

    public enum ResultState {
        COMPUTED,
        NOT_APPLICABLE,
        NON_COMPUTABLE
    }

    /** One visible Formula factor after normalization and before the final x100 output scaling. */
    public record FactorContribution(
            String factorId,
            EvidenceDimension dimension,
            BigDecimal normalizedValue,
            BigDecimal weight,
            BigDecimal weightedContribution
    ) {
        public FactorContribution {
            factorId = requireText(factorId, "factorId");
            dimension = Objects.requireNonNull(dimension, "dimension");
            normalizedValue = requireUnitInterval(normalizedValue, "normalizedValue");
            weight = requireUnitInterval(weight, "weight");
            weightedContribution = requireUnitInterval(
                    weightedContribution,
                    "weightedContribution"
            );
        }
    }

    /** Ephemeral Formula result. Persistence and canonical explanation identity are later layers. */
    public record FormulaResult(
            ResultState state,
            String reasonCode,
            String formulaId,
            int formulaVersion,
            String formulaSha256,
            String inputContractId,
            String inputSnapshotSha256,
            UUID findingId,
            BigDecimal relativeRiskIndex,
            List<FactorContribution> factorContributions
    ) {
        public FormulaResult {
            state = Objects.requireNonNull(state, "state");
            formulaId = requireText(formulaId, "formulaId");
            if (formulaVersion < 1) {
                throw new IllegalArgumentException("formulaVersion must be positive");
            }
            formulaSha256 = requireSha(formulaSha256, "formulaSha256");
            inputContractId = requireText(inputContractId, "inputContractId");
            inputSnapshotSha256 = requireSha(inputSnapshotSha256, "inputSnapshotSha256");
            findingId = Objects.requireNonNull(findingId, "findingId");
            factorContributions = List.copyOf(
                    Objects.requireNonNull(factorContributions, "factorContributions")
            );

            if (state == ResultState.COMPUTED) {
                if (reasonCode != null) {
                    throw new IllegalArgumentException("COMPUTED result must not carry a reasonCode");
                }
                Objects.requireNonNull(relativeRiskIndex, "relativeRiskIndex");
                if (relativeRiskIndex.scale() != 2
                        || relativeRiskIndex.compareTo(BigDecimal.ZERO) < 0
                        || relativeRiskIndex.compareTo(OUTPUT_MULTIPLIER) > 0) {
                    throw new IllegalArgumentException(
                            "COMPUTED relativeRiskIndex must be 0.00..100.00 with scale 2"
                    );
                }
                if (factorContributions.size() != 6) {
                    throw new IllegalArgumentException(
                            "COMPUTED result must contain exactly six Formula contributions"
                    );
                }
            } else {
                reasonCode = requireText(reasonCode, "reasonCode");
                if (relativeRiskIndex != null) {
                    throw new IllegalArgumentException(
                            "Terminal Formula result must not carry a numeric Risk Result"
                    );
                }
                if (!factorContributions.isEmpty()) {
                    throw new IllegalArgumentException(
                            "Terminal Formula result must not carry partial numeric contributions"
                    );
                }
            }
        }
    }

    public static FormulaResult evaluate(RbvmResolvedDecisionInput input) {
        Objects.requireNonNull(input, "input");
        RbvmDecisionInputSnapshot snapshot = input.snapshot();
        if (!snapshot.isV3()) {
            throw new IllegalArgumentException(
                    "RBVM Formula V1 accepts only RBVM_DECISION_INPUT_SNAPSHOT_V3"
            );
        }

        FormulaResult applicabilityGate = applicabilityGate(input);
        if (applicabilityGate != null) {
            return applicabilityGate;
        }

        for (EvidenceDimension dimension : List.of(
                EvidenceDimension.TECHNICAL_SEVERITY,
                EvidenceDimension.KNOWN_EXPLOITATION,
                EvidenceDimension.EXPLOITATION_PROBABILITY,
                EvidenceDimension.ASSET_CONTEXT,
                EvidenceDimension.NETWORK_REACHABILITY,
                EvidenceDimension.BUSINESS_MISSION_IMPACT
        )) {
            FormulaResult evidenceGate = dimensionStateGate(input, dimension);
            if (evidenceGate != null) {
                return evidenceGate;
            }
        }

        TechnicalSeverityEvidenceValue cvss = one(
                input,
                EvidenceDimension.TECHNICAL_SEVERITY,
                TechnicalSeverityEvidenceValue.class
        );
        KnownExploitationEvidenceValue kev = one(
                input,
                EvidenceDimension.KNOWN_EXPLOITATION,
                KnownExploitationEvidenceValue.class
        );
        ExploitationProbabilityEvidenceValue epss = one(
                input,
                EvidenceDimension.EXPLOITATION_PROBABILITY,
                ExploitationProbabilityEvidenceValue.class
        );
        AssetContextEvidenceValue context = one(
                input,
                EvidenceDimension.ASSET_CONTEXT,
                AssetContextEvidenceValue.class
        );

        if (context.businessCriticality() == BusinessCriticality.UNKNOWN) {
            return terminal(input, ResultState.NON_COMPUTABLE, "BUSINESS_CRITICALITY_UNKNOWN");
        }

        List<ResolvedEvidence> reachabilityValues =
                input.evidence(EvidenceDimension.NETWORK_REACHABILITY);
        if (reachabilityValues.isEmpty()) {
            throw invalidPresentShape(EvidenceDimension.NETWORK_REACHABILITY);
        }
        if (reachabilityValues.size() > 1) {
            return terminal(input, ResultState.NON_COMPUTABLE, "REACHABILITY_MULTI_SUBGRAIN");
        }
        NetworkReachabilityEvidenceValue reachability = cast(
                reachabilityValues.get(0),
                NetworkReachabilityEvidenceValue.class,
                EvidenceDimension.NETWORK_REACHABILITY
        );
        if (reachability.reachabilityStatus() == ReachabilityStatus.UNKNOWN) {
            return terminal(input, ResultState.NON_COMPUTABLE, "REACHABILITY_VALUE_UNKNOWN");
        }

        List<ResolvedEvidence> impactEvidence =
                input.evidence(EvidenceDimension.BUSINESS_MISSION_IMPACT);
        if (impactEvidence.isEmpty()) {
            throw invalidPresentShape(EvidenceDimension.BUSINESS_MISSION_IMPACT);
        }
        List<BusinessMissionImpactEvidenceValue> impacts = new ArrayList<>(impactEvidence.size());
        Set<String> normalizedServices = new HashSet<>();
        for (ResolvedEvidence value : impactEvidence) {
            BusinessMissionImpactEvidenceValue impact = cast(
                    value,
                    BusinessMissionImpactEvidenceValue.class,
                    EvidenceDimension.BUSINESS_MISSION_IMPACT
            );
            impacts.add(impact);
            normalizedServices.add(impact.businessServiceNormalized());
        }
        if (normalizedServices.size() > 1) {
            return terminal(input, ResultState.NON_COMPUTABLE, "BUSINESS_IMPACT_MULTI_SERVICE");
        }
        for (BusinessMissionImpactEvidenceValue impact : impacts) {
            if (impact.impactLevel() == ImpactLevel.UNKNOWN) {
                return terminal(
                        input,
                        ResultState.NON_COMPUTABLE,
                        "BUSINESS_IMPACT_VALUE_UNKNOWN"
                );
            }
        }

        BigDecimal normalizedCvss = cvss.baseScore().divide(BigDecimal.TEN, MATH_CONTEXT);
        BigDecimal normalizedEpss = epss.probability();
        BigDecimal normalizedKev = switch (kev.status()) {
            case LISTED -> BigDecimal.ONE;
            case NOT_LISTED -> BigDecimal.ZERO;
        };
        BigDecimal normalizedReachability = switch (reachability.reachabilityStatus()) {
            case REACHABLE -> BigDecimal.ONE;
            case NOT_REACHABLE -> BigDecimal.ZERO;
            case UNKNOWN -> throw new IllegalStateException("UNKNOWN reachability passed Formula gate");
        };
        BigDecimal normalizedCriticality = mapCriticality(context.businessCriticality());
        BigDecimal normalizedImpact = impacts.stream()
                .map(BusinessMissionImpactEvidenceValue::impactLevel)
                .map(RbvmFormulaV1::mapImpact)
                .max(BigDecimal::compareTo)
                .orElseThrow(() -> invalidPresentShape(EvidenceDimension.BUSINESS_MISSION_IMPACT));

        List<FactorContribution> contributions = List.of(
                contribution(
                        "CVSS_V31_BASE",
                        EvidenceDimension.TECHNICAL_SEVERITY,
                        normalizedCvss,
                        WEIGHT_CVSS
                ),
                contribution(
                        "EPSS_PROBABILITY",
                        EvidenceDimension.EXPLOITATION_PROBABILITY,
                        normalizedEpss,
                        WEIGHT_EPSS
                ),
                contribution(
                        "CISA_KEV_MEMBERSHIP",
                        EvidenceDimension.KNOWN_EXPLOITATION,
                        normalizedKev,
                        WEIGHT_KEV
                ),
                contribution(
                        "REACHABILITY_STATUS",
                        EvidenceDimension.NETWORK_REACHABILITY,
                        normalizedReachability,
                        WEIGHT_REACHABILITY
                ),
                contribution(
                        "BUSINESS_CRITICALITY",
                        EvidenceDimension.ASSET_CONTEXT,
                        normalizedCriticality,
                        WEIGHT_CRITICALITY
                ),
                contribution(
                        "BUSINESS_IMPACT_LEVEL",
                        EvidenceDimension.BUSINESS_MISSION_IMPACT,
                        normalizedImpact,
                        WEIGHT_IMPACT
                )
        );

        BigDecimal raw = BigDecimal.ZERO;
        for (FactorContribution contribution : contributions) {
            raw = raw.add(contribution.weightedContribution(), MATH_CONTEXT);
        }
        if (raw.compareTo(BigDecimal.ZERO) < 0 || raw.compareTo(BigDecimal.ONE) > 0) {
            throw new IllegalStateException("RBVM Formula V1 raw weighted sum escaped [0,1]");
        }
        BigDecimal result = raw.multiply(OUTPUT_MULTIPLIER, MATH_CONTEXT)
                .setScale(2, RoundingMode.HALF_EVEN);
        return computed(input, result, contributions);
    }

    private static FormulaResult applicabilityGate(RbvmResolvedDecisionInput input) {
        FormulaResult stateGate = dimensionStateGate(input, EvidenceDimension.APPLICABILITY);
        if (stateGate != null) {
            return stateGate;
        }
        ApplicabilityEvidenceValue applicability = one(
                input,
                EvidenceDimension.APPLICABILITY,
                ApplicabilityEvidenceValue.class
        );
        return switch (applicability.status()) {
            case APPLICABLE -> null;
            case NOT_APPLICABLE -> terminal(
                    input,
                    ResultState.NOT_APPLICABLE,
                    "NOT_APPLICABLE"
            );
            case UNKNOWN -> terminal(
                    input,
                    ResultState.NON_COMPUTABLE,
                    "APPLICABILITY_UNKNOWN"
            );
        };
    }

    private static FormulaResult dimensionStateGate(
            RbvmResolvedDecisionInput input,
            EvidenceDimension dimension
    ) {
        DimensionState state = input.snapshot().dimensions().get(dimension).state();
        return switch (state) {
            case PRESENT -> null;
            case MISSING, STALE, AMBIGUOUS -> terminal(
                    input,
                    ResultState.NON_COMPUTABLE,
                    dimension.name() + "_" + state.name()
            );
        };
    }

    private static FactorContribution contribution(
            String factorId,
            EvidenceDimension dimension,
            BigDecimal normalizedValue,
            BigDecimal weight
    ) {
        BigDecimal normalized = requireUnitInterval(normalizedValue, factorId + " normalized value");
        BigDecimal contribution = weight.multiply(normalized, MATH_CONTEXT);
        return new FactorContribution(
                factorId,
                dimension,
                canonicalDecimal(normalized),
                canonicalDecimal(weight),
                canonicalDecimal(contribution)
        );
    }

    private static BigDecimal mapCriticality(BusinessCriticality criticality) {
        return switch (criticality) {
            case LOW -> new BigDecimal("0.25");
            case MODERATE -> new BigDecimal("0.5");
            case HIGH -> new BigDecimal("0.75");
            case MISSION_CRITICAL -> BigDecimal.ONE;
            case UNKNOWN -> throw new IllegalStateException("UNKNOWN criticality passed Formula gate");
        };
    }

    private static BigDecimal mapImpact(ImpactLevel impactLevel) {
        return switch (impactLevel) {
            case NEGLIGIBLE -> BigDecimal.ZERO;
            case LOW -> new BigDecimal("0.25");
            case MODERATE -> new BigDecimal("0.5");
            case HIGH -> new BigDecimal("0.75");
            case SEVERE -> BigDecimal.ONE;
            case UNKNOWN -> throw new IllegalStateException("UNKNOWN impact passed Formula gate");
        };
    }

    private static <T extends ResolvedEvidence> T one(
            RbvmResolvedDecisionInput input,
            EvidenceDimension dimension,
            Class<T> expectedType
    ) {
        List<ResolvedEvidence> values = input.evidence(dimension);
        if (values.size() != 1) {
            throw invalidPresentShape(dimension);
        }
        return cast(values.get(0), expectedType, dimension);
    }

    private static <T extends ResolvedEvidence> T cast(
            ResolvedEvidence evidence,
            Class<T> expectedType,
            EvidenceDimension dimension
    ) {
        if (!expectedType.isInstance(evidence)) {
            throw new IllegalArgumentException(
                    "Resolved " + dimension + " evidence has an unexpected native value type"
            );
        }
        return expectedType.cast(evidence);
    }

    private static IllegalArgumentException invalidPresentShape(EvidenceDimension dimension) {
        return new IllegalArgumentException(
                "PRESENT " + dimension + " evidence does not satisfy Formula V1 cardinality"
        );
    }

    private static FormulaResult computed(
            RbvmResolvedDecisionInput input,
            BigDecimal result,
            List<FactorContribution> contributions
    ) {
        return new FormulaResult(
                ResultState.COMPUTED,
                null,
                FORMULA_ID,
                FORMULA_VERSION,
                FORMULA_SHA256,
                input.snapshot().contractId(),
                input.snapshot().snapshotSha256(),
                input.snapshot().findingId(),
                result,
                contributions
        );
    }

    private static FormulaResult terminal(
            RbvmResolvedDecisionInput input,
            ResultState state,
            String reasonCode
    ) {
        return new FormulaResult(
                state,
                reasonCode,
                FORMULA_ID,
                FORMULA_VERSION,
                FORMULA_SHA256,
                input.snapshot().contractId(),
                input.snapshot().snapshotSha256(),
                input.snapshot().findingId(),
                null,
                List.of()
        );
    }

    private static BigDecimal canonicalDecimal(BigDecimal value) {
        if (value.compareTo(BigDecimal.ZERO) == 0) {
            return BigDecimal.ZERO;
        }
        return value.stripTrailingZeros();
    }

    private static BigDecimal requireUnitInterval(BigDecimal value, String field) {
        Objects.requireNonNull(value, field);
        if (value.compareTo(BigDecimal.ZERO) < 0 || value.compareTo(BigDecimal.ONE) > 0) {
            throw new IllegalArgumentException(field + " must be between 0 and 1");
        }
        return value;
    }

    private static String requireSha(String value, String field) {
        if (value == null || !value.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException(field + " must be lowercase SHA-256 hex");
        }
        return value;
    }

    private static String requireText(String value, String field) {
        if (value == null || value.trim().isEmpty() || value.indexOf('\u0000') >= 0) {
            throw new IllegalArgumentException(field + " must be non-empty text");
        }
        return value.trim();
    }
}
