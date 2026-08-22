package io.rbvm.decision;

import io.rbvm.decision.RbvmDecisionInputSnapshot.DimensionState;
import io.rbvm.decision.RbvmDecisionMethodologyPolicy.EvidenceDimension;
import io.rbvm.decision.RbvmDerivedRiskMethodology.ResultState;
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

/** Shared exact-evidence gate and normalization for derived risk methodologies. */
final class RbvmDerivedRiskEvidence {
    static final MathContext MATH_CONTEXT = new MathContext(34, RoundingMode.HALF_EVEN);

    private RbvmDerivedRiskEvidence() {
    }

    sealed interface Resolution permits Vector, Terminal {
    }

    record Terminal(ResultState state, String reasonCode) implements Resolution {
        Terminal {
            state = Objects.requireNonNull(state, "state");
            if (state == ResultState.COMPUTED) {
                throw new IllegalArgumentException("Terminal state cannot be COMPUTED");
            }
            if (reasonCode == null || reasonCode.trim().isEmpty()) {
                throw new IllegalArgumentException("reasonCode must be non-empty");
            }
            reasonCode = reasonCode.trim();
        }
    }

    record Vector(
            RbvmResolvedDecisionInput input,
            BigDecimal cvss,
            BigDecimal epss,
            BigDecimal kev,
            BigDecimal reachability,
            BigDecimal businessCriticality,
            BigDecimal businessImpact
    ) implements Resolution {
        Vector {
            input = Objects.requireNonNull(input, "input");
            cvss = unit(cvss, "cvss");
            epss = unit(epss, "epss");
            kev = unit(kev, "kev");
            reachability = unit(reachability, "reachability");
            businessCriticality = unit(businessCriticality, "businessCriticality");
            businessImpact = unit(businessImpact, "businessImpact");
        }
    }

    static Resolution resolve(RbvmResolvedDecisionInput input) {
        Objects.requireNonNull(input, "input");
        if (!input.snapshot().isV3()) {
            throw new IllegalArgumentException(
                    "Derived risk methodologies accept only RBVM_DECISION_INPUT_SNAPSHOT_V3");
        }

        Terminal applicabilityState = dimensionStateGate(input, EvidenceDimension.APPLICABILITY);
        if (applicabilityState != null) {
            return applicabilityState;
        }
        ApplicabilityEvidenceValue applicability = one(
                input,
                EvidenceDimension.APPLICABILITY,
                ApplicabilityEvidenceValue.class
        );
        if (applicability.status() == ApplicabilityStatus.NOT_APPLICABLE) {
            return new Terminal(ResultState.NOT_APPLICABLE, "NOT_APPLICABLE");
        }
        if (applicability.status() == ApplicabilityStatus.UNKNOWN) {
            return new Terminal(ResultState.NON_COMPUTABLE, "APPLICABILITY_UNKNOWN");
        }

        for (EvidenceDimension dimension : List.of(
                EvidenceDimension.TECHNICAL_SEVERITY,
                EvidenceDimension.KNOWN_EXPLOITATION,
                EvidenceDimension.EXPLOITATION_PROBABILITY,
                EvidenceDimension.ASSET_CONTEXT,
                EvidenceDimension.NETWORK_REACHABILITY,
                EvidenceDimension.BUSINESS_MISSION_IMPACT
        )) {
            Terminal gate = dimensionStateGate(input, dimension);
            if (gate != null) {
                return gate;
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
            return new Terminal(ResultState.NON_COMPUTABLE, "BUSINESS_CRITICALITY_UNKNOWN");
        }

        List<ResolvedEvidence> reachabilityValues =
                input.evidence(EvidenceDimension.NETWORK_REACHABILITY);
        if (reachabilityValues.isEmpty()) {
            throw invalidPresentShape(EvidenceDimension.NETWORK_REACHABILITY);
        }
        if (reachabilityValues.size() > 1) {
            return new Terminal(ResultState.NON_COMPUTABLE, "REACHABILITY_MULTI_SUBGRAIN");
        }
        NetworkReachabilityEvidenceValue reachability = cast(
                reachabilityValues.get(0),
                NetworkReachabilityEvidenceValue.class,
                EvidenceDimension.NETWORK_REACHABILITY
        );
        if (reachability.reachabilityStatus() == ReachabilityStatus.UNKNOWN) {
            return new Terminal(ResultState.NON_COMPUTABLE, "REACHABILITY_VALUE_UNKNOWN");
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
            return new Terminal(ResultState.NON_COMPUTABLE, "BUSINESS_IMPACT_MULTI_SERVICE");
        }
        for (BusinessMissionImpactEvidenceValue impact : impacts) {
            if (impact.impactLevel() == ImpactLevel.UNKNOWN) {
                return new Terminal(
                        ResultState.NON_COMPUTABLE,
                        "BUSINESS_IMPACT_VALUE_UNKNOWN"
                );
            }
        }

        BigDecimal normalizedImpact = impacts.stream()
                .map(BusinessMissionImpactEvidenceValue::impactLevel)
                .map(RbvmDerivedRiskEvidence::mapImpact)
                .max(BigDecimal::compareTo)
                .orElseThrow(() -> invalidPresentShape(EvidenceDimension.BUSINESS_MISSION_IMPACT));

        return new Vector(
                input,
                cvss.baseScore().divide(BigDecimal.TEN, MATH_CONTEXT),
                epss.probability(),
                kev.status() == KevStatus.LISTED ? BigDecimal.ONE : BigDecimal.ZERO,
                reachability.reachabilityStatus() == ReachabilityStatus.REACHABLE
                        ? BigDecimal.ONE
                        : BigDecimal.ZERO,
                mapCriticality(context.businessCriticality()),
                normalizedImpact
        );
    }

    static BigDecimal mean(BigDecimal first, BigDecimal second, BigDecimal third) {
        return first.add(second, MATH_CONTEXT)
                .add(third, MATH_CONTEXT)
                .divide(new BigDecimal("3"), MATH_CONTEXT);
    }

    private static Terminal dimensionStateGate(
            RbvmResolvedDecisionInput input,
            EvidenceDimension dimension
    ) {
        DimensionState state = input.snapshot().dimensions().get(dimension).state();
        return switch (state) {
            case PRESENT -> null;
            case MISSING, STALE, AMBIGUOUS -> new Terminal(
                    ResultState.NON_COMPUTABLE,
                    dimension.name() + "_" + state.name()
            );
        };
    }

    private static BigDecimal mapCriticality(BusinessCriticality criticality) {
        return switch (criticality) {
            case LOW -> new BigDecimal("0.25");
            case MODERATE -> new BigDecimal("0.5");
            case HIGH -> new BigDecimal("0.75");
            case MISSION_CRITICAL -> BigDecimal.ONE;
            case UNKNOWN -> throw new IllegalStateException("UNKNOWN criticality passed gate");
        };
    }

    private static BigDecimal mapImpact(ImpactLevel impactLevel) {
        return switch (impactLevel) {
            case NEGLIGIBLE -> BigDecimal.ZERO;
            case LOW -> new BigDecimal("0.25");
            case MODERATE -> new BigDecimal("0.5");
            case HIGH -> new BigDecimal("0.75");
            case SEVERE -> BigDecimal.ONE;
            case UNKNOWN -> throw new IllegalStateException("UNKNOWN impact passed gate");
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
                    "Resolved " + dimension + " evidence has an unexpected native value type");
        }
        return expectedType.cast(evidence);
    }

    private static IllegalArgumentException invalidPresentShape(EvidenceDimension dimension) {
        return new IllegalArgumentException(
                "PRESENT " + dimension + " evidence does not satisfy derived methodology cardinality");
    }

    private static BigDecimal unit(BigDecimal value, String field) {
        Objects.requireNonNull(value, field);
        if (value.compareTo(BigDecimal.ZERO) < 0 || value.compareTo(BigDecimal.ONE) > 0) {
            throw new IllegalArgumentException(field + " must be in [0,1]");
        }
        return value;
    }
}
