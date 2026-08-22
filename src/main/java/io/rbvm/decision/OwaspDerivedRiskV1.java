package io.rbvm.decision;

import io.rbvm.decision.RbvmDerivedRiskEvidence.Resolution;
import io.rbvm.decision.RbvmDerivedRiskEvidence.Terminal;
import io.rbvm.decision.RbvmDerivedRiskEvidence.Vector;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.List;

/**
 * RBVM adaptation of the published OWASP Risk Rating model.
 *
 * <p>OWASP publishes {@code Risk = Likelihood * Impact}, a repeatable averaging approach for
 * likelihood/impact factors, 0..9 LOW/MEDIUM/HIGH axis bands, and a severity matrix. RBVM uses
 * only evidence already captured in one exact Decision Input V3 snapshot to populate those axes.
 * Therefore this is {@code STANDARD_DERIVED}; it is not an official OWASP score.</p>
 */
public final class OwaspDerivedRiskV1 implements RbvmDerivedRiskMethodology {
    public static final String METHODOLOGY_ID = "OWASP_DERIVED_RBVM_V1";
    public static final int VERSION = 1;
    public static final String METHODOLOGY_SHA256 =
            "03a72c8479e834174dc6985580d2543ad61b01628a79da5d59c5b5785e80c9c3";
    public static final String OUTPUT_NAME = "OWASP-derived RBVM Risk";
    public static final OwaspDerivedRiskV1 INSTANCE = new OwaspDerivedRiskV1();

    private static final BigDecimal NINE = new BigDecimal("9");
    private static final BigDecimal THREE = new BigDecimal("3");
    private static final BigDecimal SIX = new BigDecimal("6");

    private static final Definition DEFINITION = new Definition(
            METHODOLOGY_ID,
            VERSION,
            Classification.STANDARD_DERIVED,
            "OWASP",
            "OWASP Risk Rating Methodology",
            "Risk = Likelihood * Impact",
            "https://owasp.org/www-community/OWASP_Risk_Rating_Methodology",
            METHODOLOGY_SHA256,
            OUTPUT_NAME
    );

    private OwaspDerivedRiskV1() {
    }

    @Override
    public Definition definition() {
        return DEFINITION;
    }

    @Override
    public Evaluation evaluate(RbvmResolvedDecisionInput input) {
        Resolution resolution = RbvmDerivedRiskEvidence.resolve(input);
        if (resolution instanceof Terminal terminal) {
            return terminal(input, terminal);
        }
        Vector vector = (Vector) resolution;

        BigDecimal epssFactor = vector.epss().multiply(NINE, RbvmDerivedRiskEvidence.MATH_CONTEXT);
        BigDecimal kevFactor = vector.kev().multiply(NINE, RbvmDerivedRiskEvidence.MATH_CONTEXT);
        BigDecimal reachabilityFactor = vector.reachability()
                .multiply(NINE, RbvmDerivedRiskEvidence.MATH_CONTEXT);
        BigDecimal likelihood = RbvmDerivedRiskEvidence.mean(
                epssFactor,
                kevFactor,
                reachabilityFactor
        );

        BigDecimal cvssFactor = vector.cvss().multiply(NINE, RbvmDerivedRiskEvidence.MATH_CONTEXT);
        BigDecimal criticalityFactor = vector.businessCriticality()
                .multiply(NINE, RbvmDerivedRiskEvidence.MATH_CONTEXT);
        BigDecimal impactFactor = vector.businessImpact()
                .multiply(NINE, RbvmDerivedRiskEvidence.MATH_CONTEXT);
        BigDecimal impact = RbvmDerivedRiskEvidence.mean(
                cvssFactor,
                criticalityFactor,
                impactFactor
        );

        BigDecimal riskProduct = likelihood.multiply(
                impact,
                RbvmDerivedRiskEvidence.MATH_CONTEXT
        );
        String rating = riskRating(axisBand(likelihood), axisBand(impact));

        return new Evaluation(
                ResultState.COMPUTED,
                null,
                DEFINITION,
                input.snapshot().contractId(),
                input.snapshot().snapshotSha256(),
                input.snapshot().findingId(),
                display(riskProduct),
                "0.0000..81.0000",
                rating,
                List.of(
                        measure("EPSS_LIKELIHOOD_FACTOR", "LIKELIHOOD_FACTOR", epssFactor, "0..9"),
                        measure("KEV_LIKELIHOOD_FACTOR", "LIKELIHOOD_FACTOR", kevFactor, "0..9"),
                        measure(
                                "REACHABILITY_LIKELIHOOD_FACTOR",
                                "LIKELIHOOD_FACTOR",
                                reachabilityFactor,
                                "0..9"
                        ),
                        measure("LIKELIHOOD", "AXIS", likelihood, "0..9"),
                        measure("CVSS_IMPACT_FACTOR", "IMPACT_FACTOR", cvssFactor, "0..9"),
                        measure(
                                "BUSINESS_CRITICALITY_IMPACT_FACTOR",
                                "IMPACT_FACTOR",
                                criticalityFactor,
                                "0..9"
                        ),
                        measure(
                                "BUSINESS_IMPACT_FACTOR",
                                "IMPACT_FACTOR",
                                impactFactor,
                                "0..9"
                        ),
                        measure("IMPACT", "AXIS", impact, "0..9")
                )
        );
    }

    private enum AxisBand {
        LOW,
        MEDIUM,
        HIGH
    }

    private static AxisBand axisBand(BigDecimal value) {
        if (value.compareTo(THREE) < 0) {
            return AxisBand.LOW;
        }
        if (value.compareTo(SIX) < 0) {
            return AxisBand.MEDIUM;
        }
        return AxisBand.HIGH;
    }

    private static String riskRating(AxisBand likelihood, AxisBand impact) {
        return switch (impact) {
            case LOW -> switch (likelihood) {
                case LOW -> "NOTE";
                case MEDIUM -> "LOW";
                case HIGH -> "MEDIUM";
            };
            case MEDIUM -> switch (likelihood) {
                case LOW -> "LOW";
                case MEDIUM -> "MEDIUM";
                case HIGH -> "HIGH";
            };
            case HIGH -> switch (likelihood) {
                case LOW -> "MEDIUM";
                case MEDIUM -> "HIGH";
                case HIGH -> "CRITICAL";
            };
        };
    }

    private static Measure measure(String id, String role, BigDecimal value, String scale) {
        return new Measure(id, role, display(value), scale);
    }

    private static BigDecimal display(BigDecimal value) {
        return value.setScale(4, RoundingMode.HALF_EVEN);
    }

    private static Evaluation terminal(RbvmResolvedDecisionInput input, Terminal terminal) {
        return new Evaluation(
                terminal.state(),
                terminal.reasonCode(),
                DEFINITION,
                input.snapshot().contractId(),
                input.snapshot().snapshotSha256(),
                input.snapshot().findingId(),
                null,
                null,
                null,
                List.of()
        );
    }
}
