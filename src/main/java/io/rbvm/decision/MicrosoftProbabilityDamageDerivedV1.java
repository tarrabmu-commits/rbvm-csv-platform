package io.rbvm.decision;

import io.rbvm.decision.RbvmDerivedRiskEvidence.Resolution;
import io.rbvm.decision.RbvmDerivedRiskEvidence.Terminal;
import io.rbvm.decision.RbvmDerivedRiskEvidence.Vector;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.List;

/**
 * RBVM adaptation of Microsoft's published {@code Risk = Probability * Damage Potential} model.
 *
 * <p>Microsoft publishes 1..10 scales for Probability and Damage Potential, producing a 1..100
 * risk scale. RBVM deterministically maps exact Decision Input V3 evidence into those two axes.
 * This is {@code STANDARD_DERIVED}; it is not a Microsoft-produced score.</p>
 */
public final class MicrosoftProbabilityDamageDerivedV1 implements RbvmDerivedRiskMethodology {
    public static final String METHODOLOGY_ID = "MICROSOFT_PD_DERIVED_RBVM_V1";
    public static final int VERSION = 1;
    public static final String METHODOLOGY_SHA256 =
            "b22520b7b5a7d5f06782270feaf6729089ebafef79f20aea43dddf18396dcce6";
    public static final String OUTPUT_NAME = "Microsoft Probability x Damage-derived RBVM Risk";
    public static final MicrosoftProbabilityDamageDerivedV1 INSTANCE =
            new MicrosoftProbabilityDamageDerivedV1();

    private static final BigDecimal ONE = BigDecimal.ONE;
    private static final BigDecimal NINE = new BigDecimal("9");

    private static final Definition DEFINITION = new Definition(
            METHODOLOGY_ID,
            VERSION,
            Classification.STANDARD_DERIVED,
            "Microsoft",
            "Probability x Damage Potential",
            "Risk = Probability * Damage Potential",
            "https://download.microsoft.com/download/d/8/c/d8c02f31-64af-438c-a9f4-e31acb8e3333/threats_countermeasures.pdf",
            METHODOLOGY_SHA256,
            OUTPUT_NAME
    );

    private MicrosoftProbabilityDamageDerivedV1() {
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

        BigDecimal probabilityBase = RbvmDerivedRiskEvidence.mean(
                vector.epss(),
                vector.kev(),
                vector.reachability()
        );
        BigDecimal probability = ONE.add(
                NINE.multiply(probabilityBase, RbvmDerivedRiskEvidence.MATH_CONTEXT),
                RbvmDerivedRiskEvidence.MATH_CONTEXT
        );

        BigDecimal damageBase = RbvmDerivedRiskEvidence.mean(
                vector.cvss(),
                vector.businessCriticality(),
                vector.businessImpact()
        );
        BigDecimal damagePotential = ONE.add(
                NINE.multiply(damageBase, RbvmDerivedRiskEvidence.MATH_CONTEXT),
                RbvmDerivedRiskEvidence.MATH_CONTEXT
        );

        BigDecimal risk = probability.multiply(
                damagePotential,
                RbvmDerivedRiskEvidence.MATH_CONTEXT
        );

        return new Evaluation(
                ResultState.COMPUTED,
                null,
                DEFINITION,
                input.snapshot().contractId(),
                input.snapshot().snapshotSha256(),
                input.snapshot().findingId(),
                display(risk),
                "1.0000..100.0000",
                null,
                List.of(
                        measure("EPSS", "PROBABILITY_INPUT", vector.epss(), "0..1"),
                        measure("KEV", "PROBABILITY_INPUT", vector.kev(), "0..1"),
                        measure(
                                "REACHABILITY",
                                "PROBABILITY_INPUT",
                                vector.reachability(),
                                "0..1"
                        ),
                        measure("PROBABILITY", "AXIS", probability, "1..10"),
                        measure("CVSS", "DAMAGE_INPUT", vector.cvss(), "0..1"),
                        measure(
                                "BUSINESS_CRITICALITY",
                                "DAMAGE_INPUT",
                                vector.businessCriticality(),
                                "0..1"
                        ),
                        measure(
                                "BUSINESS_IMPACT",
                                "DAMAGE_INPUT",
                                vector.businessImpact(),
                                "0..1"
                        ),
                        measure("DAMAGE_POTENTIAL", "AXIS", damagePotential, "1..10")
                )
        );
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
