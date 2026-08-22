package io.rbvm.decision;

import io.rbvm.decision.RbvmDerivedRiskMethodology.Evaluation;
import io.rbvm.decision.RbvmDerivedRiskMethodology.Measure;
import io.rbvm.decision.RbvmDerivedRiskMethodology.ResultState;

import java.math.BigDecimal;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;

/** Acceptance checks for deterministic multi-methodology result canonicalization. */
public final class RbvmDerivedRiskCanonicalResultSelfTest {
    private static final UUID FINDING_ID =
            UUID.fromString("22222222-2222-4222-8222-222222222222");
    private static final String SNAPSHOT_SHA = "c".repeat(64);
    private static final String FROZEN_OWASP_SHA =
            "1260c23be5c03990440af13650797d382d640f77f0cc358fd1fd92dc4cdea13d";

    private RbvmDerivedRiskCanonicalResultSelfTest() {
    }

    public static void main(String[] args) {
        freezesComputedIdentity();
        normalizesMeasureOrderWithoutChangingSemantics();
        changesIdentityWhenResultSemanticsChange();
        preservesTerminalNonNumericSemantics();
        rejectsInvalidCanonicalInputs();
        System.out.println("RbvmDerivedRiskCanonicalResultSelfTest: PASS");
    }

    private static void freezesComputedIdentity() {
        RbvmDerivedRiskCanonicalResult result =
                RbvmDerivedRiskCanonicalResult.from(owaspEvaluation(measures()));

        assert result.canonicalSha256().equals(FROZEN_OWASP_SHA)
                : result.canonicalSha256();
        assert result.canonicalPayload().length == 981 : result.canonicalPayload().length;
        assert sha256(result.canonicalPayload()).equals(result.canonicalSha256());
        assert result.evaluation().definition().methodologySha256()
                .equals(OwaspDerivedRiskV1.METHODOLOGY_SHA256);
        assert result.canonicalMeasures().get(0).measureId()
                .equals("BUSINESS_CRITICALITY_IMPACT_FACTOR");
    }

    private static void normalizesMeasureOrderWithoutChangingSemantics() {
        List<Measure> reversed = new ArrayList<>(measures());
        java.util.Collections.reverse(reversed);

        RbvmDerivedRiskCanonicalResult first =
                RbvmDerivedRiskCanonicalResult.from(owaspEvaluation(measures()));
        RbvmDerivedRiskCanonicalResult second =
                RbvmDerivedRiskCanonicalResult.from(owaspEvaluation(reversed));

        assert first.canonicalSha256().equals(second.canonicalSha256());
        assert java.util.Arrays.equals(first.canonicalPayload(), second.canonicalPayload());
    }

    private static void changesIdentityWhenResultSemanticsChange() {
        RbvmDerivedRiskCanonicalResult baseline =
                RbvmDerivedRiskCanonicalResult.from(owaspEvaluation(measures()));
        Evaluation changedRating = new Evaluation(
                ResultState.COMPUTED,
                null,
                OwaspDerivedRiskV1.INSTANCE.definition(),
                RbvmDecisionInputSnapshot.V3_ID,
                SNAPSHOT_SHA,
                FINDING_ID,
                new BigDecimal("16.3350"),
                "0.0000..81.0000",
                "HIGH",
                measures()
        );
        Evaluation microsoft = new Evaluation(
                ResultState.COMPUTED,
                null,
                MicrosoftProbabilityDamageDerivedV1.INSTANCE.definition(),
                RbvmDecisionInputSnapshot.V3_ID,
                SNAPSHOT_SHA,
                FINDING_ID,
                new BigDecimal("25.5850"),
                "1.0000..100.0000",
                null,
                List.of(
                        new Measure("PROBABILITY", "AXIS", new BigDecimal("4.3000"), "1..10"),
                        new Measure(
                                "DAMAGE_POTENTIAL",
                                "AXIS",
                                new BigDecimal("5.9500"),
                                "1..10"
                        )
                )
        );

        assert !baseline.canonicalSha256().equals(
                RbvmDerivedRiskCanonicalResult.from(changedRating).canonicalSha256());
        assert !baseline.canonicalSha256().equals(
                RbvmDerivedRiskCanonicalResult.from(microsoft).canonicalSha256());
    }

    private static void preservesTerminalNonNumericSemantics() {
        Evaluation terminal = new Evaluation(
                ResultState.NON_COMPUTABLE,
                "EXPLOITATION_PROBABILITY_MISSING",
                OwaspDerivedRiskV1.INSTANCE.definition(),
                RbvmDecisionInputSnapshot.V3_ID,
                SNAPSHOT_SHA,
                FINDING_ID,
                null,
                null,
                null,
                List.of()
        );
        RbvmDerivedRiskCanonicalResult result = RbvmDerivedRiskCanonicalResult.from(terminal);

        assert result.evaluation().state() == ResultState.NON_COMPUTABLE;
        assert result.evaluation().numericScore() == null;
        assert result.evaluation().rating() == null;
        assert result.canonicalMeasures().isEmpty();
        assert sha256(result.canonicalPayload()).equals(result.canonicalSha256());
    }

    private static void rejectsInvalidCanonicalInputs() {
        Evaluation historicalInput = new Evaluation(
                ResultState.COMPUTED,
                null,
                OwaspDerivedRiskV1.INSTANCE.definition(),
                RbvmDecisionInputSnapshot.V2_ID,
                SNAPSHOT_SHA,
                FINDING_ID,
                new BigDecimal("16.3350"),
                "0.0000..81.0000",
                "MEDIUM",
                measures()
        );
        try {
            RbvmDerivedRiskCanonicalResult.from(historicalInput);
            throw new AssertionError("expected V3 input requirement");
        } catch (IllegalArgumentException expected) {
            assert expected.getMessage().contains("SNAPSHOT_V3");
        }

        List<Measure> duplicates = new ArrayList<>(measures());
        duplicates.add(new Measure("IMPACT", "AXIS", new BigDecimal("4.9500"), "0..9"));
        try {
            RbvmDerivedRiskCanonicalResult.from(owaspEvaluation(duplicates));
            throw new AssertionError("expected duplicate measure rejection");
        } catch (IllegalArgumentException expected) {
            assert expected.getMessage().contains("duplicate measureId");
        }
    }

    private static Evaluation owaspEvaluation(List<Measure> values) {
        return new Evaluation(
                ResultState.COMPUTED,
                null,
                OwaspDerivedRiskV1.INSTANCE.definition(),
                RbvmDecisionInputSnapshot.V3_ID,
                SNAPSHOT_SHA,
                FINDING_ID,
                new BigDecimal("16.3350"),
                "0.0000..81.0000",
                "MEDIUM",
                values
        );
    }

    private static List<Measure> measures() {
        return List.of(
                new Measure(
                        "EPSS_LIKELIHOOD_FACTOR",
                        "LIKELIHOOD_FACTOR",
                        new BigDecimal("0.9000"),
                        "0..9"
                ),
                new Measure(
                        "KEV_LIKELIHOOD_FACTOR",
                        "LIKELIHOOD_FACTOR",
                        new BigDecimal("0.0000"),
                        "0..9"
                ),
                new Measure(
                        "REACHABILITY_LIKELIHOOD_FACTOR",
                        "LIKELIHOOD_FACTOR",
                        new BigDecimal("9.0000"),
                        "0..9"
                ),
                new Measure("LIKELIHOOD", "AXIS", new BigDecimal("3.3000"), "0..9"),
                new Measure(
                        "CVSS_IMPACT_FACTOR",
                        "IMPACT_FACTOR",
                        new BigDecimal("5.8500"),
                        "0..9"
                ),
                new Measure(
                        "BUSINESS_CRITICALITY_IMPACT_FACTOR",
                        "IMPACT_FACTOR",
                        new BigDecimal("4.5000"),
                        "0..9"
                ),
                new Measure(
                        "BUSINESS_IMPACT_FACTOR",
                        "IMPACT_FACTOR",
                        new BigDecimal("4.5000"),
                        "0..9"
                ),
                new Measure("IMPACT", "AXIS", new BigDecimal("4.9500"), "0..9")
        );
    }

    private static String sha256(byte[] value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException(exception);
        }
    }
}
