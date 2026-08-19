package io.rbvm.csv;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.Map;

/**
 * Exact CVSS v3.1 Base-score calculator for the eight mandatory Base metrics.
 *
 * <p>The implementation follows the FIRST CVSS v3.1 equations and uses decimal arithmetic so the
 * final one-decimal Roundup operation is not affected by binary floating-point noise.</p>
 */
public final class CvssV31BaseScoreCalculator {
    private static final BigDecimal ZERO = new BigDecimal("0");
    private static final BigDecimal ONE = new BigDecimal("1");
    private static final BigDecimal TEN = new BigDecimal("10");

    private static final Map<String, BigDecimal> ATTACK_VECTOR = Map.of(
            "N", new BigDecimal("0.85"),
            "A", new BigDecimal("0.62"),
            "L", new BigDecimal("0.55"),
            "P", new BigDecimal("0.20")
    );
    private static final Map<String, BigDecimal> ATTACK_COMPLEXITY = Map.of(
            "L", new BigDecimal("0.77"),
            "H", new BigDecimal("0.44")
    );
    private static final Map<String, BigDecimal> USER_INTERACTION = Map.of(
            "N", new BigDecimal("0.85"),
            "R", new BigDecimal("0.62")
    );
    private static final Map<String, BigDecimal> IMPACT = Map.of(
            "H", new BigDecimal("0.56"),
            "L", new BigDecimal("0.22"),
            "N", ZERO
    );

    private CvssV31BaseScoreCalculator() {
    }

    public static BigDecimal calculate(String vector) {
        return calculate(CvssV31BaseEvidence.parseBaseMetrics(vector));
    }

    static BigDecimal calculate(Map<String, String> metrics) {
        String scope = metrics.get("S");

        BigDecimal iss = ONE.subtract(
                ONE.subtract(weight(IMPACT, metrics.get("C")))
                        .multiply(ONE.subtract(weight(IMPACT, metrics.get("I"))))
                        .multiply(ONE.subtract(weight(IMPACT, metrics.get("A"))))
        );

        BigDecimal impact;
        if (scope.equals("U")) {
            impact = new BigDecimal("6.42").multiply(iss);
        } else {
            impact = new BigDecimal("7.52")
                    .multiply(iss.subtract(new BigDecimal("0.029")))
                    .subtract(new BigDecimal("3.25")
                            .multiply(iss.subtract(new BigDecimal("0.02")).pow(15)));
        }

        if (impact.compareTo(ZERO) <= 0) {
            return new BigDecimal("0.0");
        }

        BigDecimal exploitability = new BigDecimal("8.22")
                .multiply(weight(ATTACK_VECTOR, metrics.get("AV")))
                .multiply(weight(ATTACK_COMPLEXITY, metrics.get("AC")))
                .multiply(privilegesRequired(metrics.get("PR"), scope))
                .multiply(weight(USER_INTERACTION, metrics.get("UI")));

        BigDecimal combined = impact.add(exploitability);
        if (scope.equals("C")) {
            combined = new BigDecimal("1.08").multiply(combined);
        }
        return roundup(combined.min(TEN));
    }

    private static BigDecimal privilegesRequired(String value, String scope) {
        if (value.equals("N")) {
            return new BigDecimal("0.85");
        }
        if (value.equals("L")) {
            return scope.equals("C") ? new BigDecimal("0.68") : new BigDecimal("0.62");
        }
        if (value.equals("H")) {
            return scope.equals("C") ? new BigDecimal("0.50") : new BigDecimal("0.27");
        }
        throw new IllegalArgumentException("Unsupported CVSS Privileges Required value: " + value);
    }

    private static BigDecimal weight(Map<String, BigDecimal> weights, String value) {
        BigDecimal weight = weights.get(value);
        if (weight == null) {
            throw new IllegalArgumentException("Unsupported CVSS metric value: " + value);
        }
        return weight;
    }

    /** FIRST Roundup semantics: smallest one-decimal value greater than or equal to the input. */
    private static BigDecimal roundup(BigDecimal input) {
        return input.setScale(1, RoundingMode.CEILING);
    }
}
