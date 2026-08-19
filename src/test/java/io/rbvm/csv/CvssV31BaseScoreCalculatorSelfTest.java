package io.rbvm.csv;

import java.math.BigDecimal;

public final class CvssV31BaseScoreCalculatorSelfTest {
    private CvssV31BaseScoreCalculatorSelfTest() {
    }

    public static void main(String[] args) {
        matchesFirstPublishedExamplesAndScopeRules();
        appliesScopeDependentPrivilegesRequiredWeights();
        handlesZeroImpact();
        rejectsScoreVectorMismatchAtEvidenceBoundary();
        System.out.println("CvssV31BaseScoreCalculatorSelfTest: PASS");
    }

    private static void matchesFirstPublishedExamplesAndScopeRules() {
        assertScore(
                "9.8",
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        );
        assertScore(
                "8.1",
                "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"
        );
        assertScore(
                "7.8",
                "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
        );
        assertScore(
                "10.0",
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
        );
    }

    private static void appliesScopeDependentPrivilegesRequiredWeights() {
        assertScore(
                "8.8",
                "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
        );
        assertScore(
                "9.9",
                "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"
        );
        assertScore(
                "7.2",
                "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"
        );
        assertScore(
                "9.1",
                "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H"
        );
    }

    private static void handlesZeroImpact() {
        assertScore(
                "0.0",
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
        );
    }

    private static void rejectsScoreVectorMismatchAtEvidenceBoundary() {
        boolean rejected = false;
        try {
            new CvssV31BaseEvidence(
                    "CVE-2026-25087",
                    "3.1",
                    new BigDecimal("7.5"),
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "https://nvd.nist.gov/vuln/detail/CVE-2026-25087",
                    java.time.Instant.parse("2026-08-19T08:00:00Z")
            );
        } catch (IllegalArgumentException expected) {
            rejected = expected.getMessage().contains("expected 9.8");
        }
        assert rejected;
    }

    private static void assertScore(String expected, String vector) {
        BigDecimal actual = CvssV31BaseScoreCalculator.calculate(vector);
        assert actual.compareTo(new BigDecimal(expected)) == 0
                : vector + " expected=" + expected + " actual=" + actual;
    }
}
