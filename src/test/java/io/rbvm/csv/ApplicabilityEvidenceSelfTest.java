package io.rbvm.csv;

import java.time.Instant;

public final class ApplicabilityEvidenceSelfTest {
    private ApplicabilityEvidenceSelfTest() {
    }

    public static void main(String[] args) {
        startsUnassessedAndUnknown();
        recordsApplicableAssessmentWithProvenance();
        recordsNotApplicableAssessmentWithProvenance();
        permitsExplicitInconclusiveAssessment();
        rejectsAssessedEvidenceWithoutReasonOrSource();
        System.out.println("ApplicabilityEvidenceSelfTest: PASS");
    }

    private static void startsUnassessedAndUnknown() {
        CanonicalFindingIdentity identity = finding();
        ApplicabilityEvidence evidence = ApplicabilityEvidence.unassessed(identity);

        assert evidence.findingIdentity().equals(identity);
        assert evidence.status() == ApplicabilityEvidence.Status.UNKNOWN;
        assert !evidence.assessed();
        assert evidence.reason() == null;
        assert evidence.evidenceSource() == null;
        assert evidence.evaluatedAt() == null;
    }

    private static void recordsApplicableAssessmentWithProvenance() {
        Instant evaluatedAt = Instant.parse("2026-08-18T18:30:00Z");
        ApplicabilityEvidence evidence = ApplicabilityEvidence.assessed(
                finding(),
                ApplicabilityEvidence.Status.APPLICABLE,
                "Affected component and deployment condition were confirmed.",
                "security-advisory:example",
                evaluatedAt
        );

        assert evidence.status() == ApplicabilityEvidence.Status.APPLICABLE;
        assert evidence.assessed();
        assert evidence.reason().contains("confirmed");
        assert evidence.evidenceSource().equals("security-advisory:example");
        assert evidence.evaluatedAt().equals(evaluatedAt);
    }

    private static void recordsNotApplicableAssessmentWithProvenance() {
        ApplicabilityEvidence evidence = ApplicabilityEvidence.assessed(
                finding(),
                ApplicabilityEvidence.Status.NOT_APPLICABLE,
                "Required vulnerable functionality is not present in this deployment.",
                "vendor-advisory:example",
                Instant.parse("2026-08-18T18:31:00Z")
        );

        assert evidence.status() == ApplicabilityEvidence.Status.NOT_APPLICABLE;
        assert evidence.assessed();
    }

    private static void permitsExplicitInconclusiveAssessment() {
        ApplicabilityEvidence evidence = ApplicabilityEvidence.assessed(
                finding(),
                ApplicabilityEvidence.Status.UNKNOWN,
                "Available CSV evidence cannot confirm the required runtime condition.",
                "analyst-review:case-42",
                Instant.parse("2026-08-18T18:32:00Z")
        );

        assert evidence.status() == ApplicabilityEvidence.Status.UNKNOWN;
        assert evidence.assessed();
        assert evidence.reason().contains("cannot confirm");
    }

    private static void rejectsAssessedEvidenceWithoutReasonOrSource() {
        boolean missingReasonRejected = false;
        try {
            ApplicabilityEvidence.assessed(
                    finding(),
                    ApplicabilityEvidence.Status.APPLICABLE,
                    " ",
                    "vendor-advisory:example",
                    Instant.parse("2026-08-18T18:33:00Z")
            );
        } catch (IllegalArgumentException expected) {
            missingReasonRejected = expected.getMessage().contains("reason");
        }
        assert missingReasonRejected;

        boolean missingSourceRejected = false;
        try {
            ApplicabilityEvidence.assessed(
                    finding(),
                    ApplicabilityEvidence.Status.NOT_APPLICABLE,
                    "Reason",
                    " ",
                    Instant.parse("2026-08-18T18:33:00Z")
            );
        } catch (IllegalArgumentException expected) {
            missingSourceRejected = expected.getMessage().contains("evidenceSource");
        }
        assert missingSourceRejected;
    }

    private static CanonicalFindingIdentity finding() {
        return new CanonicalFindingIdentity(
                "wazuh-primary",
                "hodor-aio",
                "CVE-2026-25087",
                "pyarrow",
                CanonicalFindingIdentity.Strength.SOURCE_LIMITED
        );
    }
}
