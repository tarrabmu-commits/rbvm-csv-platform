package io.rbvm.csv;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

public final class ApplicabilityCsvContractSelfTest {
    private static final String FINDING_A = "11111111-1111-4111-8111-111111111111";
    private static final String FINDING_B = "22222222-2222-4222-8222-222222222222";

    private ApplicabilityCsvContractSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        parsesExplicitAssessmentsIncludingInconclusiveUnknown();
        acceptsBomAndColumnReordering();
        deduplicatesExactAssessmentReplay();
        quarantinesConflictingSameTimestampEvidence();
        quarantinesInvalidAssessmentRows();
        rejectsMissingContractHeader();
        convertsParsedRowToFindingScopedEvidence();
        System.out.println("ApplicabilityCsvContractSelfTest: PASS");
    }

    private static void parsesExplicitAssessmentsIncludingInconclusiveUnknown() throws Exception {
        String csv = headers()
                + FINDING_A + ",APPLICABLE,Package and vulnerable feature are present,Vendor advisory,2026-08-18T10:00:00Z\r\n"
                + FINDING_B + ",UNKNOWN,Configuration evidence is inconclusive,Internal review,2026-08-18T11:00:00Z\r\n";
        List<ApplicabilityCsvAssessment> assessments = new ArrayList<>();
        ApplicabilityCsvAnalysisReport report = analyze(csv, assessments);

        assert report.contractId().equals(ApplicabilityCsvContract.ID);
        assert report.semantics().equals(ApplicabilityCsvContract.SEMANTICS);
        assert report.acceptedRows() == 2;
        assert report.quarantinedRows() == 0;
        assert report.statusDistribution().get("APPLICABLE") == 1;
        assert report.statusDistribution().get("UNKNOWN") == 1;
        assert assessments.size() == 2;
        assert assessments.get(1).status() == ApplicabilityEvidence.Status.UNKNOWN;
    }

    private static void acceptsBomAndColumnReordering() throws Exception {
        String csv = "\uFEFFApplicability_Status,Finding_ID,Evaluated_At,Evidence_Source,Applicability_Reason\r\n"
                + "NOT_APPLICABLE," + FINDING_A
                + ",2026-08-18T12:00:00Z,Vendor advisory,Vulnerable functionality is not exposed\r\n";
        ApplicabilityCsvAnalysisReport report = analyze(csv, new ArrayList<>());
        assert report.acceptedRows() == 1;
        assert report.statusDistribution().get("NOT_APPLICABLE") == 1;
    }

    private static void deduplicatesExactAssessmentReplay() throws Exception {
        String row = FINDING_A
                + ",APPLICABLE,Confirmed by deployment review,Internal change record,2026-08-18T13:00:00Z\r\n";
        ApplicabilityCsvAnalysisReport report = analyze(headers() + row + row, new ArrayList<>());
        assert report.logicalRows() == 2;
        assert report.acceptedRows() == 1;
        assert report.deduplicatedRows() == 1;
        assert report.quarantinedRows() == 0;
    }

    private static void quarantinesConflictingSameTimestampEvidence() throws Exception {
        String csv = headers()
                + FINDING_A + ",APPLICABLE,First assessment,Source A,2026-08-18T14:00:00Z\r\n"
                + FINDING_A + ",NOT_APPLICABLE,Conflicting assessment,Source B,2026-08-18T14:00:00Z\r\n";
        ApplicabilityCsvAnalysisReport report = analyze(csv, new ArrayList<>());
        assert report.acceptedRows() == 1;
        assert report.quarantinedRows() == 1;
        assert report.issueSamples().stream()
                .anyMatch(issue -> issue.code().equals("CONFLICTING_ASSESSMENT_TIMESTAMP"));
    }

    private static void quarantinesInvalidAssessmentRows() throws Exception {
        String csv = headers()
                + "not-a-uuid,APPLICABLE,Reason,Source,2026-08-18T15:00:00Z\r\n"
                + FINDING_A + ",MAYBE,Reason,Source,2026-08-18T15:00:00Z\r\n"
                + FINDING_A + ",APPLICABLE,,Source,2026-08-18T15:00:00Z\r\n"
                + FINDING_A + ",APPLICABLE,Reason,Source,2026-08-18\r\n";
        ApplicabilityCsvAnalysisReport report = analyze(csv, new ArrayList<>());
        assert report.acceptedRows() == 0;
        assert report.quarantinedRows() == 4;
        assert report.issueSamples().stream().anyMatch(issue -> issue.code().equals("INVALID_FINDING_ID"));
        assert report.issueSamples().stream().anyMatch(issue -> issue.code().equals("INVALID_APPLICABILITY_STATUS"));
        assert report.issueSamples().stream().anyMatch(issue -> issue.code().equals("MISSING_REQUIRED_VALUE"));
        assert report.issueSamples().stream().anyMatch(issue -> issue.code().equals("INVALID_EVALUATED_AT"));
    }

    private static void rejectsMissingContractHeader() throws Exception {
        String csv = "Finding_ID,Applicability_Status,Applicability_Reason,Evaluated_At\r\n";
        boolean rejected = false;
        try {
            analyze(csv, new ArrayList<>());
        } catch (CsvContractException expected) {
            rejected = expected.getMessage().contains("Evidence_Source");
        }
        assert rejected;
    }

    private static void convertsParsedRowToFindingScopedEvidence() throws Exception {
        List<ApplicabilityCsvAssessment> assessments = new ArrayList<>();
        analyze(headers()
                + FINDING_A + ",NOT_APPLICABLE,Vendor says binding is unaffected,Vendor advisory,2026-08-18T16:00:00Z\r\n",
                assessments);
        CanonicalFindingIdentity identity = new CanonicalFindingIdentity(
                "profile-a",
                "asset-a",
                "CVE-2026-25087",
                "pyarrow",
                CanonicalFindingIdentity.Strength.SOURCE_LIMITED
        );
        ApplicabilityEvidence evidence = assessments.get(0).toEvidence(identity);
        assert evidence.assessed();
        assert evidence.status() == ApplicabilityEvidence.Status.NOT_APPLICABLE;
        assert evidence.evaluatedAt().equals(Instant.parse("2026-08-18T16:00:00Z"));
    }

    private static ApplicabilityCsvAnalysisReport analyze(
            String csv,
            List<ApplicabilityCsvAssessment> assessments
    ) throws Exception {
        Path file = Files.createTempFile("applicability-csv-", ".csv");
        try {
            Files.writeString(file, csv, StandardCharsets.UTF_8);
            return new ApplicabilityCsvAnalyzer().analyze(file, 10, assessments::add);
        } finally {
            Files.deleteIfExists(file);
        }
    }

    private static String headers() {
        return "Finding_ID,Applicability_Status,Applicability_Reason,Evidence_Source,Evaluated_At\r\n";
    }
}
