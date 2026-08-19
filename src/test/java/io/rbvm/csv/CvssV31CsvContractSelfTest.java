package io.rbvm.csv;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public final class CvssV31CsvContractSelfTest {
    private static final String SOURCE = "https://nvd.nist.gov/vuln/detail/CVE-2026-25087";
    private static final String VECTOR =
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";

    private CvssV31CsvContractSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        parsesCveScopedBaseEvidence();
        acceptsBaseMetricReorderingAsSemanticReplay();
        quarantinesConflictingSameSourceTimestampEvidence();
        quarantinesInvalidCvssEvidence();
        rejectsMissingContractHeader();
        doesNotDerivePriorityOrRisk();
        System.out.println("CvssV31CsvContractSelfTest: PASS");
    }

    private static void parsesCveScopedBaseEvidence() throws Exception {
        List<CvssV31CsvEvidence> rows = new ArrayList<>();
        CvssV31CsvAnalysisReport report = analyze(
                headers() + validRow("CVE-2026-25087", "7.5", VECTOR, SOURCE,
                        "2026-08-19T08:00:00Z"),
                rows
        );

        assert report.contractId().equals(CvssV31CsvContract.ID);
        assert report.semantics().equals(CvssV31CsvContract.SEMANTICS);
        assert report.acceptedRows() == 1;
        assert report.quarantinedRows() == 0;
        assert report.uniqueCves() == 1;
        assert rows.size() == 1;
        CvssV31BaseEvidence evidence = rows.get(0).evidence();
        assert evidence.cveId().equals("CVE-2026-25087");
        assert evidence.version().equals("3.1");
        assert evidence.baseScore().toPlainString().equals("7.5");
        assert evidence.canonicalVector().equals(VECTOR);
        assert evidence.source().equals(SOURCE);
    }

    private static void acceptsBaseMetricReorderingAsSemanticReplay() throws Exception {
        String reordered = "CVSS:3.1/A:H/I:H/C:H/S:U/UI:N/PR:N/AC:L/AV:N";
        String timestamp = "2026-08-19T08:10:00Z";
        String csv = headers()
                + validRow("CVE-2026-25087", "7.5", VECTOR, SOURCE, timestamp)
                + validRow("CVE-2026-25087", "7.5", reordered, SOURCE, timestamp);

        CvssV31CsvAnalysisReport report = analyze(csv, new ArrayList<>());
        assert report.logicalRows() == 2;
        assert report.acceptedRows() == 1;
        assert report.deduplicatedRows() == 1;
        assert report.quarantinedRows() == 0;
    }

    private static void quarantinesConflictingSameSourceTimestampEvidence() throws Exception {
        String timestamp = "2026-08-19T08:20:00Z";
        String differentVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:H";
        String csv = headers()
                + validRow("CVE-2026-25087", "7.5", VECTOR, SOURCE, timestamp)
                + validRow("CVE-2026-25087", "7.5", differentVector, SOURCE, timestamp);

        CvssV31CsvAnalysisReport report = analyze(csv, new ArrayList<>());
        assert report.acceptedRows() == 1;
        assert report.quarantinedRows() == 1;
        assert report.issueSamples().stream().anyMatch(issue ->
                issue.code().equals("CONFLICTING_CVSS_EVIDENCE_TIMESTAMP"));
    }

    private static void quarantinesInvalidCvssEvidence() throws Exception {
        String missingMetric = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H";
        String temporalMetric = VECTOR + "/E:H";
        String duplicateMetric = VECTOR + "/AV:L";
        String csv = headers()
                + validRow("bad-cve", "7.5", VECTOR, SOURCE, "2026-08-19T08:30:00Z")
                + validRow("CVE-2026-25087", "8.0", VECTOR, SOURCE, "2026-08-19T08:31:00Z")
                        .replace(",3.1,", ",4.0,")
                + validRow("CVE-2026-25087", "10.1", VECTOR, SOURCE, "2026-08-19T08:32:00Z")
                + validRow("CVE-2026-25087", "7.55", VECTOR, SOURCE, "2026-08-19T08:33:00Z")
                + validRow("CVE-2026-25087", "7.5", "CVSS:4.0/AV:N", SOURCE,
                        "2026-08-19T08:34:00Z")
                + validRow("CVE-2026-25087", "7.5", missingMetric, SOURCE,
                        "2026-08-19T08:35:00Z")
                + validRow("CVE-2026-25087", "7.5", temporalMetric, SOURCE,
                        "2026-08-19T08:36:00Z")
                + validRow("CVE-2026-25087", "7.5", duplicateMetric, SOURCE,
                        "2026-08-19T08:37:00Z")
                + validRow("CVE-2026-25087", "7.5", VECTOR, "http://example.test/cvss",
                        "2026-08-19T08:38:00Z")
                + validRow("CVE-2026-25087", "7.5", VECTOR, SOURCE, "2026-08-19");

        CvssV31CsvAnalysisReport report = analyze(csv, new ArrayList<>());
        assert report.acceptedRows() == 0;
        assert report.quarantinedRows() == 10;
        assert hasIssue(report, "INVALID_CVE_ID");
        assert hasIssue(report, "INVALID_CVSS_VERSION");
        assert hasIssue(report, "INVALID_CVSS_BASE_SCORE");
        assert hasIssue(report, "INVALID_CVSS_VECTOR");
        assert hasIssue(report, "INVALID_CVSS_SOURCE");
        assert hasIssue(report, "INVALID_CVSS_OBSERVED_AT");
    }

    private static void rejectsMissingContractHeader() throws Exception {
        String csv = "CVE_ID,CVSS_Version,CVSS_Base_Score,CVSS_Vector,CVSS_Observed_At\r\n";
        boolean rejected = false;
        try {
            analyze(csv, new ArrayList<>());
        } catch (CsvContractException expected) {
            rejected = expected.getMessage().contains("CVSS_Source");
        }
        assert rejected;
    }

    private static void doesNotDerivePriorityOrRisk() throws Exception {
        List<CvssV31CsvEvidence> rows = new ArrayList<>();
        CvssV31CsvAnalysisReport report = analyze(
                headers() + validRow("CVE-2026-25087", "9.8", VECTOR, SOURCE,
                        "2026-08-19T08:40:00Z"),
                rows
        );
        assert report.acceptedRows() == 1;
        assert !rows.get(0).evidence().toMap().containsKey("priorityTier");
        assert !rows.get(0).evidence().toMap().containsKey("riskScore");
        assert !rows.get(0).evidence().toMap().containsKey("sla");
    }

    private static boolean hasIssue(CvssV31CsvAnalysisReport report, String code) {
        return report.issueSamples().stream().anyMatch(issue -> issue.code().equals(code));
    }

    private static CvssV31CsvAnalysisReport analyze(
            String csv,
            List<CvssV31CsvEvidence> rows
    ) throws Exception {
        Path file = Files.createTempFile("cvss-v31-csv-", ".csv");
        try {
            Files.writeString(file, csv, StandardCharsets.UTF_8);
            return new CvssV31CsvAnalyzer().analyze(file, 10, rows::add);
        } finally {
            Files.deleteIfExists(file);
        }
    }

    private static String headers() {
        return "CVE_ID,CVSS_Version,CVSS_Base_Score,CVSS_Vector,CVSS_Source,CVSS_Observed_At\r\n";
    }

    private static String validRow(
            String cve,
            String score,
            String vector,
            String source,
            String observedAt
    ) {
        return cve + ",3.1," + score + ',' + vector + ',' + source + ',' + observedAt + "\r\n";
    }
}
