package io.rbvm.csv;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.UUID;

public final class CsvContractSelfTest {
    private CsvContractSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        parsesEmbeddedNewlinesAndEscapedQuotes();
        separatesRowDeduplicationFromExposureReobservation();
        acceptsBomAndColumnReordering();
        fingerprintIsIndependentOfColumnOrder();
        rejectsMissingContractHeader();
        rejectsMalformedUtf8();
        rejectsInvalidCveAndTimestampIntoQuarantine();
        validatesExplicitV2LifecycleEvidence();
        enforcesImportRunTransitions();
        System.out.println("CsvContractSelfTest: PASS");
    }

    private static void parsesEmbeddedNewlinesAndEscapedQuotes() throws Exception {
        String csv = headers() +
                "agent-a,CVE-2025-1234,High,\"first line\nsecond \"\"quoted\"\" line\",pkg-a,https://example.test/cve,Ubuntu,2026-07-01T10:15:30Z\r\n";
        AnalysisReport report = analyze(csv);
        assert report.logicalRows() == 1;
        assert report.acceptedRows() == 1;
        assert report.valuesWithEmbeddedNewlines() == 1;
        assert report.maximumFieldLengths().get("CVE_Description") > 20;
    }

    private static void separatesRowDeduplicationFromExposureReobservation() throws Exception {
        String first = "agent-a,CVE-2025-1234,Medium,description,pkg-a,https://example.test/1,Ubuntu,2026-07-01T10:15:30Z\r\n";
        String second = "agent-a,CVE-2025-1234,High,description,pkg-a,https://example.test/1,Ubuntu,2026-07-02T10:15:30Z\r\n";
        AnalysisReport report = analyze(headers() + first + second + second);
        assert report.logicalRows() == 3;
        assert report.acceptedRows() == 2;
        assert report.deduplicatedRows() == 1;
        assert report.uniqueExposureKeys() == 1;
        assert report.repeatedExposureGroups() == 1;
        assert report.repeatedExposureObservations() == 1;
        assert report.exposureGroupsWithSeverityChanges() == 1;
        assert report.severityDistribution().get("MEDIUM") == 1;
        assert report.severityDistribution().get("HIGH") == 1;
    }

    private static void acceptsBomAndColumnReordering() throws Exception {
        String csv = "\uFEFFCVE_ID,Agent,Severity,CVE_Description,Affected_Product,References,OS_name,Detected_At\r\n" +
                "CVE-2025-1234,agent-a,-,description,pkg-a,https://example.test/1,Ubuntu,2026-07-01T10:15:30Z\r\n";
        AnalysisReport report = analyze(csv);
        assert report.acceptedRows() == 1;
        assert report.severityDistribution().get("UNKNOWN") == 1;
    }

    private static void fingerprintIsIndependentOfColumnOrder() throws Exception {
        String canonical = headers()
                + "agent-a,CVE-2025-1234,High,description,pkg-a,https://example.test/1,Ubuntu,2026-07-01T10:15:30Z\r\n";
        String reordered = "CVE_ID,Agent,Detected_At,Severity,CVE_Description,Affected_Product,References,OS_name\r\n"
                + "CVE-2025-1234,agent-a,2026-07-01T10:15:30Z,High,description,pkg-a,https://example.test/1,Ubuntu\r\n";
        String first = analyze(canonical).preview().get(0).get("observationFingerprint").toString();
        String second = analyze(reordered).preview().get(0).get("observationFingerprint").toString();
        assert first.equals(second) : first + " != " + second;
    }

    private static void rejectsMissingContractHeader() throws Exception {
        String csv = "Agent,CVE_ID,Severity,CVE_Description,Affected_Product,References,OS_name\r\n";
        boolean rejected = false;
        try {
            analyze(csv);
        } catch (CsvContractException expected) {
            rejected = expected.getMessage().contains("Detected_At");
        }
        assert rejected;
    }

    private static void rejectsMalformedUtf8() throws Exception {
        Path file = Files.createTempFile("wazuh-invalid-utf8-", ".csv");
        try {
            byte[] header = headers().getBytes(StandardCharsets.UTF_8);
            byte[] invalid = new byte[header.length + 2];
            System.arraycopy(header, 0, invalid, 0, header.length);
            invalid[header.length] = (byte) 0xC3;
            invalid[header.length + 1] = 0x28;
            Files.write(file, invalid);
            boolean rejected = false;
            try {
                new WazuhCsvAnalyzer("test-profile").analyze(file, 0);
            } catch (CsvContractException expected) {
                rejected = expected.getMessage().contains("UTF-8");
            }
            assert rejected;
        } finally {
            Files.deleteIfExists(file);
        }
    }

    private static void rejectsInvalidCveAndTimestampIntoQuarantine() throws Exception {
        String invalidCve = "agent-a,not-a-cve,High,description,pkg-a,https://example.test/1,Ubuntu,2026-07-01T10:15:30Z\r\n";
        String invalidTime = "agent-a,CVE-2025-1234,High,description,pkg-a,https://example.test/1,Ubuntu,2026-07-01\r\n";
        AnalysisReport report = analyze(headers() + invalidCve + invalidTime);
        assert report.logicalRows() == 2;
        assert report.acceptedRows() == 0;
        assert report.quarantinedRows() == 2;
        assert report.issueSamples().size() == 2;
    }

    private static void enforcesImportRunTransitions() throws Exception {
        AnalysisReport report = analyze(headers() +
                "agent-a,CVE-2025-1234,High,description,pkg-a,https://example.test/1,Ubuntu,2026-07-01T10:15:30Z\r\n");
        CsvImportRun run = CsvImportRun.uploaded(
                UUID.fromString("0d36497b-ebc6-49d9-a700-b663becf4aa4"),
                "tenant-a",
                "wazuh-csv-default",
                report.fileSha256(),
                Instant.parse("2026-07-20T10:00:00Z")
        );

        assert run.status() == CsvImportStatus.UPLOADED;
        run.startValidation();
        run.previewReady(report);
        run.startImport();
        run.startReconciliation();
        run.complete();
        assert run.status() == CsvImportStatus.COMPLETED;

        boolean rejectedInvalidTransition = false;
        try {
            run.startImport();
        } catch (IllegalStateException expected) {
            rejectedInvalidTransition = true;
        }
        assert rejectedInvalidTransition;
    }

    private static void validatesExplicitV2LifecycleEvidence() throws Exception {
        String headers = "Agent,Agent_ID,CVE_ID,Severity,CVE_Description,Affected_Product,"
                + "Package_Version,Package_Architecture,References,OS_name,Finding_Status,"
                + "Detected_At,Resolved_At\r\n";
        String rows = "renamed-agent,001,CVE-2026-4321,High,description,openssl,3.0.2,amd64,"
                + "https://example.test/1,Ubuntu,ACTIVE,2026-08-01T10:00:00Z,\r\n"
                + "renamed-agent,001,CVE-2026-4321,High,description,openssl,3.0.2,amd64,"
                + "https://example.test/2,Ubuntu,RESOLVED,2026-08-01T10:00:00Z,"
                + "2026-08-02T10:00:00Z\r\n"
                + "renamed-agent,001,CVE-2026-4321,High,description,openssl,3.0.2,amd64,"
                + "https://example.test/3,Ubuntu,ACTIVE,2026-08-03T10:00:00Z,"
                + "2026-08-04T10:00:00Z\r\n";
        Path file = Files.createTempFile("wazuh-csv-v2-", ".csv");
        try {
            Files.writeString(file, headers + rows, StandardCharsets.UTF_8);
            AnalysisReport report = new WazuhCsvAnalyzer("v2-profile", CsvContractV2.ID)
                    .analyze(file, 10);
            assert report.contractId().equals(CsvContractV2.ID);
            assert report.semantics().equals(CsvContractV2.SEMANTICS);
            assert report.activeRows() == 1;
            assert report.resolvedRows() == 1;
            assert report.quarantinedRows() == 1;
            assert report.issueSamples().stream()
                    .anyMatch(issue -> issue.code().equals("ACTIVE_WITH_RESOLVED_AT"));
        } finally {
            Files.deleteIfExists(file);
        }
    }

    private static AnalysisReport analyze(String csv) throws Exception {
        Path file = Files.createTempFile("wazuh-csv-v1-", ".csv");
        try {
            Files.writeString(file, csv, StandardCharsets.UTF_8);
            return new WazuhCsvAnalyzer("test-profile").analyze(file, 2);
        } finally {
            Files.deleteIfExists(file);
        }
    }

    private static String headers() {
        return "Agent,CVE_ID,Severity,CVE_Description,Affected_Product,References,OS_name,Detected_At\r\n";
    }
}
