package io.rbvm.csv;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public final class EpssCsvContractSelfTest {
    private static final String SOURCE = EpssEvidence.FIRST_EPSS_SOURCE;
    private static final String SHA = "a".repeat(64);

    private EpssCsvContractSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        acceptsIndependentProbabilityEvidence();
        rejectsInvalidProbabilityAndProvenance();
        deduplicatesSemanticReplayAndQuarantinesConflict();
        doesNotFabricateMissingEvidenceOrDeriveDecisionPolicy();
        System.out.println("EpssCsvContractSelfTest: PASS");
    }

    private static void acceptsIndependentProbabilityEvidence() throws Exception {
        Path file = csv("""
                CVE_ID,EPSS_Probability,EPSS_Percentile,EPSS_Model_Version,EPSS_Score_Date,EPSS_Source,EPSS_Observed_At,EPSS_Source_SHA256
                CVE-2026-10001,0.125,0.875,2025.03.14,2026-08-19,%s,2026-08-19T10:00:00Z,%s
                CVE-2026-10002,0,0.01,2025.03.14,2026-08-19,%s,2026-08-19T10:00:00Z,%s
                """.formatted(SOURCE, SHA, SOURCE, SHA));
        List<EpssCsvEvidence> evidence = new ArrayList<>();
        EpssCsvAnalysisReport report = new EpssCsvAnalyzer().analyze(file, 10, evidence::add);
        assert report.logicalRows() == 2;
        assert report.acceptedRows() == 2;
        assert report.quarantinedRows() == 0;
        assert report.uniqueCves() == 2;
        assert report.uniqueSnapshots() == 1;
        assert evidence.get(0).evidence().probability().toPlainString().equals("0.125");
        assert evidence.get(0).evidence().percentile().toPlainString().equals("0.875");
        assert evidence.get(0).evidence().scoreDate().toString().equals("2026-08-19");
        assert evidence.get(0).evidence().sourceSha256().equals(SHA);
    }

    private static void rejectsInvalidProbabilityAndProvenance() throws Exception {
        Path file = csv("""
                CVE_ID,EPSS_Probability,EPSS_Percentile,EPSS_Model_Version,EPSS_Score_Date,EPSS_Source,EPSS_Observed_At,EPSS_Source_SHA256
                CVE-2026-10001,1.01,0.9,2025.03.14,2026-08-19,%s,2026-08-19T10:00:00Z,%s
                CVE-2026-10002,0.2,-0.1,2025.03.14,2026-08-19,%s,2026-08-19T10:00:00Z,%s
                CVE-2026-10003,0.2,0.9,not-a-model,2026-08-19,%s,2026-08-19T10:00:00Z,%s
                CVE-2026-10004,0.2,0.9,2025.03.14,2026-08-19,https://example.invalid/epss.csv.gz,2026-08-19T10:00:00Z,%s
                CVE-2026-10005,0.2,0.9,2025.03.14,2026-08-19,%s,2026-08-19T10:00:00Z,bad
                """.formatted(SOURCE, SHA, SOURCE, SHA, SOURCE, SHA, SHA, SOURCE));
        EpssCsvAnalysisReport report = new EpssCsvAnalyzer().analyze(file, 10);
        assert report.acceptedRows() == 0;
        assert report.quarantinedRows() == 5;
        assert report.issueSamples().stream().anyMatch(issue ->
                issue.code().equals("INVALID_EPSS_PROBABILITY"));
        assert report.issueSamples().stream().anyMatch(issue ->
                issue.code().equals("INVALID_EPSS_PERCENTILE"));
        assert report.issueSamples().stream().anyMatch(issue ->
                issue.code().equals("INVALID_EPSS_MODEL_VERSION"));
        assert report.issueSamples().stream().anyMatch(issue ->
                issue.code().equals("INVALID_EPSS_SOURCE"));
        assert report.issueSamples().stream().anyMatch(issue ->
                issue.code().equals("INVALID_EPSS_SOURCE_SHA256"));
    }

    private static void deduplicatesSemanticReplayAndQuarantinesConflict() throws Exception {
        Path file = csv("""
                CVE_ID,EPSS_Probability,EPSS_Percentile,EPSS_Model_Version,EPSS_Score_Date,EPSS_Source,EPSS_Observed_At,EPSS_Source_SHA256
                CVE-2026-10001,0.10,0.900,2025.03.14,2026-08-19,%s,2026-08-19T10:00:00Z,%s
                CVE-2026-10001,0.1,0.9,2025.03.14,2026-08-19,%s,2026-08-19T10:00:00Z,%s
                CVE-2026-10001,0.2,0.9,2025.03.14,2026-08-19,%s,2026-08-19T10:00:00Z,%s
                """.formatted(SOURCE, SHA, SOURCE, SHA, SOURCE, SHA));
        EpssCsvAnalysisReport report = new EpssCsvAnalyzer().analyze(file, 10);
        assert report.acceptedRows() == 1;
        assert report.deduplicatedRows() == 1;
        assert report.quarantinedRows() == 1;
        assert report.issueSamples().stream().anyMatch(issue ->
                issue.code().equals("CONFLICTING_EPSS_EVIDENCE_TIMESTAMP"));
    }

    private static void doesNotFabricateMissingEvidenceOrDeriveDecisionPolicy() throws Exception {
        Path file = csv("""
                CVE_ID,EPSS_Probability,EPSS_Percentile,EPSS_Model_Version,EPSS_Score_Date,EPSS_Source,EPSS_Observed_At,EPSS_Source_SHA256
                CVE-2026-10001,0.25,0.95,2025.03.14,2026-08-19,%s,2026-08-19T10:00:00Z,%s
                """.formatted(SOURCE, SHA));
        EpssCsvAnalysisReport report = new EpssCsvAnalyzer().analyze(file, 10);
        assert report.acceptedRows() == 1;
        assert report.uniqueCves() == 1;
        String serialized = report.toMap().toString().toLowerCase();
        assert !serialized.contains("prioritytier");
        assert !serialized.contains("riskscore");
        assert !serialized.contains("sla");
        assert !serialized.contains("cvss");
        assert !serialized.contains("kev");
        assert !serialized.contains("assetcriticality");
    }

    private static Path csv(String content) throws Exception {
        Path path = Files.createTempFile("epss-contract-", ".csv");
        Files.writeString(path, content.stripLeading(), StandardCharsets.UTF_8);
        path.toFile().deleteOnExit();
        return path;
    }
}
