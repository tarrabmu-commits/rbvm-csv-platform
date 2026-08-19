package io.rbvm.csv;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public final class CisaKevCsvContractSelfTest {
    private static final String SOURCE =
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
    private static final String SHA = "a".repeat(64);

    private CisaKevCsvContractSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        acceptsListedAndSnapshotBoundNotListed();
        rejectsUnknownRowsAndListingMetadataOnNotListed();
        rejectsInvalidSnapshotProvenance();
        deduplicatesExactReplayAndQuarantinesConflict();
        doesNotDerivePriorityRiskEpssOrSla();
        System.out.println("CisaKevCsvContractSelfTest: PASS");
    }

    private static void acceptsListedAndSnapshotBoundNotListed() throws Exception {
        Path file = csv("""
                CVE_ID,KEV_Status,KEV_Catalog_Version,KEV_Catalog_SHA256,KEV_Catalog_Count,KEV_Source,KEV_Observed_At,KEV_Date_Added,KEV_Due_Date,Known_Ransomware_Campaign_Use
                CVE-2026-10001,LISTED,2026.08.19,%s,2,%s,2026-08-19T10:00:00Z,2026-08-18,2026-09-01,KNOWN
                CVE-2026-10002,NOT_LISTED,2026.08.19,%s,2,%s,2026-08-19T10:00:00Z,,,
                """.formatted(SHA, SOURCE, SHA, SOURCE));
        List<CisaKevCsvEvidence> evidence = new ArrayList<>();
        CisaKevCsvAnalysisReport report = new CisaKevCsvAnalyzer().analyze(file, 10, evidence::add);
        assert report.logicalRows() == 2;
        assert report.acceptedRows() == 2;
        assert report.listedRows() == 1;
        assert report.notListedRows() == 1;
        assert report.quarantinedRows() == 0;
        assert report.uniqueSnapshots() == 1;
        assert evidence.get(0).evidence().status() == CisaKevEvidence.Status.LISTED;
        assert evidence.get(1).evidence().status() == CisaKevEvidence.Status.NOT_LISTED;
        assert evidence.get(1).evidence().snapshot().sha256().equals(SHA);
    }

    private static void rejectsUnknownRowsAndListingMetadataOnNotListed() throws Exception {
        Path file = csv("""
                CVE_ID,KEV_Status,KEV_Catalog_Version,KEV_Catalog_SHA256,KEV_Catalog_Count,KEV_Source,KEV_Observed_At,KEV_Date_Added,KEV_Due_Date,Known_Ransomware_Campaign_Use
                CVE-2026-10001,UNKNOWN,2026.08.19,%s,2,%s,2026-08-19T10:00:00Z,,,
                CVE-2026-10002,NOT_LISTED,2026.08.19,%s,2,%s,2026-08-19T10:00:00Z,2026-08-18,,
                """.formatted(SHA, SOURCE, SHA, SOURCE));
        CisaKevCsvAnalysisReport report = new CisaKevCsvAnalyzer().analyze(file, 10);
        assert report.acceptedRows() == 0;
        assert report.quarantinedRows() == 2;
        assert report.issueSamples().stream().anyMatch(issue ->
                issue.code().equals("INVALID_KEV_STATUS"));
        assert report.issueSamples().stream().anyMatch(issue ->
                issue.code().equals("INVALID_KEV_DATE_ADDED"));
    }

    private static void rejectsInvalidSnapshotProvenance() throws Exception {
        Path file = csv("""
                CVE_ID,KEV_Status,KEV_Catalog_Version,KEV_Catalog_SHA256,KEV_Catalog_Count,KEV_Source,KEV_Observed_At,KEV_Date_Added,KEV_Due_Date,Known_Ransomware_Campaign_Use
                CVE-2026-10001,LISTED,2026.08.19,bad,2,%s,2026-08-19T10:00:00Z,2026-08-18,2026-09-01,UNKNOWN
                CVE-2026-10002,NOT_LISTED,2026.08.19,%s,0,%s,2026-08-19T10:00:00Z,,,
                """.formatted(SOURCE, SHA, SOURCE));
        CisaKevCsvAnalysisReport report = new CisaKevCsvAnalyzer().analyze(file, 10);
        assert report.acceptedRows() == 0;
        assert report.quarantinedRows() == 2;
    }

    private static void deduplicatesExactReplayAndQuarantinesConflict() throws Exception {
        Path file = csv("""
                CVE_ID,KEV_Status,KEV_Catalog_Version,KEV_Catalog_SHA256,KEV_Catalog_Count,KEV_Source,KEV_Observed_At,KEV_Date_Added,KEV_Due_Date,Known_Ransomware_Campaign_Use
                CVE-2026-10001,LISTED,2026.08.19,%s,2,%s,2026-08-19T10:00:00Z,2026-08-18,2026-09-01,KNOWN
                CVE-2026-10001,LISTED,2026.08.19,%s,2,%s,2026-08-19T10:00:00Z,2026-08-18,2026-09-01,KNOWN
                CVE-2026-10001,NOT_LISTED,2026.08.19,%s,2,%s,2026-08-19T10:00:00Z,,,
                """.formatted(SHA, SOURCE, SHA, SOURCE, SHA, SOURCE));
        CisaKevCsvAnalysisReport report = new CisaKevCsvAnalyzer().analyze(file, 10);
        assert report.acceptedRows() == 1;
        assert report.deduplicatedRows() == 1;
        assert report.quarantinedRows() == 1;
        assert report.issueSamples().stream().anyMatch(issue ->
                issue.code().equals("CONFLICTING_KEV_EVIDENCE_TIMESTAMP"));
    }

    private static void doesNotDerivePriorityRiskEpssOrSla() throws Exception {
        Path file = csv("""
                CVE_ID,KEV_Status,KEV_Catalog_Version,KEV_Catalog_SHA256,KEV_Catalog_Count,KEV_Source,KEV_Observed_At,KEV_Date_Added,KEV_Due_Date,Known_Ransomware_Campaign_Use
                CVE-2026-10001,LISTED,2026.08.19,%s,1,%s,2026-08-19T10:00:00Z,2026-08-18,2026-09-01,KNOWN
                """.formatted(SHA, SOURCE));
        CisaKevCsvAnalysisReport report = new CisaKevCsvAnalyzer().analyze(file, 10);
        String serialized = report.toMap().toString().toLowerCase();
        assert !serialized.contains("prioritytier");
        assert !serialized.contains("riskscore");
        assert !serialized.contains("epss");
        assert !serialized.contains("sla");
    }

    private static Path csv(String content) throws Exception {
        Path path = Files.createTempFile("cisa-kev-contract-", ".csv");
        Files.writeString(path, content.stripLeading(), StandardCharsets.UTF_8);
        path.toFile().deleteOnExit();
        return path;
    }
}
