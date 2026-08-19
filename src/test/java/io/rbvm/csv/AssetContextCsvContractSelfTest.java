package io.rbvm.csv;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

public final class AssetContextCsvContractSelfTest {
    private static final String SHA_A = "a".repeat(64);
    private static final String SHA_B = "b".repeat(64);

    private AssetContextCsvContractSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        parsesExplicitOrganizationalContext();
        matchesCanonicalV1AssetNameNormalization();
        acceptsBomAndColumnReordering();
        deduplicatesExactObservationReplay();
        quarantinesConflictingObservationIdentity();
        quarantinesInvalidContextRows();
        rejectsMissingContractHeader();
        keepsCriticalityQualitativeAndEvidenceOnly();
        System.out.println("AssetContextCsvContractSelfTest: PASS");
    }

    private static void parsesExplicitOrganizationalContext() throws Exception {
        String csv = headers()
                + "wazuh-primary,web-01,PRODUCTION,Checkout,Payments Team,MISSION_CRITICAL,CMDB export,2026-08-19T10:00:00Z," + SHA_A + "\r\n"
                + "wazuh-primary,lab-01,UNKNOWN,UNKNOWN,UNKNOWN,UNKNOWN,CMDB export,2026-08-19T10:00:00Z," + SHA_A + "\r\n";
        List<AssetContextCsvEvidence> evidence = new ArrayList<>();
        AssetContextCsvAnalysisReport report = analyze(csv, evidence);

        assert report.contractId().equals(AssetContextCsvContract.ID);
        assert report.semantics().equals(AssetContextCsvContract.SEMANTICS);
        assert report.acceptedRows() == 2;
        assert report.quarantinedRows() == 0;
        assert report.environmentDistribution().get("PRODUCTION") == 1;
        assert report.environmentDistribution().get("UNKNOWN") == 1;
        assert report.criticalityDistribution().get("MISSION_CRITICAL") == 1;
        assert report.criticalityDistribution().get("UNKNOWN") == 1;
        assert evidence.get(0).contextObservedAt().equals(Instant.parse("2026-08-19T10:00:00Z"));
    }

    private static void matchesCanonicalV1AssetNameNormalization() throws Exception {
        List<AssetContextCsvEvidence> evidence = new ArrayList<>();
        analyze(headers()
                + "wazuh-primary,  WEB-０１  ,PRODUCTION,Checkout,Payments Team,HIGH,CMDB,2026-08-19T11:00:00Z," + SHA_A + "\r\n",
                evidence);
        assert evidence.get(0).normalizedAssetName().equals("web-01");
    }

    private static void acceptsBomAndColumnReordering() throws Exception {
        String csv = "\uFEFFAsset_Name,Source_Profile_Key,Business_Criticality,Environment,Business_Owner,Business_Service,Context_Observed_At,Context_Source_SHA256,Context_Source\r\n"
                + "web-02,wazuh-primary,HIGH,PRE_PRODUCTION,Web Team,Portal,2026-08-19T12:00:00Z," + SHA_A + ",CMDB\r\n";
        AssetContextCsvAnalysisReport report = analyze(csv, new ArrayList<>());
        assert report.acceptedRows() == 1;
        assert report.environmentDistribution().get("PRE_PRODUCTION") == 1;
    }

    private static void deduplicatesExactObservationReplay() throws Exception {
        String row = "wazuh-primary,web-03,PRODUCTION,Portal,Web Team,HIGH,CMDB,2026-08-19T13:00:00Z," + SHA_A + "\r\n";
        AssetContextCsvAnalysisReport report = analyze(headers() + row + row, new ArrayList<>());
        assert report.logicalRows() == 2;
        assert report.acceptedRows() == 1;
        assert report.deduplicatedRows() == 1;
        assert report.quarantinedRows() == 0;
    }

    private static void quarantinesConflictingObservationIdentity() throws Exception {
        String csv = headers()
                + "wazuh-primary,WEB-04,PRODUCTION,Payments,Payments Team,HIGH,CMDB,2026-08-19T14:00:00Z," + SHA_A + "\r\n"
                + "wazuh-primary,web-04,PRODUCTION,Payments,Payments Team,MISSION_CRITICAL,CMDB,2026-08-19T14:00:00Z," + SHA_B + "\r\n";
        AssetContextCsvAnalysisReport report = analyze(csv, new ArrayList<>());
        assert report.acceptedRows() == 1;
        assert report.quarantinedRows() == 1;
        assert report.issueSamples().stream()
                .anyMatch(issue -> issue.code().equals("CONFLICTING_ASSET_CONTEXT_OBSERVATION"));
    }

    private static void quarantinesInvalidContextRows() throws Exception {
        String csv = headers()
                + "wazuh-primary,web-05,LIVE,Portal,Web Team,HIGH,CMDB,2026-08-19T15:00:00Z," + SHA_A + "\r\n"
                + "wazuh-primary,web-06,PRODUCTION,Portal,Web Team,EXTREME,CMDB,2026-08-19T15:00:00Z," + SHA_A + "\r\n"
                + "wazuh-primary,web-07,PRODUCTION,,Web Team,HIGH,CMDB,2026-08-19T15:00:00Z," + SHA_A + "\r\n"
                + "wazuh-primary,web-08,PRODUCTION,Portal,Web Team,HIGH,CMDB,2026-08-19," + SHA_A + "\r\n"
                + "wazuh-primary,web-09,PRODUCTION,Portal,Web Team,HIGH,CMDB,2026-08-19T15:00:00Z,ABC\r\n";
        AssetContextCsvAnalysisReport report = analyze(csv, new ArrayList<>());
        assert report.acceptedRows() == 0;
        assert report.quarantinedRows() == 5;
        assert report.issueSamples().stream().anyMatch(issue -> issue.code().equals("INVALID_ENVIRONMENT"));
        assert report.issueSamples().stream().anyMatch(issue -> issue.code().equals("INVALID_BUSINESS_CRITICALITY"));
        assert report.issueSamples().stream().anyMatch(issue -> issue.code().equals("MISSING_REQUIRED_VALUE"));
        assert report.issueSamples().stream().anyMatch(issue -> issue.code().equals("INVALID_CONTEXT_OBSERVED_AT"));
        assert report.issueSamples().stream().anyMatch(issue -> issue.code().equals("INVALID_CONTEXT_SOURCE_SHA256"));
    }

    private static void rejectsMissingContractHeader() throws Exception {
        String csv = "Source_Profile_Key,Asset_Name,Environment,Business_Service,Business_Owner,Business_Criticality,Context_Source,Context_Observed_At\r\n";
        boolean rejected = false;
        try {
            analyze(csv, new ArrayList<>());
        } catch (CsvContractException expected) {
            rejected = expected.getMessage().contains("Context_Source_SHA256");
        }
        assert rejected;
    }

    private static void keepsCriticalityQualitativeAndEvidenceOnly() throws Exception {
        List<AssetContextCsvEvidence> evidence = new ArrayList<>();
        analyze(headers()
                + "wazuh-primary,db-01,PRODUCTION,Ledger,Database Team,MISSION_CRITICAL,CMDB,2026-08-19T16:00:00Z," + SHA_A + "\r\n",
                evidence);
        AssetContextCsvEvidence item = evidence.get(0);
        assert item.businessCriticality() == AssetContextCsvEvidence.BusinessCriticality.MISSION_CRITICAL;
        String source = Files.readString(Path.of("src/main/java/io/rbvm/csv/AssetContextCsvEvidence.java"));
        assert !source.contains("riskScore");
        assert !source.contains("priorityTier");
        assert !source.contains("slaDays");
        assert !source.contains("cvss");
        assert !source.contains("epss");
        assert !source.contains("knownExploited");
    }

    private static AssetContextCsvAnalysisReport analyze(
            String csv,
            List<AssetContextCsvEvidence> evidence
    ) throws Exception {
        Path file = Files.createTempFile("asset-context-csv-", ".csv");
        try {
            Files.writeString(file, csv, StandardCharsets.UTF_8);
            return new AssetContextCsvAnalyzer().analyze(file, 10, evidence::add);
        } finally {
            Files.deleteIfExists(file);
        }
    }

    private static String headers() {
        return "Source_Profile_Key,Asset_Name,Environment,Business_Service,Business_Owner,Business_Criticality,Context_Source,Context_Observed_At,Context_Source_SHA256\r\n";
    }
}
